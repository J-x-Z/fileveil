// SPDX-License-Identifier: MPL-2.0
//! Bounded offline rendered-pixel adapters for explicitly selected media.
use fileveil_core::{Error, Format, Limits, Result};
use image::DynamicImage;
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::OnceLock,
    thread,
    time::{Duration, Instant},
};

fn executable_file(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn backend(variable: &str, name: &str) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(variable) {
        let path = PathBuf::from(path);
        return path
            .is_absolute()
            .then(|| fs::canonicalize(path).ok())
            .flatten()
            .filter(|p| executable_file(p));
    }
    let executable = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.into()
    };
    let mut paths = Vec::new();
    if let Ok(current) = std::env::current_exe()
        && let Some(parent) = current.parent()
    {
        paths.push(parent.join("backends").join(&executable));
        paths.push(parent.join("../Resources/backends").join(&executable));
    }
    for directory in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"] {
        paths.push(Path::new(directory).join(&executable));
    }
    paths
        .into_iter()
        .find_map(|p| fs::canonicalize(p).ok().filter(|p| executable_file(p)))
}

#[derive(Default)]
struct SipsFormats {
    heic_read: bool,
    heic_write: bool,
    avif_read: bool,
    avif_write: bool,
}
fn sips_formats() -> &'static SipsFormats {
    static FORMATS: OnceLock<SipsFormats> = OnceLock::new();
    FORMATS.get_or_init(|| {
        let mut formats = SipsFormats::default();
        if !cfg!(target_os = "macos") {
            return formats;
        }
        let Ok(output) = Command::new("/usr/bin/sips")
            .arg("--formats")
            .stdin(Stdio::null())
            .output()
        else {
            return formats;
        };
        if !output.status.success() {
            return formats;
        }
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            let writable = fields.contains(&"Writable");
            match fields.get(1).copied() {
                Some("heic" | "heif") => {
                    formats.heic_read = true;
                    formats.heic_write |= writable;
                }
                Some("avif") => {
                    formats.avif_read = true;
                    formats.avif_write |= writable;
                }
                _ => {}
            }
        }
        formats
    })
}

pub fn capabilities() -> Value {
    let sips = sips_formats();
    json!({"offline":true,"rendered_model":"8_bit_rgb_rgba","avif_decode": backend("FILEVEIL_AVIFDEC","avifdec").is_some() || backend("FILEVEIL_HEIFDEC","heif-convert").is_some() || sips.avif_read,
        "avif_encode":backend("FILEVEIL_AVIFENC","avifenc").is_some() || sips.avif_write,
        "heic_decode":backend("FILEVEIL_HEIFDEC","heif-convert").is_some() || sips.heic_read,
        "heic_encode":backend("FILEVEIL_HEIFENC","heif-enc").is_some() || sips.heic_write,
        "video_frame_audit": backend("FILEVEIL_FFMPEG","ffmpeg").is_some(),"auxiliary_hdr_sequences":"protected_from_pixel_rewriting"})
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn run(program: &Path, arguments: &[OsString], output: &Path, cap: u64) -> Result<()> {
    if !run_optional_output(program, arguments, output, cap)? {
        return Err(Error::Verification("Media codec produced no output".into()));
    }
    Ok(())
}
fn run_optional_output(
    program: &Path,
    arguments: &[OsString],
    output: &Path,
    cap: u64,
) -> Result<bool> {
    let child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error::Unsupported("Media codec backend could not be started".into()))?;
    let mut guard = ChildGuard(child);
    let start = Instant::now();
    loop {
        output_exists(output, cap)?;
        if start.elapsed() > Duration::from_secs(45) {
            return Err(Error::Interrupted(
                "Media codec exceeded its 45-second execution budget".into(),
            ));
        }
        if let Some(status) = guard
            .0
            .try_wait()
            .map_err(|_| Error::Io("Media backend status failed".into()))?
        {
            if !status.success() {
                return Err(Error::Blocked(
                    "Media codec rejected the selected content or encoding".into(),
                ));
            }
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    output_exists(output, cap)
}
fn output_exists(output: &Path, cap: u64) -> Result<bool> {
    let metadata = match fs::symlink_metadata(output) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(Error::Io("Could not inspect private media output".into())),
    };
    if !metadata.is_file() || metadata.len() > cap {
        return Err(Error::Blocked(
            "Media intermediate is not a bounded regular file".into(),
        ));
    }
    Ok(true)
}
fn scratch() -> Result<tempfile::TempDir> {
    let parent = std::env::var_os("FILEVEIL_PDF_STAGING")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    tempfile::Builder::new()
        .prefix(".fileveil-codec-")
        .tempdir_in(parent)
        .map_err(|_| Error::Io("Could not create private media workspace".into()))
}
fn rendered_budget(limits: &Limits) -> u64 {
    limits.max_file_bytes.min(
        limits
            .max_pixels
            .saturating_mul(8)
            .saturating_add(1024 * 1024),
    )
}

pub struct RenderedImage {
    pub image: DynamicImage,
    pub icc_profile: Option<Vec<u8>>,
}
pub fn decode(data: &[u8], format: Format, limits: &Limits) -> Result<DynamicImage> {
    Ok(decode_rendered(data, format, limits)?.image)
}
pub fn decode_rendered(data: &[u8], format: Format, limits: &Limits) -> Result<RenderedImage> {
    if matches!(format, Format::Jpeg | Format::Png) {
        return Ok(RenderedImage {
            image: crate::decode_pixels(data, limits)?,
            icc_profile: crate::image_processing::decode_profile(data, limits)?,
        });
    }
    if !matches!(format, Format::Heic | Format::Avif) {
        return Err(Error::Unsupported(
            "Rendered pixel audit supports JPEG, PNG, HEIC and AVIF".into(),
        ));
    }
    fileveil_formats::bmff::inspect(data, format, limits)?;
    fileveil_formats::bmff::validate_decoder_references(data, format, limits)?;
    fileveil_formats::bmff::validate_pixel_dimensions(data, format, limits)?;
    let directory = scratch()?;
    let input = directory.path().join(if format == Format::Avif {
        "snapshot.avif"
    } else {
        "snapshot.heic"
    });
    let output = directory.path().join("rendered.png");
    fs::write(&input, data).map_err(|_| Error::Io("Could not stage media snapshot".into()))?;
    if format == Format::Avif
        && let Some(program) = backend("FILEVEIL_AVIFDEC", "avifdec")
    {
        run(
            &program,
            &[
                "--jobs".into(),
                "1".into(),
                "--depth".into(),
                "8".into(),
                "--size-limit".into(),
                limits.max_pixels.to_string().into(),
                "--".into(),
                input.into_os_string(),
                output.clone().into_os_string(),
            ],
            &output,
            rendered_budget(limits),
        )?;
    } else if if format == Format::Avif {
        sips_formats().avif_read
    } else {
        sips_formats().heic_read
    } {
        run(
            Path::new("/usr/bin/sips"),
            &[
                "-s".into(),
                "format".into(),
                "png".into(),
                input.into_os_string(),
                "--out".into(),
                output.clone().into_os_string(),
            ],
            &output,
            rendered_budget(limits),
        )?;
    } else {
        let program = backend("FILEVEIL_HEIFDEC", "heif-convert")
            .ok_or_else(|| Error::Unsupported("A trusted HEIF decoder is unavailable".into()))?;
        run(
            &program,
            &[input.into_os_string(), output.clone().into_os_string()],
            &output,
            rendered_budget(limits),
        )?;
    }
    let png = fs::read(output).map_err(|_| Error::Io("Could not read rendered media".into()))?;
    Ok(RenderedImage {
        image: crate::decode_pixels(&png, limits)?,
        icc_profile: crate::image_processing::decode_profile(&png, limits)?,
    })
}

pub fn encode(
    image: &DynamicImage,
    format: Format,
    quality: u8,
    profile: Option<&[u8]>,
    limits: &Limits,
) -> Result<Vec<u8>> {
    if !matches!(format, Format::Heic | Format::Avif) || !(1..=100).contains(&quality) {
        return Err(Error::Input(
            "Media encoding requires HEIC/AVIF and quality 1..100".into(),
        ));
    }
    if image.width() == 0
        || image.height() == 0
        || u64::from(image.width()) * u64::from(image.height()) > limits.max_pixels
    {
        return Err(Error::Blocked("Image exceeds the pixel budget".into()));
    }
    if !matches!(
        image,
        DynamicImage::ImageRgb8(_) | DynamicImage::ImageRgba8(_)
    ) {
        return Err(Error::Blocked(
            "Rendered media encoding requires an explicit 8-bit RGB/RGBA representation".into(),
        ));
    }
    if profile.is_some_and(|profile| profile.len() > limits.max_metadata_bytes) {
        return Err(Error::Blocked(
            "Media color profile exceeds the metadata budget".into(),
        ));
    }
    let directory = scratch()?;
    let input = directory.path().join("pixels.png");
    let output = directory.path().join(if format == Format::Avif {
        "processed.avif"
    } else {
        "processed.heic"
    });
    use image::ImageEncoder;
    let output_file = fs::File::create(&input)
        .map_err(|_| Error::Io("Could not stage rendered pixels".into()))?;
    let mut encoder = image::codecs::png::PngEncoder::new(output_file);
    if let Some(profile) = profile {
        encoder.set_icc_profile(profile.to_vec()).map_err(|_| {
            Error::Verification("Media intermediate cannot preserve its ICC profile".into())
        })?;
    }
    encoder
        .write_image(
            image.as_bytes(),
            image.width(),
            image.height(),
            image.color().into(),
        )
        .map_err(|_| Error::Io("Could not encode rendered pixels".into()))?;
    output_exists(&input, rendered_budget(limits))?;
    if format == Format::Avif
        && let Some(program) = backend("FILEVEIL_AVIFENC", "avifenc")
    {
        run(
            &program,
            &[
                "--jobs".into(),
                "1".into(),
                "--speed".into(),
                "9".into(),
                "--qcolor".into(),
                quality.to_string().into(),
                "--qalpha".into(),
                "100".into(),
                "--yuv".into(),
                "444".into(),
                input.into_os_string(),
                output.clone().into_os_string(),
            ],
            &output,
            limits.max_file_bytes,
        )?;
    } else if if format == Format::Avif {
        sips_formats().avif_write
    } else {
        sips_formats().heic_write
    } {
        run(
            Path::new("/usr/bin/sips"),
            &[
                "-s".into(),
                "format".into(),
                if format == Format::Avif {
                    "avif".into()
                } else {
                    "heic".into()
                },
                "-s".into(),
                "formatOptions".into(),
                quality.to_string().into(),
                input.into_os_string(),
                "--out".into(),
                output.clone().into_os_string(),
            ],
            &output,
            limits.max_file_bytes,
        )?;
    } else {
        if format == Format::Avif {
            return Err(Error::Unsupported(
                "A trusted AVIF encoder is unavailable".into(),
            ));
        }
        let program = backend("FILEVEIL_HEIFENC", "heif-enc")
            .ok_or_else(|| Error::Unsupported("A trusted HEIF encoder is unavailable".into()))?;
        run(
            &program,
            &[
                "-q".into(),
                quality.to_string().into(),
                "-o".into(),
                output.clone().into_os_string(),
                input.into_os_string(),
            ],
            &output,
            limits.max_file_bytes,
        )?;
    }
    let bytes = fs::read(output).map_err(|_| Error::Io("Could not read encoded media".into()))?;
    fileveil_formats::bmff::inspect(&bytes, format, limits)?;
    fileveil_formats::bmff::validate_pixel_rewrite(&bytes, format, limits)?;
    Ok(bytes)
}

/// Selected frames are decoded with network protocols excluded and no audio execution.
pub fn video_frames(
    data: &[u8],
    format: Format,
    limits: &Limits,
    count: u8,
) -> Result<Vec<DynamicImage>> {
    if !matches!(format, Format::Mp4 | Format::Mov) || !(1..=8).contains(&count) {
        return Err(Error::Input(
            "Video research accepts MP4/MOV and 1..8 frames".into(),
        ));
    }
    fileveil_formats::bmff::inspect(data, format, limits)?;
    fileveil_formats::bmff::validate_decoder_references(data, format, limits)?;
    let program = backend("FILEVEIL_FFMPEG", "ffmpeg").ok_or_else(|| {
        Error::Unsupported("Video frame research requires a configured local FFmpeg backend".into())
    })?;
    let directory = scratch()?;
    let input = directory.path().join(if format == Format::Mp4 {
        "snapshot.mp4"
    } else {
        "snapshot.mov"
    });
    fs::write(&input, data).map_err(|_| Error::Io("Could not stage video snapshot".into()))?;
    let mut frames = Vec::new();
    let mut pixels = 0u64;
    for index in 0..count {
        let output = directory.path().join("frame.png");
        // Select bounded whole-second observations. An absent later frame ends sampling.
        let present = run_optional_output(
            &program,
            &[
                "-nostdin".into(),
                "-v".into(),
                "error".into(),
                "-protocol_whitelist".into(),
                "file,pipe".into(),
                "-threads".into(),
                "1".into(),
                "-max_pixels".into(),
                limits.max_pixels.to_string().into(),
                "-ss".into(),
                index.to_string().into(),
                "-i".into(),
                input.clone().into_os_string(),
                "-map".into(),
                "0:v:0".into(),
                "-frames:v".into(),
                "1".into(),
                "-an".into(),
                "-sn".into(),
                "-dn".into(),
                "-y".into(),
                output.clone().into_os_string(),
            ],
            &output,
            rendered_budget(limits),
        )?;
        if !present {
            if index > 0 {
                break;
            }
            return Err(Error::Verification(
                "Video decoder produced no primary frame".into(),
            ));
        }
        let frame = crate::decode_pixels(
            &fs::read(&output).map_err(|_| Error::Io("Could not read video frame".into()))?,
            limits,
        )?;
        pixels = pixels.saturating_add(u64::from(frame.width()) * u64::from(frame.height()));
        if pixels > limits.max_pixels {
            return Err(Error::Blocked(
                "Video frames exceed the aggregate pixel budget".into(),
            ));
        }
        frames.push(frame);
        fs::remove_file(&output)
            .map_err(|_| Error::Io("Could not recycle private video frame".into()))?;
    }
    Ok(frames)
}
