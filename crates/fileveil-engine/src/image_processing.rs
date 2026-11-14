// SPDX-License-Identifier: MPL-2.0
//! Explicit image-sample transformations with recipe-bound verification.
//! These operations do not identify or certify removal of unknown watermarks.
use super::{Snapshot, decode_pixels, os, output_directory, publish, unassessed};
use fileveil_core::{
    Action, Confidence, Error, Finding, FindingState, Format, ImageProcessMode,
    ImageProcessOptions, ImageProcessingReport, Integrity, Limits, Outcome, Policy, Report, Result,
    RiskLayer, digest,
};
use image::{
    DynamicImage, ExtendedColorType, ImageDecoder, ImageEncoder, ImageReader, RgbImage,
    codecs::{jpeg::JpegEncoder, png::PngEncoder},
    imageops::{self, FilterType},
};
use std::{
    io::{Cursor, Write},
    path::Path,
};

const RESIZE_SCALE: f64 = 0.95;
const BLUR_SIGMA: f64 = 0.5;
const JPEG_QUALITY: u8 = 88;

fn validate_options(options: &ImageProcessOptions) -> Result<()> {
    if options.mode == ImageProcessMode::LowBits && !(1..=3).contains(&options.low_bits) {
        return Err(Error::Input(
            "RGB low-bit processing accepts 1, 2 or 3 bits".into(),
        ));
    }
    Ok(())
}
fn validate_output_path(output: Option<&Path>) -> Result<()> {
    if output
        .and_then(Path::extension)
        .is_some_and(|extension| !extension.eq_ignore_ascii_case("png"))
    {
        return Err(Error::Input(
            "Processed images use lossless PNG output. Choose a PNG output path".into(),
        ));
    }
    Ok(())
}
fn inspect_input(
    snapshot: &Snapshot,
    hint: &Path,
    limits: &Limits,
) -> Result<fileveil_core::Inspection> {
    let inspection = super::inspect_snapshot(&snapshot.bytes, hint, limits)?;
    if !inspection.format.is_image() {
        return Err(Error::Unsupported(
            "Image processing supports JPEG and PNG inputs".into(),
        ));
    }
    if !inspection.blockers.is_empty() {
        return Err(Error::Blocked(inspection.blockers.join(". ")));
    }
    if snapshot
        .attributes
        .iter()
        .any(|attribute| attribute.name == "com.apple.ResourceFork")
    {
        return Err(Error::Blocked(
            "Resource-fork images require a semantic-preservation backend".into(),
        ));
    }
    if inspection.format == Format::Png
        && snapshot
            .bytes
            .get(24..26)
            .is_none_or(|header| header[0] != 8 || !matches!(header[1], 2 | 6))
    {
        return Err(Error::Unsupported(
            "Image processing currently requires 8-bit RGB or RGBA PNG samples".into(),
        ));
    }
    if inspection.format == Format::Jpeg && jpeg_components(&snapshot.bytes)? != 3 {
        return Err(Error::Unsupported(
            "Image processing currently requires three-component JPEG images".into(),
        ));
    }
    Ok(inspection)
}
fn jpeg_components(data: &[u8]) -> Result<u8> {
    let mut offset = 2usize;
    while offset < data.len() {
        while data.get(offset) == Some(&0xff) {
            offset += 1;
        }
        let marker = *data
            .get(offset)
            .ok_or_else(|| Error::Blocked("Truncated JPEG marker".into()))?;
        offset += 1;
        if marker == 0x01 {
            continue;
        }
        let length = data
            .get(offset..offset + 2)
            .ok_or_else(|| Error::Blocked("Truncated JPEG header".into()))?;
        let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
        if matches!(marker, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf) {
            if data.get(offset + 2) != Some(&8) {
                return Err(Error::Unsupported(
                    "Image processing requires 8-bit JPEG sample precision".into(),
                ));
            }
            return data
                .get(offset + 7)
                .copied()
                .ok_or_else(|| Error::Blocked("Truncated JPEG frame".into()));
        }
        offset = offset
            .checked_add(length)
            .filter(|value| *value <= data.len())
            .ok_or_else(|| Error::Blocked("Invalid JPEG segment length".into()))?;
    }
    Err(Error::Blocked("JPEG frame header is missing".into()))
}
pub(crate) fn decode_profile(data: &[u8], limits: &Limits) -> Result<Option<Vec<u8>>> {
    let reader = ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .map_err(|_| Error::Verification("Could not identify image color metadata".into()))?;
    let mut decoder = reader
        .into_decoder()
        .map_err(|_| Error::Verification("Could not decode image color metadata".into()))?;
    let profile = decoder
        .icc_profile()
        .map_err(|_| Error::Blocked("Could not read the image ICC profile".into()))?;
    if let Some(profile) = &profile {
        if profile.len() > limits.max_metadata_bytes {
            return Err(Error::Blocked(
                "ICC profile exceeds the metadata limit".into(),
            ));
        }
        if profile.len() < 128
            || profile.get(36..40) != Some(b"acsp")
            || profile.get(16..20) != Some(b"RGB ")
        {
            return Err(Error::Blocked(
                "ICC profile is invalid or incompatible with RGB image processing".into(),
            ));
        }
    }
    Ok(profile)
}

fn transform(
    original: &DynamicImage,
    options: &ImageProcessOptions,
    limits: &Limits,
) -> Result<DynamicImage> {
    if !matches!(
        original,
        DynamicImage::ImageRgb8(_) | DynamicImage::ImageRgba8(_)
    ) {
        return Err(Error::Unsupported(
            "Image processing requires decoded 8-bit RGB or RGBA samples".into(),
        ));
    }
    match options.mode {
        ImageProcessMode::LowBits => {
            let mut output = original.clone();
            let (samples, channels): (&mut [u8], usize) = match &mut output {
                DynamicImage::ImageRgb8(image) => (image.as_mut(), 3),
                DynamicImage::ImageRgba8(image) => (image.as_mut(), 4),
                _ => return Err(Error::Unsupported("Unsupported image samples".into())),
            };
            let keep = u8::MAX << options.low_bits;
            for pixel in samples.chunks_exact_mut(channels) {
                for sample in &mut pixel[..3] {
                    *sample &= keep;
                }
            }
            Ok(output)
        }
        ImageProcessMode::Signal => {
            let rgb = match original {
                DynamicImage::ImageRgb8(rgb) => std::borrow::Cow::Borrowed(rgb),
                _ => std::borrow::Cow::Owned(original.to_rgb8()),
            };
            let down_width = (u64::from(rgb.width()) * 95 / 100).max(1) as u32;
            let down_height = (u64::from(rgb.height()) * 95 / 100).max(1) as u32;
            let smaller =
                imageops::resize(rgb.as_ref(), down_width, down_height, FilterType::Lanczos3);
            let restored =
                imageops::resize(&smaller, rgb.width(), rgb.height(), FilterType::Lanczos3);
            drop(smaller);
            drop(rgb);
            let blurred: RgbImage = imageops::blur(&restored, BLUR_SIGMA as f32);
            drop(restored);
            let mut encoded = Vec::new();
            JpegEncoder::new_with_quality(&mut encoded, JPEG_QUALITY)
                .write_image(
                    blurred.as_raw(),
                    blurred.width(),
                    blurred.height(),
                    ExtendedColorType::Rgb8,
                )
                .map_err(|_| {
                    Error::Verification("JPEG signal transformation could not be encoded".into())
                })?;
            if encoded.len() as u64 > limits.max_file_bytes {
                return Err(Error::Blocked(
                    "Intermediate JPEG exceeds the configured byte limit".into(),
                ));
            }
            drop(blurred);
            let jpeg = decode_pixels(&encoded, limits)?.into_rgb8();
            drop(encoded);
            if let DynamicImage::ImageRgba8(source) = original {
                let mut output = source.clone();
                for (destination, rgb) in output.pixels_mut().zip(jpeg.pixels()) {
                    destination.0[..3].copy_from_slice(&rgb.0);
                }
                Ok(DynamicImage::ImageRgba8(output))
            } else {
                Ok(DynamicImage::ImageRgb8(jpeg))
            }
        }
    }
}

pub(crate) fn color_chunks(data: &[u8]) -> Result<Vec<(&[u8], &[u8])>> {
    if !data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Ok(Vec::new());
    }
    let mut offset = 8usize;
    let mut chunks = Vec::new();
    while offset < data.len() {
        let header = data
            .get(offset..offset + 8)
            .ok_or_else(|| Error::Blocked("Truncated PNG color record".into()))?;
        let length = u32::from_be_bytes(
            header[..4]
                .try_into()
                .map_err(|_| Error::Blocked("Invalid PNG length".into()))?,
        ) as usize;
        let end = offset
            .checked_add(length)
            .and_then(|value| value.checked_add(12))
            .filter(|end| *end <= data.len())
            .ok_or_else(|| Error::Blocked("PNG color record exceeds the container".into()))?;
        let kind = &header[4..8];
        if matches!(
            kind,
            b"iCCP"
                | b"sRGB"
                | b"gAMA"
                | b"cHRM"
                | b"sBIT"
                | b"pHYs"
                | b"bKGD"
                | b"cICP"
                | b"mDCV"
                | b"cLLI"
                | b"mDCv"
                | b"cLLi"
        ) {
            chunks.push((kind, &data[offset..end]));
        }
        offset = end;
        if kind == b"IEND" {
            break;
        }
    }
    Ok(chunks)
}
pub(crate) fn encode_png(
    image: &DynamicImage,
    source: &[u8],
    profile: Option<Vec<u8>>,
) -> Result<Vec<u8>> {
    let retained = color_chunks(source)?;
    if retained.iter().any(|(kind, chunk)| {
        *kind == b"sBIT" && chunk.len() - 12 != usize::from(image.color().channel_count())
    }) {
        return Err(Error::Unsupported(
            "PNG significant-bit metadata requires matching output channels".into(),
        ));
    }
    let mut encoded = Vec::new();
    let mut encoder = PngEncoder::new(&mut encoded);
    if !source.starts_with(b"\x89PNG\r\n\x1a\n")
        && let Some(profile) = profile
    {
        encoder
            .set_icc_profile(profile)
            .map_err(|_| Error::Blocked("PNG output cannot preserve the ICC profile".into()))?;
    }
    encoder
        .write_image(
            image.as_bytes(),
            image.width(),
            image.height(),
            image.color().into(),
        )
        .map_err(|_| Error::Verification("Processed PNG encoding failed".into()))?;
    if retained.is_empty() {
        return Ok(encoded);
    }
    let header_end = 33;
    let mut output = Vec::with_capacity(
        encoded.len() + retained.iter().map(|(_, chunk)| chunk.len()).sum::<usize>(),
    );
    output.extend_from_slice(
        encoded.get(..header_end).ok_or_else(|| {
            Error::Verification("PNG encoder produced an incomplete header".into())
        })?,
    );
    for (_, chunk) in retained {
        output.extend_from_slice(chunk);
    }
    output.extend_from_slice(&encoded[header_end..]);
    Ok(output)
}

fn metrics(
    original: &DynamicImage,
    output: &DynamicImage,
    options: &ImageProcessOptions,
) -> Result<ImageProcessingReport> {
    if original.width() != output.width()
        || original.height() != output.height()
        || original.color() != output.color()
    {
        return Err(Error::Verification(
            "Processed image dimensions or sample type differ from the recipe".into(),
        ));
    }
    let channels = usize::from(original.color().channel_count());
    let mut changed_samples = 0u64;
    let mut max_delta = 0u8;
    let mut squared_error = 0u64;
    let mut low_bits_clear = true;
    let low_mask = if options.mode == ImageProcessMode::LowBits {
        (1u8 << options.low_bits) - 1
    } else {
        0
    };
    for (before, after) in original
        .as_bytes()
        .chunks_exact(channels)
        .zip(output.as_bytes().chunks_exact(channels))
    {
        if channels == 4 && before[3] != after[3] {
            return Err(Error::Verification(
                "Image processing changed alpha samples".into(),
            ));
        }
        for channel in 0..3 {
            let delta = before[channel].abs_diff(after[channel]);
            changed_samples += u64::from(delta != 0);
            max_delta = max_delta.max(delta);
            squared_error += u64::from(delta) * u64::from(delta);
            low_bits_clear &= after[channel] & low_mask == 0;
        }
    }
    if options.mode == ImageProcessMode::LowBits && (!low_bits_clear || max_delta > low_mask) {
        return Err(Error::Verification(
            "Decoded output did not satisfy the RGB low-bit clearing guarantee".into(),
        ));
    }
    let signal = options.mode == ImageProcessMode::Signal;
    Ok(ImageProcessingReport {
        mode: options.mode,
        low_bits: (!signal).then_some(options.low_bits),
        resize_scale: signal.then_some(RESIZE_SCALE),
        blur_sigma: signal.then_some(BLUR_SIGMA),
        jpeg_quality: signal.then_some(JPEG_QUALITY),
        input_dimensions: [original.width(), original.height()],
        output_dimensions: [output.width(), output.height()],
        changed_samples,
        max_delta,
        mse: squared_error as f64
            / (u64::from(original.width()) * u64::from(original.height()) * 3) as f64,
        verified_low_bits: (!signal).then_some(low_bits_clear),
        detector_status: "not_assessed".into(),
    })
}

fn verify_snapshots(
    original: &Snapshot,
    output: &Snapshot,
    input_hint: &Path,
    options: &ImageProcessOptions,
    limits: &Limits,
) -> Result<Report> {
    validate_options(options)?;
    let before = inspect_input(original, input_hint, limits)?;
    let after = fileveil_formats::inspect(&output.bytes, Path::new("processed.png"), limits)?;
    if after.format != Format::Png || !after.blockers.is_empty() {
        return Err(Error::Verification(
            "Processed output must be a valid static PNG".into(),
        ));
    }
    if after
        .findings
        .iter()
        .any(|finding| matches!(finding.action, Action::Remove | Action::Normalize))
    {
        return Err(Error::Verification(
            "Rebuilt PNG still contains supported privacy metadata".into(),
        ));
    }
    if original.attributes != output.attributes {
        return Err(Error::Verification(
            "Platform attributes or security markers differ".into(),
        ));
    }
    let input_profile = decode_profile(&original.bytes, limits)?;
    if input_profile != decode_profile(&output.bytes, limits)? {
        return Err(Error::Verification(
            "Processed output changed the ICC profile".into(),
        ));
    }
    let before_colors = color_chunks(&original.bytes)?;
    let after_colors = color_chunks(&output.bytes)?;
    if before.format == Format::Png {
        if before_colors != after_colors {
            return Err(Error::Verification(
                "Processed PNG changed preserved color or display records".into(),
            ));
        }
    } else if after_colors.iter().any(|(kind, _)| *kind != b"iCCP") {
        return Err(Error::Verification(
            "JPEG conversion added unexpected PNG display records".into(),
        ));
    }
    let input_pixels = decode_pixels(&original.bytes, limits)?;
    let actual = decode_pixels(&output.bytes, limits)?;
    let expected = transform(&input_pixels, options, limits)?;
    if expected.color() != actual.color()
        || expected.width() != actual.width()
        || expected.height() != actual.height()
        || expected.as_bytes() != actual.as_bytes()
    {
        return Err(Error::Verification(
            "Decoded output does not match the requested image-processing recipe".into(),
        ));
    }
    drop(expected);
    let processing = metrics(&input_pixels, &actual, options)?;
    let equal = input_pixels.as_bytes() == actual.as_bytes();
    let mut report = Report::new("verify", before.format);
    report.policy = Policy::Research;
    report.result = Outcome::PartiallyVerified;
    report.input_sha256 = Some(digest(&original.bytes));
    report.output_sha256 = Some(digest(&output.bytes));
    report.integrity = Integrity {
        parseable: true,
        decodeable: Some(true),
        pixel_equal: Some(equal),
        content_equal: Some(equal),
        original_unchanged: Some(true),
        security_markers_preserved: Some(true),
    };
    for mut finding in before.findings {
        if finding.code.ends_with(".icc") {
            finding.location = "PNG/iCCP".into();
            finding.action = Action::Preserve;
            finding.state = FindingState::Remains;
        } else if after.findings.iter().any(|retained| {
            retained.code == finding.code
                && retained.location.split(" at byte ").next()
                    == finding.location.split(" at byte ").next()
        }) {
            finding.state = FindingState::Remains;
        } else {
            if finding.action == Action::AskUser {
                finding.summary =
                    "Original ancillary record was omitted when rebuilding the PNG".into();
            }
            finding.action = Action::Remove;
            finding.state = FindingState::RemovedVerified;
            finding.confidence = Confidence::Verified;
        }
        report.findings.push(finding);
    }
    report.findings.extend(
        os::findings(&original.attributes)
            .into_iter()
            .map(|mut finding| {
                finding.state = FindingState::Remains;
                finding
            }),
    );
    report.findings.extend(unassessed(before.format));
    let mut executed = Finding::new(
        "image.processing.executed",
        RiskLayer::ContentWatermark,
        "RGB sample matrix",
        "Requested image transformation was applied and redecoded for recipe verification",
        Action::Rebuild,
    );
    executed.confidence = Confidence::Verified;
    executed.state = FindingState::AppliedVerified;
    report.findings.push(executed);
    report.warnings.push("PNG rebuilding intentionally changes image samples and omits original privacy metadata and non-color ancillary records.".into());
    report.warnings.push("Color profiles, applicable PNG display records, alpha samples and readable platform attributes are preserved.".into());
    report.warnings.push("Compiled-in synthetic LSB and public Stable Diffusion dwtDct detectors were repeated after processing. Unknown and proprietary watermarks remain unassessed. Low-bit clearing alone establishes sample-bit clearing.".into());
    let detections_before =
        crate::watermark::detect_decoded(Some(&input_pixels), before.format, limits)?;
    let detections_after = crate::watermark::detect_decoded(Some(&actual), Format::Png, limits)?;
    let detector_retests = detections_before
        .iter()
        .zip(&detections_after)
        .map(|(before, after)| {
            serde_json::json!({
                "method_id": before.method_id,
                "before": before,
                "after": after,
                "result": retest_result(before.status, after.status),
                "scope": "same_method_retest"
            })
        })
        .collect::<Vec<_>>();
    let detected_before = &detections_before[0];
    let detected_after = &detections_after[0];
    report.advanced = Some(serde_json::json!({
        "signal_processing": "algorithm_applied",
        "watermark_retest": {
            "method_id": "synthetic_lsb_v1",
            "before": detected_before,
            "after": detected_after,
            "result": retest_result(detected_before.status, detected_after.status),
            "scope": "fileveil_synthetic_packet_only"
        },
        "detector_retests": detector_retests
    }));
    report.image_processing = Some(processing);
    Ok(report)
}

fn retest_result(
    before: crate::watermark::DetectionStatus,
    after: crate::watermark::DetectionStatus,
) -> &'static str {
    use crate::watermark::DetectionStatus::{Detected, NotDetected};
    match (before, after) {
        (Detected, NotDetected) => "detector_no_longer_detects",
        (Detected, Detected) => "detector_still_detects",
        (Detected, _) => "indeterminate",
        _ => "not_assessed",
    }
}

pub fn process_image_in(
    input: &Path,
    output: Option<&Path>,
    options: &ImageProcessOptions,
    limits: &Limits,
    staging: Option<&Path>,
) -> Result<Report> {
    validate_options(options)?;
    validate_output_path(output)?;
    if let Some(path) = output {
        super::ensure_new_path(path)?;
    }
    let original = Snapshot::open(input, limits)?;
    inspect_input(&original, input, limits)?;
    let profile = decode_profile(&original.bytes, limits)?;
    let image = decode_pixels(&original.bytes, limits)?;
    let transformed = transform(&image, options, limits)?;
    let encoded = encode_png(&transformed, &original.bytes, profile)?;
    drop(transformed);
    drop(image);
    if encoded.len() as u64 > limits.max_file_bytes {
        return Err(Error::Blocked(
            "Processed PNG exceeds the configured byte limit".into(),
        ));
    }
    let directory = output_directory(input, output);
    let mut temporary = tempfile::Builder::new()
        .prefix(".fileveil-image-")
        .tempfile_in(staging.unwrap_or(&directory))
        .map_err(|_| Error::Io("Could not create private image-processing staging file".into()))?;
    temporary
        .write_all(&encoded)
        .map_err(|_| Error::Io("Could not write processed PNG".into()))?;
    drop(encoded);
    os::write(temporary.as_file(), temporary.path(), &original.attributes)?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| Error::Io("Could not synchronize processed PNG".into()))?;
    let candidate = Snapshot::open(temporary.path(), limits)?;
    let mut report = verify_snapshots(&original, &candidate, input, options, limits)?;
    if !original.unchanged(input, limits)? {
        return Err(Error::Blocked(
            "Original changed during image processing".into(),
        ));
    }
    let png_hint = input.with_extension("png");
    let target = publish(temporary.into_temp_path(), &png_hint, output)?;
    report.operation = "sanitize".into();
    report.output_name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned());
    Ok(report)
}

pub fn verify_processed_image(
    original: &Path,
    output: &Path,
    options: &ImageProcessOptions,
    limits: &Limits,
) -> Result<Report> {
    let first = Snapshot::open(original, limits)?;
    let second = Snapshot::open(output, limits)?;
    let report = verify_snapshots(&first, &second, original, options, limits)?;
    if !first.unchanged(original, limits)? || !second.unchanged(output, limits)? {
        return Err(Error::Blocked(
            "A verification input changed during image-processing checks".into(),
        ));
    }
    Ok(report)
}

pub fn publish_processed_staged(
    input: &Path,
    staged: &Path,
    output: Option<&Path>,
    report: &mut Report,
    limits: &Limits,
) -> Result<()> {
    validate_output_path(output)?;
    let processing = report
        .image_processing
        .as_ref()
        .ok_or_else(|| Error::Verification("Image-processing report is missing".into()))?;
    let options = ImageProcessOptions {
        mode: processing.mode,
        low_bits: processing.low_bits.unwrap_or(2),
    };
    validate_options(&options)?;
    if report.operation != "sanitize"
        || report.policy != Policy::Research
        || report.result != Outcome::PartiallyVerified
        || !report.integrity.parseable
        || report.integrity.decodeable != Some(true)
        || report.integrity.original_unchanged != Some(true)
        || report.integrity.security_markers_preserved != Some(true)
        || processing.detector_status != "not_assessed"
        || (processing.mode == ImageProcessMode::LowBits
            && processing.verified_low_bits != Some(true))
    {
        return Err(Error::Verification(
            "Worker report does not authorize processed artifact publication".into(),
        ));
    }
    let original = Snapshot::open(input, limits)?;
    let artifact = Snapshot::open(staged, limits)?;
    super::ensure_new_artifact(&original.file, &artifact.file)?;
    if report.input_sha256.as_deref() != Some(digest(&original.bytes).as_str())
        || report.output_sha256.as_deref() != Some(digest(&artifact.bytes).as_str())
        || original.attributes != artifact.attributes
    {
        return Err(Error::Blocked(
            "Image-processing input or private artifact changed before publication".into(),
        ));
    }
    let temporary = tempfile::TempPath::try_from_path(staged)
        .map_err(|_| Error::Io("Could not acquire processed artifact".into()))?;
    drop(artifact);
    let target = publish(temporary, &input.with_extension("png"), output)?;
    report.output_name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn frame() -> DynamicImage {
        let payload = b"FileVeil";
        let mut image = image::RgbaImage::new(8, 8);
        for (index, pixel) in image.pixels_mut().enumerate() {
            let bit = (payload[index / 8] >> (7 - index % 8)) & 1;
            *pixel = image::Rgba([
                ((index * 3) as u8 & !7) | bit,
                (index * 29) as u8 | 7,
                (index * 11) as u8 | 7,
                (index * 17) as u8,
            ]);
        }
        DynamicImage::ImageRgba8(image)
    }
    fn png(image: &DynamicImage) -> Vec<u8> {
        let mut bytes = Vec::new();
        PngEncoder::new(&mut bytes)
            .write_image(
                image.as_bytes(),
                image.width(),
                image.height(),
                image.color().into(),
            )
            .unwrap();
        bytes
    }
    fn chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(kind);
        bytes.extend_from_slice(payload);
        let mut crc = u32::MAX;
        for byte in &bytes[4..] {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
            }
        }
        bytes.extend_from_slice(&(!crc).to_be_bytes());
        bytes
    }
    fn write_frame(directory: &Path) -> std::path::PathBuf {
        let path = directory.join("synthetic.png");
        fs::write(&path, png(&frame())).unwrap();
        path
    }
    fn fixture(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    #[test]
    fn synthetic_lsb_payload_is_cleared_alpha_preserved_and_error_bounded() {
        for bits in 1..=3 {
            let directory = tempfile::tempdir().unwrap();
            let input = write_frame(directory.path());
            let output = directory.path().join("processed.png");
            let original = fs::read(&input).unwrap();
            let options = ImageProcessOptions {
                mode: ImageProcessMode::LowBits,
                low_bits: bits,
            };
            let report =
                process_image_in(&input, Some(&output), &options, &Limits::default(), None)
                    .unwrap();
            assert_eq!(report.policy, Policy::Research);
            assert_eq!(report.result, Outcome::PartiallyVerified);
            let summary = report.image_processing.as_ref().unwrap();
            assert_eq!(summary.verified_low_bits, Some(true));
            assert_eq!(summary.detector_status, "not_assessed");
            assert!(summary.changed_samples > 0);
            let mask = (1u8 << bits) - 1;
            assert!(summary.max_delta <= mask);
            assert!(summary.mse <= f64::from(mask) * f64::from(mask));
            let decoded = decode_pixels(&fs::read(&output).unwrap(), &Limits::default())
                .unwrap()
                .into_rgba8();
            let source = frame().into_rgba8();
            for (original, processed) in source.pixels().zip(decoded.pixels()) {
                assert_eq!(original[3], processed[3]);
                assert!(processed.0[..3].iter().all(|sample| sample & mask == 0));
            }
            let recovered: Vec<_> = decoded.pixels().map(|pixel| pixel[0] & 1).collect();
            assert!(recovered.iter().all(|bit| *bit == 0));
            assert_eq!(fs::read(&input).unwrap(), original);
            let verified =
                verify_processed_image(&input, &output, &options, &Limits::default()).unwrap();
            assert_eq!(verified.operation, "verify");
            assert_eq!(verified.image_processing, report.image_processing);
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.state == FindingState::NotAssessed)
            );
        }
    }

    #[test]
    fn signal_recipe_recomputes_exactly_and_preserves_alpha() {
        let directory = tempfile::tempdir().unwrap();
        let input = write_frame(directory.path());
        let output = directory.path().join("signal.png");
        let options = ImageProcessOptions {
            mode: ImageProcessMode::Signal,
            low_bits: 2,
        };
        let processed =
            process_image_in(&input, Some(&output), &options, &Limits::default(), None).unwrap();
        let verified =
            verify_processed_image(&input, &output, &options, &Limits::default()).unwrap();
        assert_eq!(processed.image_processing, verified.image_processing);
        let processing = processed.image_processing.unwrap();
        assert_eq!(processing.jpeg_quality, Some(88));
        assert_eq!(processing.resize_scale, Some(0.95));
        assert_eq!(processing.blur_sigma, Some(0.5));
        assert_eq!(processing.verified_low_bits, None);
        assert!(processing.changed_samples > 0);
        assert!(processing.mse > 0.0);
        assert_eq!(processed.result, Outcome::PartiallyVerified);
        let decoded = decode_pixels(&fs::read(output).unwrap(), &Limits::default())
            .unwrap()
            .into_rgba8();
        for (before, after) in frame().into_rgba8().pixels().zip(decoded.pixels()) {
            assert_eq!(before[3], after[3]);
        }
    }

    #[test]
    fn privacy_metadata_is_removed_and_profiles_survive_png_and_jpeg_conversion() {
        for name in ["png_itxt_exif_icc.png", "jpeg_exif_gps_author.jpg"] {
            let directory = tempfile::tempdir().unwrap();
            let input = directory.path().join(name);
            fs::copy(fixture(name), &input).unwrap();
            let output = directory.path().join("processed.png");
            let report = process_image_in(
                &input,
                Some(&output),
                &ImageProcessOptions::default(),
                &Limits::default(),
                None,
            )
            .unwrap();
            assert_eq!(
                decode_profile(&fs::read(&input).unwrap(), &Limits::default()).unwrap(),
                decode_profile(&fs::read(&output).unwrap(), &Limits::default()).unwrap()
            );
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.layer == RiskLayer::EmbeddedMetadata
                        && finding.state == FindingState::RemovedVerified)
            );
            let scan = fileveil_formats::inspect(
                &fs::read(output).unwrap(),
                Path::new("processed.png"),
                &Limits::default(),
            )
            .unwrap();
            assert!(
                !scan
                    .findings
                    .iter()
                    .any(|finding| matches!(finding.action, Action::Remove | Action::Normalize))
            );
        }
    }

    #[test]
    fn retained_color_and_hdr_records_are_never_reported_removed() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("hdr.png");
        let mut original = png(&frame());
        let mut display = chunk(b"cICP", &[1, 13, 0, 1]);
        display.extend_from_slice(&chunk(b"mDCv", &[0; 24]));
        original.splice(33..33, display);
        fs::write(&input, &original).unwrap();
        let output = directory.path().join("processed.png");
        let report = process_image_in(
            &input,
            Some(&output),
            &ImageProcessOptions::default(),
            &Limits::default(),
            None,
        )
        .unwrap();
        let result = fs::read(&output).unwrap();
        assert_eq!(
            color_chunks(&original).unwrap(),
            color_chunks(&result).unwrap()
        );
        let hdr = report
            .findings
            .iter()
            .find(|finding| {
                finding.code == "png.unknown_ancillary" && finding.location.contains("mDCv")
            })
            .unwrap();
        assert_eq!(hdr.state, FindingState::Remains);
        assert_eq!(hdr.action, Action::AskUser);
    }

    #[test]
    fn protected_orientation_provenance_and_unsupported_samples_do_not_publish() {
        let orientation =
            b"II\x2a\0\x08\0\0\0\x01\0\x12\x01\x03\0\x01\0\0\0\x06\0\0\0\0\0\0\0".to_vec();
        let cases = [chunk(b"caBX", b"jumb/c2pa"), chunk(b"eXIf", &orientation)];
        for extra in cases {
            let directory = tempfile::tempdir().unwrap();
            let input = directory.path().join("protected.png");
            let mut bytes = png(&frame());
            bytes.splice(33..33, extra);
            fs::write(&input, bytes).unwrap();
            let output = directory.path().join("must-not-exist.png");
            assert!(matches!(
                process_image_in(
                    &input,
                    Some(&output),
                    &ImageProcessOptions::default(),
                    &Limits::default(),
                    None
                ),
                Err(Error::Blocked(_))
            ));
            assert!(!output.exists());
            assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        }
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("gray.png");
        fs::write(
            &input,
            png(&DynamicImage::ImageLuma8(image::GrayImage::new(2, 2))),
        )
        .unwrap();
        assert!(matches!(
            process_image_in(
                &input,
                None,
                &ImageProcessOptions::default(),
                &Limits::default(),
                None
            ),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn wrong_recipe_and_tampered_samples_fail_verification() {
        let directory = tempfile::tempdir().unwrap();
        let input = write_frame(directory.path());
        let output = directory.path().join("processed.png");
        process_image_in(
            &input,
            Some(&output),
            &ImageProcessOptions::default(),
            &Limits::default(),
            None,
        )
        .unwrap();
        let wrong = ImageProcessOptions {
            mode: ImageProcessMode::LowBits,
            low_bits: 1,
        };
        assert!(matches!(
            verify_processed_image(&input, &output, &wrong, &Limits::default()),
            Err(Error::Verification(_))
        ));
        let mut changed = decode_pixels(&fs::read(&output).unwrap(), &Limits::default())
            .unwrap()
            .into_rgba8();
        changed.get_pixel_mut(0, 0)[0] = 4;
        fs::write(&output, png(&DynamicImage::ImageRgba8(changed))).unwrap();
        assert!(matches!(
            verify_processed_image(
                &input,
                &output,
                &ImageProcessOptions::default(),
                &Limits::default()
            ),
            Err(Error::Verification(_))
        ));
    }

    #[test]
    fn safe_publication_rejects_no_op_research_reports_and_processed_publication_binds_hashes() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("black.png");
        fs::write(&input, png(&DynamicImage::ImageRgb8(RgbImage::new(2, 2)))).unwrap();
        let staged = directory.path().join("staged.png");
        let target = directory.path().join("published.png");
        let mut report = process_image_in(
            &input,
            Some(&staged),
            &ImageProcessOptions::default(),
            &Limits::default(),
            None,
        )
        .unwrap();
        assert_eq!(report.integrity.content_equal, Some(true));
        assert!(
            super::super::publish_staged(
                &input,
                &staged,
                Some(&target),
                &mut report,
                &Limits::default()
            )
            .is_err()
        );
        assert!(!target.exists());
        let bytes = fs::read(&staged).unwrap();
        fs::write(&staged, b"changed").unwrap();
        assert!(matches!(
            publish_processed_staged(
                &input,
                &staged,
                Some(&target),
                &mut report,
                &Limits::default()
            ),
            Err(Error::Blocked(_))
        ));
        fs::write(&staged, bytes).unwrap();
        publish_processed_staged(
            &input,
            &staged,
            Some(&target),
            &mut report,
            &Limits::default(),
        )
        .unwrap();
        assert!(target.is_file());
        assert!(!staged.exists());
        assert_eq!(report.output_name.as_deref(), Some("published.png"));
        assert!(matches!(
            process_image_in(
                &input,
                Some(&target),
                &ImageProcessOptions::default(),
                &Limits::default(),
                None
            ),
            Err(Error::Input(_))
        ));
    }

    #[test]
    fn invalid_bit_counts_and_lossy_output_names_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let input = write_frame(directory.path());
        let output = directory.path().join("invalid.png");
        for bits in [0, 4, 255] {
            let options = ImageProcessOptions {
                mode: ImageProcessMode::LowBits,
                low_bits: bits,
            };
            assert!(matches!(
                process_image_in(&input, Some(&output), &options, &Limits::default(), None),
                Err(Error::Input(_))
            ));
        }
        assert!(matches!(
            process_image_in(
                &input,
                Some(&directory.path().join("lossy.jpg")),
                &ImageProcessOptions::default(),
                &Limits::default(),
                None
            ),
            Err(Error::Input(_))
        ));
        assert!(!output.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn image_processing_preserves_security_origin_attributes() {
        let directory = tempfile::tempdir().unwrap();
        let input = write_frame(directory.path());
        xattr::set(
            &input,
            "com.apple.quarantine",
            b"0081;00000000;FileVeilTest;synthetic",
        )
        .unwrap();
        xattr::set(
            &input,
            "com.apple.metadata:kMDItemWhereFroms",
            b"https://fictional.invalid/source",
        )
        .unwrap();
        let output = directory.path().join("processed.png");
        let report = process_image_in(
            &input,
            Some(&output),
            &ImageProcessOptions::default(),
            &Limits::default(),
            None,
        )
        .unwrap();
        assert_eq!(report.integrity.security_markers_preserved, Some(true));
        assert_eq!(
            xattr::get(&input, "com.apple.quarantine").unwrap(),
            xattr::get(&output, "com.apple.quarantine").unwrap()
        );
        assert_eq!(
            xattr::get(&input, "com.apple.metadata:kMDItemWhereFroms").unwrap(),
            xattr::get(&output, "com.apple.metadata:kMDItemWhereFroms").unwrap()
        );
    }
}

// FVPROV1 40787 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJhYzE2MDgwZjg5NWMwMGIzNWQzMTk3MjllYTc4MjA3NWFiYzgxZTFjNDg0NmE4Y2EzMzdhNGZmYjRkMDdjOThmIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4yIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMiIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL2ltYWdlX3Byb2Nlc3NpbmcucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI1N2I0NWUyZWMxYTg3YjNlZjAyYjBkNTQ3MjFhMTRiOGZjYTgxNzQ1OThlNTZiYmVhOTJlZWFlNWI3ZjFhYTMyOWMwZWVjMmU0OTlkMDVjYjRkNzY1OTA2YmIwMTAxMGQzY2UxOGZiOGM3YjQ2NWUzY2FmZTE2MzBmYzA3NzMwNiJ9XX1d FVPROV1-END
