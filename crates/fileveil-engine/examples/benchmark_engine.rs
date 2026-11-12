// SPDX-License-Identifier: MPL-2.0
//! Developer JSONL runner for bounded, repeatable pixel-watermark benchmarks.
//! Sources and intermediates are caller-owned test files. This is not a product API.
use fileveil_core::{Limits, digest};
use fileveil_engine::heritage::robust;
use image::DynamicImage;
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{self, BufRead, Cursor, Read};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    action: String,
    input: PathBuf,
    output: Option<PathBuf>,
    #[serde(default = "default_work")]
    work_id: String,
    #[serde(default = "default_strength")]
    strength: u8,
    #[serde(default = "default_protocol")]
    protocol: String,
}
fn default_protocol() -> String {
    "v1".into()
}
fn default_work() -> String {
    "FileVeil benchmark work".into()
}
fn default_strength() -> u8 {
    32
}

#[cfg(unix)]
fn resources() -> (Option<f64>, Option<u64>) {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage writes the provided fixed-size, initialized OS structure.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return (None, None);
    }
    // SAFETY: successful getrusage initialized the entire structure.
    let usage = unsafe { usage.assume_init() };
    let seconds = usage.ru_utime.tv_sec as f64
        + usage.ru_stime.tv_sec as f64
        + (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) as f64 / 1_000_000.0;
    let rss = usage.ru_maxrss.max(0) as u64;
    (
        Some(seconds),
        Some(if cfg!(target_os = "macos") {
            rss
        } else {
            rss * 1024
        }),
    )
}
#[cfg(not(unix))]
fn resources() -> (Option<f64>, Option<u64>) {
    (None, None)
}

fn execute(request: Request) -> Result<Value, String> {
    let start = Instant::now();
    let (cpu_start, _) = resources();
    if std::fs::metadata(&request.input)
        .map_err(|error| error.to_string())?
        .len()
        > 32 * 1024 * 1024
    {
        return Err("Benchmark input exceeds 32 MiB".into());
    }
    let bytes = std::fs::read(&request.input).map_err(|error| error.to_string())?;
    let mut reader = image::ImageReader::new(Cursor::new(&bytes))
        .with_guessed_format()
        .map_err(|error| error.to_string())?;
    let mut decoder_limits = image::Limits::default();
    decoder_limits.max_image_width = Some(4096);
    decoder_limits.max_image_height = Some(4096);
    decoder_limits.max_alloc = Some(128 * 1024 * 1024);
    reader.limits(decoder_limits);
    let image = reader
        .decode()
        .map_err(|error| error.to_string())?
        .to_rgb8();
    if u64::from(image.width()) * u64::from(image.height()) > 16_777_216 {
        return Err("Benchmark input exceeds 16 MP".into());
    }
    let image = DynamicImage::ImageRgb8(image);
    let limits = Limits {
        max_pixels: 16_777_216,
        ..Default::default()
    };
    let (output, report) = if request.protocol == "v1" {
        match request.action.as_str() {
            "embed" => {
                let (marked, report) =
                    robust::embed(&image, &request.work_id, request.strength, &limits)
                        .map_err(|error| error.to_string())?;
                (Some(marked), serde_json::to_value(report).unwrap())
            }
            "detect" | "analyze" => (
                None,
                serde_json::to_value(
                    robust::detect(&image, &limits).map_err(|error| error.to_string())?,
                )
                .unwrap(),
            ),
            "clean" => {
                let (cleaned, report) =
                    robust::clean(&image, &limits).map_err(|error| error.to_string())?;
                (Some(cleaned), serde_json::to_value(report).unwrap())
            }
            _ => return Err("Unknown benchmark action".into()),
        }
    } else {
        return Err("Unknown benchmark protocol".into());
    };
    if let Some(output) = output {
        let destination = request
            .output
            .ok_or("Benchmark write requires output path")?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
            .map_err(|error| error.to_string())?;
        output
            .write_to(&mut file, image::ImageFormat::Png)
            .map_err(|error| error.to_string())?;
    }
    let (cpu_end, peak) = resources();
    Ok(
        json!({"ok":true,"input_sha256":digest(&bytes),"width":image.width(),"height":image.height(),
        "wall_seconds":start.elapsed().as_secs_f64(),"cpu_seconds":cpu_end.zip(cpu_start).map(|(end,start)|end-start),
        "process_peak_rss_bytes":peak,"memory_scope":"persistent_worker_process_lifetime_high_water_mark", "report":report}),
    )
}
fn main() {
    let input = io::stdin();
    let mut input = input.lock();
    loop {
        let mut line = String::new();
        let read = (&mut input).take(65_538).read_line(&mut line);
        let response = match read {
            Ok(0) => break,
            Ok(_) if line.len() <= 65_536 => serde_json::from_str::<Request>(&line)
                .map_err(|error| error.to_string())
                .and_then(execute),
            Ok(_) => {
                println!(
                    "{}",
                    json!({"ok":false,"error":"Benchmark request exceeds 64 KiB"})
                );
                break;
            }
            Err(error) => Err(error.to_string()),
        };
        println!(
            "{}",
            response.unwrap_or_else(|error| json!({"ok":false,"error":error}))
        );
    }
}
