// SPDX-License-Identifier: MPL-2.0
//! Native-window acceptance captures rendered framebuffer pixels through eframe.
use eframe::egui;
use std::{io::Write, path::PathBuf};

pub struct SmokeProbe {
    report: PathBuf,
    frames: u8,
}
impl SmokeProbe {
    pub fn new(report: PathBuf) -> Self {
        Self { report, frames: 0 }
    }

    pub fn frame(&mut self, context: &egui::Context) {
        self.frames = self.frames.saturating_add(1);
        if self.frames == 3 {
            let report = self.report.clone();
            let callback_context = context.clone();
            context.request_screenshot(move |image| {
                let result = (|| -> Result<(), Box<dyn std::error::Error>> {
                    let pixels: Vec<u8> = image.pixels.iter().flat_map(|pixel| pixel.to_array()).collect();
                    let screenshot = report.with_extension("png");
                    let mut output = std::fs::OpenOptions::new().write(true).create_new(true).open(&screenshot)?;
                    use image::ImageEncoder;
                    image::codecs::png::PngEncoder::new(&mut output).write_image(
                        &pixels, image.width() as u32, image.height() as u32, image::ExtendedColorType::Rgba8)?;
                    output.sync_all()?;
                    let value = serde_json::json!({"native_window_rendered":true,"frames_before_capture":3,
                        "width":image.width(),"height":image.height(),"renderer":"eframe_glow",
                        "os":std::env::consts::OS,"arch":std::env::consts::ARCH,
                        "version":env!("CARGO_PKG_VERSION")});
                    let mut output = std::fs::OpenOptions::new().write(true).create_new(true).open(report)?;
                    output.write_all(serde_json::to_string_pretty(&value)?.as_bytes())?;
                    output.sync_all()?;
                    Ok(())
                })();
                if let Err(error) = result { eprintln!("Native GUI smoke capture failed. {error}"); }
                callback_context.send_viewport_cmd(egui::ViewportCommand::Close);
                callback_context.request_repaint();
            });
        }
        context.request_repaint_after(std::time::Duration::from_millis(50));
    }
}
