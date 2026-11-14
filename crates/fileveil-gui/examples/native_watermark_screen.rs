// SPDX-License-Identifier: MPL-2.0
//! Developer-only native framebuffer capture. JSONL requests reuse one window.
use eframe::egui;
use image::ImageEncoder;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::{self, BufRead, Read, Write},
    path::PathBuf,
    sync::mpsc,
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: String,
    input: PathBuf,
    output: PathBuf,
    #[serde(default = "default_side")]
    max_side_points: f32,
    #[serde(default = "default_zoom")]
    zoom_factor: f32,
}
fn default_side() -> f32 {
    384.0
}
fn default_zoom() -> f32 {
    1.0
}

struct Pending {
    request: Request,
    texture: egui::TextureHandle,
    input_dimensions: [usize; 2],
    input_sha256: String,
    frames: u32,
    requested: bool,
    started: Instant,
}

fn load(request: Request, context: &egui::Context) -> Result<Pending, String> {
    if request.id.len() > 128
        || !(128.0..=600.0).contains(&request.max_side_points)
        || !(0.5..=2.0).contains(&request.zoom_factor)
    {
        return Err("Invalid capture ID, display size or zoom factor".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&request.input)
        .map_err(|error| error.to_string())?
        .take(32 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 32 * 1024 * 1024 {
        return Err("Capture input exceeds 32 MiB".into());
    }
    let mut reader = image::ImageReader::new(io::Cursor::new(&bytes))
        .with_guessed_format()
        .map_err(|error| error.to_string())?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(4096);
    limits.max_image_height = Some(4096);
    limits.max_alloc = Some(64 * 1024 * 1024);
    reader.limits(limits);
    let pixels = reader
        .decode()
        .map_err(|error| error.to_string())?
        .to_rgb8();
    let dimensions = [pixels.width() as usize, pixels.height() as usize];
    if dimensions.contains(&0) || dimensions[0] * dimensions[1] > 16_777_216 {
        return Err("Capture input exceeds the rendered pixel budget".into());
    }
    context.set_zoom_factor(request.zoom_factor);
    let texture = context.load_texture(
        "benchmark-image",
        egui::ColorImage::from_rgb(dimensions, pixels.as_raw()),
        egui::TextureOptions::LINEAR,
    );
    Ok(Pending {
        request,
        texture,
        input_dimensions: dimensions,
        input_sha256: fileveil_core::digest(&bytes),
        frames: 0,
        requested: false,
        started: Instant::now(),
    })
}

fn capture(
    pending: &Pending,
    rectangle: egui::Rect,
    context: &egui::Context,
    sender: mpsc::Sender<Value>,
) {
    let id = pending.request.id.clone();
    let output = pending.request.output.clone();
    let ppp = context.pixels_per_point();
    let native_ppp = context.native_pixels_per_point();
    let zoom = context.zoom_factor();
    let dimensions = pending.input_dimensions;
    let input_sha256 = pending.input_sha256.clone();
    let frames = pending.frames;
    let elapsed = pending.started;
    context.request_screenshot(move |framebuffer| {
        let result = (|| -> Result<Value, String> {
            let left = (rectangle.left() * ppp).round().max(0.0) as usize;
            let top = (rectangle.top() * ppp).round().max(0.0) as usize;
            let right = (rectangle.right() * ppp).round().max(0.0) as usize;
            let bottom = (rectangle.bottom() * ppp).round().max(0.0) as usize;
            if right > framebuffer.width() || bottom > framebuffer.height() || right <= left || bottom <= top {
                return Err("Rendered image rectangle is outside the captured framebuffer".into());
            }
            let width = right - left;
            let height = bottom - top;
            if width * height > 4_194_304 { return Err("Captured crop exceeds 4 MP".into()); }
            let mut rgba = Vec::with_capacity(width * height * 4);
            for y in top..bottom {
                for pixel in &framebuffer.pixels[y * framebuffer.width() + left..y * framebuffer.width() + right] {
                    rgba.extend_from_slice(&pixel.to_array());
                }
            }
            let mut png = Vec::new();
            image::codecs::png::PngEncoder::new(&mut png).write_image(&rgba, width as u32, height as u32, image::ExtendedColorType::Rgba8).map_err(|error| error.to_string())?;
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(output).map_err(|error| error.to_string())?;
            file.write_all(&png).map_err(|error| error.to_string())?;
            file.sync_all().map_err(|error| error.to_string())?;
            Ok(json!({"ok":true,"id":id,"capture_scope":"native_egui_glow_framebuffer_image_crop","os_desktop_capture":false,
                "input_sha256":input_sha256,"capture_sha256":fileveil_core::digest(&png),"input_dimensions":dimensions,"capture_dimensions":[width,height],
                "framebuffer_dimensions":[framebuffer.width(),framebuffer.height()],"image_rect_pixels":[left,top,right,bottom],
                "image_rect_points":[rectangle.left(),rectangle.top(),rectangle.right(),rectangle.bottom()],"pixels_per_point":ppp,
                "native_pixels_per_point":native_ppp,"zoom_factor":zoom,"texture_filter":"linear","frames_before_capture":frames,
                "capture_wall_seconds":elapsed.elapsed().as_secs_f64(),"renderer":"eframe_glow","platform":std::env::consts::OS,"arch":std::env::consts::ARCH,
                "compiled_capture_source_sha256":fileveil_core::digest(include_bytes!("native_watermark_screen.rs"))}))
        })();
        let value = result.unwrap_or_else(|error| json!({"ok":false,"id":id,"error":error}));
        let _ = sender.send(value);
    });
}

struct CaptureApp {
    requests: mpsc::Receiver<Result<Request, String>>,
    completed: mpsc::Receiver<Value>,
    completion_sender: mpsc::Sender<Value>,
    pending: Option<Pending>,
}

fn respond(value: Value) {
    println!("{value}");
    let _ = io::stdout().flush();
}

impl eframe::App for CaptureApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let context = ui.ctx().clone();
        if let Ok(value) = self.completed.try_recv() {
            respond(value);
            self.pending = None;
        }
        if self.pending.is_none() {
            match self.requests.try_recv() {
                Ok(Ok(request)) => {
                    let id = request.id.clone();
                    match load(request, &context) {
                        Ok(pending) => self.pending = Some(pending),
                        Err(error) => respond(json!({"ok":false,"id":id,"error":error})),
                    }
                }
                Ok(Err(error)) => respond(json!({"ok":false,"error":error})),
                Err(mpsc::TryRecvError::Disconnected) => {
                    context.send_viewport_cmd(egui::ViewportCommand::Close)
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        ui.painter()
            .rect_filled(ui.max_rect(), 0.0, egui::Color32::from_gray(24));
        if let Some(pending) = &mut self.pending {
            let [width, height] = pending.input_dimensions;
            let side = pending.request.max_side_points;
            let scale = side / width.max(height) as f32;
            let ppp = context.pixels_per_point();
            let size = egui::vec2(
                (width as f32 * scale * ppp).round() / ppp,
                (height as f32 * scale * ppp).round() / ppp,
            );
            let origin = ui.max_rect().min + egui::vec2(24.0, 24.0);
            let origin = egui::pos2(
                (origin.x * ppp).round() / ppp,
                (origin.y * ppp).round() / ppp,
            );
            let rectangle = egui::Rect::from_min_size(origin, size);
            if !ui.max_rect().contains_rect(rectangle)
                || pending.started.elapsed() > Duration::from_secs(15)
            {
                respond(
                    json!({"ok":false,"id":pending.request.id,"error":"Capture rectangle does not fit the window or capture timed out"}),
                );
                self.pending = None;
            } else {
                ui.painter().image(
                    pending.texture.id(),
                    rectangle,
                    egui::Rect::from_min_max(egui::Pos2::ZERO, egui::pos2(1.0, 1.0)),
                    egui::Color32::WHITE,
                );
                pending.frames += 1;
                if pending.frames >= 4 && !pending.requested {
                    pending.requested = true;
                    capture(pending, rectangle, &context, self.completion_sender.clone());
                }
            }
        }
        context.request_repaint_after(Duration::from_millis(25));
    }
}

fn main() -> eframe::Result {
    let (sender, requests) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut reader = io::stdin().lock();
        loop {
            let mut line = String::new();
            let result = reader.by_ref().take(8193).read_line(&mut line);
            if result.as_ref().is_ok_and(|count| *count == 0) {
                break;
            }
            let request = if line.len() > 8192 {
                Err("Capture request exceeds 8 KiB".into())
            } else {
                result
                    .map_err(|error| error.to_string())
                    .and_then(|_| serde_json::from_str(&line).map_err(|error| error.to_string()))
            };
            if sender.send(request).is_err() {
                break;
            }
        }
    });
    let (completion_sender, completed) = mpsc::channel();
    let app = CaptureApp {
        requests,
        completed,
        completion_sender,
        pending: None,
    };
    eframe::run_native(
        "FileVeil native framebuffer benchmark",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([800.0, 700.0])
                .with_min_inner_size([720.0, 640.0]),
            renderer: eframe::Renderer::Glow,
            centered: true,
            ..Default::default()
        },
        Box::new(move |_| Ok(Box::new(app))),
    )
}

// FVPROV1 10421 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIxMmY5OTVmYTBiYjViOTVmNGRmZWY2MDljYjUwMmEzZjMzMWI1NzhiODk3NDM5OTg2NjQyNThkY2Q3ODkzZTE1IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvZXhhbXBsZXMvbmF0aXZlX3dhdGVybWFya19zY3JlZW4ucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI2Y2Y4MmMzMDA2YzU3ZTAxZWUwYjIyYjFmNjEwMzI2YzMyZjE3YmZjNTRjZGY1NDI1MWY4MjEzNTc1OWE1ZDA4ZTM2ZmIwMzk4M2E3M2Y4YzAyNzYwYmZhZjk4NDc2MTg1Yzk2NDc0YjI3OGQxOWRkYTQ4ODkyNmEzMWQ4MWYwZiJ9XX1d FVPROV1-END
