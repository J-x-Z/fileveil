// SPDX-License-Identifier: MPL-2.0
//! Native-window acceptance captures rendered framebuffer pixels through eframe.
use eframe::egui;
use serde::Serialize;
use std::{collections::BTreeMap, io::Write, path::PathBuf};

const INTERACTION_ENABLED: &str = "fileveil_native_interaction_enabled";
const INTERACTION_OBSERVATIONS: &str = "fileveil_native_interaction_observations";

#[derive(Clone, Default, Serialize)]
struct Observations {
    targets: BTreeMap<String, Target>,
    actions: BTreeMap<String, u32>,
    workspace: String,
    result: Option<serde_json::Value>,
}

#[derive(Clone, Serialize)]
struct Target {
    center: [f32; 2],
    enabled: bool,
}

/// Test-only observation. Ordinary application sessions never enable this data.
pub(crate) fn target(response: &egui::Response, name: &str) {
    let clicked = response.clicked();
    response.ctx.data_mut(|data| {
        if data.get_temp::<bool>(egui::Id::unique(INTERACTION_ENABLED)) != Some(true) {
            return;
        }
        let observations = data
            .get_temp_mut_or_default::<Observations>(egui::Id::unique(INTERACTION_OBSERVATIONS));
        observations.targets.insert(
            name.into(),
            Target {
                center: [response.rect.center().x, response.rect.center().y],
                enabled: response.enabled(),
            },
        );
        if clicked {
            *observations.actions.entry(name.into()).or_default() += 1;
        }
    });
}

pub(crate) fn workspace(context: &egui::Context, name: &str) {
    context.data_mut(|data| {
        if data.get_temp::<bool>(egui::Id::unique(INTERACTION_ENABLED)) == Some(true) {
            data.get_temp_mut_or_default::<Observations>(egui::Id::unique(
                INTERACTION_OBSERVATIONS,
            ))
            .workspace = name.into();
        }
    });
}

pub(crate) fn result(context: &egui::Context, report: &fileveil_core::Report) {
    context.data_mut(|data| {
        if data.get_temp::<bool>(egui::Id::unique(INTERACTION_ENABLED)) == Some(true) {
            data.get_temp_mut_or_default::<Observations>(egui::Id::unique(
                INTERACTION_OBSERVATIONS,
            ))
            .result = Some(serde_json::json!({
                "operation":report.operation, "result":report.result,
                "original_unchanged":report.integrity.original_unchanged,
                "detections":report.advanced.as_ref().and_then(|details| details.get("detections")),
                "advanced":{"heritage":report.advanced.as_ref().and_then(|details| details.get("heritage"))}
            }));
        }
    });
}

pub struct SmokeProbe {
    report: PathBuf,
    frames: u32,
    interactive: bool,
    capture_requested: bool,
    result_frames: u8,
    pointer_events: Vec<serde_json::Value>,
}
impl SmokeProbe {
    pub fn new(report: PathBuf) -> Self {
        Self {
            report,
            frames: 0,
            interactive: std::env::var_os("FILEVEIL_NATIVE_INTERACTION")
                .is_some_and(|value| value == "1"),
            capture_requested: false,
            result_frames: 0,
            pointer_events: Vec::new(),
        }
    }

    pub fn frame(&mut self, context: &egui::Context) {
        self.frames = self.frames.saturating_add(1);
        let interaction = if self.interactive {
            context.data_mut(|data| data.insert_temp(egui::Id::unique(INTERACTION_ENABLED), true));
            context.input(|input| {
                for event in &input.raw.events {
                    if let egui::Event::PointerButton {
                        pos,
                        button,
                        pressed,
                        ..
                    } = event
                        && self.pointer_events.len() < 16
                    {
                        self.pointer_events.push(serde_json::json!({
                            "frame":self.frames,"position":[pos.x,pos.y],
                            "button":format!("{button:?}"),"pressed":pressed
                        }));
                    }
                }
            });
            let observations = context.data(|data| {
                data.get_temp::<Observations>(egui::Id::unique(INTERACTION_OBSERVATIONS))
                    .unwrap_or_default()
            });
            self.result_frames = if observations.result.is_some() {
                self.result_frames.saturating_add(1)
            } else {
                0
            };
            let value = serde_json::json!({
                "frames":self.frames, "pixels_per_point":context.pixels_per_point(),
                "observations":observations,"pointer_events":self.pointer_events,
                "input_source":"native_window_event_loop"
            });
            let state = self.report.with_extension("state.json");
            let temporary = self.report.with_extension("state.pending");
            let written = serde_json::to_vec(&value)
                .map_err(std::io::Error::other)
                .and_then(|bytes| std::fs::write(&temporary, bytes))
                .and_then(|()| std::fs::rename(&temporary, state));
            if let Err(error) = written {
                eprintln!("Native interaction observation failed. {error}");
            }
            Some(value)
        } else {
            None
        };
        let ready = if self.interactive {
            self.result_frames >= 3
        } else {
            self.frames == 3
        };
        if ready && !self.capture_requested {
            self.capture_requested = true;
            let report = self.report.clone();
            let frames = self.frames;
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
                    let value = serde_json::json!({"native_window_rendered":true,"frames_before_capture":frames,
                        "width":image.width(),"height":image.height(),"renderer":"eframe_glow",
                        "os":std::env::consts::OS,"arch":std::env::consts::ARCH,
                        "version":env!("CARGO_PKG_VERSION"),"interaction":interaction});
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

// FVPROV1 7410 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJmZDhmMzViZjBiNTY3ZDhiMTc3MWE1NjJjOGI0NGViNjY1YWUxMWYzNWNmOTE0NjRjNjMzM2VlZGU5ZjM1N2U5IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvc3JjL3Ntb2tlLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiMWZmNzcyZjBjZDBlYTUxYzU2M2IyNGEwZWRlOTdjZmE4ZDFlYzQxOWU0NDRkZjYwMTIzMGM1M2U2ZTcwOGNjMzM4MmYyMWFmZDA1MGYyNTk1NmI5MjEwZmI0OTQ2ZTgwY2Q1YjBhMWQ1NDJiYzM5NmE4NzI0NWI3NTc3YzJhMDUifV19XQ== FVPROV1-END
