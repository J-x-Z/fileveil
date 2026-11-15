// SPDX-License-Identifier: MPL-2.0
//! Explicit pixel-processing controls. Processing and verification stay in the shared engine.
use crate::{i18n::Language, session::Session};
use eframe::egui;
use fileveil_core::{ImageProcessMode, ImageProcessOptions};
use std::path::{Path, PathBuf};

pub struct ImageProcessingDialog {
    id: u64,
    input: PathBuf,
    output_directory: Option<PathBuf>,
    options: ImageProcessOptions,
    error: Option<String>,
}

impl ImageProcessingDialog {
    pub fn new(id: u64, input: PathBuf, output_directory: Option<PathBuf>) -> Self {
        Self {
            id,
            input,
            output_directory,
            options: ImageProcessOptions {
                mode: ImageProcessMode::LowBits,
                low_bits: 2,
            },
            error: None,
        }
    }

    /// Returns whether the dialog should remain open after this frame.
    pub fn show(
        &mut self,
        context: &egui::Context,
        language: Language,
        session: &mut Session,
    ) -> bool {
        let mut cancel = false;
        let mut process = false;
        let width = (context.viewport_rect().width() - 80.0).clamp(300.0, 560.0);
        let maximum_height = (context.viewport_rect().height() - 200.0).clamp(200.0, 500.0);
        let response = egui::Modal::new(egui::Id::unique(("image_processing_dialog", self.id)))
            .frame(egui::Frame::popup(context.global_style().as_ref()).inner_margin(egui::Margin::same(20)))
            .show(context, |ui| {
                ui.set_min_width(width);
                ui.set_max_width(width);
                ui.heading(text(language, "图片水印处理", "Image watermark processing"));
                let name = self.input.file_name().unwrap_or(self.input.as_os_str());
                ui.add(egui::Label::new(name.to_string_lossy()).truncate());
                ui.add_space(8.0);
                egui::ScrollArea::vertical()
                    .id_salt(("image_processing_options", self.id))
                    .max_height(maximum_height)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        ui.add(
                            egui::Label::new(text(
                                language,
                                "所选处理会作用于图像像素，并生成新的 PNG 副本。",
                                "The selected processing operates on image pixels and creates a new PNG copy.",
                            ))
                            .wrap(),
                        );
                        ui.add(
                            egui::Label::new(text(
                                language,
                                "作者、时间等可识别的基础元数据默认同步净化。",
                                "Recognized basic metadata, including author and timestamps, is cleaned during processing.",
                            ))
                            .wrap(),
                        );
                        ui.add_space(12.0);
                        ui.strong(text(language, "处理模式", "Processing mode"));
                        ui.horizontal_wrapped(|ui| {
                            ui.radio_value(
                                &mut self.options.mode,
                                ImageProcessMode::LowBits,
                                text(language, "低位清理", "Clear low bits"),
                            );
                            ui.radio_value(
                                &mut self.options.mode,
                                ImageProcessMode::Signal,
                                text(language, "信号处理（实验）", "Signal processing (experimental)"),
                            );
                        });
                        ui.add_space(10.0);
                        match self.options.mode {
                            ImageProcessMode::LowBits => {
                                ui.label(text(language, "RGB 清零位数", "RGB bits to clear"));
                                ui.horizontal_wrapped(|ui| {
                                    for (bits, chinese, english) in [
                                        (1, "1 位", "1 bit"),
                                        (2, "2 位", "2 bits"),
                                        (3, "3 位", "3 bits"),
                                    ] {
                                        ui.selectable_value(
                                            &mut self.options.low_bits,
                                            bits,
                                            text(language, chinese, english),
                                        );
                                    }
                                });
                                ui.add_space(8.0);
                                ui.add(
                                    egui::Label::new(text(
                                        language,
                                        "将 RGB 各通道选定数量的最低位清零，保留 Alpha 透明度。输出为 PNG。",
                                        "Clear the selected number of least-significant bits in each RGB channel while retaining alpha transparency. Output is PNG.",
                                    ))
                                    .wrap(),
                                );
                                ui.add(
                                    egui::Label::new(text(
                                        language,
                                        "验证范围包括 RGB 目标低位归零和输出文件完整性。",
                                        "Verification covers zeroed RGB low bits and output-file integrity.",
                                    ))
                                    .wrap(),
                                );
                            }
                            ImageProcessMode::Signal => {
                                ui.add(
                                    egui::Label::new(text(
                                        language,
                                        "缩小至 95% 后恢复原始尺寸，再进行 σ 0.5 高斯平滑，以及质量 88 的 JPEG 编码和重新解码。最终输出为 PNG。",
                                        "Resize to 95% and restore the original dimensions, apply Gaussian smoothing with sigma 0.5, then encode and decode JPEG at quality 88. Final output is PNG.",
                                    ))
                                    .wrap(),
                                );
                                ui.add_space(8.0);
                                ui.add(
                                    egui::Label::new(text(
                                        language,
                                        "缩放、平滑和 JPEG 转换会影响图像细节与颜色。",
                                        "Resizing, smoothing and JPEG conversion affect image detail and color.",
                                    ))
                                    .wrap(),
                                );
                            }
                        }
                        ui.add_space(12.0);
                        ui.separator();
                        ui.add_space(8.0);
                        ui.add(
                            egui::Label::new(text(
                                language,
                                "未知密钥水印检测未运行。报告仅覆盖所选处理与可执行验证。",
                                "Unknown keyed-watermark detection remains unassessed. Reports cover the selected processing and executable verification.",
                            ))
                            .wrap(),
                        );
                    });
                if let Some(error) = &self.error {
                    ui.add_space(8.0);
                    ui.colored_label(ui.visuals().error_fg_color, error);
                }
                ui.add_space(14.0);
                let ready = session.can_process_image(self.id);
                if !ready {
                    ui.label(text(
                        language,
                        "等待当前文件就绪后可进行图片处理。",
                        "Wait until this file is ready for image processing.",
                    ));
                }
                ui.horizontal(|ui| {
                    process = ui
                        .add_enabled(ready, egui::Button::new(text(language, "处理并保存副本", "Process and save copy")))
                        .clicked();
                    cancel = ui.button(text(language, "取消", "Cancel")).clicked();
                });
            });
        if cancel || response.should_close() {
            return false;
        }
        if !process {
            return true;
        }
        self.error = None;
        let directory = self
            .output_directory
            .as_deref()
            .or_else(|| self.input.parent())
            .unwrap_or(Path::new("."));
        let selected = rfd::FileDialog::new()
            .set_title(text(language, "处理并保存副本", "Process and save copy"))
            .set_directory(directory)
            .set_file_name(default_output_name(&self.input))
            .add_filter("PNG", &["png"])
            .save_file();
        let Some(mut output) = selected else {
            return true;
        };
        if !output
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("png"))
        {
            output.set_extension("png");
        }
        if std::fs::symlink_metadata(&output).is_ok() {
            self.error = Some(
                text(
                    language,
                    "输出文件已存在，请选择新的文件名。",
                    "The output already exists. Choose a new filename.",
                )
                .into(),
            );
            return true;
        }
        session.queue_image_process(self.id, output, self.options.clone());
        false
    }
}

fn text(language: Language, chinese: &'static str, english: &'static str) -> &'static str {
    crate::i18n::text(language, chinese, english)
}

fn default_output_name(input: &Path) -> String {
    let stem = input.file_stem().unwrap_or(input.as_os_str());
    format!("{}.processed.png", stem.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_names_preserve_unicode_stems_and_use_png() {
        assert_eq!(
            default_output_name(Path::new("图片 原件.jpeg")),
            "图片 原件.processed.png"
        );
        assert_eq!(
            default_output_name(Path::new("sample.photo.png")),
            "sample.photo.processed.png"
        );
    }

    #[test]
    fn dialog_defaults_to_two_rgb_low_bits() {
        let dialog = ImageProcessingDialog::new(3, PathBuf::from("input.png"), None);
        assert!(matches!(dialog.options.mode, ImageProcessMode::LowBits));
        assert_eq!(dialog.options.low_bits, 2);
    }
}

// FVPROV1 11258 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJlNzQ4NWIwNGRjODQyZWJkNDE5YmQ4YjYzOWZiYmExYWU2M2NiMDc0OGZmNjI1OTQ0ZmU1ZDExOWM0ZmJlNTFmIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvc3JjL2ltYWdlX3Byb2Nlc3NpbmcucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiJjNWQ2NzY1Njc2MjEzNjVkMTdiMTE3OWYzNzk3OWUxMzJlNjQyMjIwNzBmMWQ4ZjM1ZDVhMDNmMTViOGJkYWM1NDhlYmI5ZWIzZDk1YjMwZDI2MThhYWNkZjI1YWE1NTA0ODcwMTA2OTEzZjRhNzAxNDQ2NTc1ODdmZGM1MjIwOCJ9XX1d FVPROV1-END
