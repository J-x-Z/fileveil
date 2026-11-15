// SPDX-License-Identifier: MPL-2.0
use crate::{i18n::Language, jobs::JobKind};
use eframe::egui;
use std::path::PathBuf;

fn t(language: Language, zh: &'static str, en: &'static str) -> &'static str {
    if language == Language::Chinese {
        zh
    } else {
        en
    }
}
pub struct ComputePanel {
    path: Option<PathBuf>,
    tensor: String,
    rows: String,
    seeds: String,
    layouts: String,
    offset: String,
    error: Option<String>,
}
impl Default for ComputePanel {
    fn default() -> Self {
        Self {
            path: None,
            tensor: "model.embed_tokens.weight".into(),
            rows: String::new(),
            seeds: String::new(),
            layouts: "108,132,148,152".into(),
            offset: "0".into(),
            error: None,
        }
    }
}
impl ComputePanel {
    pub fn ui(&mut self, ui: &mut egui::Ui, language: Language, idle: bool) -> Option<JobKind> {
        ui.label(t(language,"实验性 · 比较候选 Philox 初始化布局。需要已知种子和未训练的二维嵌入行；结果不代表物理 GPU 身份或训练地点。","Experimental · Compare candidate Philox initialization layouts. Requires supplied seeds and untouched 2D embedding rows; results do not identify a physical GPU or training location."));
        ui.small(t(language,"仅按需读取 safetensors 行，不执行模型代码。最多 65,536 个采样值、3,200 万次候选计算，单次最长 60 秒。","Reads selected safetensors rows without model execution. At most 65,536 sampled values, 32 million candidate draws and 60 seconds."));
        ui.add_enabled_ui(idle, |ui| {
            if ui
                .button(t(
                    language,
                    "选择权重或分片索引",
                    "Choose weights or shard index",
                ))
                .clicked()
            {
                self.path = rfd::FileDialog::new()
                    .add_filter("Safetensors / shard index", &["safetensors", "json"])
                    .pick_file();
            }
            if let Some(path) = &self.path {
                ui.label(path.file_name().unwrap_or_default().to_string_lossy());
            }
            egui::Grid::new("compute-settings")
                .num_columns(2)
                .show(ui, |ui| {
                    for (label, value) in [
                        (t(language, "张量名称", "Tensor name"), &mut self.tensor),
                        (
                            t(language, "行号（逗号分隔）", "Rows (comma separated)"),
                            &mut self.rows,
                        ),
                        (t(language, "候选种子", "Candidate seeds"), &mut self.seeds),
                        (
                            t(language, "候选 SM 数量", "Candidate SM counts"),
                            &mut self.layouts,
                        ),
                        (
                            t(
                                language,
                                "Philox 偏移（4 的倍数）",
                                "Philox offset (multiple of 4)",
                            ),
                            &mut self.offset,
                        ),
                    ] {
                        ui.label(label);
                        ui.text_edit_singleline(value);
                        ui.end_row();
                    }
                });
        });
        let mut job = None;
        if ui
            .add_enabled(
                idle && self.path.is_some(),
                egui::Button::new(t(language, "分析候选布局", "Analyze candidate layouts")),
            )
            .clicked()
        {
            let parse = |value: &str| {
                value
                    .split(',')
                    .map(|s| s.trim().parse::<u64>().map_err(|_| "Invalid integer list"))
                    .collect::<Result<Vec<_>, _>>()
            };
            let request = (|| {
                Ok::<_, &str>(fileveil_engine::compute::ComputeRequest {
                    path: self.path.clone().ok_or("Select weights")?,
                    tensor: self.tensor.trim().into(),
                    rows: parse(&self.rows)?,
                    seeds: parse(&self.seeds)?,
                    sm_counts: parse(&self.layouts)?
                        .into_iter()
                        .map(|n| u32::try_from(n).map_err(|_| "Invalid layout"))
                        .collect::<Result<_, _>>()?,
                    philox_offset: self.offset.trim().parse().map_err(|_| "Invalid offset")?,
                    rows_per_shard: None,
                    seed_per_rank: 0,
                })
            })();
            match request {
                Ok(request) => {
                    self.error = None;
                    job = Some(JobKind::Compute {
                        request: Box::new(request),
                    });
                }
                Err(message) => self.error = Some(message.into()),
            }
        }
        if let Some(error) = &self.error {
            ui.label(error);
        }
        job
    }
}
pub fn report_ui(ui: &mut egui::Ui, language: Language, value: &serde_json::Value) {
    ui.strong(t(
        language,
        "计算指纹 · 实验性结果",
        "Compute fingerprint · Experimental result",
    ));
    ui.label(match value["status"].as_str() {
        Some("candidate_layout_match") => t(
            language,
            "发现符合假设的候选初始化布局",
            "Candidate initialization layout matches under stated assumptions",
        ),
        _ => t(language, "无法判定", "Unable to determine"),
    });
    ui.label(t(
        language,
        "置信度未校准；不是硬件身份鉴定。",
        "Confidence is uncalibrated; this is not hardware identity attribution.",
    ));
    egui::Grid::new("compute-results")
        .striped(true)
        .show(ui, |ui| {
            for header in ["Seed", "SMs", "Median r", "Rows ≥ 0.98"] {
                ui.strong(header);
            }
            ui.end_row();
            if let Some(candidates) = value["candidates"].as_array() {
                for c in candidates {
                    for key in ["seed", "sm_count", "median_correlation", "rows_above_0_98"] {
                        ui.monospace(c[key].to_string());
                    }
                    ui.end_row();
                }
            }
        });
    ui.small(format!(
        "{} ms · {} sampled bytes",
        value["resource_usage"]["elapsed_ms"], value["sampled_bytes"]
    ));
}

// FVPROV1 6648 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJkYTg1ZGNiNGFhOTU2NmViZDlhMTJhMzJmODM2YmY2MzBmNjY5NGIwYjc3Zjk3MTM2ODhkODU2NmIxYzQzZTczIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvc3JjL2NvbXB1dGVfdWkucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiJhOWY3MmIzZmNiNjk4MTk3NjVjY2UxN2E2MWYxZGQyMjY3NWM2ZDZhMDEyZDNiZDAxMzEyYTZjOGUzYmI2ZDE0NGM1MDkyZWFhYWNiZDViZWVjNDE3ZGU5MDQyMzkxMGFjYWFkOGU1NTZiMmU5NGViMTc3YWRhYTI4OGI1Y2YwMyJ9XX1d FVPROV1-END
