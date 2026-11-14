// SPDX-License-Identifier: MPL-2.0
//! Software watermark operations use the shared isolated worker and real reports.
use crate::{
    i18n::{Language, text},
    jobs::JobKind,
};
use eframe::egui;
use fileveil_engine::{
    project::ProjectKey,
    software::{SoftwareAction, SoftwareMode, SoftwareRequest},
};
use std::path::{Path, PathBuf};

#[derive(Default)]
pub(crate) struct IdentityPicker {
    file: Option<PathBuf>,
    system: bool,
    reference: String,
}
impl IdentityPicker {
    pub fn key(&self) -> Option<ProjectKey> {
        if self.system {
            (!self.reference.trim().is_empty()).then(|| ProjectKey::System {
                key_id: self.reference.trim().into(),
            })
        } else {
            self.file.clone().map(|path| ProjectKey::File { path })
        }
    }
    pub fn ui(&mut self, ui: &mut egui::Ui, language: Language, optional: bool) {
        ui.horizontal_wrapped(|ui| {
            ui.label(if optional {
                t(language, "可选提取密钥", "Optional extraction key")
            } else {
                t(language, "签名身份", "Signing identity")
            });
            ui.selectable_value(&mut self.system, false, t(language, "密钥文件", "Key file"));
            ui.selectable_value(
                &mut self.system,
                true,
                t(language, "系统密钥存储", "System key store"),
            );
        });
        if self.system {
            ui.text_edit_singleline(&mut self.reference);
        } else {
            ui.horizontal_wrapped(|ui| {
                if ui
                    .button(t(language, "选择密钥文件", "Choose key file"))
                    .clicked()
                {
                    self.file = rfd::FileDialog::new().pick_file();
                }
                if let Some(path) = &self.file {
                    ui.small(path.file_name().unwrap_or_default().to_string_lossy());
                }
                if self.file.is_some() && ui.small_button(t(language, "移除", "Remove")).clicked()
                {
                    self.file = None;
                }
            });
        }
    }
}

pub struct SoftwarePanel {
    request: SoftwareRequest,
    identity: IdentityPicker,
    compiler_arguments: String,
    test_arguments: String,
    trusted_keys: String,
    notice: Option<String>,
}
impl Default for SoftwarePanel {
    fn default() -> Self {
        Self {
            request: SoftwareRequest {
                action: SoftwareAction::Mark,
                work_id: String::new(),
                copy_id: "development".into(),
                version: "1".into(),
                ..Default::default()
            },
            identity: Default::default(),
            compiler_arguments: "[]".into(),
            test_arguments: "[[]]".into(),
            trusted_keys: "[]".into(),
            notice: None,
        }
    }
}
impl SoftwarePanel {
    fn output_filename(&self) -> String {
        if self.request.action == SoftwareAction::Lab {
            return "software-lab.json".into();
        }
        let prefix = if self.request.action == SoftwareAction::Clean {
            "clean"
        } else {
            "marked"
        };
        match self.request.mode {
            SoftwareMode::Source => format!(
                "{prefix}-copy.{}",
                self.request
                    .input_path
                    .extension()
                    .and_then(std::ffi::OsStr::to_str)
                    .unwrap_or("c")
            ),
            SoftwareMode::Ir => format!("{prefix}-copy.ll"),
            SoftwareMode::Compiler => format!("{prefix}-program{}", std::env::consts::EXE_SUFFIX),
            SoftwareMode::Structure => self.request.input_path.extension().map_or_else(
                || format!("{prefix}-copy"),
                |extension| format!("{prefix}-copy.{}", extension.to_string_lossy()),
            ),
        }
    }
    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        language: Language,
        idle: bool,
        selected: Option<&Path>,
        forensics: bool,
    ) -> Option<JobKind> {
        if forensics
            && !matches!(
                self.request.action,
                SoftwareAction::Inspect
                    | SoftwareAction::Verify
                    | SoftwareAction::Compare
                    | SoftwareAction::Clean
            )
        {
            self.request.action = SoftwareAction::Inspect;
        }
        if forensics && self.request.action != SoftwareAction::Compare {
            self.request.allow_execution = false;
        }
        if self.request.action == SoftwareAction::Lab {
            self.request.mode = SoftwareMode::Compiler;
        }
        let mut start = false;
        ui.label(if forensics {
            t(language,"解析 ELF、PE 和 Mach-O 结构、签名及已知载体，按需分析指令和控制流。","Inspect ELF, PE and Mach-O structures, signatures and known carriers, with optional instruction and CFG analysis.")
        } else {
            t(language,"对 C/C++ 源码、LLVM IR 或独立构建产物植入可验证水印。编译和运行在本地隔离 worker 中执行。","Mark C/C++ source, LLVM IR or independently built artifacts. Compilation and execution use a local isolated worker.")
        });
        ui.add_enabled_ui(idle,|ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(t(language,"操作","Operation"));
                egui::ComboBox::from_id_salt(if forensics {"forensic_action"} else {"software_action"})
                    .selected_text(action_label(language,self.request.action)).show_ui(ui,|ui| {
                        let actions:&[SoftwareAction]=if forensics {&[SoftwareAction::Inspect,SoftwareAction::Verify,SoftwareAction::Compare,SoftwareAction::Clean]}
                            else {&[SoftwareAction::Mark,SoftwareAction::Verify,SoftwareAction::Clean,SoftwareAction::Lab,SoftwareAction::BuildPlugin]};
                        if !actions.contains(&self.request.action) { self.request.action=actions[0]; }
                        for &action in actions {ui.selectable_value(&mut self.request.action,action,action_label(language,action));}
                    });
            });
            if forensics {self.request.mode=SoftwareMode::Structure;}
            else if !matches!(self.request.action,SoftwareAction::BuildPlugin|SoftwareAction::Lab) {
                ui.horizontal_wrapped(|ui| {
                    ui.label(t(language,"处理阶段","Processing stage"));
                    for (mode,label) in [(SoftwareMode::Source,t(language,"源代码副本","Source copy")),(SoftwareMode::Ir,"LLVM IR"),(SoftwareMode::Compiler,t(language,"编译器构建","Compiler build")),(SoftwareMode::Structure,t(language,"容器结构","Container structure"))] {
                        ui.selectable_value(&mut self.request.mode,mode,label);
                    }
                });
            }
            ui.horizontal_wrapped(|ui| {
                if ui.button(t(language,"选择输入","Choose input")).clicked() {
                    let picked=if self.request.action==SoftwareAction::BuildPlugin {rfd::FileDialog::new().pick_folder()} else {rfd::FileDialog::new().pick_file()};
                    if let Some(path)=picked {self.request.input_path=path;}
                }
                if let Some(selected)=selected && self.request.action!=SoftwareAction::BuildPlugin
                    && ui.button(t(language,"使用所选文件","Use selected file")).clicked() {
                    self.request.input_path=selected.into();
                }
                if !self.request.input_path.as_os_str().is_empty() {ui.small(self.request.input_path.display().to_string());}
            });
            if matches!(self.request.action,SoftwareAction::Mark|SoftwareAction::Clean|SoftwareAction::BuildPlugin|SoftwareAction::Lab) {
                ui.horizontal_wrapped(|ui| {
                    if ui.button(t(language,"选择输出位置","Choose output location")).clicked() {
                        self.request.output_path=if self.request.action==SoftwareAction::BuildPlugin {rfd::FileDialog::new().pick_folder()}
                            else {rfd::FileDialog::new().set_file_name(self.output_filename()).save_file()};
                    }
                    if let Some(path)=&self.request.output_path {ui.small(path.display().to_string());}
                });
            }
            if self.request.action==SoftwareAction::Compare || (self.request.action==SoftwareAction::Clean && self.request.mode==SoftwareMode::Compiler) {
                ui.horizontal_wrapped(|ui| {
                    if ui.button(t(language,"选择对照原件","Choose reference original")).clicked() {self.request.reference_path=rfd::FileDialog::new().pick_file();}
                    if let Some(path)=&self.request.reference_path {ui.small(path.display().to_string());}
                });
            }
            if self.request.action!=SoftwareAction::BuildPlugin {
                let optional=!matches!(self.request.action,SoftwareAction::Mark|SoftwareAction::Lab)
                    && !(self.request.action==SoftwareAction::Clean&&self.request.mode==SoftwareMode::Source);
                self.identity.ui(ui,language,optional);
                if matches!(self.request.action,SoftwareAction::Mark|SoftwareAction::Lab) {
                    egui::Grid::new("software_claims").num_columns(2).show(ui,|ui| {
                        field(ui,language,"作品 ID","Work ID",&mut self.request.work_id);
                        field(ui,language,"发行副本 ID","Copy ID",&mut self.request.copy_id);
                        field(ui,language,"作者声明","Author declaration",&mut self.request.author);
                        field(ui,language,"版本","Version",&mut self.request.version);
                    });
                }
            }
            egui::CollapsingHeader::new(if forensics {t(language,"分析工具与验证参数","Analysis tools and verification")}else{t(language,"编译工具与验证参数","Compiler tools and verification")}).show(ui,|ui| {
                optional_path(ui,language,"LLVM 工具目录","LLVM tool directory",&mut self.request.llvm_directory,true);
                if !forensics {
                optional_path(ui,language,"LLVM 插件","LLVM pass plugin",&mut self.request.plugin_path,false);
                ui.horizontal(|ui| {
                    ui.label(t(language,"优化级别","Optimization"));
                    egui::ComboBox::from_id_salt("software_optimization").selected_text(&self.request.optimization).show_ui(ui,|ui| {
                        for value in ["O0","O1","O2","O3","Os","Oz","LTO"] {ui.selectable_value(&mut self.request.optimization,value.into(),value);}
                    });
                });
                let mut target=self.request.target_triple.clone().unwrap_or_default();
                ui.label(t(language,"交叉编译目标（留空为本机）","Cross target (empty for native)"));
                if ui.text_edit_singleline(&mut target).changed() {self.request.target_triple=(!target.trim().is_empty()).then(||target.trim().into());}
                ui.label(t(language,"额外编译参数（JSON 参数数组）","Additional compiler arguments (JSON array)"));
                ui.text_edit_multiline(&mut self.compiler_arguments);
                }
                if !forensics || self.request.action==SoftwareAction::Compare {
                ui.checkbox(&mut self.request.allow_execution,t(language,"允许运行本次构建程序和探针","Allow execution of this build and its probes"));
                ui.small(t(language,"仅启用后才运行程序。功能对比只覆盖指定输入，编译本身仍会使用本机工具。","Program execution requires this option. Functional comparisons cover supplied inputs. Compilation still uses local tools."));
                ui.label(t(language,"功能测试参数（JSON 二维数组）","Functional test arguments (JSON array of arrays)"));
                ui.text_edit_multiline(&mut self.test_arguments);
                }
                ui.label(t(language,"受信任公钥（JSON 数组）","Trusted public keys (JSON array)"));
                ui.text_edit_multiline(&mut self.trusted_keys);
                ui.checkbox(&mut self.request.disclose_private,t(language,"在报告中显示已解密声明","Show decrypted declarations in report"));
            });
            start=ui.add_enabled(self.can_submit(),
                egui::Button::new(action_label(language,self.request.action))).clicked();
        });
        if let Some(notice) = &self.notice {
            ui.label(crate::i18n::tr(language, notice));
        }
        if !start {
            return None;
        }
        match self.prepared_request(forensics) {
            Ok(request) => {
                self.notice = None;
                Some(JobKind::Software {
                    request: Box::new(request),
                })
            }
            Err(message) => {
                self.notice = Some(message.into());
                None
            }
        }
    }

    fn can_submit(&self) -> bool {
        let input = !self.request.input_path.as_os_str().is_empty();
        let output = self.request.output_path.is_some();
        let identity = self.identity.key().is_some();
        let reference = self.request.reference_path.is_some();
        match self.request.action {
            SoftwareAction::BuildPlugin => output,
            SoftwareAction::Mark => {
                input
                    && output
                    && identity
                    && !self.request.work_id.trim().is_empty()
                    && !self.request.copy_id.trim().is_empty()
            }
            SoftwareAction::Lab => {
                input
                    && identity
                    && !self.request.work_id.trim().is_empty()
                    && !self.request.copy_id.trim().is_empty()
            }
            SoftwareAction::Compare => input && reference,
            SoftwareAction::Clean => {
                input
                    && output
                    && match self.request.mode {
                        SoftwareMode::Source => identity,
                        SoftwareMode::Compiler => reference,
                        _ => true,
                    }
            }
            _ => input,
        }
    }

    fn prepared_request(&self, forensics: bool) -> Result<SoftwareRequest, &'static str> {
        let mut request = self.request.clone();
        request.key = self.identity.key();
        if forensics {
            request.mode = SoftwareMode::Structure;
            request.plugin_path = None;
            request.target_triple = None;
            request.compiler_arguments.clear();
        } else {
            request.compiler_arguments = serde_json::from_str(&self.compiler_arguments)
                .map_err(|_| "Compiler arguments must be a JSON array of strings")?;
        }
        if matches!(
            request.action,
            SoftwareAction::Inspect | SoftwareAction::Detect | SoftwareAction::Verify
        ) {
            request.output_path = None;
            request.reference_path = None;
            request.allow_execution = false;
        }
        request.test_arguments = if request.allow_execution {
            serde_json::from_str(&self.test_arguments)
                .map_err(|_| "Test arguments must be a JSON array of arrays")?
        } else {
            Vec::new()
        };
        request.trusted_keys = serde_json::from_str(&self.trusted_keys)
            .map_err(|_| "Trusted keys must be a JSON array of public keys")?;
        Ok(request)
    }
}

fn action_label(language: Language, action: SoftwareAction) -> &'static str {
    match action {
        SoftwareAction::Inspect | SoftwareAction::Detect => t(
            language,
            "分析结构与水印",
            "Analyze structure and watermarks",
        ),
        SoftwareAction::Mark => t(language, "Mark 植入并验证", "Mark and verify"),
        SoftwareAction::Clean => t(language, "Clean 创建净化副本", "Clean into a new copy"),
        SoftwareAction::Verify => t(language, "Verify 验证来源", "Verify provenance"),
        SoftwareAction::Compare => t(language, "比较两个版本", "Compare two versions"),
        SoftwareAction::BuildPlugin => t(language, "构建本机 LLVM 插件", "Build local LLVM plugin"),
        SoftwareAction::Lab => t(
            language,
            "运行编译器攻防基准",
            "Run compiler watermark benchmark",
        ),
    }
}
fn field(ui: &mut egui::Ui, language: Language, zh: &str, en: &str, value: &mut String) {
    ui.label(t(language, zh, en));
    ui.text_edit_singleline(value);
    ui.end_row();
}
pub(crate) fn optional_path(
    ui: &mut egui::Ui,
    language: Language,
    zh: &str,
    en: &str,
    value: &mut Option<PathBuf>,
    folder: bool,
) {
    ui.horizontal_wrapped(|ui| {
        if ui.button(t(language, zh, en)).clicked() {
            *value = if folder {
                rfd::FileDialog::new().pick_folder()
            } else {
                rfd::FileDialog::new().pick_file()
            };
        }
        if let Some(path) = value.as_ref() {
            ui.small(path.display().to_string());
        }
        if value.is_some() && ui.small_button(t(language, "移除", "Remove")).clicked() {
            *value = None;
        }
    });
}
pub fn report_ui(ui: &mut egui::Ui, language: Language, value: &serde_json::Value) {
    ui.strong(t(language, "软件验证结果", "Software verification result"));
    for key in [
        "verification_scope",
        "runtime_witness_removal",
        "llvm_version",
    ] {
        if let Some(value) = value[key].as_str() {
            ui.small(value);
        }
    }
    let packet = value
        .get("packet")
        .or_else(|| {
            value["binary"]["packets"]
                .as_array()
                .and_then(|packets| packets.first())
        })
        .or_else(|| {
            value["after"]["packets"]
                .as_array()
                .and_then(|packets| packets.first())
        });
    if let Some(packet) = packet {
        egui::Grid::new("software_signature_result").show(ui, |ui| {
            for (key, zh, en) in [
                ("signature", "签名", "Signature"),
                ("trust", "本地信任", "Local trust"),
                ("decryption", "声明解密", "Claim decryption"),
            ] {
                ui.label(t(language, zh, en));
                ui.monospace(packet[key].as_str().unwrap_or("not_assessed"));
                ui.end_row();
            }
        });
    }
    if let Some(functional) = value.get("functional") {
        ui.label(format!(
            "{}  {}",
            t(
                language,
                "指定输入功能对比",
                "Supplied-input functional comparison"
            ),
            functional["all_equal"]
                .as_bool()
                .map_or("not_assessed", |value| if value {
                    "equal"
                } else {
                    "different"
                })
        ));
    }
    if let Some(lab) = value.get("lab") {
        ui.label(format!(
            "{} / {}",
            lab["known_carrier_detections"], lab["case_count"]
        ));
        if let Some(rows) = lab["cases"].as_array() {
            egui::Grid::new("software_lab_results")
                .striped(true)
                .show(ui, |ui| {
                    for (zh, en) in [
                        ("优化", "Optimization"),
                        ("状态", "Status"),
                        ("字节数", "Bytes"),
                        ("CPU 秒", "CPU seconds"),
                        ("内存峰值 MiB", "Peak memory MiB"),
                        ("运行见证", "Runtime witness"),
                    ] {
                        ui.strong(t(language, zh, en));
                    }
                    ui.end_row();
                    for row in rows.iter().take(32) {
                        for key in ["optimization", "status", "marked_bytes"] {
                            ui.label(
                                row[key]
                                    .as_str()
                                    .map_or_else(|| row[key].to_string(), str::to_owned),
                            );
                        }
                        let metrics = &row["mark"]["functional"]["tests"][0]["output"]["metrics"];
                        ui.label(
                            metrics["cpu_seconds"]
                                .as_f64()
                                .map_or_else(|| "—".into(), |value| format!("{value:.3}")),
                        );
                        ui.label(metrics["peak_rss_bytes"].as_u64().map_or_else(
                            || "—".into(),
                            |value| format!("{:.2}", value as f64 / (1024. * 1024.)),
                        ));
                        ui.label(row["runtime"]["witness_matches"].to_string());
                        ui.end_row();
                    }
                });
        }
    }
    if let Some(disassembly) = value.get("disassembly") {
        ui.label(format!(
            "{} {} · {} {} · CFG {}",
            t(language, "函数", "Functions"),
            disassembly["function_count"],
            t(language, "指令", "Instructions"),
            disassembly["instruction_count"],
            disassembly["cfg_candidates"].as_array().map_or(0, Vec::len)
        ));
        if let Some(hash) = disassembly["normalized_instruction_sha256"].as_str() {
            ui.monospace(hash);
        }
    }
    if let (Some(before), Some(after)) = (
        value["before_disassembly"]["normalized_instruction_sha256"].as_str(),
        value["after_disassembly"]["normalized_instruction_sha256"].as_str(),
    ) {
        ui.label(format!(
            "{} {}",
            t(
                language,
                "归一化指令摘要相同",
                "Normalized instruction hashes match"
            ),
            before == after
        ));
    }
    let binary = value.get("binary").or_else(|| value.get("after"));
    if let Some(binary) = binary
        && let Some(sections) = binary["sections"].as_array()
    {
        egui::CollapsingHeader::new(t(language, "容器数据区", "Container sections")).show(
            ui,
            |ui| {
                egui::Grid::new("binary_sections")
                    .striped(true)
                    .show(ui, |ui| {
                        for section in sections.iter().take(64) {
                            ui.monospace(section["name"].as_str().unwrap_or("?"));
                            ui.label(section["size"].to_string());
                            ui.end_row();
                        }
                    });
            },
        );
    }
    ui.small(t(language,"已知载体、签名、信任和实际运行分别评级。未知软件水印仍可能存在。","Known carriers, signatures, trust and actual execution have separate results. Unknown software watermarks may remain."));
}
fn t<'a>(language: Language, zh: &'a str, en: &'a str) -> &'a str {
    text(language, zh, en)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binary_inspection_needs_no_key_and_discards_execution_parameters() {
        let mut panel = SoftwarePanel::default();
        panel.request.action = SoftwareAction::Inspect;
        panel.request.input_path = "sample.bin".into();
        panel.request.output_path = Some("stale-output".into());
        panel.request.reference_path = Some("stale-reference".into());
        panel.request.plugin_path = Some("stale-plugin".into());
        panel.request.target_triple = Some("stale-target".into());
        panel.request.allow_execution = true;
        panel.compiler_arguments = "irrelevant invalid JSON".into();
        panel.test_arguments = "irrelevant invalid JSON".into();
        assert!(panel.can_submit());
        let request = panel.prepared_request(true).unwrap();
        assert_eq!(request.action, SoftwareAction::Inspect);
        assert_eq!(request.mode, SoftwareMode::Structure);
        assert!(request.key.is_none());
        assert!(!request.allow_execution);
        assert!(request.compiler_arguments.is_empty() && request.test_arguments.is_empty());
        assert!(request.output_path.is_none() && request.reference_path.is_none());
        assert!(request.plugin_path.is_none() && request.target_triple.is_none());
    }
    #[test]
    fn forensic_action_is_enabled_without_identity_in_all_languages() {
        for language in Language::ALL {
            let context = egui::Context::default();
            context.enable_accesskit();
            let mut panel = SoftwarePanel::default();
            panel.request.input_path = "sample.bin".into();
            let output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1060., 700.),
                    )),
                    ..Default::default()
                },
                |ui| {
                    assert!(panel.ui(ui, language, true, None, true).is_none());
                },
            );
            let nodes = &output
                .platform_output
                .accesskit_update
                .as_ref()
                .unwrap()
                .nodes;
            let button = nodes
                .iter()
                .find(|(_, node)| {
                    node.role() == egui::Role::Button
                        && node.label() == Some(action_label(language, SoftwareAction::Inspect))
                })
                .expect("forensics action button");
            assert!(!button.1.is_disabled());
            assert!(!panel.request.allow_execution);
            output.drop_without_applying_deltas();
        }
    }
}

// FVPROV1 26210 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJjODY2OTQ4NGQ5ZGI3ODRjYThlMDk5YWU5MGVmZTQ2N2Q4ZmZkNjcyMmY4NWE3ZmFlNzA3ZWU0Zjc0ZjRjNTA4IiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvc3JjL3NvZnR3YXJlX3VpLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiNGQ1NDczNGNmMmUwNzg4M2U4ZjdhYWVjN2JmNDM4YTUxYWYxMmRmYzkzMWQ0YTUxYjRmNDFkNGVhOWJhM2MzNTkwNjZhNDY0MTdlYjQzMjFkODhhZTkzMGY4NWEyZTQxZDBjNDY2ZDIwNTkwYzJmMTQzMDZmMTQxZTRjOGM0MDMifV19XQ== FVPROV1-END
