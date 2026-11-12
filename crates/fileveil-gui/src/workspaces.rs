// SPDX-License-Identifier: MPL-2.0
//! Advanced workspaces run real isolated jobs and retain their verification reports.
use crate::{
    i18n::{Language, outcome},
    jobs::{JobHandle, JobKind, JobRequest, JobResult},
    session::Session,
};
use eframe::egui;
use fileveil_core::{Policy, SanitizeOptions};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum Workspace {
    #[default]
    Files,
    Deep,
    Images,
    Lab,
    Provenance,
    Tasks,
}
impl Workspace {
    pub fn label(self, language: Language) -> &'static str {
        match self {
            Self::Files => t(language, "文件扫描", "Files"),
            Self::Deep => t(language, "深度净化", "Deep clean"),
            Self::Images => t(language, "图片水印", "Image watermarks"),
            Self::Lab => t(language, "差异实验室", "Diff Lab"),
            Self::Provenance => t(language, "AI 来源", "AI Provenance"),
            Self::Tasks => t(language, "批量与验证", "Tasks & verification"),
        }
    }
}

pub struct Workspaces {
    pub selected: Workspace,
    options: SanitizeOptions,
    samples: Vec<PathBuf>,
    trust_roots: Option<PathBuf>,
    active: Option<JobHandle>,
    result: Option<JobResult>,
    last_write: Option<(PathBuf, SanitizeOptions)>,
    notice: Option<String>,
}
impl Default for Workspaces {
    fn default() -> Self {
        Self {
            selected: Workspace::Files,
            options: SanitizeOptions {
                policy: Policy::Deep,
                ..Default::default()
            },
            samples: Vec::new(),
            trust_roots: None,
            active: None,
            result: None,
            last_write: None,
            notice: None,
        }
    }
}
impl Workspaces {
    pub fn poll(&mut self, context: &egui::Context) {
        if let Some(result) = self.active.as_ref().and_then(JobHandle::try_recv) {
            self.result = Some(result);
            self.active = None;
        }
        if self.active.is_some() {
            context.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
    pub fn tabs(&mut self, ui: &mut egui::Ui, language: Language) {
        ui.horizontal_wrapped(|ui| {
            for workspace in [
                Workspace::Files,
                Workspace::Deep,
                Workspace::Images,
                Workspace::Lab,
                Workspace::Provenance,
                Workspace::Tasks,
            ] {
                ui.selectable_value(&mut self.selected, workspace, workspace.label(language));
            }
        });
        ui.separator();
    }
    fn start(&mut self, kind: JobKind, session: &Session, context: &egui::Context) {
        let mut request = JobRequest::new(kind);
        request.limits = session.limits.clone();
        request.timeout_seconds = session.timeout_seconds;
        let notify = context.clone();
        self.active = Some(JobHandle::spawn(
            request,
            Arc::new(move || notify.request_repaint()),
        ));
        self.result = None;
        self.notice = None;
    }
    /// Returns true when the existing Research parameter dialog should open.
    pub fn ui(&mut self, ui: &mut egui::Ui, language: Language, session: &mut Session) -> bool {
        let mut process_image = false;
        let path = session.selected_item().map(|item| item.path.clone());
        let idle = self.active.is_none() && session.active.is_none();
        ui.heading(self.selected.label(language));
        if let Some(path) = &path {
            ui.label(
                path.file_name()
                    .unwrap_or(path.as_os_str())
                    .to_string_lossy(),
            );
        }
        ui.add_space(12.0);
        match self.selected {
            Workspace::Deep => self.deep(ui, language, session, path.as_deref(), idle),
            Workspace::Images => {
                ui.label(t(language,"合成 LSB 包检测器可识别 FileVeil 公开测试协议。专有与未知水印的状态单独保持未评估。","The synthetic LSB detector recognizes FileVeil’s public test protocol. Proprietary and unknown schemes remain unassessed."));
                if ui
                    .add_enabled(
                        idle && path.is_some(),
                        egui::Button::new(t(language, "执行水印检测", "Run watermark detector")),
                    )
                    .clicked()
                {
                    self.start(
                        JobKind::DetectWatermark {
                            path: path.clone().expect("selected file"),
                        },
                        session,
                        ui.ctx(),
                    );
                }
                ui.add_space(12.0);
                ui.strong("Experimental Signal Processing");
                ui.label(t(language,"低位清理、缩放、模糊和重编码会改变像素。报告记录处理参数、像素差异及对应检测器的复验结果。","Low-bit clearing, resizing, smoothing and re-encoding change pixels. Reports retain parameters, measured differences and method-specific detector retests."));
                process_image = ui
                    .add_enabled(
                        idle && session
                            .selected
                            .is_some_and(|id| session.can_process_image(id)),
                        egui::Button::new(t(
                            language,
                            "配置图片信号处理",
                            "Configure image signal processing",
                        )),
                    )
                    .clicked();
            }
            Workspace::Lab => self.lab(ui, language, session, idle),
            Workspace::Provenance => {
                ui.label(t(language,"离线验证 C2PA 签名和文件绑定，可选择本地 PEM 信任根。来源凭据、个人身份关联及私有统计水印分别报告。","Validate C2PA signatures and asset binding offline with optional local PEM trust roots. Source credentials, identity links and proprietary statistical watermarks have separate results."));
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            idle,
                            egui::Button::new(t(
                                language,
                                "选择本地信任根",
                                "Choose local trust roots",
                            )),
                        )
                        .clicked()
                    {
                        self.trust_roots = rfd::FileDialog::new()
                            .add_filter("PEM", &["pem", "crt"])
                            .pick_file();
                    }
                    if self.trust_roots.is_some()
                        && ui.small_button(t(language, "移除", "Remove")).clicked()
                    {
                        self.trust_roots = None;
                    }
                });
                if let Some(roots) = &self.trust_roots {
                    ui.label(
                        roots
                            .file_name()
                            .unwrap_or(roots.as_os_str())
                            .to_string_lossy(),
                    );
                }
                ui.label(t(language,"私有文本统计水印检测接口尚未配置。网络上传默认关闭。","Proprietary text-watermark detection interfaces are unconfigured. Network uploads are disabled by default."));
                if ui
                    .add_enabled(
                        idle && path.is_some(),
                        egui::Button::new(t(language, "审计 AI 来源", "Audit AI provenance")),
                    )
                    .clicked()
                {
                    self.start(
                        JobKind::Provenance {
                            path: path.clone().expect("selected file"),
                            trust_roots: self.trust_roots.clone(),
                        },
                        session,
                        ui.ctx(),
                    );
                }
            }
            Workspace::Tasks => {
                ui.label(format!(
                    "{}  {}",
                    t(language, "排队任务", "Queued tasks"),
                    session.pending.len()
                ));
                if ui
                    .add_enabled(
                        idle && !session.items.is_empty(),
                        egui::Button::new(t(language, "扫描全部文件", "Scan all files")),
                    )
                    .clicked()
                {
                    session.queue_scan_all();
                }
                if ui
                    .add_enabled(
                        idle && !session.items.is_empty(),
                        egui::Button::new(t(language, "批量创建 Safe 副本", "Batch Safe copies")),
                    )
                    .clicked()
                {
                    session.queue_sanitize_all();
                }
                for item in &session.items {
                    ui.horizontal(|ui| {
                        ui.label(
                            item.path
                                .file_name()
                                .unwrap_or(item.path.as_os_str())
                                .to_string_lossy(),
                        );
                        if let Some(report) = &item.latest {
                            ui.label(outcome(language, report.result));
                        }
                    });
                }
                ui.label(t(language,"文件工作区保留每个副本的二次验证、原件哈希和报告导出。","The Files workspace retains each copy’s second-pass verification, original hash and report export."));
            }
            Workspace::Files => {}
        }
        if let Some(active) = &self.active {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(t(
                    language,
                    "正在隔离进程中执行",
                    "Running in an isolated worker",
                ));
                if ui.button(t(language, "取消", "Cancel")).clicked() {
                    active.cancel();
                }
            });
        }
        if let Some(notice) = &self.notice {
            ui.label(notice);
        }
        self.result_ui(ui, language, idle, session);
        process_image
    }
    fn deep(
        &mut self,
        ui: &mut egui::Ui,
        language: Language,
        session: &Session,
        input: Option<&Path>,
        idle: bool,
    ) {
        ui.label(t(language,"明确选择清理范围。Deep 可以删除文档内容与历史，输出会逐项复验，并记录保真验证范围。","Choose the cleanup scope explicitly. Deep can remove document content and history. Each output is checked against the selected scope."));
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.options.policy, Policy::Safe, "Safe");
            ui.selectable_value(&mut self.options.policy, Policy::Deep, "Deep");
        });
        ui.add_enabled_ui(idle,|ui| {
            egui::CollapsingHeader::new(t(language,"Office 深度范围","Office content scope")).default_open(true).show(ui,|ui| {
                ui.add_enabled_ui(self.options.policy==Policy::Deep,|ui| {
                    ui.checkbox(&mut self.options.deep.remove_comments,t(language,"批注与作者","Comments and authors"));
                    ui.checkbox(&mut self.options.deep.accept_revisions,t(language,"接受简单 Word 修订","Accept simple Word revisions"));
                    ui.checkbox(&mut self.options.deep.remove_hidden_text,t(language,"显式隐藏的 Word 文本","Explicitly hidden Word text"));
                    ui.checkbox(&mut self.options.deep.remove_custom_xml,t(language,"自定义 XML 与绑定","Custom XML and bindings"));
                    ui.checkbox(&mut self.options.deep.remove_embedded_objects,t(language,"可安全解除引用的嵌入对象","Embedded objects with supported references"));
                    ui.checkbox(&mut self.options.deep.remove_external_relationships,t(language,"外部超链接关系","External hyperlink relationships"));
                    ui.checkbox(&mut self.options.deep.remove_internal_identifiers,t(language,"内部编辑标识符","Internal editing identifiers"));
                });
                ui.label(t(language,"隐藏工作表及复杂公式、图表和修订依赖会报告阻断原因。","Hidden sheets and complex formula, chart or revision dependencies report explicit blockers."));
            });
            egui::CollapsingHeader::new(t(language,"PDF 深度范围","PDF content scope")).show(ui,|ui| {
                ui.add_enabled_ui(self.options.policy==Policy::Deep,|ui| {
                    ui.checkbox(&mut self.options.pdf.remove_attachments,t(language,"附件及嵌入文件","Attachments and embedded files"));
                    ui.checkbox(&mut self.options.pdf.remove_javascript,t(language,"JavaScript 主动内容","JavaScript active content"));
                    ui.checkbox(&mut self.options.pdf.remove_annotations,t(language,"注释与批注","Annotations and comments"));
                });
                ui.label(t(language,"带签名、加密或受保护表单的操作将报告阻断原因。","Signed, encrypted and protected form structures report explicit blockers."));
            });
            egui::CollapsingHeader::new(t(language,"文本与 HTML","Text and HTML")).show(ui,|ui| {
                ui.checkbox(&mut self.options.text.remove_bom,t(language,"移除开头 BOM","Remove leading BOM"));
                ui.checkbox(&mut self.options.text.remove_control_characters,t(language,"异常控制符与非语言标记","Abnormal controls and nonlinguistic markers"));
                ui.checkbox(&mut self.options.text.remove_html_metadata,t(language,"HTML 作者、生成器和来源字段","HTML author, generator and source fields"));
                ui.checkbox(&mut self.options.text.remove_html_comments,t(language,"HTML 注释","HTML comments"));
                ui.label(t(language,"保留 ZWJ、ZWNJ 和合法双向文本字符。复杂 HTML 结构会安全失败。","ZWJ, ZWNJ and legitimate bidirectional text are preserved. Unsupported complex HTML structures fail safely."));
            });
            egui::CollapsingHeader::new(t(language,"文件系统隐私属性","Filesystem privacy attributes")).show(ui,|ui| {
                ui.checkbox(&mut self.options.filesystem.remove_download_origin,t(language,"macOS 下载来源","macOS download origins"));
                ui.checkbox(&mut self.options.filesystem.remove_finder_tags,t(language,"Finder 标签","Finder tags"));
                ui.checkbox(&mut self.options.filesystem.remove_user_attributes,t(language,"Unix user.* 扩展属性","Unix user.* attributes"));
                ui.checkbox(&mut self.options.filesystem.remove_ntfs_private_streams,t(language,"NTFS 私有数据流","NTFS private data streams"));
                ui.checkbox(&mut self.options.filesystem.normalize_output_timestamps,t(language,"新副本修改时间规范化","Normalize new-copy modification time"));
                ui.label(t(language,"保留 Quarantine、Mark-of-the-Web 和受保护属性。资源叉会阻断重写。","Quarantine, Mark-of-the-Web and protected attributes are preserved. Resource forks block rewriting."));
            });
        });
        if self.options.policy == Policy::Safe {
            self.options.deep = Default::default();
        }
        if ui
            .add_enabled(
                idle && input.is_some(),
                egui::Button::new(t(
                    language,
                    "保存并复验净化副本",
                    "Save and verify clean copy",
                )),
            )
            .clicked()
        {
            let input = input.expect("selected file");
            let name = input.file_stem().unwrap_or_default().to_string_lossy();
            let extension = input.extension().unwrap_or_default().to_string_lossy();
            if let Some(output) = rfd::FileDialog::new()
                .set_directory(input.parent().unwrap_or(Path::new(".")))
                .set_file_name(format!("{name}.deep.{extension}"))
                .save_file()
            {
                self.last_write = Some((input.to_path_buf(), self.options.clone()));
                self.start(
                    JobKind::SanitizeAdvanced {
                        input: input.to_path_buf(),
                        output: Some(output),
                        options: self.options.clone(),
                    },
                    session,
                    ui.ctx(),
                );
            }
        }
    }
    fn lab(&mut self, ui: &mut egui::Ui, language: Language, session: &Session, idle: bool) {
        ui.label(t(language,"选择 2 至 8 张样本。加入干净图、编码变化与传感器噪声对照，可比较同设备、同场景或处理前后的变化。","Choose 2 to 8 samples with clean, encoding and sensor-noise controls. Compare same-device, same-scene and before/after experiments."));
        if ui
            .add_enabled(
                idle,
                egui::Button::new(t(language, "选择对照样本", "Choose control samples")),
            )
            .clicked()
            && let Some(paths) = rfd::FileDialog::new()
                .add_filter("JPEG / PNG", &["jpg", "jpeg", "png"])
                .pick_files()
        {
            if (2..=8).contains(&paths.len()) {
                self.samples = paths;
                self.notice = None;
            } else {
                self.notice =
                    Some(t(language, "请选择 2 至 8 个样本", "Select 2 to 8 samples").into());
            }
        }
        for (index, path) in self.samples.iter().enumerate() {
            ui.label(format!(
                "{}  {}",
                index + 1,
                path.file_name()
                    .unwrap_or(path.as_os_str())
                    .to_string_lossy()
            ));
        }
        ui.label(t(language,"分析像素差分、RGB 低位、信息熵和 DCT/DFT 频域特征。单项异常无法确认水印或厂商归因。","Analyze pixel differences, RGB low bits, entropy and DCT/DFT frequency features. A statistical anomaly alone cannot establish a watermark or OEM attribution."));
        if ui
            .add_enabled(
                idle && self.samples.len() >= 2,
                egui::Button::new(t(language, "执行差异分析", "Analyze differences")),
            )
            .clicked()
        {
            self.start(
                JobKind::Lab {
                    paths: self.samples.clone(),
                },
                session,
                ui.ctx(),
            );
        }
    }
    fn result_ui(&mut self, ui: &mut egui::Ui, language: Language, idle: bool, session: &Session) {
        let Some(result) = &self.result else {
            return;
        };
        ui.separator();
        ui.strong(outcome(language, result.report.result));
        if let Some(name) = &result.report.output_name {
            ui.label(name);
        }
        if let Some(details) = &result.report.provenance {
            for (key, zh, en) in [
                ("signature", "签名", "Signature"),
                ("asset_binding", "文件绑定", "Asset binding"),
                ("trust", "根信任", "Root trust"),
                ("revocation", "吊销证据", "Revocation evidence"),
            ] {
                ui.label(format!(
                    "{}  {}",
                    t(language, zh, en),
                    status(language, details[key].as_str().unwrap_or("not_assessed"))
                ));
            }
        }
        if let Some(details) = &result.report.advanced {
            if let Some(detection) = details.get("detection") {
                ui.label(format!(
                    "{}  {}",
                    t(language, "检测结果", "Detection result"),
                    status(
                        language,
                        detection["status"].as_str().unwrap_or("not_assessed")
                    )
                ));
            }
            if let Some(lab) = details.get("lab") {
                if let Some(samples) = lab["samples"].as_array() {
                    for sample in samples {
                        ui.label(format!(
                            "{} · {} × {}",
                            sample["sample_index"], sample["width"], sample["height"]
                        ));
                        if let Some(channels) = sample["channels"].as_array() {
                            ui.label(format!(
                                "{}  {}",
                                t(language, "RGB 信息熵", "RGB entropy"),
                                channels
                                    .iter()
                                    .map(|channel| format!(
                                        "{:.3}",
                                        channel["entropy_bits"].as_f64().unwrap_or_default()
                                    ))
                                    .collect::<Vec<_>>()
                                    .join(" / ")
                            ));
                        }
                    }
                }
            }
        }
        for finding in &result.report.findings {
            ui.label(crate::i18n::finding_summary(language, finding));
        }
        for warning in &result.report.warnings {
            ui.small(crate::i18n::tr(language, warning));
        }
        let report = result.report.clone();
        let output = result.output_path.clone();
        ui.horizontal(|ui| {
            if ui
                .button(t(language, "导出报告", "Export report"))
                .clicked()
                && let Some(path) = rfd::FileDialog::new()
                    .set_file_name("fileveil-report.json")
                    .save_file()
            {
                let saved = (|| -> Result<(), Box<dyn std::error::Error>> {
                    use std::io::Write;
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(path)?;
                    file.write_all(&serde_json::to_vec_pretty(&report)?)?;
                    Ok(())
                })();
                self.notice = Some(if saved.is_ok() {
                    t(language, "报告已保存", "Report saved").into()
                } else {
                    t(
                        language,
                        "报告保存失败，请选择新路径",
                        "Report could not be saved. Choose a new path",
                    )
                    .into()
                });
            }
            if let Some((input, options)) = &self.last_write
                && let Some(output) = output
                && ui
                    .add_enabled(
                        idle,
                        egui::Button::new(t(language, "再次验证副本", "Verify copy again")),
                    )
                    .clicked()
            {
                self.start(
                    JobKind::VerifyAdvanced {
                        original: input.clone(),
                        output,
                        options: options.clone(),
                    },
                    session,
                    ui.ctx(),
                );
            }
        });
    }
}
fn status(language: Language, value: &str) -> &str {
    if language == Language::English {
        return value;
    }
    match value {
        "valid" => "有效",
        "invalid" => "无效",
        "trusted" => "受信任",
        "untrusted" => "不受信任",
        "unverifiable" => "无法验证",
        "detected" => "检测到",
        "not_detected" => "未检测到",
        "indeterminate" => "无法判断",
        "not_assessed" => "未评估",
        _ => value,
    }
}
fn t<'a>(language: Language, zh: &'a str, en: &'a str) -> &'a str {
    if language == Language::Chinese {
        zh
    } else {
        en
    }
}
