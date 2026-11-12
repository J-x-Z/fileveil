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
    result_workspace: Workspace,
    result_input: Option<PathBuf>,
    result_samples: Vec<PathBuf>,
    last_write: Option<(PathBuf, SanitizeOptions)>,
    last_output: Option<PathBuf>,
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
            result_workspace: Workspace::Files,
            result_input: None,
            result_samples: Vec::new(),
            last_write: None,
            last_output: None,
            notice: None,
        }
    }
}
impl Workspaces {
    pub fn poll(&mut self, context: &egui::Context) {
        if let Some(result) = self.active.as_ref().and_then(JobHandle::try_recv) {
            self.record_result(result);
            self.active = None;
        }
        if self.active.is_some() {
            context.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
    pub fn busy(&self) -> bool {
        self.active.is_some()
    }
    pub fn cancel(&self) {
        if let Some(active) = &self.active {
            active.cancel();
        }
    }
    fn idle(&self, session: &Session) -> bool {
        !self.busy() && session.active.is_none() && session.pending.is_empty()
    }
    fn record_result(&mut self, result: JobResult) {
        if self.result_workspace == Workspace::Deep && result.report.operation == "sanitize" {
            self.last_output = result.output_path.clone();
        }
        self.result = Some(result);
    }
    fn verification_request(&self) -> Option<JobKind> {
        if self.selected != Workspace::Deep || self.result_workspace != Workspace::Deep {
            return None;
        }
        let (input, options) = self.last_write.as_ref()?;
        let output = self
            .result
            .as_ref()?
            .output_path
            .clone()
            .or_else(|| self.last_output.clone())?;
        Some(JobKind::VerifyAdvanced {
            original: input.clone(),
            output,
            options: options.clone(),
        })
    }
    pub fn tabs(&mut self, ui: &mut egui::Ui, language: Language) {
        let previous = self.selected;
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
                if self.busy() && self.result_workspace == workspace {
                    ui.spinner();
                }
            }
        });
        if self.selected != previous {
            self.notice = None;
        }
        ui.separator();
    }
    fn start(&mut self, kind: JobKind, session: &Session, context: &egui::Context) {
        if !self.idle(session) {
            return;
        }
        self.result_workspace = self.selected;
        self.result_samples = match &kind {
            JobKind::Lab { paths } | JobKind::LabGrouped { paths, .. } => paths.clone(),
            _ => Vec::new(),
        };
        self.result_input = match &kind {
            JobKind::SanitizeAdvanced { input, .. }
            | JobKind::Sanitize { input, .. }
            | JobKind::ProcessImage { input, .. } => Some(input.clone()),
            JobKind::VerifyAdvanced { original, .. }
            | JobKind::Verify { original, .. }
            | JobKind::VerifyImage { original, .. } => Some(original.clone()),
            JobKind::Provenance { path, .. }
            | JobKind::DetectWatermark { path }
            | JobKind::Scan { path } => Some(path.clone()),
            JobKind::Lab { .. } | JobKind::LabGrouped { .. } => None,
        };
        if matches!(kind, JobKind::SanitizeAdvanced { .. }) {
            self.last_output = None;
        }
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
        let idle = self.idle(session);
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
                ui.strong(t(
                    language,
                    "实验性图像信号处理",
                    "Experimental Signal Processing",
                ));
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
                if let Some(item) = session.selected_item()
                    && let Some(report) = item.latest.as_ref()
                    && let Some(processing) = &report.image_processing
                {
                    ui.separator();
                    ui.strong(t(
                        language,
                        "最近一次图片处理结果",
                        "Latest image processing result",
                    ));
                    ui.label(outcome(language, report.result));
                    if let Some(output) = &item.output_path {
                        ui.label(
                            output
                                .file_name()
                                .unwrap_or(output.as_os_str())
                                .to_string_lossy(),
                        );
                    }
                    ui.label(format!(
                        "{}  {} · {}  {} · MSE  {:.4}",
                        t(language, "改动通道数", "Changed samples"),
                        processing.changed_samples,
                        t(language, "最大变化", "Maximum change"),
                        processing.max_delta,
                        processing.mse
                    ));
                    if let Some(bits) = processing.low_bits {
                        ui.label(format!(
                            "{}  {}",
                            t(language, "RGB 清理低位数", "RGB low bits cleared"),
                            bits
                        ));
                    } else {
                        ui.label(format!(
                            "{}  {:.2} · {}  {:.2} · JPEG  {}",
                            t(language, "缩放", "Scale"),
                            processing.resize_scale.unwrap_or(1.0),
                            t(language, "模糊", "Blur"),
                            processing.blur_sigma.unwrap_or_default(),
                            processing.jpeg_quality.unwrap_or_default()
                        ));
                    }
                    method_retest_ui(ui, language, report);
                    ui.small(t(
                        language,
                        "未知及专有水印仍未评估。",
                        "Unknown and proprietary watermarks remain unassessed.",
                    ));
                }
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
                        && let Some(roots) = rfd::FileDialog::new()
                            .add_filter("PEM", &["pem", "crt"])
                            .pick_file()
                    {
                        self.trust_roots = Some(roots);
                    }
                    if self.trust_roots.is_some()
                        && ui
                            .add_enabled(
                                idle,
                                egui::Button::new(t(language, "移除", "Remove")).small(),
                            )
                            .clicked()
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
                let eligible = eligible_safe_copies(session);
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
                        idle && eligible > 0,
                        egui::Button::new(t(language, "批量创建 Safe 副本", "Batch Safe copies")),
                    )
                    .clicked()
                {
                    session.queue_sanitize_all();
                }
                ui.label(format!(
                    "{}  {}",
                    t(
                        language,
                        "可创建 Safe 副本的文件",
                        "Files eligible for Safe copies"
                    ),
                    eligible
                ));
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
        let mime = session
            .selected_item()
            .and_then(|item| item.scan.as_ref())
            .map(|report| report.input_format.as_str())
            .unwrap_or("");
        let office = mime.starts_with("application/vnd.openxmlformats-officedocument.");
        let text = matches!(mime, "text/plain" | "text/markdown" | "text/html");
        let credentials = matches!(
            mime,
            "image/jpeg" | "image/png" | "application/pdf" | "text/plain" | "text/markdown"
        );
        ui.add_enabled_ui(
            idle && self.options.policy == Policy::Deep && credentials,
            |ui| {
                ui.checkbox(
                    &mut self.options.remove_provenance,
                    t(
                        language,
                        "移除可移除来源凭据及其签名",
                        "Remove removable source credentials and their signatures",
                    ),
                );
            },
        );
        if self.options.remove_provenance && credentials && self.options.policy == Policy::Deep {
            ui.label(t(language,"输出副本将失去这些来源签名，其他来源关联仍需对应检测器评估。","The copy will lose these source signatures. Other source associations require their corresponding detectors."));
        }
        ui.add_enabled_ui(idle,|ui| {
            egui::CollapsingHeader::new(t(language,"Office 深度范围","Office content scope")).default_open(true).show(ui,|ui| {
                ui.add_enabled_ui(self.options.policy==Policy::Deep && office,|ui| {
                    ui.checkbox(&mut self.options.deep.remove_comments,t(language,"批注与作者","Comments and authors"));
                    ui.add_enabled_ui(mime == fileveil_core::Format::Docx.mime(), |ui| {
                        ui.checkbox(&mut self.options.deep.accept_revisions,t(language,"接受简单 Word 修订","Accept simple Word revisions"));
                        ui.checkbox(&mut self.options.deep.remove_hidden_text,t(language,"显式隐藏的 Word 文本","Explicitly hidden Word text"));
                        ui.checkbox(&mut self.options.deep.remove_internal_identifiers,t(language,"Word 内部编辑标识符","Word internal editing identifiers"));
                    });
                    ui.add_enabled_ui(mime == fileveil_core::Format::Xlsx.mime(), |ui| {
                        ui.checkbox(&mut self.options.deep.remove_hidden_sheets,t(language,"无依赖的隐藏工作表","Hidden worksheets without dependencies"));
                    });
                    ui.checkbox(&mut self.options.deep.remove_custom_xml,t(language,"自定义 XML 与绑定","Custom XML and bindings"));
                    ui.checkbox(&mut self.options.deep.remove_embedded_objects,t(language,"可安全解除引用的嵌入对象","Embedded objects with supported references"));
                    ui.checkbox(&mut self.options.deep.remove_external_relationships,t(language,"外部超链接关系","External hyperlink relationships"));
                });
                ui.label(t(language,"存在公式、共享字符串、图表或复杂修订依赖时会报告阻断原因。","Formula, shared-string, chart and complex revision dependencies report explicit blockers."));
            });
            egui::CollapsingHeader::new(t(language,"PDF 深度范围","PDF content scope")).show(ui,|ui| {
                ui.add_enabled_ui(self.options.policy==Policy::Deep && mime == "application/pdf",|ui| {
                    ui.checkbox(&mut self.options.pdf.remove_attachments,t(language,"附件及嵌入文件","Attachments and embedded files"));
                    ui.checkbox(&mut self.options.pdf.remove_javascript,t(language,"JavaScript 主动内容","JavaScript active content"));
                    ui.checkbox(&mut self.options.pdf.remove_annotations,t(language,"注释与批注","Annotations and comments"));
                });
                ui.label(t(language,"带签名、加密或受保护表单的操作将报告阻断原因。","Signed, encrypted and protected form structures report explicit blockers."));
            });
            egui::CollapsingHeader::new(t(language,"文本与 HTML","Text and HTML")).show(ui,|ui| {
                ui.add_enabled_ui(text, |ui| {
                ui.checkbox(&mut self.options.text.remove_bom,t(language,"移除开头 BOM","Remove leading BOM"));
                ui.checkbox(&mut self.options.text.remove_control_characters,t(language,"异常控制符与非语言标记","Abnormal controls and nonlinguistic markers"));
                ui.add_enabled_ui(mime == "text/html", |ui| {
                    ui.checkbox(&mut self.options.text.remove_html_metadata,t(language,"HTML 作者、生成器和来源字段","HTML author, generator and source fields"));
                    ui.checkbox(&mut self.options.text.remove_html_comments,t(language,"HTML 注释","HTML comments"));
                });
                ui.label(t(language,"保留 ZWJ、ZWNJ 和合法双向文本字符。复杂 HTML 结构会安全失败。","ZWJ, ZWNJ and legitimate bidirectional text are preserved. Unsupported complex HTML structures fail safely."));
                });
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
        if let Some(scan) = session.selected_item().and_then(|item| item.scan.as_ref()) {
            egui::CollapsingHeader::new(t(
                language,
                "文件系统属性计划",
                "Filesystem attribute plan",
            ))
            .show(ui, |ui| {
                for finding in scan
                    .findings
                    .iter()
                    .filter(|finding| finding.layer == fileveil_core::RiskLayer::Filesystem)
                {
                    let remove = match finding.code.as_str() {
                        "filesystem.download_origin" => {
                            self.options.filesystem.remove_download_origin
                        }
                        "filesystem.finder_tags" => self.options.filesystem.remove_finder_tags,
                        _ => false,
                    };
                    let action = if finding.code == "filesystem.resource_fork" {
                        t(language, "阻断重写", "Blocks rewriting")
                    } else if remove {
                        t(language, "移除", "Remove")
                    } else {
                        t(
                            language,
                            "保留，按所选命名空间进一步判定",
                            "Preserve or evaluate the selected namespace",
                        )
                    };
                    ui.label(format!(
                        "{} · {}",
                        crate::i18n::finding_title(language, finding),
                        action
                    ));
                }
            });
        }
        let supported = session
            .selected_item()
            .and_then(|item| item.scan.as_ref())
            .is_some_and(|report| {
                report.result != fileveil_core::Outcome::Unsupported
                    && !matches!(mime, "audio/mpeg" | "application/octet-stream")
            });
        if !supported {
            ui.label(t(language,"当前格式或处理后端未提供净化能力，可在文件扫描中查看具体状态。","Cleaning is unavailable for this format or backend. The Files scan records its capability status."));
        }
        if ui
            .add_enabled(
                idle && input.is_some() && supported,
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
                let options = options_for_format(&self.options, mime);
                self.last_write = Some((input.to_path_buf(), options.clone()));
                self.start(
                    JobKind::SanitizeAdvanced {
                        input: input.to_path_buf(),
                        output: Some(output),
                        options,
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
        if self.result_workspace != self.selected {
            return;
        }
        let Some(result) = &self.result else {
            return;
        };
        ui.separator();
        if let Some(input) = &self.result_input {
            ui.label(format!(
                "{}  {}",
                t(language, "报告对应文件", "Report for"),
                input
                    .file_name()
                    .unwrap_or(input.as_os_str())
                    .to_string_lossy()
            ));
        }
        ui.strong(outcome(language, result.report.result));
        if let Some(name) = &result.report.output_name {
            ui.label(name);
        }
        if let Some(details) = &result.report.provenance {
            if result
                .report
                .advanced
                .as_ref()
                .is_some_and(|advanced| advanced.get("provenance_removal").is_some())
            {
                ui.strong(t(language, "原件来源凭据", "Original source credentials"));
                ui.label(t(language, "输出复验未发现对应凭据或来源引用，其签名已随所选凭据移除。", "Output verification found no corresponding credentials or source references. Their signatures were discarded with the selected credentials."));
            }
            for (key, zh, en) in [
                ("signature", "签名", "Signature"),
                ("asset_binding", "文件绑定", "Asset binding"),
                ("manifest_validation", "凭据整体校验", "Manifest validation"),
                ("trust", "根信任", "Root trust"),
                ("revocation", "吊销证据", "Revocation evidence"),
            ] {
                ui.label(format!(
                    "{}  {}",
                    t(language, zh, en),
                    status(language, details[key].as_str().unwrap_or("not_assessed"))
                ));
            }
            if let Some(scope) = details.get("text_scope").filter(|value| value.is_object()) {
                ui.label(t(
                    language,
                    "实验性标准文本来源包装",
                    "Experimental standard text credential wrappers",
                ));
                if scope["removal_supported"] == false {
                    ui.small(t(
                        language,
                        "当前包装上下文受到保护，无法安全移除。",
                        "The current wrapper context is protected from removal.",
                    ));
                }
                if details["asset_binding_scope"] == "nfc_normalization_required_not_performed" {
                    ui.small(t(language, "保留原始 Unicode 字节，非 NFC 文本的资产绑定无法完整验证。", "Original Unicode bytes are preserved. Asset binding for non-NFC text cannot be fully verified."));
                }
            }
        } else if self.result_workspace == Workspace::Provenance {
            ui.label(t(language,"本次未取得可读取的 C2PA 来源凭据，未知 AI 水印仍未评估。","This run obtained no readable C2PA credentials. Unknown AI watermarks remain unassessed."));
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
            if let Some(lab) = details.get("lab")
                && let Some(samples) = lab["samples"].as_array()
            {
                for sample in samples {
                    let index = sample["sample_index"].as_u64().unwrap_or_default() as usize;
                    let name = self
                        .result_samples
                        .get(index)
                        .map(|path| {
                            path.file_name()
                                .unwrap_or(path.as_os_str())
                                .to_string_lossy()
                        })
                        .unwrap_or_default();
                    ui.label(format!(
                        "{}  {} · {} × {}",
                        index + 1,
                        name,
                        sample["width"],
                        sample["height"]
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
                        ui.label(format!(
                            "{}  {}",
                            t(
                                language,
                                "RGB 最低位为 1 的通道数",
                                "RGB lowest-bit one counts"
                            ),
                            channels
                                .iter()
                                .map(|channel| channel["lsb_one_counts"][0].to_string())
                                .collect::<Vec<_>>()
                                .join(" / ")
                        ));
                    }
                    if let Some(frequency) = sample.get("frequency") {
                        ui.label(format!(
                            "{}  {:.5} · {}  {:.5}",
                            t(language, "DFT 交流能量", "DFT AC energy"),
                            frequency["dft_ac_energy"].as_f64().unwrap_or_default(),
                            t(language, "DCT 交流能量", "DCT AC energy"),
                            frequency["dct_ac_energy"].as_f64().unwrap_or_default()
                        ));
                    }
                    if sample["converted_to_rgb8"] == true {
                        ui.small(t(language,"该样本已转换为 RGB8，低位统计采用转换后的样本。","This sample was converted to RGB8. Low-bit statistics use the converted samples."));
                    }
                    egui::CollapsingHeader::new(t(
                        language,
                        "分布与频域图",
                        "Distributions and frequency bands",
                    ))
                    .id_salt(("lab-plots", index))
                    .show(ui, |ui| sample_plots(ui, language, sample));
                }
                if let Some(comparisons) = lab["comparisons"].as_array() {
                    ui.add_space(8.0);
                    ui.strong(t(language, "样本差分", "Sample comparisons"));
                    for comparison in comparisons {
                        let first = comparison["first_sample"].as_u64().unwrap_or_default() + 1;
                        let second = comparison["second_sample"].as_u64().unwrap_or_default() + 1;
                        if let Some(pixels) = comparison.get("pixels") {
                            ui.label(format!(
                                "{first} ↔ {second} · MSE {:.4} · {} {:.2}% / {:.2}%",
                                pixels["mean_squared_error"].as_f64().unwrap_or_default(),
                                t(language, "低两位差异", "Two low-bit differences"),
                                pixels["lsb_disagreement_fraction"][0]
                                    .as_f64()
                                    .unwrap_or_default()
                                    * 100.0,
                                pixels["lsb_disagreement_fraction"][1]
                                    .as_f64()
                                    .unwrap_or_default()
                                    * 100.0
                            ));
                        } else {
                            ui.label(format!(
                                "{first} ↔ {second} · {}",
                                t(
                                    language,
                                    "尺寸不同，像素差分未执行",
                                    "Different dimensions. Pixel comparison was not performed"
                                )
                            ));
                        }
                        ui.small(format!(
                            "{} {:.5} · {} {:.5}",
                            t(language, "DFT 差异", "DFT difference"),
                            comparison["dft_band_distance"].as_f64().unwrap_or_default(),
                            t(language, "DCT 差异", "DCT difference"),
                            comparison["dct_band_distance"].as_f64().unwrap_or_default()
                        ));
                    }
                }
            }
        }
        for finding in &result.report.findings {
            ui.label(format!(
                "{} · {}",
                crate::i18n::finding_title(language, finding),
                crate::i18n::state(language, finding.state)
            ));
            if finding.state != fileveil_core::FindingState::RemovedVerified {
                ui.small(crate::i18n::finding_summary(language, finding));
            }
        }
        for warning in &result.report.warnings {
            ui.small(crate::i18n::tr(language, warning));
        }
        let report = result.report.clone();
        let verification = self.verification_request();
        ui.horizontal(|ui| {
            if ui
                .button(t(language, "导出报告", "Export report"))
                .clicked()
                && let Some(path) = rfd::FileDialog::new()
                    .set_file_name("fileveil-report.json")
                    .save_file()
            {
                let saved = serde_json::to_vec_pretty(&report)
                    .map_err(|_| "Could not serialize report".to_string())
                    .and_then(|bytes| crate::app::save_report(&path, &bytes));
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
            if let Some(verification) = verification
                && ui
                    .add_enabled(
                        idle,
                        egui::Button::new(t(language, "再次验证副本", "Verify copy again")),
                    )
                    .clicked()
            {
                self.start(verification, session, ui.ctx());
            }
        });
    }
}
fn status(language: Language, value: &str) -> &str {
    match value {
        "valid" => t(language, "有效", "Valid"),
        "invalid" => t(language, "无效", "Invalid"),
        "trusted" => t(language, "受信任", "Trusted"),
        "untrusted" => t(language, "不受信任", "Untrusted"),
        "unverifiable" => t(language, "无法验证", "Unverifiable"),
        "detected" => t(language, "检测到", "Detected"),
        "not_detected" => t(language, "未检测到", "Not detected"),
        "indeterminate" => t(language, "无法判断", "Indeterminate"),
        "not_assessed" => t(language, "未评估", "Not assessed"),
        "detector_no_longer_detects" => t(
            language,
            "对应检测器复验未检出",
            "Detector no longer detects",
        ),
        "detector_still_detects" => t(language, "对应检测器复验仍检出", "Detector still detects"),
        _ => value,
    }
}

fn eligible_safe_copies(session: &Session) -> usize {
    session
        .items
        .iter()
        .filter(|item| session.can_sanitize(item.id))
        .count()
}

pub(crate) fn method_retest_ui(
    ui: &mut egui::Ui,
    language: Language,
    report: &fileveil_core::Report,
) {
    if let Some(summary) = method_retest_summary(language, report) {
        ui.small(t(
            language,
            "特定合成检测器复验",
            "Method-specific synthetic detector retest",
        ));
        ui.label(summary);
    }
}

pub(crate) fn method_retest_summary(
    language: Language,
    report: &fileveil_core::Report,
) -> Option<String> {
    let retest = report.advanced.as_ref()?.get("watermark_retest")?;
    Some(format!(
        "{} · {} → {} · {}",
        retest["method_id"].as_str().unwrap_or("synthetic_lsb_v1"),
        status(
            language,
            retest["before"]["status"]
                .as_str()
                .unwrap_or("not_assessed")
        ),
        status(
            language,
            retest["after"]["status"].as_str().unwrap_or("not_assessed")
        ),
        status(
            language,
            retest["result"].as_str().unwrap_or("not_assessed")
        )
    ))
}

fn sample_plots(ui: &mut egui::Ui, language: Language, sample: &serde_json::Value) {
    if let Some(channels) = sample["channels"].as_array() {
        ui.small(t(
            language,
            "RGB 每 16 个亮度级合并一组，悬停显示分组计数。",
            "RGB values use 16-level bins. Hover to inspect each count.",
        ));
        let mut low_bits = Vec::new();
        let pixels =
            sample["width"].as_f64().unwrap_or(0.0) * sample["height"].as_f64().unwrap_or(0.0);
        for (index, channel) in channels.iter().enumerate() {
            let name = ["R", "G", "B"].get(index).unwrap_or(&"RGB");
            if let Some(histogram) = channel["histogram"].as_array() {
                let values = histogram
                    .as_chunks::<16>()
                    .0
                    .iter()
                    .map(|bin| {
                        bin.iter()
                            .map(|count| count.as_f64().unwrap_or_default())
                            .sum()
                    })
                    .collect::<Vec<_>>();
                let labels = (0..values.len())
                    .map(|bin| (bin * 16).to_string())
                    .collect::<Vec<_>>();
                bar_plot(ui, name, &values, &labels, None);
            }
            if pixels > 0.0 {
                low_bits.extend((0..2).map(|bit| {
                    channel["lsb_one_counts"][bit].as_f64().unwrap_or_default() / pixels
                }));
            }
        }
        let labels = ["R0", "R1", "G0", "G1", "B0", "B1"].map(String::from);
        bar_plot(
            ui,
            t(
                language,
                "RGB 低两位为 1 的占比",
                "RGB two-low-bit one fractions",
            ),
            &low_bits,
            &labels,
            Some(1.0),
        );
    }
    for (key, title) in [
        (
            "dft_radial_power",
            t(
                language,
                "DFT 16×16 交流频带能量",
                "DFT 16×16 AC band power",
            ),
        ),
        (
            "dct_frequency_power",
            t(language, "DCT 8×8 交流频带能量", "DCT 8×8 AC band power"),
        ),
    ] {
        if let Some(bands) = sample["frequency"][key].as_array() {
            let values = bands
                .iter()
                .map(|value| value.as_f64().unwrap_or_default())
                .collect::<Vec<_>>();
            let labels = (1..=values.len())
                .map(|index| index.to_string())
                .collect::<Vec<_>>();
            bar_plot(ui, title, &values, &labels, None);
        }
    }
}

fn bar_plot(
    ui: &mut egui::Ui,
    title: &str,
    values: &[f64],
    labels: &[String],
    fixed_maximum: Option<f64>,
) {
    if values.is_empty() {
        return;
    }
    let maximum = fixed_maximum
        .unwrap_or_else(|| values.iter().copied().fold(0.0, f64::max))
        .max(f64::EPSILON);
    ui.horizontal(|ui| {
        ui.label(title);
        ui.small(format!("0–{maximum}"));
    });
    let (rectangle, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width().clamp(120.0, 640.0), 72.0),
        egui::Sense::hover(),
    );
    let width = rectangle.width() / values.len() as f32;
    let bottom = rectangle.bottom() - 16.0;
    let color = ui.visuals().widgets.noninteractive.fg_stroke.color;
    for (index, value) in values.iter().enumerate() {
        let left = rectangle.left() + index as f32 * width;
        let top = bottom - (value / maximum).clamp(0.0, 1.0) as f32 * (rectangle.height() - 16.0);
        let bar = egui::Rect::from_min_max(
            egui::pos2(left + 1.0, top),
            egui::pos2(left + width - 1.0, bottom),
        );
        ui.painter().rect_filled(bar, 0.0, color);
        let label = labels.get(index).map(String::as_str).unwrap_or("");
        let cell = egui::Rect::from_min_max(
            egui::pos2(left, rectangle.top()),
            egui::pos2(left + width, rectangle.bottom()),
        );
        ui.interact(
            cell,
            ui.scope_id().with((title, index)),
            egui::Sense::hover(),
        )
        .on_hover_text(format!("{label}  {value}"));
        if values.len() <= 8 || index.is_multiple_of(4) {
            ui.painter().text(
                egui::pos2(left + width / 2.0, bottom + 3.0),
                egui::Align2::CENTER_TOP,
                label,
                egui::FontId::proportional(10.0),
                ui.visuals().text_color(),
            );
        }
    }
}
fn options_for_format(saved: &SanitizeOptions, mime: &str) -> SanitizeOptions {
    let mut options = saved.clone();
    let office = mime.starts_with("application/vnd.openxmlformats-officedocument.");
    if !office || options.policy != Policy::Deep {
        options.deep = Default::default();
    }
    if mime != fileveil_core::Format::Docx.mime() {
        options.deep.accept_revisions = false;
        options.deep.remove_hidden_text = false;
        options.deep.remove_internal_identifiers = false;
    }
    if mime != fileveil_core::Format::Xlsx.mime() {
        options.deep.remove_hidden_sheets = false;
    }
    if mime != "application/pdf" || options.policy != Policy::Deep {
        options.pdf = Default::default();
    }
    if !matches!(mime, "text/plain" | "text/markdown" | "text/html") {
        options.text = Default::default();
    }
    if mime != "text/html" {
        options.text.remove_html_metadata = false;
        options.text.remove_html_comments = false;
    }
    if !matches!(
        mime,
        "image/jpeg" | "image/png" | "application/pdf" | "text/plain" | "text/markdown"
    ) || options.policy != Policy::Deep
    {
        options.remove_provenance = false;
    }
    options
}

fn t<'a>(language: Language, zh: &'a str, en: &'a str) -> &'a str {
    if language == Language::Chinese {
        zh
    } else {
        en
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{FileItem, ItemStatus, PendingTask, TaskKind};
    use fileveil_core::{Action, Finding, Format, Outcome, Report, RiskLayer};

    fn result(operation: &str, output: Option<PathBuf>) -> JobResult {
        let mut report = Report::new(operation, Format::Png);
        report.result = Outcome::PartiallyVerified;
        JobResult {
            report,
            exit_code: 0,
            output_path: output,
        }
    }

    #[test]
    fn repeated_deep_verification_retains_the_saved_copy_and_original_options() {
        let original = PathBuf::from("original.png");
        let output = PathBuf::from("saved.png");
        let mut options = SanitizeOptions {
            policy: Policy::Deep,
            ..SanitizeOptions::default()
        };
        options.remove_provenance = true;
        let mut workspaces = Workspaces {
            selected: Workspace::Deep,
            result_workspace: Workspace::Deep,
            last_write: Some((original.clone(), options.clone())),
            ..Workspaces::default()
        };
        workspaces.record_result(result("sanitize", Some(output.clone())));
        workspaces.options = SanitizeOptions::default();
        workspaces.record_result(result("verify", None));
        let Some(JobKind::VerifyAdvanced {
            original: requested_original,
            output: requested_output,
            options: requested_options,
        }) = workspaces.verification_request()
        else {
            panic!("verification request is retained")
        };
        assert_eq!(requested_original, original);
        assert_eq!(requested_output, output);
        assert_eq!(requested_options, options);
        workspaces.selected = Workspace::Lab;
        assert!(workspaces.verification_request().is_none());
        workspaces.selected = Workspace::Deep;
        workspaces.record_result(result("sanitize", None));
        assert!(workspaces.verification_request().is_none());
    }

    #[test]
    fn switching_formats_keeps_preferences_and_passes_only_applicable_options() {
        let mut saved = SanitizeOptions {
            policy: Policy::Deep,
            remove_provenance: true,
            ..Default::default()
        };
        saved.deep.remove_comments = true;
        saved.pdf.remove_annotations = true;
        saved.text.remove_bom = true;
        saved.text.remove_html_comments = true;
        saved.text.remove_html_metadata = true;
        saved.filesystem.normalize_output_timestamps = true;
        for mime in [
            "image/png",
            "application/pdf",
            "text/plain",
            "text/markdown",
        ] {
            let effective = options_for_format(&saved, mime);
            assert!(!effective.deep.any());
            assert_eq!(effective.pdf.any(), mime == "application/pdf");
            assert_eq!(effective.text.any(), mime.starts_with("text/"));
            assert!(effective.remove_provenance);
            assert!(!effective.text.remove_html_comments);
            assert!(!effective.text.remove_html_metadata);
            assert!(effective.filesystem.normalize_output_timestamps);
        }
        let office = options_for_format(&saved, Format::Docx.mime());
        assert!(office.deep.remove_comments);
        assert!(!office.pdf.any() && !office.text.any());
        assert!(!office.remove_provenance);
        assert!(saved.deep.remove_comments);
        saved.deep.accept_revisions = true;
        saved.deep.remove_hidden_text = true;
        saved.deep.remove_internal_identifiers = true;
        saved.deep.remove_hidden_sheets = true;
        let spreadsheet = options_for_format(&saved, Format::Xlsx.mime());
        assert!(!spreadsheet.deep.accept_revisions);
        assert!(!spreadsheet.deep.remove_hidden_text);
        assert!(!spreadsheet.deep.remove_internal_identifiers);
        assert!(spreadsheet.deep.remove_hidden_sheets);
        let word = options_for_format(&saved, Format::Docx.mime());
        assert!(word.deep.accept_revisions);
        assert!(!word.deep.remove_hidden_sheets);
        saved.policy = Policy::Safe;
        let safe = options_for_format(&saved, Format::Docx.mime());
        assert!(!safe.deep.any() && !safe.pdf.any());
        assert!(!safe.remove_provenance);
        assert!(saved.deep.remove_comments);
    }

    #[test]
    fn queued_session_work_blocks_an_advanced_worker_start() {
        let mut session = Session::default();
        let workspaces = Workspaces::default();
        assert!(workspaces.idle(&session));
        session.pending.push_back(PendingTask {
            id: 1,
            kind: TaskKind::Scan,
        });
        assert!(!workspaces.idle(&session));
    }

    #[test]
    fn batch_safe_counts_only_scanned_eligible_idle_files() {
        let mut session = Session::default();
        assert_eq!(eligible_safe_copies(&session), 0);
        let mut report = Report::new("scan", Format::Png);
        report.result = Outcome::PartiallyVerified;
        report.integrity.parseable = true;
        report.findings.push(Finding::new(
            "png.text",
            RiskLayer::EmbeddedMetadata,
            "PNG/text",
            "Synthetic metadata",
            Action::Remove,
        ));
        session.items.push(FileItem {
            id: 1,
            path: "sample.png".into(),
            size: 1,
            scan: Some(report.clone()),
            latest: Some(report),
            output_path: None,
            output_processing: None,
            status: ItemStatus::Finished,
        });
        assert_eq!(eligible_safe_copies(&session), 1);
        session.queue_sanitize_all();
        assert_eq!(session.pending.len(), 1);
        assert_eq!(eligible_safe_copies(&session), 0);
    }

    #[test]
    fn processing_retest_summary_distinguishes_specific_and_unknown_results() {
        let mut report = Report::new("sanitize", Format::Png);
        assert!(method_retest_summary(Language::Chinese, &report).is_none());
        report.advanced = Some(serde_json::json!({"watermark_retest": {
            "method_id": "synthetic_lsb_v1", "before": {"status":"detected"},
            "after": {"status":"not_detected"}, "result":"detector_no_longer_detects"
        }}));
        let chinese = method_retest_summary(Language::Chinese, &report).unwrap();
        assert!(chinese.contains("检测到 → 未检测到"));
        assert!(chinese.contains("对应检测器复验未检出"));
        let english = method_retest_summary(Language::English, &report).unwrap();
        assert!(english.contains("Detected → Not detected"));
        assert!(!english.contains("removed"));
    }

    #[test]
    fn native_distribution_charts_render_for_both_languages() {
        let mut histogram = vec![0; 256];
        histogram[32] = 4;
        let channel = serde_json::json!({"histogram":histogram,"lsb_one_counts":[2,1]});
        let sample = serde_json::json!({"width":2,"height":2,"channels":[channel.clone(),channel.clone(),channel],
            "frequency":{"dft_radial_power":[0.1,0.0,0.2,0.0,0.1,0.0,0.0,0.0],"dct_frequency_power":[0.0,0.2,0.0,0.1,0.0,0.0,0.0,0.0]}});
        for language in [Language::Chinese, Language::English] {
            let context = egui::Context::default();
            let mut output = context.run_ui(egui::RawInput::default(), |ui| {
                sample_plots(ui, language, &sample);
            });
            assert!(!output.shapes.is_empty());
            output.textures_delta.clear();
        }
    }
}
