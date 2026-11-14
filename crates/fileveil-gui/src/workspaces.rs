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
    collections::{BTreeMap, HashMap},
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
    Heritage,
}
impl Workspace {
    pub fn label(self, language: Language) -> &'static str {
        match self {
            Self::Files => t(language, "Verify 文件", "Verify files"),
            Self::Deep => t(language, "Clean 文件", "Clean files"),
            Self::Images => t(language, "Lab 图像", "Lab signals"),
            Self::Lab => t(language, "Lab 差异", "Lab comparison"),
            Self::Provenance => t(language, "Verify 来源", "Verify provenance"),
            Self::Tasks => t(language, "Clean 批量", "Clean batch"),
            Self::Heritage => t(language, "Mark / Trace", "Mark / Trace"),
        }
    }
}

pub struct Workspaces {
    pub selected: Workspace,
    options: SanitizeOptions,
    samples: Vec<PathBuf>,
    sample_groups: Vec<String>,
    trust_roots: Option<PathBuf>,
    active: Option<JobHandle>,
    result: Option<JobResult>,
    result_workspace: Workspace,
    result_input: Option<PathBuf>,
    result_samples: Vec<PathBuf>,
    last_write: Option<(PathBuf, SanitizeOptions)>,
    last_output: Option<PathBuf>,
    notice: Option<String>,
    preview_textures: HashMap<String, egui::TextureHandle>,
    heritage_panel: crate::heritage_ui::HeritagePanel,
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
            sample_groups: Vec::new(),
            trust_roots: None,
            active: None,
            result: None,
            result_workspace: Workspace::Files,
            result_input: None,
            result_samples: Vec::new(),
            last_write: None,
            last_output: None,
            notice: None,
            preview_textures: HashMap::new(),
            heritage_panel: Default::default(),
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
        self.preview_textures.clear();
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
                Workspace::Heritage,
            ] {
                let response =
                    ui.selectable_value(&mut self.selected, workspace, workspace.label(language));
                if workspace == Workspace::Images {
                    crate::smoke::target(&response, "images_tab");
                }
                if workspace == Workspace::Heritage {
                    crate::smoke::target(&response, "heritage_tab");
                }
                if self.busy() && self.result_workspace == workspace {
                    ui.spinner();
                }
            }
        });
        if self.selected != previous {
            self.notice = None;
        }
        crate::smoke::workspace(
            ui.ctx(),
            match self.selected {
                Workspace::Images => "images",
                Workspace::Heritage => "heritage",
                _ => "other",
            },
        );
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
            | JobKind::Scan { path }
            | JobKind::Heritage { path, .. } => Some(path.clone()),
            JobKind::HeritageKeygen { .. } | JobKind::SystemKeygen => None,
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
        self.preview_textures.clear();
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
                ui.label(t(language,"离线检测公开的 Stable Diffusion / SDXL 图像水印和 FileVeil 合成 LSB 协议。每种方法单独报告结果与复验范围。","Detect public Stable Diffusion / SDXL image watermarks and the FileVeil synthetic LSB protocol offline. Each method has its own result and retest scope."));
                let detect = ui.add_enabled(
                    idle && path.is_some(),
                    egui::Button::new(t(language, "执行水印检测", "Run watermark detector")),
                );
                crate::smoke::target(&detect, "run_detector");
                if detect.clicked() {
                    self.start(
                        JobKind::DetectWatermark {
                            path: path.clone().expect("selected file"),
                        },
                        session,
                        ui.ctx(),
                    );
                }
                if ui
                    .add_enabled(
                        idle && session.has_detectable_images(),
                        egui::Button::new(t(language, "检测队列图片", "Detect queued images")),
                    )
                    .clicked()
                {
                    session.queue_detect_images();
                    self.result = None;
                }
                if let Some(item) = session.selected_item()
                    && let Some(report) = item
                        .latest
                        .as_ref()
                        .filter(|report| report.operation == "detect_watermark")
                {
                    ui.separator();
                    ui.strong(t(language, "队列检测结果", "Queued detection result"));
                    ui.label(outcome(language, report.result));
                    for warning in &report.warnings {
                        ui.small(crate::i18n::tr(language, warning));
                    }
                    if let Some(detections) = report
                        .advanced
                        .as_ref()
                        .and_then(|details| details["detections"].as_array())
                    {
                        for detection in detections {
                            detection_ui(ui, language, detection);
                        }
                    }
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
                    if let Some(output) = &item.output_path {
                        ui.horizontal_wrapped(|ui| {
                            if ui
                                .add_enabled(
                                    idle,
                                    egui::Button::new(t(
                                        language,
                                        "复检输出水印",
                                        "Detect watermarks in output",
                                    )),
                                )
                                .clicked()
                            {
                                self.start(
                                    JobKind::DetectWatermark {
                                        path: output.clone(),
                                    },
                                    session,
                                    ui.ctx(),
                                );
                            }
                            if ui
                                .add_enabled(
                                    idle,
                                    egui::Button::new(t(
                                        language,
                                        "比较原件与副本",
                                        "Compare original and copy",
                                    )),
                                )
                                .clicked()
                            {
                                self.samples = vec![item.path.clone(), output.clone()];
                                self.sample_groups = vec![String::new(); 2];
                                self.selected = Workspace::Lab;
                                self.notice = None;
                            }
                        });
                    }
                    ui.small(t(
                        language,
                        "未知及专有水印仍未评估。",
                        "Unknown and proprietary watermarks remain unassessed.",
                    ));
                }
            }
            Workspace::Lab => self.lab(ui, language, session, idle),
            Workspace::Provenance => {
                ui.label(t(language,"离线验证 C2PA 签名、文件绑定和公开图像水印。可选择本地 PEM 信任根，检测证据与个人身份关联分别记录。","Validate C2PA signatures, asset binding and public image watermarks offline. Choose optional local PEM trust roots. Detection evidence and personal identity links have separate results."));
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
            Workspace::Heritage => {
                if let Some(job) = self.heritage_panel.ui(ui, language, session, idle) {
                    self.start(job, session, ui.ctx());
                }
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
            .and_then(|item| session.current_scan(item.id))
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
                        ui.checkbox(&mut self.options.deep.accept_revisions,t(language,"接受受支持的 Word 修订","Accept supported Word revisions"));
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
                ui.checkbox(&mut self.options.filesystem.remove_download_origin,t(language,"macOS 下载来源与下载时间","macOS download origins and dates"));
                ui.checkbox(&mut self.options.filesystem.remove_usage_metadata,t(language,"macOS 最近使用时间属性","macOS last-used attributes"));
                ui.checkbox(&mut self.options.filesystem.remove_finder_tags,t(language,"Finder 标签","Finder tags"));
                ui.checkbox(&mut self.options.filesystem.remove_user_attributes,t(language,"Unix user.* 扩展属性","Unix user.* attributes"));
                ui.checkbox(&mut self.options.filesystem.remove_ntfs_private_streams,t(language,"NTFS 私有数据流","NTFS private data streams"));
                ui.checkbox(&mut self.options.filesystem.normalize_output_timestamps,t(language,"新副本修改时间规范化","Normalize new-copy modification time"));
                ui.add_enabled_ui(cfg!(any(target_os = "macos", windows)), |ui| {
                    ui.checkbox(&mut self.options.filesystem.normalize_creation_time,
                        t(language,"新副本创建时间规范化","Normalize new-copy creation time"));
                });
                ui.small(t(language,"选中的时间规范化为 2000-01-01 UTC，仅处理新副本。文件系统日志、快照和备份历史保留独立范围。","Selected times are normalized to 2000-01-01 UTC on the new copy. Filesystem journals, snapshots and backups have separate scope."));
                ui.label(t(language,"保留 Quarantine、Mark-of-the-Web 和受保护属性。资源叉会阻断重写。","Quarantine, Mark-of-the-Web and protected attributes are preserved. Resource forks block rewriting."));
            });
        });
        if let Some(scan) = session
            .selected_item()
            .and_then(|item| session.current_scan(item.id))
        {
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
                        "filesystem.download_origin" | "filesystem.download_date" => {
                            self.options.filesystem.remove_download_origin
                        }
                        "filesystem.usage_time" => self.options.filesystem.remove_usage_metadata,
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
            .and_then(|item| session.current_scan(item.id))
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
                self.sample_groups = vec![String::new(); paths.len()];
                self.samples = paths;
                self.notice = None;
            } else {
                self.notice =
                    Some(t(language, "请选择 2 至 8 个样本", "Select 2 to 8 samples").into());
            }
        }
        self.sample_groups.resize(self.samples.len(), String::new());
        for (index, path) in self.samples.iter().enumerate() {
            ui.horizontal_wrapped(|ui| {
                ui.label(format!(
                    "{}  {}",
                    index + 1,
                    path.file_name()
                        .unwrap_or(path.as_os_str())
                        .to_string_lossy()
                ));
                ui.add_enabled(
                    idle,
                    egui::TextEdit::singleline(&mut self.sample_groups[index])
                        .desired_width(160.0)
                        .char_limit(64)
                        .hint_text(t(language, "参考组（可选）", "Reference group (optional)")),
                );
            });
        }
        let groups = reference_groups(&self.sample_groups);
        let groups_valid = groups.iter().all(|group| group.sample_indices.len() >= 2);
        ui.small(t(language, "给同设备或同编码对照填写相同组名，每组至少两张图。留空可只比较样本。", "Use a shared group name for same-device or encoding controls, with at least two images per group. Leave empty for sample comparisons."));
        if !groups_valid {
            ui.label(t(
                language,
                "每个参考组至少需要两张样本。",
                "Each reference group needs at least two samples.",
            ));
        }
        ui.label(t(language,"分析像素差分、RGB 低位、信息熵、原分辨率 DCT/Haar 特征和参考组残差。统计结果提供研究线索，厂商归因保持独立验证。","Analyze pixel differences, RGB low bits, entropy, original-resolution DCT/Haar features and reference-group residuals. Statistics provide research leads. OEM attribution requires independent validation."));
        if ui
            .add_enabled(
                idle && self.samples.len() >= 2 && groups_valid,
                egui::Button::new(t(language, "执行差异分析", "Analyze differences")),
            )
            .clicked()
        {
            self.start(
                if groups.is_empty() {
                    JobKind::Lab {
                        paths: self.samples.clone(),
                    }
                } else {
                    JobKind::LabGrouped {
                        paths: self.samples.clone(),
                        groups,
                    }
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
        crate::smoke::result(ui.ctx(), &result.report);
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
        if let Some(pdf) = &result.report.pdf
            && pdf["scan_status"] == "complete"
            && pdf["safe_rewrite_allowed"] == false
        {
            ui.label(t(
                language,
                "PDF 扫描完成，Safe 改写受保护",
                "PDF scan complete. Safe rewriting is protected",
            ));
            if let Some(restrictions) = pdf["rewrite_restrictions"].as_array() {
                for restriction in restrictions.iter().filter_map(serde_json::Value::as_str) {
                    ui.small(crate::i18n::tr(language, restriction));
                }
            }
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
            if let Some(heritage) = details.get("heritage") {
                heritage_report_ui(ui, language, heritage);
            }
            if details["media"]["retained_encoded_payload_and_structure_equal"] == true {
                ui.label(t(
                    language,
                    "保留的媒体编码内容与结构验证通过",
                    "Retained encoded media and structure verified",
                ));
                ui.small(t(language, "本次运行未执行平台解码验证。未知厂商字段及信号水印按报告范围保留。", "Platform decoding was not performed in this run. Unknown vendor fields and signal watermarks retain their reported scope."));
            }
            if let Some(detections) = details
                .get("detections")
                .or_else(|| details.get("watermark_detections"))
                .and_then(serde_json::Value::as_array)
            {
                for detection in detections {
                    detection_ui(ui, language, detection);
                }
            } else if let Some(detection) = details.get("detection") {
                detection_ui(ui, language, detection);
            }
            if self.result_workspace == Workspace::Provenance {
                provenance_capabilities_ui(ui, language, details);
            }
            if let Some(observation) = details
                .get("signal_analysis")
                .filter(|value| value.is_object())
            {
                if observation["converted_to_rgb8"] == true {
                    ui.small(t(language, "该样本已转换为 RGB8，低位统计采用转换后的样本。", "This sample was converted to RGB8. Low-bit statistics use the converted samples."));
                }
                ui.push_id("single-image-signal", |ui| {
                    signal_statistics_ui(ui, language, &observation["signal"]);
                });
                ui.horizontal_wrapped(|ui| {
                    preview_image(
                        ui,
                        &mut self.preview_textures,
                        "single-low",
                        t(language, "RGB 最低位均值", "Mean RGB lowest bits"),
                        &observation["previews"]["low_bits"],
                    );
                    preview_image(
                        ui,
                        &mut self.preview_textures,
                        "single-residual",
                        t(language, "高通残差 ×8 +128", "High-pass residual ×8 +128"),
                        &observation["previews"]["residual"],
                    );
                });
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
                    if let Some(signal) = sample.get("signal") {
                        ui.push_id(("sample-signal", index), |ui| {
                            signal_statistics_ui(ui, language, signal);
                        });
                    }
                    ui.horizontal_wrapped(|ui| {
                        preview_image(
                            ui,
                            &mut self.preview_textures,
                            &format!("sample-{index}-low"),
                            t(language, "RGB 最低位均值", "Mean RGB lowest bits"),
                            &sample["previews"]["low_bits"],
                        );
                        preview_image(
                            ui,
                            &mut self.preview_textures,
                            &format!("sample-{index}-residual"),
                            t(language, "高通残差 ×8 +128", "High-pass residual ×8 +128"),
                            &sample["previews"]["residual"],
                        );
                    });
                    egui::CollapsingHeader::new(t(
                        language,
                        "分布与频域图",
                        "Distributions and frequency bands",
                    ))
                    .id_salt(("lab-plots", index))
                    .show(ui, |ui| sample_plots(ui, language, sample));
                }
                if let Some(groups) = lab["groups"].as_array().filter(|groups| !groups.is_empty()) {
                    ui.strong(t(
                        language,
                        "参考组残差比较",
                        "Reference-group residual comparisons",
                    ));
                    ui.small(t(language, "组内样本采用留一法，组外样本使用整个参考组。NCC 关联分数未校准身份或厂商归因。", "Within-group samples use leave-one-out references. Other samples use the whole reference group. NCC scores are uncalibrated for identity or OEM attribution."));
                    for group in groups {
                        ui.label(group["label"].as_str().unwrap_or_default());
                        if let Some(tests) = group["tests"].as_array() {
                            for test in tests {
                                let index = test["sample_index"].as_u64().unwrap_or_default() + 1;
                                let score = test["ncc"]
                                    .as_f64()
                                    .map(|value| format!("{value:.5}"))
                                    .unwrap_or_else(|| status(language, "not_assessed").into());
                                ui.label(format!(
                                    "{} {} · NCC {} · {} {} · {}",
                                    t(language, "样本", "Sample"),
                                    index,
                                    score,
                                    test["reference_count"],
                                    t(language, "参考样本", "reference samples"),
                                    if test["leave_one_out"] == true {
                                        t(language, "留一法", "Leave-one-out")
                                    } else {
                                        t(language, "组外比较", "Outside-group comparison")
                                    }
                                ));
                            }
                        }
                    }
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
                        if let Some(correlation) = comparison["residual_correlation"].as_f64() {
                            ui.label(format!(
                                "{} {:.5}",
                                t(language, "高通残差相关", "High-pass residual correlation"),
                                correlation
                            ));
                        }
                        preview_image(
                            ui,
                            &mut self.preview_textures,
                            &format!("difference-{first}-{second}"),
                            t(language, "平均绝对差 ×8", "Mean absolute difference ×8"),
                            &comparison["difference_preview"],
                        );
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
        let report = &result.report;
        let verification = self.verification_request();
        let mut verify_requested = false;
        ui.horizontal(|ui| {
            if ui
                .button(t(language, "导出报告", "Export report"))
                .clicked()
                && let Some(path) = rfd::FileDialog::new()
                    .set_file_name("fileveil-report.json")
                    .save_file()
            {
                let saved = serde_json::to_vec_pretty(report)
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
            if verification.is_some()
                && ui
                    .add_enabled(
                        idle,
                        egui::Button::new(t(language, "再次验证副本", "Verify copy again")),
                    )
                    .clicked()
            {
                verify_requested = true;
            }
        });
        if verify_requested && let Some(verification) = verification {
            self.start(verification, session, ui.ctx());
        }
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
        "available" => t(language, "可用", "Available"),
        "unavailable" => t(language, "未配置可用检测器", "Detector unavailable"),
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
            "特定检测器复验",
            "Method-specific detector retests",
        ));
        ui.label(summary);
    }
}

pub(crate) fn method_retest_summary(
    language: Language,
    report: &fileveil_core::Report,
) -> Option<String> {
    let details = report.advanced.as_ref()?;
    let retests = details
        .get("detector_retests")
        .and_then(serde_json::Value::as_array);
    let entries = retests
        .map(Vec::as_slice)
        .filter(|entries| !entries.is_empty())
        .or_else(|| details.get("watermark_retest").map(std::slice::from_ref))?;
    Some(
        entries
            .iter()
            .map(|retest| {
                format!(
                    "{} · {} → {} · {}",
                    detector_name(
                        language,
                        retest["method_id"].as_str().unwrap_or("synthetic_lsb_v1")
                    ),
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
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

fn reference_groups(labels: &[String]) -> Vec<fileveil_engine::lab::SampleGroup> {
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, label) in labels.iter().enumerate() {
        let label = label.trim();
        if !label.is_empty() {
            groups.entry(label.to_owned()).or_default().push(index);
        }
    }
    groups
        .into_iter()
        .map(
            |(label, sample_indices)| fileveil_engine::lab::SampleGroup {
                label,
                sample_indices,
            },
        )
        .collect()
}

fn detector_name(language: Language, method: &str) -> &str {
    match method {
        "synthetic_lsb_v1" => t(language, "合成 LSB 测试协议", "Synthetic LSB test protocol"),
        "stable_diffusion_dwt_dct_v1" => "Stable Diffusion 1.x DWT",
        "stable_diffusion_xl_dwt_dct" => "SDXL DWT",
        _ => method,
    }
}

fn detection_ui(ui: &mut egui::Ui, language: Language, detection: &serde_json::Value) {
    let method = detection["method_id"].as_str().unwrap_or("unknown");
    ui.strong(format!(
        "{} · {}",
        detector_name(language, method),
        status(
            language,
            detection["status"].as_str().unwrap_or("not_assessed")
        )
    ));
    egui::CollapsingHeader::new(t(language, "检测证据与范围", "Detection evidence and scope"))
        .id_salt(("detector-evidence", method)).show(ui, |ui| {
            ui.label(format!("{} {} · {} {}", t(language, "方法", "Method"), method,
                t(language, "版本", "Version"), detection["detector_version"].as_str().unwrap_or("—")));
            if let Some(codes) = detection["evidence_codes"].as_array() {
                for code in codes.iter().filter_map(serde_json::Value::as_str) {
                    ui.monospace(code);
                }
            }
            ui.small(if method.starts_with("stable_diffusion") {
                t(language,
                    "匹配公开的固定消息只证明该水印模式的信号，复制消息也可产生匹配。裁剪、缩放和重编码可能导致漏检，无法据此验证生成模型或个人身份。",
                    "A public fixed-message match establishes the named signal pattern. Copied messages can also match. Cropping, scaling and re-encoding can cause missed detections. Model and personal identity remain unverified.")
            } else {
                t(language,
                    "检测范围仅限所列协议。阴性结果保留其他水印未知的状态，消息摘要无法认证作者或设备。",
                    "Detection covers the named protocol. A negative result leaves other watermarks unknown. Message digests do not authenticate an author or device.")
            });
        });
}

fn provider_name(language: Language, provider: &str) -> &str {
    match provider {
        "c2pa" => t(language, "C2PA 来源凭据", "C2PA source credentials"),
        "stable_diffusion_v1" => "Stable Diffusion 1.x",
        "stable_diffusion_xl" => "SDXL",
        "openai_statistical_text" => t(language, "OpenAI 文本水印", "OpenAI text watermarks"),
        "anthropic_statistical_text" => {
            t(language, "Anthropic 文本水印", "Anthropic text watermarks")
        }
        "google_synthid_image" => t(language, "Google SynthID 图像", "Google SynthID images"),
        "google_synthid_text" => t(language, "Google SynthID 文本", "Google SynthID text"),
        "proprietary_image_watermark" => t(
            language,
            "其他专有图像水印",
            "Other proprietary image watermarks",
        ),
        "oem_device_fingerprint" => t(language, "OEM 设备归因", "OEM device attribution"),
        _ => provider,
    }
}

fn provenance_capabilities_ui(ui: &mut egui::Ui, language: Language, details: &serde_json::Value) {
    let Some(capabilities) = details["capabilities"].as_array() else {
        return;
    };
    egui::CollapsingHeader::new(t(language, "检测能力", "Detector availability"))
        .show(ui, |ui| {
            for capability in capabilities {
                let provider = capability["provider_id"].as_str().unwrap_or("unknown");
                ui.label(format!("{} · {}", provider_name(language, provider),
                    status(language, capability["status"].as_str().unwrap_or("not_assessed"))));
            }
            ui.small(t(language,
                "当前执行本机离线检测。专有文本和 SynthID 检测需要适用的密钥或服务授权，当前未执行。",
                "This run uses local offline detectors. Proprietary text and SynthID detection require applicable keys or service access and were not executed."));
        });
}

fn preview_image(
    ui: &mut egui::Ui,
    textures: &mut HashMap<String, egui::TextureHandle>,
    key: &str,
    title: &str,
    preview: &serde_json::Value,
) {
    if !textures.contains_key(key) {
        let Some(width) = preview["width"]
            .as_u64()
            .filter(|value| (1..=128).contains(value))
        else {
            return;
        };
        let Some(height) = preview["height"]
            .as_u64()
            .filter(|value| (1..=128).contains(value))
        else {
            return;
        };
        let Some(values) = preview["gray"]
            .as_array()
            .filter(|values| values.len() == (width * height) as usize)
        else {
            return;
        };
        let Ok(gray) = values
            .iter()
            .map(|value| u8::try_from(value.as_u64().unwrap_or(256)))
            .collect::<Result<Vec<_>, _>>()
        else {
            return;
        };
        let image = egui::ColorImage::from_gray([width as usize, height as usize], &gray);
        textures.insert(
            key.to_owned(),
            ui.ctx()
                .load_texture(key, image, egui::TextureOptions::NEAREST),
        );
    }
    if let Some(texture) = textures.get(key) {
        ui.vertical(|ui| {
            ui.small(title);
            ui.add(egui::Image::new(texture).fit_to_exact_size(egui::vec2(128.0, 128.0)));
        });
    }
}

fn signal_statistics_ui(ui: &mut egui::Ui, language: Language, signal: &serde_json::Value) {
    egui::CollapsingHeader::new(t(language, "低位、频域与编码结构", "Low bits, frequency and encoding"))
        .id_salt(("signal-analysis", ui.scope_id())).show(ui, |ui| {
            ui.small(t(language,
                "统计结果提供研究线索。编码、传感器噪声和正常图像处理均会影响这些指标，厂商或设备归因需要独立对照。",
                "Statistics provide research leads. Encoding, sensor noise and ordinary image processing affect these metrics. OEM or device attribution requires independent controls."));
            for channel in 0..3 {
                ui.label(format!("{} · {} {:.3} / {} · {} {:.4}",
                    ["R", "G", "B"][channel],
                    t(language, "LSB 值对 χ² / 自由度", "LSB pair χ² / degrees of freedom"),
                    signal["lsb_pair_chi_square"][channel].as_f64().unwrap_or_default(),
                    signal["lsb_pair_degrees_of_freedom"][channel],
                    t(language, "相邻低位相关", "Adjacent low-bit correlation"),
                    signal["lsb_adjacent_correlation"][channel].as_f64().unwrap_or_default()));
            }
            ui.label(format!("{} {:.5}",
                t(language, "高通残差均方根", "High-pass residual RMS"),
                signal["noise_residual_rms"].as_f64().unwrap_or_default()));
            if let Some(power) = signal["block_dct_ac_power"].as_array() {
                let values = power.iter().map(|value| value.as_f64().unwrap_or_default()).collect::<Vec<_>>();
                ui.label(format!("{} · {} {}",
                    t(language, "原分辨率 8×8 块 DCT 采样", "Sampled original-resolution 8×8 block DCT"),
                    signal["block_dct_blocks"], t(language, "块", "blocks")));
                dct_heatmap(ui, &values);
            }
            if let Some(power) = signal["haar_detail_power"].as_array() {
                let values = power.iter().map(|value| value.as_f64().unwrap_or_default()).collect::<Vec<_>>();
                let labels = ["LH", "HL", "HH"].map(String::from);
                bar_plot(ui, t(language, "Haar 细节采样能量", "Sampled Haar detail power"), &values, &labels, None);
            }
            if let Some(jpeg) = signal.get("jpeg").filter(|value| value.is_object()) {
                ui.label(format!("JPEG · {} {} · {}",
                    jpeg["quantization_tables"], t(language, "量化表", "quantization tables"),
                    if jpeg["progressive"] == true { t(language, "渐进式", "Progressive") }
                    else { t(language, "顺序式", "Sequential") }));
                if let Some(components) = jpeg["frame_components"].as_array() {
                    for component in components {
                        ui.label(format!("{} {} · {} × {} · Q {}",
                            t(language, "分量", "Component"), component["id"],
                            component["horizontal_sampling"], component["vertical_sampling"],
                            component["quantization_table"]));
                    }
                }
                if let Some(hash) = jpeg["quantization_sha256"].as_str() {
                    ui.small(t(language, "量化表 SHA-256", "Quantization SHA-256"));
                    ui.label(egui::RichText::new(hash).monospace().small()).on_hover_text(hash);
                }
            }
        });
}

fn dct_heatmap(ui: &mut egui::Ui, values: &[f64]) {
    if values.len() != 64 {
        return;
    }
    let maximum = values.iter().copied().fold(0.0, f64::max).max(f64::EPSILON);
    let (rectangle, _) = ui.allocate_exact_size(egui::vec2(160.0, 160.0), egui::Sense::hover());
    for (index, value) in values.iter().enumerate() {
        let x = index % 8;
        let y = index / 8;
        let cell = egui::Rect::from_min_size(
            rectangle.min + egui::vec2(x as f32 * 20.0, y as f32 * 20.0),
            egui::vec2(20.0, 20.0),
        );
        let intensity = ((value / maximum).max(0.0).sqrt().clamp(0.0, 1.0) * 224.0 + 16.0) as u8;
        ui.painter()
            .rect_filled(cell.shrink(0.5), 0.0, egui::Color32::from_gray(intensity));
        ui.interact(
            cell,
            ui.scope_id().with(("dct-cell", index)),
            egui::Sense::hover(),
        )
        .on_hover_text(format!("DCT ({x}, {y})  {value:.6}"));
    }
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
        ui.small(format!("0–{maximum:.3e}"));
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

fn heritage_report_ui(ui: &mut egui::Ui, language: Language, details: &serde_json::Value) {
    ui.separator();
    ui.strong(t(
        language,
        "水印与来源验证结果",
        "Watermark and provenance results",
    ));
    if let Some(public) = details.get("public_key") {
        ui.label(t(
            language,
            "本地 Ed25519 密钥已创建",
            "Local Ed25519 key created",
        ));
        ui.monospace(public["key_id"].as_str().unwrap_or_default());
        if ui
            .button(t(
                language,
                "复制公钥信任策略",
                "Copy public-key trust policy",
            ))
            .clicked()
        {
            let policy =
                serde_json::json!({"trusted_issuers":[public],"minimum_issuer_signatures":1});
            ui.ctx()
                .copy_text(serde_json::to_string_pretty(&policy).unwrap_or_default());
        }
    }
    let label = |value: &serde_json::Value| -> String {
        let text = value.as_str().unwrap_or("not_assessed");
        if language == Language::English {
            return text.replace('_', " ");
        }
        match text {
            "valid" => "有效",
            "invalid" => "无效",
            "untrusted" => "未受本地信任",
            "detected" => "检测到",
            "not_detected" => "未检测到",
            "indeterminate" => "无法判断",
            "unsupported" => "不支持",
            "blocked" => "已阻止",
            "verified_within_scope" => "范围内验证通过",
            "partially_verified" => "部分验证",
            "failed" => "验证失败",
            _ => "未评估",
        }
        .into()
    };
    if let Some(legacy) = details.get("legacy") {
        ui.label(format!(
            "{} · {}",
            if details["action"] == "clean" {
                t(language, "输入历史结构", "Input legacy structures")
            } else {
                t(language, "历史结构", "Legacy structures")
            },
            label(&legacy["status"])
        ));
        if let Some(locations) = legacy["locations"].as_array() {
            for location in locations {
                ui.horizontal_wrapped(|ui| {
                    ui.monospace(location["kind"].as_str().unwrap_or_default());
                    ui.label(format!(
                        "{} {} · {} {} · {} {}",
                        t(language, "偏移", "offset"),
                        location["offset"],
                        t(language, "字节", "bytes"),
                        location["bytes"],
                        t(language, "记录", "records"),
                        location["record_count"]
                    ));
                });
                let evidence = location["evidence_status"].as_str().unwrap_or_default();
                ui.small(if language == Language::Chinese {
                    match evidence {
                        "reference_sample_confirmed_format" => "真实参考样本确认的结构",
                        "structure_confirmed" => "公开结构匹配，尚缺设备原样本",
                        "candidate_unverified" => "尚未确认的结构候选",
                        _ => evidence,
                    }
                } else {
                    evidence
                });
                ui.small(format!(
                    "{} · {}",
                    t(language, "历史密码学状态", "Legacy cryptographic state"),
                    label(&location["crypto_status"])
                ));
            }
        }
        if let Some(warnings) = legacy["warnings"].as_array() {
            for warning in warnings {
                if let Some(text) = warning.as_str() {
                    ui.small(crate::i18n::tr(language, text));
                }
            }
        }
        if let Some(records) = legacy["decoded_records"].as_array() {
            for record in records {
                if let Some(identifier) = record["identifier"].as_str() {
                    ui.monospace(identifier);
                }
                ui.small(record["key_profile"].as_str().unwrap_or_default());
            }
        }
    }
    for (section, zh, en) in [
        ("verification", "当前载体记录", "Current carrier records"),
        (
            "reference_verification",
            "参考记录对当前内容的验证",
            "Reference records against current content",
        ),
    ] {
        if let Some(verification) = details.get(section) {
            ui.strong(t(language, zh, en));
            egui::Grid::new(("heritage_verification", section))
                .num_columns(2)
                .show(ui, |ui| {
                    for (key, zh, en) in [
                        ("signature", "密码学签名", "Cryptographic signature"),
                        ("content_binding", "当前文件绑定", "Current asset binding"),
                        ("chain", "传播记录链", "Custody chain"),
                        ("trust", "本地发行者信任", "Local issuer trust"),
                    ] {
                        ui.label(t(language, zh, en));
                        ui.label(label(&verification[key]));
                        ui.end_row();
                    }
                });
        }
    }
    for key in ["robust", "robust_recheck"] {
        if let Some(signal) = details.get(key) {
            ui.strong(if key == "robust_recheck" {
                t(language, "处理后复检", "Post-processing recheck")
            } else {
                t(language, "内容水印", "Content watermark")
            });
            let signals = signal["detections"]
                .as_array()
                .cloned()
                .unwrap_or_else(|| vec![signal.clone()]);
            for signal in signals {
                if signal["method_id"]
                    .as_str()
                    .is_some_and(|method| method.starts_with("fileveil_"))
                {
                    ui.label(format!(
                        "{} · {}",
                        signal["method_id"].as_str().unwrap_or_default(),
                        label(&signal["status"])
                    ));
                    for (field, zh, en) in [
                        ("work_id_digest", "作品摘要", "Work digest"),
                        ("copy_id_digest", "副本摘要", "Copy digest"),
                        ("key_id", "水印密钥摘要", "Watermark key digest"),
                    ] {
                        if let Some(value) = signal[field].as_str() {
                            ui.label(t(language, zh, en));
                            ui.monospace(value);
                        }
                    }
                    if let Some(authenticated) = signal["authenticated"].as_bool()
                        && signal["method_id"] == fileveil_engine::heritage::robust_v2::METHOD_ID
                    {
                        ui.small(if authenticated { t(language,"水印载荷 MAC 验证通过。作者及当前文件绑定另行验证。","Watermark payload MAC verified. Authorship and current asset binding are checked separately.") }
                            else { t(language,"水印载荷尚未通过密钥认证。","The watermark payload has no successful key authentication.") });
                    }
                    if let Some(corrected) = signal["corrected_codeword_bits"].as_u64() {
                        ui.small(format!(
                            "{} {corrected}",
                            t(language, "BCH 纠正位数", "BCH corrected bits")
                        ));
                    }
                    if let Some(angle) = signal["deskew_degrees"].as_f64() {
                        ui.small(format!(
                            "{} {angle:.2}°",
                            t(language, "几何校正", "Geometric correction")
                        ));
                    }
                    if let Some(scope) = signal["scope"].as_str() {
                        ui.small(match scope {
                            "blind_keyed_work_and_copy_reference_with_bch_and_96_bit_mac" => t(language,"密钥盲检作品与副本摘要，采用 BCH 纠错与 96 位 MAC。","Blind keyed work and copy references with BCH correction and a 96-bit MAC."),
                            "public_work_reference_signal_without_identity_authentication" => t(language,"公开作品参考信号，身份认证单独评估。","Public work-reference signal with identity assessed separately."),
                            "explicit_watermark_key_required" => t(language,"请选择明确授权的水印密钥以检测 2.0 载荷。","Choose an explicitly authorized watermark key to detect the Engine 2 payload."),
                            _ => crate::i18n::tr(language,scope),
                        });
                    }
                } else if signal["method_id"].as_str().is_some() {
                    detection_ui(ui, language, &signal);
                }
            }
        }
    }
    if let Some(copy_match) = details["copy_digest_match"].as_bool() {
        ui.label(if copy_match {
            t(language, "发行副本摘要匹配", "Issue-copy digest matches")
        } else {
            t(language, "发行副本摘要不匹配", "Issue-copy digest mismatch")
        });
    }
    for section in [
        "external_provenance",
        "checkpoint_verification",
        "evidence_verification",
        "timestamp",
        "c2pa_association",
    ] {
        if let Some(value) = details.get(section) {
            egui::CollapsingHeader::new(match section {
                "external_provenance" => t(
                    language,
                    "外部检查点与时间戳结果",
                    "External checkpoint and timestamp results",
                ),
                "checkpoint_verification" => {
                    t(language, "签名检查点结果", "Signed checkpoint result")
                }
                "evidence_verification" => t(language, "版权证据结果", "Copyright evidence result"),
                "timestamp" => t(
                    language,
                    "RFC 3161 验证结果",
                    "RFC 3161 verification result",
                ),
                _ => t(
                    language,
                    "C2PA 作品与水印关联",
                    "C2PA work and watermark association",
                ),
            })
            .show(ui, |ui| {
                ui.monospace(serde_json::to_string_pretty(value).unwrap_or_default());
            });
        }
    }
    if let Some(matched) = details["trace_reference_match"].as_bool() {
        ui.label(if matched {
            t(
                language,
                "恢复的作品摘要与所选参考一致",
                "Recovered work reference matches the selected reference",
            )
        } else {
            t(
                language,
                "恢复的作品摘要与所选参考不匹配",
                "Recovered work reference does not match the selected reference",
            )
        });
        ui.small(t(
            language,
            "摘要匹配与当前内容绑定分别验证。",
            "Reference recovery and current asset binding are assessed separately.",
        ));
    }
    for key in ["records", "reference_records"] {
        if let Some(records) = details[key].as_array() {
            for record in records {
                ui.collapsing(
                    format!(
                        "{} {} · {}",
                        t(language, "签名记录", "Signed record"),
                        record["sequence"],
                        record["kind"].as_str().unwrap_or_default()
                    ),
                    |ui| {
                        for field in [
                            "work_id",
                            "author",
                            "edition",
                            "version",
                            "parent_version",
                            "actor_key_id",
                            "transfer_to_key_id",
                            "record_sha256",
                            "content_sha256",
                        ] {
                            if let Some(value) = record[field].as_str() {
                                ui.label(format!("{field}  {value}"));
                            }
                        }
                    },
                );
            }
        }
    }
    if let Some(lab) = details.get("lab") {
        if let Some(frames) = lab["frames"].as_array() {
            ui.label(format!(
                "{} {}",
                t(language, "已分析视频帧", "Analyzed video frames"),
                frames.len()
            ));
            if let Some(reason) = lab["reason"].as_str() {
                ui.small(crate::i18n::tr(language, reason));
            }
            for frame in frames {
                ui.label(format!(
                    "{}s · {}",
                    frame["second"],
                    label(&frame["watermarks"]["primary"]["status"])
                ));
            }
            ui.small(t(language,"仅覆盖选定帧，时域水印与其他帧未评估。", "Assessment covers selected frames. Temporal watermarks and other frames remain unassessed."));
        } else if let Some(rows) = lab["rows"].as_array() {
            ui.label(format!(
                "{} {} / {}",
                t(language, "已检出变体", "Detected variants"),
                lab["detected_variants"],
                lab["tested_variants"]
            ));
            for row in rows {
                ui.label(format!(
                    "{} · {}",
                    row["operation"].as_str().unwrap_or_default(),
                    label(row.get("result").unwrap_or(&row["robust"]["status"]))
                ));
                if let Some(present) = row["structural_manifest_present"].as_bool() {
                    ui.small(if present {
                        t(
                            language,
                            "结构记录仍在当前变体中",
                            "Structural record remains in this variant",
                        )
                    } else {
                        t(
                            language,
                            "当前变体未包含结构记录",
                            "Structural record absent from this variant",
                        )
                    });
                    if present {
                        ui.small(format!(
                            "{} · {}  {} · {}  {} · {}",
                            t(language, "签名", "Signature"),
                            label(&row["signature"]),
                            t(language, "当前文件绑定", "Current asset binding"),
                            label(&row["content_binding"]),
                            t(language, "本地信任", "Local trust"),
                            label(&row["trust"])
                        ));
                    }
                }
                if let Some(reason) = row["reason"].as_str() {
                    ui.small(crate::i18n::tr(language, reason));
                }
            }
            ui.label(format!(
                "{} {} / {}",
                t(language, "阴性对照检出数", "Negative-control positives"),
                lab["control_positive_count"],
                lab["control_count"]
            ));
            ui.small(t(
                language,
                "统计仅覆盖这些输入、操作与声明为阴性的对照。",
                "Measurements cover these inputs, operations and user-declared negative controls.",
            ));
        } else {
            ui.label(t(
                language,
                "当前格式不支持像素标记实验。",
                "Pixel watermark experiments are unsupported for this format.",
            ));
        }
    }
    if let Some(verification) = details.get("legacy_verification").filter(|v| v.is_object()) {
        ui.label(format!(
            "{} · {}",
            t(language, "历史清理后复验", "Legacy post-clean verification"),
            label(&verification["result"])
        ));
        ui.label(format!(
            "{} {} · {} {}",
            t(language, "已移除结构", "Removed structures"),
            verification["removed_locations"].as_u64().unwrap_or(0),
            t(language, "剩余检测", "Remaining detection"),
            label(&verification["remaining_status"])
        ));
        ui.label(if verification["retained_bytes_unchanged"] == true {
            t(
                language,
                "保留区域逐字节一致",
                "Retained regions are byte-for-byte identical",
            )
        } else {
            t(
                language,
                "保留区域一致性未通过",
                "Retained-region equality did not pass",
            )
        });
    }
    if details["modern_manifest_removed"] == true {
        ui.label(t(
            language,
            "FileVeil 结构水印已移除并复检",
            "FileVeil structural watermark removed and rechecked",
        ));
    }
    if let Some(mse) = details["pixel_mse_rgba8"].as_f64() {
        ui.label(format!("RGBA8 MSE  {mse:.4}"));
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
    fn reference_group_names_map_to_the_explicit_sample_indices() {
        let labels = [
            " device A ",
            "encoding control",
            "device A",
            "",
            "encoding control",
        ]
        .map(str::to_owned);
        let groups = reference_groups(&labels);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].label, "device A");
        assert_eq!(groups[0].sample_indices, vec![0, 2]);
        assert_eq!(groups[1].sample_indices, vec![1, 4]);
        assert!(reference_groups(&[String::new(), "  ".into()]).is_empty());
    }

    #[test]
    fn multiple_detector_retests_keep_their_individual_outcomes() {
        let mut report = Report::new("sanitize", Format::Png);
        report.advanced = Some(serde_json::json!({"detector_retests":[
            {"method_id":"synthetic_lsb_v1", "before":{"status":"not_detected"},
             "after":{"status":"not_detected"}, "result":"indeterminate"},
            {"method_id":"stable_diffusion_dwt_dct_v1", "before":{"status":"detected"},
             "after":{"status":"not_detected"}, "result":"detector_no_longer_detects"},
            {"method_id":"stable_diffusion_xl_dwt_dct", "before":{"status":"detected"},
             "after":{"status":"detected"}, "result":"detector_still_detects"}
        ]}));
        for language in [Language::Chinese, Language::English] {
            let summary = method_retest_summary(language, &report).unwrap();
            assert_eq!(summary.lines().count(), 3);
            assert!(summary.contains("Stable Diffusion 1.x DWT"));
            assert!(summary.contains("SDXL DWT"));
            assert!(summary.contains(status(language, "detector_no_longer_detects")));
            assert!(summary.contains(status(language, "detector_still_detects")));
        }
    }

    #[test]
    fn bounded_preview_textures_are_cached_and_released_with_the_result() {
        let context = egui::Context::default();
        let mut workspaces = Workspaces::default();
        let preview = serde_json::json!({"width":2,"height":2,"gray":[0,64,128,255]});
        let mut output = context.run_ui(egui::RawInput::default(), |ui| {
            preview_image(
                ui,
                &mut workspaces.preview_textures,
                "sample",
                "Low bits",
                &preview,
            );
            preview_image(
                ui,
                &mut workspaces.preview_textures,
                "oversize",
                "Oversize",
                &serde_json::json!({"width":129,"height":1,"gray":[0]}),
            );
            preview_image(
                ui,
                &mut workspaces.preview_textures,
                "invalid",
                "Invalid",
                &serde_json::json!({"width":1,"height":1,"gray":[256]}),
            );
        });
        output.textures_delta.clear();
        assert_eq!(workspaces.preview_textures.len(), 1);
        let id = workspaces.preview_textures["sample"].id();
        let mut output = context.run_ui(egui::RawInput::default(), |ui| {
            preview_image(
                ui,
                &mut workspaces.preview_textures,
                "sample",
                "Low bits",
                &preview,
            );
        });
        output.textures_delta.clear();
        assert_eq!(workspaces.preview_textures["sample"].id(), id);
        workspaces.record_result(result("detect_watermark", None));
        assert!(workspaces.preview_textures.is_empty());
    }

    #[test]
    fn signal_plots_and_detector_results_render_in_both_languages() {
        let signal = serde_json::json!({
            "lsb_pair_chi_square":[1.1,2.2,3.3],
            "lsb_pair_degrees_of_freedom":[127,127,127],
            "lsb_adjacent_correlation":[0.01,0.02,0.03],
            "noise_residual_rms":2.1,
            "block_dct_ac_power":vec![0.5;64],"block_dct_blocks":128,
            "haar_detail_power":[0.1,0.2,0.3],
            "jpeg":{"quantization_sha256":"00".repeat(32),"quantization_tables":2,
                "frame_components":[{"id":1,"horizontal_sampling":2,"vertical_sampling":2,"quantization_table":0}],
                "progressive":false}
        });
        for language in [Language::Chinese, Language::English] {
            let context = egui::Context::default();
            let mut output = context.run_ui(egui::RawInput::default(), |ui| {
                signal_statistics_ui(ui, language, &signal);
                dct_heatmap(ui, &[0.5; 64]);
                for method in [
                    "synthetic_lsb_v1",
                    "stable_diffusion_dwt_dct_v1",
                    "stable_diffusion_xl_dwt_dct",
                ] {
                    detection_ui(
                        ui,
                        language,
                        &serde_json::json!({
                        "method_id":method,"status":"detected","detector_version":"1.0.0",
                        "evidence_codes":["matched_bits=48","total_bits=48"]}),
                    );
                }
            });
            assert!(!output.shapes.is_empty());
            output.textures_delta.clear();
        }
    }

    #[test]
    fn queued_detection_failures_explain_the_reason_in_both_languages() {
        for language in [Language::Chinese, Language::English] {
            let context = egui::Context::default();
            context.enable_accesskit();
            let mut workspaces = Workspaces {
                selected: Workspace::Images,
                ..Default::default()
            };
            let mut report = Report::new("detect_watermark", Format::Png);
            report.result = Outcome::Blocked;
            report.warnings.extend([
                "Image exceeds the pixel budget".into(),
                "PNG pixel-count limit exceeded".into(),
                "JPEG pixel-count limit exceeded".into(),
            ]);
            let mut session = Session::default();
            session.items.push(FileItem {
                id: 1,
                path: "large.png".into(),
                size: 0,
                scan: None,
                latest: Some(report),
                output_path: None,
                output_processing: None,
                status: ItemStatus::Finished,
            });
            session.selected = Some(1);
            let output = context.run_ui(Default::default(), |ui| {
                workspaces.ui(ui, language, &mut session);
            });
            for warning in [
                "Image exceeds the pixel budget",
                "PNG pixel-count limit exceeded",
                "JPEG pixel-count limit exceeded",
            ] {
                let expected = crate::i18n::tr(language, warning);
                assert!(
                    output
                        .platform_output
                        .accesskit_update
                        .as_ref()
                        .unwrap()
                        .nodes
                        .iter()
                        .any(|(_, node)| node.label() == Some(expected)
                            || node.value() == Some(expected))
                );
            }
            output.drop_without_applying_deltas();
        }
    }

    #[test]
    fn heritage_nonpixel_lab_explains_unsupported_scope_without_null_statistics() {
        for language in [Language::Chinese, Language::English] {
            let context = egui::Context::default();
            context.enable_accesskit();
            let details = serde_json::json!({"legacy":{"status":"unsupported","locations":[]},"lab":{"pixel_protocol":"unsupported","scope":"legacy_structure_comparison"}});
            let output = context.run_ui(egui::RawInput::default(), |ui| {
                heritage_report_ui(ui, language, &details);
            });
            let texts: Vec<_> = output
                .platform_output
                .accesskit_update
                .as_ref()
                .unwrap()
                .nodes
                .iter()
                .flat_map(|(_, node)| {
                    [node.label(), node.value()]
                        .into_iter()
                        .flatten()
                        .map(str::to_owned)
                })
                .collect();
            let expected = t(
                language,
                "当前格式不支持像素标记实验。",
                "Pixel watermark experiments are unsupported for this format.",
            );
            output.drop_without_applying_deltas();
            assert!(texts.iter().any(|text| text == expected), "{texts:?}");
            assert!(texts.iter().all(|text| !text.contains("null")));
        }
    }

    #[test]
    fn heritage_clean_reports_input_detection_and_post_clean_verification_separately() {
        let context = egui::Context::default();
        context.enable_accesskit();
        let details = serde_json::json!({"action":"clean","legacy":{"status":"detected","locations":[]},"legacy_verification":{"result":"verified_within_scope","removed_locations":1,"remaining_status":"not_detected","retained_bytes_unchanged":true}});
        let output = context.run_ui(egui::RawInput::default(), |ui| {
            heritage_report_ui(ui, Language::Chinese, &details);
        });
        let texts: Vec<_> = output
            .platform_output
            .accesskit_update
            .as_ref()
            .unwrap()
            .nodes
            .iter()
            .flat_map(|(_, node)| {
                [node.label(), node.value()]
                    .into_iter()
                    .flatten()
                    .map(str::to_owned)
            })
            .collect();
        output.drop_without_applying_deltas();
        assert!(
            texts.iter().any(|s| s == "输入历史结构 · 检测到"),
            "{texts:?}"
        );
        assert!(
            texts.iter().any(|s| s == "历史清理后复验 · 范围内验证通过"),
            "{texts:?}"
        );
        assert!(
            texts
                .iter()
                .any(|s| s.contains("已移除结构 1") && s.contains("未检测到")),
            "{texts:?}"
        );
        assert!(texts.iter().any(|s| s == "保留区域逐字节一致"), "{texts:?}");
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

// FVPROV1 109995 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI2OTI2YWE2MTVmOGZlZWE3MTMwYzY2NTM3NzEzZDY5Yzg3MTQxZGQ1MmM2NTljOWY5YTA5YTg0ODljNzIzNGVjIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvc3JjL3dvcmtzcGFjZXMucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiJhOTQ3NzllZDg3YzAxNTBkMTFmOGExM2U2MDY2NDdkYzIzMjZhOGNiYmQ4N2IzOTFmNDkyYjk1MjFhMDFlY2E5ODQwMGUyNGFhZDcyMWQxN2EyYmVmOWUwMzE3NjVkMzRiOTkzZmQxZmE3OTkzYTQ3MTIwOWI0ZTNiYmIxZjAwZiJ9XX1d FVPROV1-END
