// SPDX-License-Identifier: MPL-2.0
//! Heritage forms dispatch the same isolated jobs as the CLI and MCP.
use crate::{i18n::Language, jobs::JobKind, session::Session};
use eframe::egui;
use fileveil_engine::heritage::{
    HeritageAction, HeritageRequest, MarkSettings,
    signing::{RecordKind, SignMode},
};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Tab {
    #[default]
    Mark,
    Clean,
    Verify,
    Trace,
    Lab,
}

pub struct HeritagePanel {
    tab: Tab,
    mark: MarkSettings,
    keys: Vec<PathBuf>,
    trust: Option<PathBuf>,
    c2pa_roots: Option<PathBuf>,
    previous: Option<PathBuf>,
    reference: Option<PathBuf>,
    controls: Vec<PathBuf>,
    transfer_target: String,
    certificate: Option<PathBuf>,
    private_key: Option<PathBuf>,
    c2pa_mark: bool,
    c2pa_pixel: bool,
    disclose_identifiers: bool,
    disclose_claims: bool,
    clean_signal: bool,
    remove_c2pa: bool,
    notice: Option<String>,
    watermark_key: Option<PathBuf>,
    watermark_system_ref: String,
    use_system_signers: bool,
    system_signers: String,
    rotation_target: String,
    trace_action: HeritageAction,
    checkpoint_paths: Vec<PathBuf>,
    checkpoint_anchors: Option<PathBuf>,
    timestamp_response: Option<PathBuf>,
    timestamp_query: Option<PathBuf>,
    timestamp_roots: Option<PathBuf>,
    max_pixel_mse: f64,
}

impl Default for HeritagePanel {
    fn default() -> Self {
        Self {
            tab: Tab::Mark,
            mark: MarkSettings {
                signature_v2: true,
                watermark_version: 2,
                copy_id: "original".into(),
                strength: fileveil_engine::heritage::robust_v2::DEFAULT_STRENGTH,
                ..Default::default()
            },
            keys: Vec::new(),
            trust: None,
            c2pa_roots: None,
            previous: None,
            reference: None,
            controls: Vec::new(),
            transfer_target: String::new(),
            certificate: None,
            private_key: None,
            c2pa_mark: false,
            c2pa_pixel: false,
            disclose_identifiers: false,
            disclose_claims: false,
            clean_signal: false,
            remove_c2pa: false,
            notice: None,
            watermark_key: None,
            watermark_system_ref: String::new(),
            use_system_signers: false,
            system_signers: String::new(),
            rotation_target: String::new(),
            trace_action: HeritageAction::Trace,
            checkpoint_paths: Vec::new(),
            checkpoint_anchors: None,
            timestamp_response: None,
            timestamp_query: None,
            timestamp_roots: None,
            max_pixel_mse: 64.0,
        }
    }
}

impl HeritagePanel {
    pub fn ui(
        &mut self,
        ui: &mut egui::Ui,
        language: Language,
        session: &Session,
        idle: bool,
    ) -> Option<JobKind> {
        let input = session.selected_item().map(|item| item.path.clone());
        let mut job = None;
        ui.horizontal_wrapped(|ui| {
            for (tab, zh, en) in [
                (Tab::Mark, "Mark 植入", "Mark"),
                (Tab::Clean, "Clean 净化", "Clean"),
                (Tab::Verify, "Verify 验证", "Verify"),
                (Tab::Trace, "Trace 追踪", "Trace"),
                (Tab::Lab, "Lab 实验", "Lab"),
            ] {
                let response = ui.selectable_value(&mut self.tab, tab, t(language, zh, en));
                if tab == Tab::Verify {
                    crate::smoke::target(&response, "heritage_verify_tab");
                }
            }
        });
        ui.add_space(10.0);
        if let Some(input) = &input {
            ui.label(file_name(input))
                .on_hover_text(input.display().to_string());
        } else {
            ui.label(t(
                language,
                "请先在文件扫描中选择文件。",
                "Select a file in Files first.",
            ));
        }
        ui.add_space(8.0);
        ui.add_enabled_ui(idle, |ui| {
            match self.tab {
                Tab::Mark => job = self.mark_ui(ui, language),
                Tab::Clean => self.clean_ui(ui, language),
                Tab::Verify => {
                    ui.label(t(language, "离线检查签名、来源记录链和当前内容绑定，单独报告信任状态。", "Check signatures, the provenance chain and current content binding offline, with separate trust results."));
                    pick_path(ui, language, "信任策略 JSON", "Trust policy JSON", &mut self.trust, &["json"]);
                    pick_path(ui, language, "C2PA 本地根证书 PEM", "Local C2PA trust roots PEM", &mut self.c2pa_roots, &["pem", "crt"]);
                    self.disclosure_ui(ui, language);
                }
                Tab::Trace => {
                    egui::ComboBox::from_id_salt("provenance_action").selected_text(provenance_label(self.trace_action,language)).show_ui(ui,|ui| {
                        for action in [HeritageAction::Trace,HeritageAction::Checkpoint,HeritageAction::EvidenceExport,HeritageAction::EvidenceVerify,HeritageAction::TimestampQuery,HeritageAction::TimestampVerify,HeritageAction::TransferPrepare,HeritageAction::TransferAccept] {
                            if ui.selectable_value(&mut self.trace_action,action,provenance_label(action,language)).clicked() { ui.close(); }
                        }
                    });
                    if matches!(self.trace_action,HeritageAction::EvidenceExport|HeritageAction::TransferPrepare|HeritageAction::TransferAccept) {
                        ui.small(t(language,"导出的证据文件包含已签声明中的作者、作品与副本原文。","Exported evidence includes the signed author, work and copy claims in full."));
                    }
                    if matches!(self.trace_action,HeritageAction::Checkpoint|HeritageAction::EvidenceExport|HeritageAction::TransferPrepare|HeritageAction::TransferAccept) {
                        self.signer_sources(ui,language);
                    }
                    if self.trace_action==HeritageAction::TransferPrepare {
                        ui.label(t(language,"接收方公钥 SHA-256","Recipient public-key SHA-256"));
                        ui.text_edit_singleline(&mut self.transfer_target);
                        ui.small(t(language,"发送方准备提案后，接收方在自己的设备上联签。","The sender prepares a proposal. The receiver co-signs on their own device."));
                    }
                    ui.label(t(language, "查看签名记录中的创建、修改、发行与转移关系。可用参考文件核对像素标记与作品标识。", "Inspect signed creation, modification, issue and transfer records. A reference file can match the pixel marker to a work identifier."));
                    pick_path(ui, language, "参考文件", "Reference file", &mut self.reference, &[]);
                    pick_path(ui, language, "信任策略 JSON", "Trust policy JSON", &mut self.trust, &["json"]);
                    pick_path(ui, language, "C2PA 本地根证书 PEM", "Local C2PA trust roots PEM", &mut self.c2pa_roots, &["pem", "crt"]);
                    self.disclosure_ui(ui, language);
                    egui::CollapsingHeader::new(t(language,"链检查点与 RFC 3161 时间戳","Checkpoints and RFC 3161 timestamps")).show(ui,|ui| {
                        pick_paths(ui,language,"选择外部检查点","Choose external checkpoints",&mut self.checkpoint_paths,16);
                        pick_path(ui,language,"检查点信任公钥 JSON","Checkpoint trust keys JSON",&mut self.checkpoint_anchors,&["json"]);
                        pick_path(ui,language,"时间戳响应 DER","Timestamp response DER",&mut self.timestamp_response,&["tsr","tst","der"]);
                        pick_path(ui,language,"原始时间戳查询","Original timestamp query",&mut self.timestamp_query,&["tsq","der"]);
                        pick_path(ui,language,"时间戳信任根 PEM","Timestamp trust roots PEM",&mut self.timestamp_roots,&["pem"]);
                        ui.small(t(language,"查询与响应通过文件交换。时间戳校验默认离线。版权证据导出包含作者及作品声明。","Queries and responses are exchanged as files. Timestamp validation is offline. Exported copyright evidence includes author and work claims."));
                    });
                }
                Tab::Lab => {
                    ui.label(t(language, "在内存中测试重编码、缩放等处理后的标记检出与误匹配，并对照选定的阴性样本。", "Measure marker detection after in-memory re-encoding and resizing, and compare selected negative controls."));
                    pick_paths(ui, language, "选择阴性对照", "Choose negative controls", &mut self.controls, 8);
                    ui.small(t(language, "结果覆盖本次样本和参数。设备归属及未知水印需要独立证据。", "Results cover these samples and parameters. Device attribution and unknown watermark families require independent evidence."));
                }
            }
            if matches!(self.tab,Tab::Verify|Tab::Trace|Tab::Clean|Tab::Lab) { self.watermark_key_ui(ui,language); }
            ui.add_space(12.0);
            let request = self.request();
            let configured = self.configured();
            if self.tab == Tab::Mark && !configured {
                if self.c2pa_mark {
                    ui.small(t(language, "作品标识、版本、证书链和证书私钥必填。", "Work identifier, version, certificate chain and certificate private key are required."));
                } else {
                    ui.small(t(language, "作品标识、版本、时间声明和签名密钥必填。", "Work identifier, version, asserted time and signing keys are required."));
                }
            }
            let action_label = if self.tab==Tab::Trace { provenance_label(self.trace_action,language) } else { match self.tab {
                Tab::Mark => t(language, "保存标记副本并复验", "Save marked copy and verify"),
                Tab::Clean => t(language, "保存清理副本并复验", "Save cleaned copy and verify"),
                Tab::Verify => t(language, "验证当前文件", "Verify current file"),
                Tab::Trace => t(language, "检查来源链", "Inspect provenance chain"),
                Tab::Lab => t(language, "运行标记实验", "Run watermark lab"),
            }};
            let response = ui.add_enabled(input.is_some() && configured && job.is_none(), egui::Button::new(action_label));
            crate::smoke::target(&response, "heritage_run");
            if response.clicked()
                && let Some(path) = &input
            {
                if request.writes_file() {
                    let sidecar=matches!(request.action,HeritageAction::Checkpoint|HeritageAction::EvidenceExport|HeritageAction::TimestampQuery|HeritageAction::TransferPrepare|HeritageAction::TransferAccept);
                    let selected=if sidecar { choose_sidecar(path,request.action,language) } else { choose_output(path,self.tab,language) };
                    if let Some(output) = selected {
                        if output.exists() {
                            self.notice = Some(t(language, "目标文件已存在，请另选新文件名。", "The destination exists. Choose a new file name.").into());
                        } else if !sidecar && path.extension().map(|value| value.to_ascii_lowercase()) != output.extension().map(|value| value.to_ascii_lowercase()) {
                            self.notice = Some(t(language, "副本扩展名需要与原文件一致。", "The copy must keep the original file extension.").into());
                        } else {
                            self.notice = None;
                            job = Some(JobKind::Heritage { path: path.clone(), output: Some(output), request: Box::new(request) });
                        }
                    }
                } else {
                    self.notice = None;
                    job = Some(JobKind::Heritage { path: path.clone(), output: None, request: Box::new(request) });
                }
            }
        });
        if let Some(notice) = &self.notice {
            ui.label(notice);
        }
        job
    }

    fn mark_ui(&mut self, ui: &mut egui::Ui, language: Language) -> Option<JobKind> {
        let mut job = None;
        ui.checkbox(
            &mut self.c2pa_mark,
            t(
                language,
                "使用 C2PA 证书签名",
                "Use C2PA certificate signing",
            ),
        );
        egui::Grid::new("heritage_claims")
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                field(
                    ui,
                    t(language, "作品标识", "Work identifier"),
                    &mut self.mark.work_id,
                );
                field(
                    ui,
                    t(language, "发行副本标识", "Copy identifier"),
                    &mut self.mark.copy_id,
                );
                field(
                    ui,
                    t(language, "作者声明", "Author claim"),
                    &mut self.mark.author,
                );
                field(
                    ui,
                    t(language, "发行版本", "Edition"),
                    &mut self.mark.edition,
                );
                field(
                    ui,
                    t(language, "版本标识", "Version"),
                    &mut self.mark.version,
                );
                field(
                    ui,
                    t(language, "创建时间声明", "Created-at claim"),
                    &mut self.mark.created_at,
                );
            });
        if ui
            .small_button(t(language, "使用当前时间声明", "Use current-time claim"))
            .clicked()
        {
            match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
                Ok(now) => self.mark.created_at = format!("unix:{}", now.as_secs()),
                Err(_) => {
                    self.notice = Some(
                        t(
                            language,
                            "当前系统时间早于 Unix 纪元，请检查系统时钟。",
                            "The system time precedes the Unix epoch. Check the system clock.",
                        )
                        .into(),
                    )
                }
            }
        }
        ui.small(t(language, "离线时间属于用户声明，未取得可信时间戳认证。", "Offline time is a user assertion. Trusted timestamp authority validation remains unassessed."));
        if self.c2pa_mark {
            ui.label(t(language, "使用你提供的本地证书与私钥创建标准来源凭据。证书信任和吊销状态由验证结果单独报告。", "Create standard Content Credentials with your local certificate and private key. Verification reports certificate trust and revocation separately."));
            pick_path(
                ui,
                language,
                "证书链 PEM",
                "Certificate chain PEM",
                &mut self.certificate,
                &["pem", "crt"],
            );
            pick_path(
                ui,
                language,
                "证书私钥 PEM",
                "Certificate private key PEM",
                &mut self.private_key,
                &["pem", "key"],
            );
            ui.checkbox(
                &mut self.c2pa_pixel,
                t(
                    language,
                    "关联 Engine 2 像素水印",
                    "Link an Engine 2 pixel watermark",
                ),
            );
            if self.c2pa_pixel {
                self.watermark_key_ui(ui, language);
                ui.add(egui::Slider::new(&mut self.mark.strength, 12..=64).text(t(
                    language,
                    "水印强度",
                    "Watermark strength",
                )));
                ui.small(t(language,"像素标记与 C2PA 使用相同作品和副本标识。需要单独授权的 Ed25519 水印密钥。","The pixel mark and C2PA share work and copy identifiers. A separately authorized Ed25519 watermark key is required."));
            }
            return job;
        }
        ui.label(t(
            language,
            "为作品添加本地 Ed25519 签名记录，可选择额外的图像像素标记。",
            "Add a local Ed25519-signed work record, with an optional image pixel marker.",
        ));
        ui.horizontal_wrapped(|ui| {
            ui.label(t(language, "记录类型", "Record type"));
            egui::ComboBox::from_id_salt("heritage_record_kind")
                .selected_text(kind_label(self.mark.kind, language))
                .show_ui(ui, |ui| {
                    for kind in [
                        RecordKind::Create,
                        RecordKind::Modify,
                        RecordKind::Issue,
                        RecordKind::Transfer,
                        RecordKind::RotateKey,
                    ] {
                        ui.selectable_value(&mut self.mark.kind, kind, kind_label(kind, language));
                    }
                });
            egui::ComboBox::from_id_salt("heritage_sign_mode")
                .selected_text(mode_label(self.mark.mode, language))
                .show_ui(ui, |ui| {
                    for mode in [SignMode::SelfSign, SignMode::NatiSign] {
                        ui.selectable_value(&mut self.mark.mode, mode, mode_label(mode, language));
                    }
                });
        });
        if self.mark.kind == RecordKind::Transfer {
            ui.label(t(
                language,
                "接收方公钥标识 SHA-256",
                "Recipient public-key identifier SHA-256",
            ));
            ui.text_edit_singleline(&mut self.transfer_target);
        }
        if self.mark.kind == RecordKind::RotateKey {
            ui.label(t(
                language,
                "继任密钥公钥 SHA-256",
                "Successor public-key SHA-256",
            ));
            ui.text_edit_singleline(&mut self.rotation_target);
            ui.small(t(
                language,
                "轮换记录须由当前密钥和继任密钥共同签署。",
                "Rotation requires signatures from the current and successor keys.",
            ));
        }
        if self.mark.mode == SignMode::NatiSign {
            ui.horizontal(|ui| {
                ui.label(t(language, "发行签名阈值", "Issuer signature threshold"));
                ui.add(egui::DragValue::new(&mut self.mark.issuer_threshold).range(1..=32));
            });
            ui.small(t(language, "NATI 采用选定发行密钥的阈值策略。信任关系由验证方的本地策略确定。", "NATI uses a threshold policy over the selected issuer keys. The verifier's local policy establishes trust."));
        }
        self.system_signer_ui(ui, language);
        pick_paths(
            ui,
            language,
            "选择本地签名密钥",
            "Choose local signing keys",
            &mut self.keys,
            32,
        );
        ui.small(t(language, "首个密钥对应本条记录的持有人，其余密钥用于联签。", "The first key identifies this record's custodian. Additional keys provide co-signatures."));
        if ui
            .button(t(
                language,
                "生成本地签名密钥",
                "Generate local signing key",
            ))
            .clicked()
            && let Some(output) = rfd::FileDialog::new()
                .add_filter(
                    t(
                        language,
                        "KEY 二进制签名私钥",
                        "KEY binary signing private key",
                    ),
                    &["key"],
                )
                .set_file_name("FileVeil-signing.key")
                .save_file()
        {
            if output.exists() {
                self.notice = Some(
                    t(
                        language,
                        "密钥目标已存在，请选择新文件。",
                        "The key destination exists. Choose a new file.",
                    )
                    .into(),
                );
            } else {
                self.notice = None;
                job = Some(JobKind::HeritageKeygen { output });
            }
        }
        if ui
            .button(t(
                language,
                "生成系统密钥库密钥",
                "Generate system-keystore key",
            ))
            .clicked()
        {
            job = Some(JobKind::SystemKeygen);
        }
        pick_path(
            ui,
            language,
            "上一版本或来源链文件",
            "Previous version or history file",
            &mut self.previous,
            &[],
        );
        ui.checkbox(
            &mut self.mark.robust,
            t(language, "嵌入图像像素标记", "Embed image pixel marker"),
        );
        if self.mark.robust {
            egui::ComboBox::from_id_salt("watermark_protocol")
                .selected_text(if self.mark.watermark_version == 2 {
                    "Watermark Engine 2"
                } else {
                    "0.4 compatibility"
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.mark.watermark_version, 2, "Watermark Engine 2");
                    ui.selectable_value(&mut self.mark.watermark_version, 1, "0.4 compatibility");
                });
            ui.small(t(language,"2.0 使用密钥化载体与纠错。默认从持有人签名密钥派生像素密钥，复验时请明确选择相同密钥。","Engine 2 uses keyed carriers and error correction. Its default pixel key is derived from the custodian key. Explicitly select the same key when verifying."));
            ui.label(t(language, "像素标记会改变图像信号，JPEG 也会重新编码。保存后执行检测与复验。", "Pixel marking changes the image signal and re-encodes JPEG. Detection and verification run after saving."));
            ui.add(
                egui::Slider::new(
                    &mut self.mark.strength,
                    if self.mark.watermark_version == 2 {
                        12..=64
                    } else {
                        16..=64
                    },
                )
                .text(t(language, "强度", "Strength")),
            );
        }
        job
    }

    fn clean_ui(&mut self, ui: &mut egui::Ui, language: Language) {
        ui.label(t(language, "清理标准隐私元数据与已识别的结构水印，并复验保留内容。受保护的签名结构需要明确选择。", "Clean standard privacy metadata and recognized structural watermarks, then verify retained content. Protected signature structures require an explicit selection."));
        ui.checkbox(
            &mut self.clean_signal,
            t(
                language,
                "定向处理已检出的受支持图像水印",
                "Target detected supported image watermarks",
            ),
        );
        if self.clean_signal {
            ui.small(t(
                language,
                "此操作改变像素与编码，结果包含对应检测器的处理后复检。",
                "This changes pixels and encoding. Results include a post-process detector check.",
            ));
        }
        ui.checkbox(
            &mut self.remove_c2pa,
            t(
                language,
                "明确移除可移除的 C2PA 来源凭据",
                "Explicitly remove removable C2PA Content Credentials",
            ),
        );
        if self.remove_c2pa {
            ui.small(t(language, "移除来源凭据会破坏其签名关联，结果报告保留验证范围。", "Removing credentials breaks their signed provenance association. Results retain a scoped verification report."));
        }
    }

    fn disclosure_ui(&mut self, ui: &mut egui::Ui, language: Language) {
        ui.checkbox(
            &mut self.disclose_claims,
            t(
                language,
                "在报告中显示作者和作品声明值",
                "Include author and work claim values in reports",
            ),
        );
        ui.checkbox(
            &mut self.disclose_identifiers,
            t(
                language,
                "在报告中显示可解码的历史设备标识",
                "Include decodable legacy device identifiers in reports",
            ),
        );
    }

    fn system_signer_refs(&self) -> Vec<fileveil_engine::heritage::key_store::KeyStoreRef> {
        self.system_signers
            .split_whitespace()
            .map(|id| fileveil_engine::heritage::key_store::KeyStoreRef {
                key_id: id.to_ascii_lowercase(),
            })
            .collect()
    }
    fn has_signer(&self) -> bool {
        if self.use_system_signers {
            let refs = self.system_signer_refs();
            !refs.is_empty()
                && refs.iter().all(|r| {
                    r.key_id.len() == 64 && r.key_id.bytes().all(|b| b.is_ascii_hexdigit())
                })
        } else {
            !self.keys.is_empty()
        }
    }
    fn system_signer_ui(&mut self, ui: &mut egui::Ui, language: Language) {
        ui.checkbox(
            &mut self.use_system_signers,
            t(language, "使用系统密钥库", "Use system key storage"),
        );
        if self.use_system_signers {
            ui.label(t(
                language,
                "公钥标识 SHA-256，多密钥用空格分隔",
                "Public-key SHA-256 identifiers, space-separated for co-signing",
            ));
            ui.text_edit_singleline(&mut self.system_signers);
        }
    }
    fn signer_sources(&mut self, ui: &mut egui::Ui, language: Language) {
        self.system_signer_ui(ui, language);
        if !self.use_system_signers {
            pick_paths(
                ui,
                language,
                "选择联签密钥",
                "Choose signing keys",
                &mut self.keys,
                32,
            );
        }
    }
    fn watermark_key_ui(&mut self, ui: &mut egui::Ui, language: Language) {
        pick_path(
            ui,
            language,
            "2.0 水印密钥文件",
            "Engine 2 watermark key file",
            &mut self.watermark_key,
            &["key"],
        );
        ui.label(t(
            language,
            "或系统水印密钥公钥标识",
            "Or system watermark-key public identifier",
        ));
        ui.text_edit_singleline(&mut self.watermark_system_ref);
        if self.clean_signal && self.tab == Tab::Clean {
            ui.horizontal(|ui| {
                ui.label(t(language, "最大 RGBA8 均方误差", "Maximum RGBA8 MSE"));
                ui.add(egui::DragValue::new(&mut self.max_pixel_mse).range(0.0..=65025.0));
            });
        }
    }
    fn configured(&self) -> bool {
        if self.tab == Tab::Trace
            && matches!(
                self.trace_action,
                HeritageAction::Checkpoint
                    | HeritageAction::EvidenceExport
                    | HeritageAction::TransferPrepare
                    | HeritageAction::TransferAccept
            )
        {
            return self.has_signer()
                && (self.trace_action != HeritageAction::TransferPrepare
                    || self.transfer_target.len() == 64);
        }
        if self.tab != Tab::Mark {
            return true;
        }
        if self.mark.work_id.trim().is_empty() || self.mark.version.trim().is_empty() {
            return false;
        }
        if self.c2pa_mark {
            return self.certificate.is_some()
                && self.private_key.is_some()
                && (!self.c2pa_pixel
                    || (self.watermark_key.is_some() || self.watermark_system_ref.len() == 64));
        }
        !self.mark.created_at.trim().is_empty()
            && self.has_signer()
            && (self.mark.mode != SignMode::NatiSign
                || self.mark.issuer_threshold as usize
                    <= if self.use_system_signers {
                        self.system_signer_refs().len()
                    } else {
                        self.keys.len()
                    })
            && (self.mark.kind != RecordKind::Transfer
                || (self.transfer_target.len() == 64
                    && self
                        .transfer_target
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())))
    }

    fn request(&self) -> HeritageRequest {
        let action = match self.tab {
            Tab::Mark if self.c2pa_mark => HeritageAction::C2paMark,
            Tab::Mark => HeritageAction::Mark,
            Tab::Clean => HeritageAction::Clean,
            Tab::Verify => HeritageAction::Verify,
            Tab::Trace => self.trace_action,
            Tab::Lab => HeritageAction::Lab,
        };
        let mut request = HeritageRequest {
            action,
            ..Default::default()
        };
        if matches!(
            action,
            HeritageAction::Mark
                | HeritageAction::Verify
                | HeritageAction::Trace
                | HeritageAction::Lab
        ) {
            request.trust_store = self.trust.clone();
        }
        if matches!(
            action,
            HeritageAction::Verify | HeritageAction::Trace | HeritageAction::Lab
        ) {
            request.c2pa_trust_roots = self.c2pa_roots.clone();
        }
        if action == HeritageAction::Mark {
            request.mark = self.mark.clone();
            request.mark.transfer_to_key_id = (self.mark.kind == RecordKind::Transfer)
                .then(|| self.transfer_target.to_ascii_lowercase());
            if self.use_system_signers {
                request.key_refs = self.system_signer_refs();
            } else {
                request.key_paths = self.keys.clone();
            }
            request.mark.rotation_to_key_id = (self.mark.kind == RecordKind::RotateKey)
                .then(|| self.rotation_target.to_ascii_lowercase());
            request.previous = self.previous.clone();
        }
        if action == HeritageAction::C2paMark {
            request.mark = MarkSettings {
                work_id: self.mark.work_id.clone(),
                copy_id: self.mark.copy_id.clone(),
                author: self.mark.author.clone(),
                edition: self.mark.edition.clone(),
                version: self.mark.version.clone(),
                created_at: self.mark.created_at.clone(),
                robust: self.c2pa_pixel,
                watermark_version: 2,
                strength: self.mark.strength,
                ..Default::default()
            };
            request.certificate = self.certificate.clone();
            request.private_key = self.private_key.clone();
        }
        if self.tab == Tab::Trace {
            request.reference = self.reference.clone();
            request.checkpoints = self.checkpoint_paths.clone();
            request.checkpoint_anchors = self.checkpoint_anchors.clone();
            request.timestamp_response = self.timestamp_response.clone();
            request.timestamp_query = self.timestamp_query.clone();
            request.timestamp_roots = self.timestamp_roots.clone();
            if matches!(
                action,
                HeritageAction::Checkpoint
                    | HeritageAction::EvidenceExport
                    | HeritageAction::TransferPrepare
                    | HeritageAction::TransferAccept
            ) {
                if self.use_system_signers {
                    request.key_refs = self.system_signer_refs();
                } else {
                    request.key_paths = self.keys.clone();
                }
                request.mark = self.mark.clone();
                request.mark.transfer_to_key_id = Some(self.transfer_target.to_ascii_lowercase());
            }
        }
        if action != HeritageAction::C2paMark || self.c2pa_pixel {
            request.watermark_key = self.watermark_key.clone();
            if !self.watermark_system_ref.trim().is_empty() {
                request.watermark_key_ref =
                    Some(fileveil_engine::heritage::key_store::KeyStoreRef {
                        key_id: self.watermark_system_ref.trim().to_ascii_lowercase(),
                    });
            }
        }
        if self.tab == Tab::Lab {
            request.controls = self.controls.clone();
        }
        if matches!(self.tab, Tab::Verify | Tab::Trace) {
            request.disclose_identifiers = self.disclose_identifiers;
            request.disclose_claims = self.disclose_claims;
        }
        if self.tab == Tab::Clean {
            request.clean_signal = self.clean_signal;
            request.clean_metadata = true;
            if self.clean_signal {
                request.max_pixel_mse = Some(self.max_pixel_mse);
            }
            request.remove_c2pa = self.remove_c2pa;
        }
        request
    }
}

fn t<'a>(language: Language, chinese: &'a str, english: &'a str) -> &'a str {
    crate::i18n::text(language, chinese, english)
}

fn field(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.label(label);
    ui.add(egui::TextEdit::singleline(value).desired_width(300.0));
    ui.end_row();
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}

fn pick_path(
    ui: &mut egui::Ui,
    language: Language,
    zh: &str,
    en: &str,
    value: &mut Option<PathBuf>,
    extensions: &[&str],
) {
    ui.horizontal_wrapped(|ui| {
        if ui.button(t(language, zh, en)).clicked() {
            let mut dialog = rfd::FileDialog::new();
            if !extensions.is_empty() {
                dialog = dialog.add_filter(t(language, zh, en), extensions);
            }
            if let Some(path) = dialog.pick_file() {
                *value = Some(path);
            }
        }
        if let Some(path) = value {
            ui.label(file_name(path))
                .on_hover_text(path.display().to_string());
            if ui.small_button(t(language, "移除", "Remove")).clicked() {
                *value = None;
            }
        }
    });
}

fn pick_paths(
    ui: &mut egui::Ui,
    language: Language,
    zh: &str,
    en: &str,
    values: &mut Vec<PathBuf>,
    limit: usize,
) {
    ui.horizontal_wrapped(|ui| {
        if ui
            .add_enabled(values.len() < limit, egui::Button::new(t(language, zh, en)))
            .clicked()
            && let Some(paths) = rfd::FileDialog::new().pick_files()
        {
            for path in paths {
                if values.len() >= limit {
                    break;
                }
                if !values.contains(&path) {
                    values.push(path);
                }
            }
        }
        if !values.is_empty()
            && ui
                .small_button(t(language, "清空选择", "Clear selection"))
                .clicked()
        {
            values.clear();
        }
    });
    let mut remove = None;
    for (index, path) in values.iter().enumerate() {
        ui.horizontal(|ui| {
            ui.label(file_name(path))
                .on_hover_text(path.display().to_string());
            if ui.small_button(t(language, "移除", "Remove")).clicked() {
                remove = Some(index);
            }
        });
    }
    if let Some(index) = remove {
        values.remove(index);
    }
}

fn choose_output(input: &Path, tab: Tab, language: Language) -> Option<PathBuf> {
    let extension = input.extension().unwrap_or_default().to_string_lossy();
    let name = input.file_stem().unwrap_or_default().to_string_lossy();
    let suffix = if tab == Tab::Mark { "marked" } else { "clean" };
    let mut dialog = rfd::FileDialog::new()
        .set_directory(input.parent().unwrap_or(Path::new(".")))
        .set_file_name(format!("{name}.{suffix}.{extension}"));
    if !extension.is_empty() {
        dialog = dialog.add_filter(
            t(language, "原文件格式", "Original format"),
            &[extension.as_ref()],
        );
    }
    dialog.save_file()
}

fn provenance_label(action: HeritageAction, language: Language) -> &'static str {
    match action {
        HeritageAction::Checkpoint => t(language, "导出签名链检查点", "Export signed checkpoint"),
        HeritageAction::EvidenceExport => {
            t(language, "导出版权证据包", "Export copyright evidence")
        }
        HeritageAction::EvidenceVerify => t(language, "独立验证证据包", "Verify evidence package"),
        HeritageAction::TimestampQuery => {
            t(language, "导出 RFC 3161 查询", "Export RFC 3161 query")
        }
        HeritageAction::TimestampVerify => {
            t(language, "验证 RFC 3161 响应", "Verify RFC 3161 response")
        }
        HeritageAction::TransferPrepare => t(
            language,
            "发送方准备交接提案",
            "Prepare sender transfer proposal",
        ),
        HeritageAction::TransferAccept => t(
            language,
            "接收方联签交接提案",
            "Co-sign receiver transfer proposal",
        ),
        _ => t(language, "检查版本与交接链", "Inspect versions and custody"),
    }
}
fn choose_sidecar(input: &Path, action: HeritageAction, language: Language) -> Option<PathBuf> {
    let extension = if action == HeritageAction::TimestampQuery {
        "tsq"
    } else {
        "json"
    };
    let stem = input.file_stem().unwrap_or_default().to_string_lossy();
    rfd::FileDialog::new()
        .set_directory(input.parent().unwrap_or(Path::new(".")))
        .add_filter(t(language, "证据文件", "Evidence file"), &[extension])
        .set_file_name(format!("{stem}.evidence.{extension}"))
        .save_file()
}

fn kind_label(kind: RecordKind, language: Language) -> &'static str {
    match kind {
        RecordKind::Create => t(language, "创建", "Create"),
        RecordKind::Modify => t(language, "修改", "Modify"),
        RecordKind::Issue => t(language, "发行", "Issue"),
        RecordKind::Transfer => t(language, "转移", "Transfer"),
        RecordKind::RotateKey => t(language, "轮换密钥", "Rotate signing key"),
    }
}

fn mode_label(mode: SignMode, language: Language) -> &'static str {
    match mode {
        SignMode::SelfSign => t(language, "SELF 本地签名", "SELF local signing"),
        SignMode::NatiSign => t(language, "NATI 发行策略", "NATI issuer policy"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_tabs_omit_retained_private_key_and_previous_version_selections() {
        let mut panel = HeritagePanel {
            keys: vec![PathBuf::from("private-signing-key.json")],
            previous: Some(PathBuf::from("previous.jpg")),
            certificate: Some(PathBuf::from("chain.pem")),
            private_key: Some(PathBuf::from("private.pem")),
            ..Default::default()
        };
        for tab in [Tab::Verify, Tab::Trace, Tab::Lab] {
            panel.tab = tab;
            let request = panel.request();
            assert!(request.key_paths.is_empty());
            assert!(request.previous.is_none());
            assert!(request.certificate.is_none());
            assert!(request.private_key.is_none());
            assert!(!request.writes_file());
        }
    }

    #[test]
    fn c2pa_action_passes_only_its_selected_certificate_credentials() {
        let panel = HeritagePanel {
            c2pa_mark: true,
            keys: vec![PathBuf::from("private-signing-key.json")],
            certificate: Some(PathBuf::from("chain.pem")),
            private_key: Some(PathBuf::from("private.pem")),
            ..Default::default()
        };
        let request = panel.request();
        assert_eq!(request.action, HeritageAction::C2paMark);
        assert!(request.key_paths.is_empty());
        assert_eq!(request.certificate, panel.certificate);
        assert_eq!(request.private_key, panel.private_key);
        assert!(!panel.configured());
        let mut panel = panel;
        panel.mark.work_id = "synthetic-work".into();
        assert!(panel.configured());
        panel.mark.version.clear();
        assert!(!panel.configured());
    }

    #[test]
    fn c2pa_mark_carries_entered_claims_and_verify_uses_separate_pem_roots() {
        let mut panel = HeritagePanel {
            c2pa_mark: true,
            certificate: Some("certificate.pem".into()),
            private_key: Some("private.pem".into()),
            trust: Some("old-modern-policy.json".into()),
            c2pa_roots: Some("local-root.pem".into()),
            mark: MarkSettings {
                work_id: "authored-work".into(),
                author: "Synthetic author".into(),
                robust: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let request = panel.request();
        assert_eq!(request.action, HeritageAction::C2paMark);
        assert_eq!(request.mark.work_id, "authored-work");
        assert_eq!(request.mark.author, "Synthetic author");
        assert!(!request.mark.robust);
        assert!(request.trust_store.is_none());
        assert!(request.c2pa_trust_roots.is_none());
        panel.tab = Tab::Verify;
        let request = panel.request();
        assert!(request.private_key.is_none());
        assert_eq!(
            request.c2pa_trust_roots,
            Some(PathBuf::from("local-root.pem"))
        );
    }

    #[test]
    fn mark_requires_asserted_time_and_valid_transfer_destination() {
        let mut panel = HeritagePanel {
            keys: vec![PathBuf::from("private-signing-key.json")],
            ..Default::default()
        };
        panel.mark.work_id = "test-work".into();
        assert!(!panel.configured());
        panel.mark.created_at = "2026-11-12T00:00:00Z".into();
        assert!(panel.configured());
        panel.mark.kind = RecordKind::Transfer;
        assert!(!panel.configured());
        panel.transfer_target = "AB".repeat(32);
        assert!(panel.configured());
        assert_eq!(
            panel.request().mark.transfer_to_key_id,
            Some("ab".repeat(32))
        );
    }

    #[test]
    fn clean_options_and_disclosure_are_explicitly_scoped_to_the_current_action() {
        let mut panel = HeritagePanel {
            tab: Tab::Clean,
            clean_signal: true,
            remove_c2pa: true,
            disclose_claims: true,
            disclose_identifiers: true,
            ..Default::default()
        };
        let clean = panel.request();
        assert!(clean.clean_signal && clean.remove_c2pa);
        assert!(!clean.disclose_claims && !clean.disclose_identifiers);
        panel.tab = Tab::Verify;
        let verify = panel.request();
        assert!(!verify.clean_signal && !verify.remove_c2pa);
        assert!(verify.disclose_claims && verify.disclose_identifiers);
    }
}

// FVPROV1 43789 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJhNzMzYjgzZDdiYmIwOTkyMjA5ODllN2Y3OGQ2ZTNkNTRhMWJiZjI3YjBlZGNkYWU5OTQ0OWVlZDI5NDY0NTUwIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvc3JjL2hlcml0YWdlX3VpLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiYTI4ODkzZWZhZmJjMGZmYWYyODkwODE1Y2ZmNzcxNDBjOGQ0NWU3ZDliM2MwMGViY2U5NGY2MDE3YTQxZWMwNjMyZTFkMDVkN2RhY2M4NDI5MGE4MWMzMzFmYjVjZGMxYjEzYzk5YTNiN2I0NWE5MzNiMDc3MTRiOWQwNDNiMGMifV19XQ== FVPROV1-END
