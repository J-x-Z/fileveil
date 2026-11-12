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
    disclose_identifiers: bool,
    disclose_claims: bool,
    clean_signal: bool,
    remove_c2pa: bool,
    notice: Option<String>,
}

impl Default for HeritagePanel {
    fn default() -> Self {
        Self {
            tab: Tab::Mark,
            mark: MarkSettings::default(),
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
            disclose_identifiers: false,
            disclose_claims: false,
            clean_signal: false,
            remove_c2pa: false,
            notice: None,
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
                (Tab::Mark, "添加标记", "Mark"),
                (Tab::Clean, "清理标记", "Clean"),
                (Tab::Verify, "验证", "Verify"),
                (Tab::Trace, "来源链", "Trace"),
                (Tab::Lab, "标记实验室", "Heritage Lab"),
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
                    ui.label(t(language, "查看签名记录中的创建、修改、发行与转移关系。可用参考文件核对像素标记与作品标识。", "Inspect signed creation, modification, issue and transfer records. A reference file can match the pixel marker to a work identifier."));
                    pick_path(ui, language, "参考文件", "Reference file", &mut self.reference, &[]);
                    pick_path(ui, language, "信任策略 JSON", "Trust policy JSON", &mut self.trust, &["json"]);
                    pick_path(ui, language, "C2PA 本地根证书 PEM", "Local C2PA trust roots PEM", &mut self.c2pa_roots, &["pem", "crt"]);
                    self.disclosure_ui(ui, language);
                }
                Tab::Lab => {
                    ui.label(t(language, "在内存中测试重编码、缩放等处理后的标记检出与误匹配，并对照选定的阴性样本。", "Measure marker detection after in-memory re-encoding and resizing, and compare selected negative controls."));
                    pick_paths(ui, language, "选择阴性对照", "Choose negative controls", &mut self.controls, 8);
                    ui.small(t(language, "结果覆盖本次样本和参数。设备归属及未知水印需要独立证据。", "Results cover these samples and parameters. Device attribution and unknown watermark families require independent evidence."));
                }
            }
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
            let action_label = match self.tab {
                Tab::Mark => t(language, "保存标记副本并复验", "Save marked copy and verify"),
                Tab::Clean => t(language, "保存清理副本并复验", "Save cleaned copy and verify"),
                Tab::Verify => t(language, "验证当前文件", "Verify current file"),
                Tab::Trace => t(language, "检查来源链", "Inspect provenance chain"),
                Tab::Lab => t(language, "运行标记实验", "Run Heritage Lab"),
            };
            let response = ui.add_enabled(input.is_some() && configured && job.is_none(), egui::Button::new(action_label));
            crate::smoke::target(&response, "heritage_run");
            if response.clicked()
                && let Some(path) = &input
            {
                if request.writes_file() {
                    if let Some(output) = choose_output(path, self.tab, language) {
                        if output.exists() {
                            self.notice = Some(t(language, "目标文件已存在，请另选新文件名。", "The destination exists. Choose a new file name.").into());
                        } else if path.extension().map(|value| value.to_ascii_lowercase()) != output.extension().map(|value| value.to_ascii_lowercase()) {
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
        if self.mark.mode == SignMode::NatiSign {
            ui.horizontal(|ui| {
                ui.label(t(language, "发行签名阈值", "Issuer signature threshold"));
                ui.add(egui::DragValue::new(&mut self.mark.issuer_threshold).range(1..=32));
            });
            ui.small(t(language, "NATI 采用选定发行密钥的阈值策略。信任关系由验证方的本地策略确定。", "NATI uses a threshold policy over the selected issuer keys. The verifier's local policy establishes trust."));
        }
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
            ui.label(t(language, "像素标记会改变图像信号，JPEG 也会重新编码。保存后执行检测与复验。", "Pixel marking changes the image signal and re-encodes JPEG. Detection and verification run after saving."));
            ui.add(
                egui::Slider::new(&mut self.mark.strength, 16..=64)
                    .text(t(language, "强度", "Strength")),
            );
        }
        job
    }

    fn clean_ui(&mut self, ui: &mut egui::Ui, language: Language) {
        ui.label(t(language, "移除可识别的 FileVeil 来源载体和已确认的历史标记，并核对保留内容。NATISIGN 未验证候选受到保护。", "Remove recognized FileVeil provenance carriers and confirmed legacy markers, then check retained content. Unverified NATISIGN candidates are protected."));
        ui.checkbox(
            &mut self.clean_signal,
            t(
                language,
                "处理检测到的 FileVeil 图像像素标记",
                "Process a detected FileVeil image pixel marker",
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

    fn configured(&self) -> bool {
        if self.tab != Tab::Mark {
            return true;
        }
        if self.mark.work_id.trim().is_empty() || self.mark.version.trim().is_empty() {
            return false;
        }
        if self.c2pa_mark {
            return self.certificate.is_some() && self.private_key.is_some();
        }
        !self.mark.created_at.trim().is_empty()
            && !self.keys.is_empty()
            && (self.mark.mode != SignMode::NatiSign
                || self.mark.issuer_threshold as usize <= self.keys.len())
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
            Tab::Trace => HeritageAction::Trace,
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
            request.key_paths = self.keys.clone();
            request.previous = self.previous.clone();
        }
        if action == HeritageAction::C2paMark {
            request.mark = MarkSettings {
                work_id: self.mark.work_id.clone(),
                author: self.mark.author.clone(),
                edition: self.mark.edition.clone(),
                version: self.mark.version.clone(),
                created_at: self.mark.created_at.clone(),
                ..Default::default()
            };
            request.certificate = self.certificate.clone();
            request.private_key = self.private_key.clone();
        }
        if self.tab == Tab::Trace {
            request.reference = self.reference.clone();
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
            request.remove_c2pa = self.remove_c2pa;
        }
        request
    }
}

fn t<'a>(language: Language, chinese: &'a str, english: &'a str) -> &'a str {
    match language {
        Language::Chinese => chinese,
        Language::English => english,
    }
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

fn kind_label(kind: RecordKind, language: Language) -> &'static str {
    match kind {
        RecordKind::Create => t(language, "创建", "Create"),
        RecordKind::Modify => t(language, "修改", "Modify"),
        RecordKind::Issue => t(language, "发行", "Issue"),
        RecordKind::Transfer => t(language, "转移", "Transfer"),
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
