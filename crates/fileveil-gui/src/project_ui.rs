// SPDX-License-Identifier: MPL-2.0
//! Project configuration and debounced automation using isolated, bounded jobs.
use crate::{
    i18n::{Language, text},
    jobs::JobKind,
};
use eframe::egui;
use fileveil_core::{Outcome, Report};
use fileveil_engine::project::{
    ProjectAction, ProjectConfig, ProjectFileMode, ProjectKey, ProjectRequest, ProjectRule,
    ProjectTrigger, SyncOptions,
};
use std::{
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Default)]
struct KeySelection {
    system: bool,
    file: Option<PathBuf>,
    reference: String,
}
impl KeySelection {
    fn selected(&self) -> Option<ProjectKey> {
        if self.system {
            (!self.reference.trim().is_empty()).then(|| ProjectKey::System {
                key_id: self.reference.trim().into(),
            })
        } else {
            self.file.clone().map(|path| ProjectKey::File { path })
        }
    }
}

pub struct ProjectPanel {
    config_path: Option<PathBuf>,
    config: ProjectConfig,
    loaded_config: Option<ProjectConfig>,
    include: String,
    exclude: String,
    key: KeySelection,
    rotation: KeySelection,
    state_directory: Option<PathBuf>,
    version: String,
    created_at: String,
    git_ref: String,
    build_command: String,
    trust_keys: String,
    allow_work_migration: bool,
    watching: bool,
    next_poll: Instant,
    last_probe: Option<String>,
    last_probe_cost: Duration,
    last_strong_check: Instant,
    last_strong_cost: Duration,
    force_strong_check: bool,
    confirming_strong_change: bool,
    candidate: Option<(String, Instant)>,
    sync_due: bool,
    awaiting_action: Option<ProjectAction>,
    pending_started: Instant,
    load_config: bool,
    pending_rotation: bool,
    cancel_requested: bool,
    clear_results_requested: bool,
    notice: Option<String>,
}
impl Default for ProjectPanel {
    fn default() -> Self {
        let config = ProjectConfig {
            source_root: PathBuf::new(),
            ..Default::default()
        };
        Self {
            include: config.include.join("\n"),
            exclude: config.exclude.join("\n"),
            config,
            config_path: None,
            loaded_config: None,
            key: KeySelection::default(),
            rotation: KeySelection::default(),
            state_directory: None,
            version: String::new(),
            created_at: String::new(),
            git_ref: String::new(),
            build_command: String::new(),
            trust_keys: "[]".into(),
            allow_work_migration: false,
            watching: false,
            next_poll: Instant::now(),
            last_probe: None,
            last_probe_cost: Duration::ZERO,
            last_strong_check: Instant::now(),
            last_strong_cost: Duration::ZERO,
            force_strong_check: true,
            confirming_strong_change: false,
            candidate: None,
            sync_due: false,
            awaiting_action: None,
            pending_started: Instant::now(),
            load_config: false,
            pending_rotation: false,
            cancel_requested: false,
            clear_results_requested: false,
            notice: None,
        }
    }
}

impl ProjectPanel {
    pub fn stop_watching(&mut self) {
        self.watching = false;
        self.candidate = None;
        self.sync_due = false;
        self.confirming_strong_change = false;
    }

    pub fn take_cancel_requested(&mut self) -> bool {
        std::mem::take(&mut self.cancel_requested)
    }

    pub fn take_clear_results_requested(&mut self) -> bool {
        std::mem::take(&mut self.clear_results_requested)
    }

    pub fn pending(&self) -> bool {
        self.awaiting_action.is_some()
    }

    pub fn pending_probe(&self) -> bool {
        self.awaiting_action == Some(ProjectAction::WatchProbe)
    }

    pub fn manifest_path(&self, details: &serde_json::Value) -> Option<PathBuf> {
        let parent = self.config_path.as_ref()?.parent()?;
        let config: ProjectConfig = serde_json::from_value(details.get("config")?.clone()).ok()?;
        let output = if config.output_directory.is_absolute() {
            config.output_directory
        } else {
            parent.join(config.output_directory)
        };
        let relative = details.get("manifest_relative_path")?.as_str()?;
        if relative.is_empty()
            || relative.contains('\\')
            || Path::new(relative)
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return None;
        }
        Some(output.join(relative))
    }

    pub fn record_result(&mut self, report: &Report) {
        self.record_result_at(report, Instant::now());
    }

    fn record_result_at(&mut self, report: &Report, now: Instant) {
        let action = self.awaiting_action.take();
        let details = report
            .advanced
            .as_ref()
            .and_then(|value| value.get("project"));
        if action == Some(ProjectAction::WatchProbe)
            && let Some(fingerprint) = details
                .and_then(|value| value.get("source_fingerprint"))
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
            && !matches!(
                report.result,
                Outcome::Failed | Outcome::Blocked | Outcome::Unsupported
            )
        {
            self.last_probe_cost = now.saturating_duration_since(self.pending_started);
            match &self.last_probe {
                Some(previous) if previous != fingerprint => {
                    self.candidate = Some((fingerprint.into(), now));
                    self.sync_due = false;
                }
                Some(_) if !self.confirming_strong_change => {
                    if let Some((_, since)) = self.candidate {
                        self.sync_due = now.saturating_duration_since(since)
                            >= Duration::from_millis(self.config.debounce_ms);
                    }
                }
                _ => {}
            }
            self.last_probe = Some(fingerprint.into());
            self.next_poll = if self.sync_due || self.force_strong_check {
                now
            } else {
                now + self.probe_interval()
            };
            return;
        }
        let succeeded = matches!(
            report.result,
            Outcome::VerifiedWithinScope | Outcome::PartiallyVerified
        );
        if succeeded
            && self.load_config
            && let Some(config) = details
                .and_then(|value| value.get("config"))
                .and_then(|value| serde_json::from_value::<ProjectConfig>(value.clone()).ok())
        {
            self.include = config.include.join("\n");
            self.exclude = config.exclude.join("\n");
            self.build_command = if config.build_argv.is_empty() {
                String::new()
            } else {
                serde_json::to_string(&config.build_argv).unwrap_or_default()
            };
            self.loaded_config = Some(config.clone());
            self.config = config;
        }
        self.load_config = false;
        if !succeeded {
            self.candidate = None;
            self.sync_due = false;
            self.next_poll = now + Duration::from_millis(self.config.poll_interval_ms.max(5000));
            if matches!(report.result, Outcome::Blocked | Outcome::Unsupported) {
                self.stop_watching();
            }
            return;
        }
        if action == Some(ProjectAction::Sync) {
            self.candidate = None;
            self.sync_due = false;
            self.confirming_strong_change = false;
            if self.pending_rotation {
                self.rotation = KeySelection::default();
                self.key = KeySelection::default();
            }
        }
        self.pending_rotation = false;
        if matches!(action, Some(ProjectAction::Status | ProjectAction::Sync)) {
            self.last_strong_check = now;
            self.last_strong_cost = now.saturating_duration_since(self.pending_started);
            self.force_strong_check = false;
        }
        if self.watching && action == Some(ProjectAction::Status) {
            let dirty = details
                .and_then(|value| value.get("dirty"))
                .and_then(serde_json::Value::as_bool);
            let fingerprint = details
                .and_then(|value| value.get("source_fingerprint"))
                .and_then(serde_json::Value::as_str);
            if dirty == Some(true)
                && let Some(fingerprint) = fingerprint
            {
                match &self.candidate {
                    Some((previous, since)) if previous == fingerprint => {
                        self.sync_due = now.saturating_duration_since(*since)
                            >= Duration::from_millis(self.config.debounce_ms);
                    }
                    _ => self.candidate = Some((fingerprint.into(), now)),
                }
                self.confirming_strong_change = true;
            } else {
                self.candidate = None;
                self.sync_due = false;
                self.confirming_strong_change = false;
            }
        }
        self.next_poll = if self.sync_due {
            now
        } else {
            now + self.probe_interval()
        };
    }

    fn probe_interval(&self) -> Duration {
        Duration::from_millis(self.config.poll_interval_ms.max(200))
            .max(self.last_probe_cost.saturating_mul(2))
    }

    pub fn watch_job(&mut self, context: &egui::Context, idle: bool) -> Option<JobKind> {
        self.watch_job_at(Instant::now(), idle, context)
    }

    fn watch_job_at(
        &mut self,
        now: Instant,
        idle: bool,
        context: &egui::Context,
    ) -> Option<JobKind> {
        if !self.watching {
            return None;
        }
        context.request_repaint_after(
            self.next_poll
                .saturating_duration_since(now)
                .max(Duration::from_millis(100)),
        );
        if !idle || self.awaiting_action.is_some() || now < self.next_poll {
            return None;
        }
        let strong_interval = Duration::from_millis(self.config.full_rescan_interval_ms)
            .max(self.last_strong_cost.saturating_mul(2));
        let action = if self.sync_due {
            ProjectAction::Sync
        } else if self.last_probe.is_some()
            && (self.force_strong_check
                || self.confirming_strong_change
                || now.saturating_duration_since(self.last_strong_check) >= strong_interval)
        {
            ProjectAction::Status
        } else {
            ProjectAction::WatchProbe
        };
        match self.request(action, true) {
            Ok(job) => {
                self.pending_started = now;
                Some(job)
            }
            Err(message) => {
                self.notice = Some(message.into());
                self.stop_watching();
                None
            }
        }
    }

    fn configured_value(&self) -> Result<ProjectConfig, &'static str> {
        let mut config = self.config.clone();
        config.include = patterns(&self.include);
        config.exclude = patterns(&self.exclude);
        config.build_argv = if self.build_command.trim().is_empty() {
            Vec::new()
        } else {
            parse_build_command(&self.build_command)?
        };
        Ok(config)
    }

    fn has_unsaved_changes(&self) -> bool {
        self.loaded_config
            .as_ref()
            .is_some_and(|loaded| self.configured_value().as_ref() != Ok(loaded))
    }

    fn request(&mut self, action: ProjectAction, automatic: bool) -> Result<JobKind, &'static str> {
        let config_path = self
            .config_path
            .clone()
            .ok_or("Open or create a project first")?;
        let init = if matches!(action, ProjectAction::Init | ProjectAction::UpdateConfig) {
            Some(self.configured_value()?)
        } else {
            None
        };
        let trusted_keys = if matches!(action, ProjectAction::Sync | ProjectAction::Verify) {
            serde_json::from_str(&self.trust_keys)
                .map_err(|_| "Trusted keys must be a JSON array of public keys")?
        } else {
            Vec::new()
        };
        let rotate_to = if action == ProjectAction::Sync {
            self.rotation.selected()
        } else {
            None
        };
        let options = SyncOptions {
            automatic,
            force_full_scan: automatic
                && (action == ProjectAction::Status
                    || (action == ProjectAction::Sync && self.confirming_strong_change)),
            version: if automatic {
                String::new()
            } else {
                self.version.trim().into()
            },
            created_at: self.created_at.trim().into(),
            trigger: automatic.then_some(ProjectTrigger::Watch),
            git_ref: (!self.git_ref.trim().is_empty()).then(|| self.git_ref.trim().into()),
            rotate_to,
            allow_work_migration: self.allow_work_migration,
            trusted_keys,
            ..Default::default()
        };
        self.pending_rotation = options.rotate_to.is_some();
        self.awaiting_action = Some(action);
        self.pending_started = Instant::now();
        self.load_config |= matches!(action, ProjectAction::Init | ProjectAction::UpdateConfig);
        self.load_config |=
            !automatic && action == ProjectAction::Sync && !self.has_unsaved_changes();
        let key = if matches!(
            action,
            ProjectAction::Init | ProjectAction::UpdateConfig | ProjectAction::Sync
        ) {
            self.key.selected()
        } else {
            None
        };
        self.notice = None;
        Ok(JobKind::Project {
            request: Box::new(ProjectRequest {
                action,
                config_path,
                state_directory: self.state_directory.clone(),
                init,
                key,
                options,
                ..Default::default()
            }),
            after: None,
        })
    }

    fn run_action(&mut self, action: ProjectAction) -> Option<JobKind> {
        match self.request(action, false) {
            Ok(job) => Some(job),
            Err(message) => {
                self.notice = Some(message.into());
                None
            }
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, language: Language, idle: bool) -> Option<JobKind> {
        let mut job = None;
        ui.label(t(
            language,
            "为整个项目维护增量清单、签名及版本关联。",
            "Maintain incremental manifests, signatures and version links for a project.",
        ));
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    idle && !self.watching,
                    egui::Button::new(t(language, "新建项目", "New project")),
                )
                .clicked()
            {
                *self = Self::default();
                self.clear_results_requested = true;
            }
            if ui
                .add_enabled(
                    idle && !self.watching,
                    egui::Button::new(t(language, "打开项目", "Open project")),
                )
                .clicked()
                && let Some(path) = rfd::FileDialog::new()
                    .add_filter(t(language, "FileVeil 项目", "FileVeil project"), &["json"])
                    .pick_file()
            {
                self.config_path = Some(path);
                self.loaded_config = None;
                self.key = KeySelection::default();
                self.rotation = KeySelection::default();
                self.state_directory = None;
                self.load_config = true;
                job = self.run_action(ProjectAction::Status);
            }
            if let Some(path) = &self.config_path {
                ui.label(path.display().to_string());
            }
        });

        ui.add_enabled_ui(idle && !self.watching, |ui| {
            egui::Grid::new("project-settings").num_columns(2).spacing([12.0, 7.0]).show(ui, |ui| {
                field(ui, language, "作品标识", "Work identifier", &mut self.config.work_id);
                field(ui, language, "作者声明", "Author claim", &mut self.config.author);
                field(ui, language, "发行副本标识", "Copy identifier", &mut self.config.copy_id);
                path_field(ui, language, "项目来源目录", "Project source folder", &mut self.config.source_root);
                path_field(ui, language, "项目发行目录", "Project release folder", &mut self.config.output_directory);
                path_field(ui, language, "构建工作目录", "Build working folder", &mut self.config.build_directory);
                ui.label(t(language, "触发方式", "Trigger"));
                egui::ComboBox::from_id_salt("project-trigger").selected_text(trigger_label(language, self.config.trigger)).show_ui(ui, |ui| {
                    for trigger in [ProjectTrigger::BuildRelease, ProjectTrigger::Git, ProjectTrigger::Watch, ProjectTrigger::Manual] {
                        ui.selectable_value(&mut self.config.trigger, trigger, trigger_label(language, trigger));
                    }
                });
                ui.end_row();
            });
            key_ui(ui, language, "项目签名密钥", "Project signing key", &mut self.key);
            ui.small(t(language, "密钥文件和私有状态须位于来源及发行目录之外。留空运行密钥可复用已保存的绑定。", "Keep key files and private state outside the source and release folders. An empty runtime key uses the saved binding."));
            egui::CollapsingHeader::new(t(language, "文件选择与处理规则", "File selection and processing rules")).show(ui, |ui| {
                ui.label(t(language, "包含规则，每行一条", "Include patterns, one per line"));
                ui.add(egui::TextEdit::multiline(&mut self.include).desired_rows(2).desired_width(f32::INFINITY));
                ui.label(t(language, "排除规则，每行一条", "Exclude patterns, one per line"));
                ui.add(egui::TextEdit::multiline(&mut self.exclude).desired_rows(3).desired_width(f32::INFINITY));
                embedding_rules_ui(ui, language, &mut self.config.rules);
                ui.checkbox(&mut self.config.copy_external_files, t(language, "同时复制外部清单覆盖的原始文件", "Also copy files covered by external manifests"));
                ui.small(t(language, "源码、可执行文件和安装包默认由外部签名清单绑定。嵌入规则会在发行目录生成标记副本。", "Source code, executables and installers use external signed manifests by default. Embedding rules create marked copies in the release folder."));
                ui.horizontal(|ui| {
                    ui.label(t(language, "防抖时长（毫秒）", "Debounce (milliseconds)"));
                    ui.add(egui::DragValue::new(&mut self.config.debounce_ms).range(0..=300_000));
                    ui.label(t(language, "检查间隔（毫秒）", "Polling interval (milliseconds)"));
                    ui.add(egui::DragValue::new(&mut self.config.poll_interval_ms).range(100..=3_600_000));
                });
            });
            egui::CollapsingHeader::new(t(language, "续签与信任设置", "Renewal and trust settings")).show(ui, |ui| {
                field_row(ui, language, "版本标识，留空自动生成", "Version, empty for automatic", &mut self.version);
                field_row(ui, language, "时间声明，留空使用系统时间", "Time claim, empty for system time", &mut self.created_at);
                field_row(ui, language, "Git 提交或标签", "Git commit or tag", &mut self.git_ref);
                ui.small(t(language, "离线时间属于用户声明。完整性、签名、信任和历史连续性分别验证。", "Offline time is a user assertion. Integrity, signatures, trust and history continuity are verified separately."));
                key_ui(ui, language, "轮换后的签名密钥", "New signing key for rotation", &mut self.rotation);
                ui.checkbox(&mut self.allow_work_migration, t(language, "允许显式作品迁移", "Allow explicit work migration"));
                ui.label(t(language, "外部信任公钥 JSON", "External trusted public keys JSON"));
                ui.add(egui::TextEdit::multiline(&mut self.trust_keys).code_editor().desired_rows(2).desired_width(f32::INFINITY));
                ui.small("[{\"key_id\":\"…\",\"ed25519_hex\":\"…\"}]");
                ui.horizontal_wrapped(|ui| {
                    ui.label(t(language, "私有状态目录", "Private state folder"));
                    ui.label(self.state_directory.as_ref().map(|path| path.display().to_string()).unwrap_or_else(|| t(language, "系统管理", "System managed").into()));
                    if ui.button(t(language, "选择目录", "Choose folder")).clicked()
                        && let Some(path) = rfd::FileDialog::new().pick_folder()
                    {
                        self.state_directory = Some(path);
                    }
                    if ui.small_button(t(language, "使用默认值", "Use default")).clicked() { self.state_directory = None; }
                });
            });
            egui::CollapsingHeader::new(t(language, "项目资源预算", "Project resource budgets")).show(ui, |ui| {
                ui.small(t(language, "外部清单按流式预算处理。图像和文档嵌入另受全局解析预算限制。", "External manifests use streaming budgets. Image and document embedding also obey the global parser budgets."));
                let mut file_mib = self.config.max_file_bytes / (1024 * 1024);
                let mut total_mib = self.config.max_total_bytes / (1024 * 1024);
                ui.horizontal_wrapped(|ui| {
                    ui.label(t(language, "项目单文件上限（MiB）", "Project file limit (MiB)"));
                    if ui.add(egui::DragValue::new(&mut file_mib).range(1..=1_048_576)).changed() { self.config.max_file_bytes = file_mib * 1024 * 1024; }
                    ui.label(t(language, "项目总量上限（MiB）", "Project total limit (MiB)"));
                    if ui.add(egui::DragValue::new(&mut total_mib).range(1..=1_048_576)).changed() { self.config.max_total_bytes = total_mib * 1024 * 1024; }
                });
                ui.horizontal_wrapped(|ui| {
                    ui.label(t(language, "项目文件数上限", "Project file-count limit"));
                    ui.add(egui::DragValue::new(&mut self.config.max_files).range(1..=100_000));
                    ui.label(t(language, "完整哈希复查间隔（分钟）", "Full hash recheck interval (minutes)"));
                    let mut minutes = self.config.full_rescan_interval_ms / 60_000;
                    if ui.add(egui::DragValue::new(&mut minutes).range(1..=1440)).changed() { self.config.full_rescan_interval_ms = minutes * 60_000; }
                });
            });
            if self.config.trigger == ProjectTrigger::BuildRelease {
                ui.label(t(language, "构建命令 JSON 参数数组", "Build command JSON argument array"));
                ui.add(egui::TextEdit::singleline(&mut self.build_command).hint_text("[\"cargo\",\"build\",\"--release\",\"--offline\"]").desired_width(f32::INFINITY));
                ui.small(t(language, "点击后执行该命令，退出码为零才同步发行文件。", "Clicking runs this command. Release files are synced only after exit code zero."));
            }
            ui.horizontal_wrapped(|ui| {
                let can_create = !self.config.source_root.as_os_str().is_empty() && !self.config.work_id.trim().is_empty() && !self.config.copy_id.trim().is_empty();
                if ui.add_enabled(can_create && self.loaded_config.is_none(), egui::Button::new(t(language, "创建项目配置", "Create project configuration"))).clicked() {
                    let mut dialog = rfd::FileDialog::new().add_filter(t(language, "FileVeil 项目", "FileVeil project"), &["json"]).set_file_name("fileveil.project.json");
                    if self.config.source_root.is_absolute() { dialog = dialog.set_directory(&self.config.source_root); }
                    if let Some(path) = dialog.save_file() {
                        if path.parent() == Some(self.config.source_root.as_path()) { self.config.source_root = ".".into(); }
                        self.config_path = Some(path);
                        job = self.run_action(ProjectAction::Init);
                    }
                }
                if ui.add_enabled(self.loaded_config.is_some() && self.has_unsaved_changes(), egui::Button::new(t(language, "保存项目设置", "Save project settings"))).clicked() {
                    job = self.run_action(ProjectAction::UpdateConfig);
                }
            });
        });

        let unsaved = self.has_unsaved_changes();
        if unsaved {
            ui.small(t(
                language,
                "先保存项目设置，再同步或启动自动执行。",
                "Save project settings before syncing or starting automation.",
            ));
        }
        let ready = idle && self.loaded_config.is_some() && !unsaved && !self.watching;
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    ready,
                    egui::Button::new(t(language, "同步项目并复验", "Sync project and verify")),
                )
                .clicked()
            {
                job = self.run_action(ProjectAction::Sync);
            }
            if ui
                .add_enabled(
                    idle && self.loaded_config.is_some() && !self.watching,
                    egui::Button::new(t(language, "验证项目", "Verify project")),
                )
                .clicked()
            {
                job = self.run_action(ProjectAction::Verify);
            }
            if ui
                .add_enabled(
                    idle && self.config_path.is_some() && !self.watching,
                    egui::Button::new(t(language, "刷新项目状态", "Refresh project status")),
                )
                .clicked()
            {
                self.load_config = !self.has_unsaved_changes();
                job = self.run_action(ProjectAction::Status);
            }
            if self.watching {
                if ui
                    .button(t(language, "停止监视", "Stop watching"))
                    .clicked()
                {
                    self.stop_watching();
                    self.cancel_requested = true;
                }
            } else if self.config.trigger == ProjectTrigger::Watch
                && ui
                    .add_enabled(
                        ready,
                        egui::Button::new(t(language, "开始监视", "Start watching")),
                    )
                    .clicked()
            {
                self.watching = true;
                self.candidate = None;
                self.last_probe = None;
                self.force_strong_check = true;
                self.confirming_strong_change = false;
                self.sync_due = false;
                self.next_poll = Instant::now();
                ui.ctx().request_repaint();
            }
        });
        if self.watching {
            ui.label(t(language, "正在监视项目。文件稳定后自动续签，每轮执行独立复验。", "Watching the project. Stable changes renew signatures and run verification for each generation."));
        }
        if self.config.trigger == ProjectTrigger::BuildRelease {
            ui.add_space(8.0);
            if ui
                .add_enabled(
                    ready && executable_build_command(&self.build_command).is_ok(),
                    egui::Button::new(t(language, "构建成功后同步", "Build then sync")),
                )
                .clicked()
            {
                job = self.build_then_sync();
            }
        }
        if let Some(notice) = &self.notice {
            ui.label(crate::i18n::tr(language, notice));
        }
        job
    }

    fn build_then_sync(&mut self) -> Option<JobKind> {
        let command = match executable_build_command(&self.build_command) {
            Ok(command) => command,
            Err(message) => {
                self.notice = Some(message.into());
                return None;
            }
        };
        let JobKind::Project { request, .. } = self.run_action(ProjectAction::Sync)? else {
            return None;
        };
        Some(JobKind::Project {
            request,
            after: Some(command),
        })
    }
}

pub fn report_ui(ui: &mut egui::Ui, language: Language, details: &serde_json::Value) {
    for (key, chinese, english) in [
        ("integrity", "项目完整性", "Project integrity"),
        ("signature", "项目签名", "Project signature"),
        ("trust", "发行者信任", "Publisher trust"),
        ("history", "历史连续性", "History continuity"),
    ] {
        if let Some(state) = details.get(key).and_then(serde_json::Value::as_str) {
            ui.label(format!(
                "{} · {}",
                t(language, chinese, english),
                verification_label(language, state)
            ));
        }
    }
    ui.horizontal_wrapped(|ui| {
        for (key, chinese, english) in [
            ("added", "新增", "Added"),
            ("modified", "修改", "Modified"),
            ("deleted", "删除", "Deleted"),
            ("renamed", "重命名", "Renamed"),
            ("unchanged", "跳过未修改文件", "Unchanged files skipped"),
        ] {
            if let Some(count) = details.get(key).and_then(serde_json::Value::as_u64) {
                ui.label(format!("{} {count}", t(language, chinese, english)));
            }
        }
    });
    ui.horizontal_wrapped(|ui| {
        for (key, chinese, english) in [
            (
                "fresh_hash_count",
                "本轮新读取的 SHA-256",
                "Fresh SHA-256 reads",
            ),
            (
                "cached_hash_count",
                "复用的 SHA-256 缓存",
                "Reused SHA-256 cache",
            ),
        ] {
            if let Some(count) = details.get(key).and_then(serde_json::Value::as_u64) {
                ui.label(format!("{} {count}", t(language, chinese, english)));
            }
        }
    });
    if let Some(generation) = details
        .get("generation")
        .and_then(serde_json::Value::as_str)
    {
        ui.label(format!(
            "{} · {generation}",
            t(language, "发行版本", "Release generation")
        ));
    }
    if let Some(published) = details
        .get("published")
        .and_then(serde_json::Value::as_bool)
    {
        ui.label(if published {
            t(
                language,
                "本轮发行副本已提交",
                "This generation was published",
            )
        } else {
            t(
                language,
                "本轮未生成新发行副本",
                "This run did not publish a new generation",
            )
        });
    }
    if let Some(hash) = details
        .get("manifest_sha256")
        .and_then(serde_json::Value::as_str)
    {
        ui.label(format!(
            "{} · {hash}",
            t(language, "签名清单摘要", "Signed manifest digest")
        ));
    }
    if let Some(scope) = details
        .get("trust_scope")
        .and_then(serde_json::Value::as_str)
    {
        ui.small(scope);
    }
    if let Some(files) = details.get("files").and_then(serde_json::Value::as_array) {
        let total = details
            .get("file_results_total")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(files.len() as u64);
        egui::CollapsingHeader::new(format!(
            "{} · {} / {total}",
            t(language, "最近发行版本中的文件", "Latest generation files"),
            files.len()
        ))
        .show(ui, |ui| {
            for file in files.iter().take(100) {
                let mode = serde_json::from_value::<ProjectFileMode>(file["mode"].clone())
                    .unwrap_or_default();
                ui.label(format!(
                    "{} · {}",
                    file["path"].as_str().unwrap_or(""),
                    rule_mode_label(language, mode)
                ))
                .on_hover_text(format!(
                    "{} · {}\n{} · {}",
                    t(language, "原件 SHA-256", "Original SHA-256"),
                    file["source_sha256"].as_str().unwrap_or(""),
                    t(language, "输出 SHA-256", "Output SHA-256"),
                    file["output_sha256"].as_str().unwrap_or("—")
                ));
            }
        });
    }
}

fn patterns(value: &str) -> Vec<String> {
    value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

fn embedding_rules_ui(ui: &mut egui::Ui, language: Language, rules: &mut Vec<ProjectRule>) {
    let mut remove = None;
    let mut move_up = None;
    for (index, rule) in rules.iter_mut().enumerate() {
        ui.push_id(index, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut rule.pattern)
                        .hint_text(t(language, "文件匹配规则", "File pattern"))
                        .desired_width(160.0),
                );
                egui::ComboBox::from_id_salt("project-rule-mode")
                    .selected_text(rule_mode_label(language, rule.mode))
                    .show_ui(ui, |ui| {
                        for mode in [
                            ProjectFileMode::External,
                            ProjectFileMode::Structure,
                            ProjectFileMode::Invisible,
                        ] {
                            ui.selectable_value(
                                &mut rule.mode,
                                mode,
                                rule_mode_label(language, mode),
                            );
                        }
                    });
                if rule.mode == ProjectFileMode::Invisible {
                    ui.label(t(language, "水印强度", "Watermark strength"));
                    ui.add(egui::DragValue::new(&mut rule.strength).range(12..=64));
                }
                if ui
                    .add_enabled(index > 0, egui::Button::new("↑"))
                    .on_hover_text(t(language, "上移规则", "Move rule up"))
                    .clicked()
                {
                    move_up = Some(index);
                }
                if ui
                    .small_button(t(language, "移除规则", "Remove rule"))
                    .clicked()
                {
                    remove = Some(index);
                }
            });
        });
    }
    if let Some(index) = remove {
        rules.remove(index);
    } else if let Some(index) = move_up {
        rules.swap(index, index - 1);
    }
    if ui
        .button(t(language, "添加文件规则", "Add file rule"))
        .clicked()
    {
        rules.push(ProjectRule {
            pattern: "**/*.png".into(),
            ..Default::default()
        });
    }
    ui.small(t(
        language,
        "后面的匹配规则优先。",
        "Later matching rules take precedence.",
    ));
}

fn rule_mode_label(language: Language, mode: ProjectFileMode) -> &'static str {
    match mode {
        ProjectFileMode::External => t(language, "外部签名清单", "External signed manifest"),
        ProjectFileMode::Structure => t(language, "结构标记", "Structural mark"),
        ProjectFileMode::Invisible => t(language, "隐形水印", "Invisible watermark"),
    }
}

fn parse_build_command(value: &str) -> Result<Vec<String>, &'static str> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    let arguments: Vec<String> = serde_json::from_str(value)
        .map_err(|_| "Build command must be a JSON array of arguments")?;
    if arguments
        .first()
        .is_some_and(|program| program.trim().is_empty())
        || arguments.iter().any(|value| value.contains('\0'))
    {
        return Err("Build command must be a JSON array of arguments");
    }
    Ok(arguments)
}

fn executable_build_command(value: &str) -> Result<Vec<String>, &'static str> {
    let arguments = parse_build_command(value)?;
    if arguments.is_empty() {
        return Err("Build command must be a JSON array of arguments");
    }
    Ok(arguments)
}

fn field(ui: &mut egui::Ui, language: Language, chinese: &str, english: &str, value: &mut String) {
    ui.label(t(language, chinese, english));
    ui.add(egui::TextEdit::singleline(value).desired_width(330.0));
    ui.end_row();
}
fn field_row(
    ui: &mut egui::Ui,
    language: Language,
    chinese: &str,
    english: &str,
    value: &mut String,
) {
    ui.horizontal_wrapped(|ui| {
        ui.label(t(language, chinese, english));
        ui.add(egui::TextEdit::singleline(value).desired_width(300.0));
    });
}
fn path_field(
    ui: &mut egui::Ui,
    language: Language,
    chinese: &str,
    english: &str,
    value: &mut PathBuf,
) {
    ui.label(t(language, chinese, english));
    ui.push_id(english, |ui| {
        ui.horizontal_wrapped(|ui| {
            let mut display = value.to_string_lossy().into_owned();
            if ui
                .add(egui::TextEdit::singleline(&mut display).desired_width(260.0))
                .changed()
            {
                *value = PathBuf::from(display);
            }
            if ui
                .button(t(language, "选择目录", "Choose folder"))
                .clicked()
                && let Some(path) = rfd::FileDialog::new().pick_folder()
            {
                *value = path;
            }
        });
    });
    ui.end_row();
}
fn key_ui(
    ui: &mut egui::Ui,
    language: Language,
    chinese: &str,
    english: &str,
    selection: &mut KeySelection,
) {
    ui.push_id(english, |ui| {
        ui.label(t(language, chinese, english));
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(
                &mut selection.system,
                false,
                t(language, "密钥文件", "Key file"),
            );
            ui.selectable_value(
                &mut selection.system,
                true,
                t(language, "系统密钥", "System key"),
            );
            if selection.system {
                ui.add(
                    egui::TextEdit::singleline(&mut selection.reference)
                        .hint_text(t(
                            language,
                            "公钥 SHA-256 标识",
                            "Public-key SHA-256 identifier",
                        ))
                        .desired_width(280.0),
                );
            } else {
                if ui
                    .button(t(language, "选择签名密钥", "Choose signing key"))
                    .clicked()
                    && let Some(path) = rfd::FileDialog::new()
                        .add_filter("Ed25519", &["key"])
                        .pick_file()
                {
                    selection.file = Some(path);
                }
                if let Some(path) = &selection.file {
                    ui.label(
                        path.file_name()
                            .unwrap_or(path.as_os_str())
                            .to_string_lossy(),
                    );
                }
            }
            if ui.small_button(t(language, "清空", "Clear")).clicked() {
                *selection = KeySelection::default();
            }
        });
    });
}

fn trigger_label(language: Language, trigger: ProjectTrigger) -> &'static str {
    match trigger {
        ProjectTrigger::BuildRelease => t(language, "构建 / 发行", "Build / Release"),
        ProjectTrigger::Git => "Git",
        ProjectTrigger::Watch => t(language, "文件监视", "Watch files"),
        ProjectTrigger::Manual => t(language, "手动同步", "Manual sync"),
    }
}
fn verification_label(language: Language, state: &str) -> &str {
    match state {
        "valid" => t(language, "有效", "Valid"),
        "invalid" => t(language, "无效", "Invalid"),
        "untrusted" => t(language, "不受信任", "Untrusted"),
        "not_assessed" => t(language, "未评估", "Not assessed"),
        _ => state,
    }
}
fn t<'a>(language: Language, chinese: &'a str, english: &'a str) -> &'a str {
    text(language, chinese, english)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn panel() -> ProjectPanel {
        let config = ProjectConfig {
            source_root: ".".into(),
            ..Default::default()
        };
        ProjectPanel {
            config_path: Some(Path::new("/project/fileveil.project.json").into()),
            loaded_config: Some(config.clone()),
            config,
            ..Default::default()
        }
    }

    #[test]
    fn project_requests_keep_private_bindings_out_of_public_configuration() {
        let mut panel = panel();
        panel.key.file = Some("/private/owner.key".into());
        panel.state_directory = Some("/private/state".into());
        let JobKind::Project { request, after } =
            panel.request(ProjectAction::Init, false).unwrap()
        else {
            panic!("project job");
        };
        assert!(after.is_none());
        assert!(request.key.is_some());
        let config = serde_json::to_string(request.init.as_ref().unwrap()).unwrap();
        assert!(!config.contains("/private"));
        assert!(!request.init.unwrap().copy_external_files);
    }

    #[test]
    fn build_arguments_are_structured_and_preserve_literals() {
        assert_eq!(
            parse_build_command(r#"["tool","a b","$(literal)"]"#).unwrap(),
            ["tool", "a b", "$(literal)"]
        );
        for invalid in ["tool --flag", r#"[""]"#, r#"["tool", "\u0000"]"#] {
            assert!(parse_build_command(invalid).is_err());
        }
        for empty in ["", "  ", "[]", " [] "] {
            assert!(parse_build_command(empty).unwrap().is_empty());
            assert!(executable_build_command(empty).is_err());
        }
    }

    #[test]
    fn empty_core_build_arguments_allow_init_save_and_plain_sync() {
        let mut panel = panel();
        let config = panel.config.clone();
        panel.awaiting_action = Some(ProjectAction::Status);
        panel.load_config = true;
        let mut report = Report::new("project", fileveil_core::Format::Unknown);
        report.result = Outcome::PartiallyVerified;
        report.advanced = Some(serde_json::json!({"project":{"config":config}}));
        panel.record_result(&report);
        assert!(panel.config.build_argv.is_empty());
        for text in ["", "[]"] {
            panel.build_command = text.into();
            assert!(!panel.has_unsaved_changes());
            for action in [
                ProjectAction::Init,
                ProjectAction::UpdateConfig,
                ProjectAction::Sync,
            ] {
                let JobKind::Project { request, after } = panel.request(action, false).unwrap()
                else {
                    panic!("project job");
                };
                assert!(after.is_none());
                if let Some(config) = request.init {
                    assert!(config.build_argv.is_empty());
                }
            }
            panel.awaiting_action = None;
            assert!(panel.build_then_sync().is_none());
            assert!(panel.awaiting_action.is_none());
        }
    }

    #[test]
    fn watch_waits_for_a_stable_fingerprint_and_stop_prevents_rescheduling() {
        let mut panel = panel();
        panel.config.debounce_ms = 750;
        panel.config.poll_interval_ms = 200;
        let context = egui::Context::default();
        let start = Instant::now();
        panel.watching = true;
        panel.next_poll = start;
        let mut probe = Report::new("project", fileveil_core::Format::Unknown);
        probe.result = Outcome::NotAssessed;
        probe.advanced = Some(
            serde_json::json!({"project":{"source_fingerprint":"a","source_sha256_assessed":false}}),
        );
        let mut report = Report::new("project", fileveil_core::Format::Unknown);
        report.result = Outcome::VerifiedWithinScope;
        report.advanced =
            Some(serde_json::json!({"project":{"dirty":false,"source_fingerprint":"sha"}}));
        assert!(
            matches!(panel.watch_job_at(start, true, &context), Some(JobKind::Project { request, .. }) if request.action == ProjectAction::WatchProbe && request.options.automatic)
        );
        panel.record_result_at(&probe, start);
        assert!(
            matches!(panel.watch_job_at(start + Duration::from_millis(1), true, &context), Some(JobKind::Project { request, .. }) if request.action == ProjectAction::Status)
        );
        panel.record_result_at(&report, start + Duration::from_millis(2));
        probe.advanced = Some(
            serde_json::json!({"project":{"source_fingerprint":"b","source_sha256_assessed":false}}),
        );
        assert!(
            matches!(panel.watch_job_at(start + Duration::from_millis(250), true, &context), Some(JobKind::Project { request, .. }) if request.action == ProjectAction::WatchProbe)
        );
        panel.record_result_at(&probe, start + Duration::from_millis(250));
        assert!(!panel.sync_due);
        assert!(
            matches!(panel.watch_job_at(start + Duration::from_millis(500), true, &context), Some(JobKind::Project { request, .. }) if request.action == ProjectAction::WatchProbe)
        );
        panel.record_result_at(&probe, start + Duration::from_millis(500));
        assert!(!panel.sync_due);
        assert!(
            matches!(panel.watch_job_at(start + Duration::from_millis(1100), true, &context), Some(JobKind::Project { request, .. }) if request.action == ProjectAction::WatchProbe)
        );
        panel.record_result_at(&probe, start + Duration::from_millis(1100));
        assert!(
            matches!(panel.watch_job_at(start + Duration::from_millis(1101), true, &context), Some(JobKind::Project { request, .. }) if request.action == ProjectAction::Sync && request.options.automatic && request.options.version.is_empty())
        );
        panel.stop_watching();
        panel.awaiting_action = None;
        assert!(
            panel
                .watch_job_at(start + Duration::from_secs(5), true, &context)
                .is_none()
        );
    }

    #[test]
    fn project_configuration_retains_explicit_build_arguments() {
        let mut panel = panel();
        panel.build_command = r#"["cargo","build","--offline"]"#.into();
        assert!(panel.has_unsaved_changes());
        assert_eq!(
            panel.configured_value().unwrap().build_argv,
            ["cargo", "build", "--offline"]
        );
    }

    #[test]
    fn manifest_links_stay_inside_the_selected_release_folder() {
        let panel = panel();
        let mut details = serde_json::json!({"config":panel.config,"manifest_relative_path":"project/generation/manifest.json"});
        assert!(
            panel
                .manifest_path(&details)
                .unwrap()
                .ends_with("project/generation/manifest.json")
        );
        for path in [
            "../outside.json",
            "/outside.json",
            "project/../outside.json",
            "project\\outside.json",
            "",
        ] {
            details["manifest_relative_path"] = path.into();
            assert!(panel.manifest_path(&details).is_none(), "{path}");
        }
    }

    #[test]
    fn project_panel_renders_action_states_in_all_languages() {
        for language in Language::ALL {
            let context = egui::Context::default();
            context.enable_accesskit();
            let mut panel = ProjectPanel::default();
            let output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1060.0, 700.0),
                    )),
                    ..Default::default()
                },
                |ui| {
                    assert!(panel.ui(ui, language, true).is_none());
                },
            );
            let nodes = &output
                .platform_output
                .accesskit_update
                .as_ref()
                .unwrap()
                .nodes;
            let sync = nodes
                .iter()
                .find(|(_, node)| {
                    node.label() == Some(t(language, "同步项目并复验", "Sync project and verify"))
                })
                .expect("sync button");
            assert!(sync.1.is_disabled());
            assert!(
                nodes
                    .iter()
                    .any(|(_, node)| node.label() == Some(t(language, "打开项目", "Open project")))
            );
            assert!(!panel.pending());
            output.drop_without_applying_deltas();
        }
    }
}

// FVPROV1 49896 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJjNWNiZjc5NDg1ZjQ5ZWY3MTRlMTQwMDQ1NjI1YzZmNDY2MDEwNGE5ZWYyZTdlMjJlYzk5M2IyMzc3NjY3Mzk3IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvc3JjL3Byb2plY3RfdWkucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiIzNDE2MzhmYWJiNjM2MTAwMjdhYjc2NWFhYmQ1NjcyOTY2YzJiYTRlNTVlM2JhNDUzMmRkZGMwMTk1NjAwNjIyNTRhMWI1NTMwYTNmNzdjMmUxNzg1NWNkNzQ3ZjBmYzA3ODdjYTQ2ZDE4NzkwOGM2ZjVlMTE4OTUwNTIwM2QwZCJ9XX1d FVPROV1-END
