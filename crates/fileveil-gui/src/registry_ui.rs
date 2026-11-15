// SPDX-License-Identifier: MPL-2.0
//! Private project references, inherited defaults and actual registry jobs.
use crate::{
    i18n::{Language, text},
    jobs::JobKind,
    software_ui::{IdentityPicker, optional_path},
};
use eframe::egui;
use fileveil_core::Report;
use fileveil_engine::project::{
    ProjectRule, SyncOptions,
    registry::{
        CompilerBackend, ProjectOverrides, RegistryAction, RegistryCompilerConfig,
        RegistryCompilerTarget, RegistryDefaults, RegistryPolicy, RegistryRequest,
    },
};
use std::path::PathBuf;

#[derive(Default, Clone, serde::Deserialize)]
#[serde(default)]
struct ProjectRow {
    project_id: String,
    name: String,
    source_root: PathBuf,
    project_root: PathBuf,
    config_path: PathBuf,
    overrides: ProjectOverrides,
    compiler: Option<RegistryCompilerConfig>,
    work_id: Option<String>,
    legacy_config_path: Option<PathBuf>,
}

pub struct RegistryPanel {
    registry_path: Option<PathBuf>,
    defaults: RegistryDefaults,
    identity: IdentityPicker,
    build_argv: String,
    projects: Vec<ProjectRow>,
    selected: Option<String>,
    project_path: Option<PathBuf>,
    legacy_config: Option<PathBuf>,
    legacy_state: Option<PathBuf>,
    name: String,
    overrides: ProjectOverrides,
    override_policy: bool,
    policy: RegistryPolicy,
    compiler: RegistryCompilerConfig,
    compiler_args: String,
    compiler_tests: String,
    all: bool,
    version: String,
    notice: Option<String>,
    ci: fileveil_engine::project::ci::CiConfig,
    ci_build: String,
    ci_test: String,
    ci_yaml: String,
    ci_command: String,
    ci_json: String,
}
impl Default for RegistryPanel {
    fn default() -> Self {
        Self {
            registry_path: None,
            defaults: Default::default(),
            identity: Default::default(),
            build_argv: "[]".into(),
            projects: Vec::new(),
            selected: None,
            project_path: None,
            legacy_config: None,
            legacy_state: None,
            name: String::new(),
            overrides: Default::default(),
            override_policy: false,
            policy: RegistryPolicy::ManifestOnly,
            compiler: RegistryCompilerConfig {
                optimization: "O2".into(),
                ..Default::default()
            },
            compiler_args: "[]".into(),
            compiler_tests: "[[]]".into(),
            all: false,
            version: String::new(),
            notice: None,
            ci: Default::default(),
            ci_build: "[]".into(),
            ci_test: "[]".into(),
            ci_yaml: String::new(),
            ci_command: String::new(),
            ci_json: String::new(),
        }
    }
}
impl RegistryPanel {
    pub fn selection_id(&self) -> Option<&str> {
        self.selected.as_deref()
    }
    pub fn record_result(&mut self, report: &Report) {
        let Some(registry) = report
            .advanced
            .as_ref()
            .and_then(|value| value.get("registry"))
        else {
            return;
        };
        if let Ok(defaults) = serde_json::from_value(registry["defaults"].clone()) {
            self.defaults = defaults;
            self.build_argv =
                serde_json::to_string(&self.defaults.build_argv).unwrap_or_else(|_| "[]".into());
        }
        let action = registry["action"].as_str().unwrap_or_default();
        if action == "list" {
            self.projects.clear();
        }
        if action == "remove" {
            self.projects
                .retain(|row| Some(&row.project_id) != self.selected.as_ref());
            self.selected = None;
        } else if let Some(rows) = registry["projects"].as_array() {
            for value in rows {
                let work_id = value["report"]["advanced"]["project"]["config"]["work_id"]
                    .as_str()
                    .map(str::to_owned);
                if value.get("source_root").is_none() {
                    if let Some(id) = value["project_id"].as_str()
                        && let Some(row) = self.projects.iter_mut().find(|row| row.project_id == id)
                        && work_id.is_some()
                    {
                        row.work_id = work_id;
                    }
                    continue;
                }
                if let Ok(row) = serde_json::from_value::<ProjectRow>(value.clone()) {
                    if row.project_id.is_empty() {
                        continue;
                    }
                    self.projects
                        .retain(|previous| previous.project_id != row.project_id);
                    self.projects.push(row);
                }
            }
            self.projects.sort_by(|a, b| a.name.cmp(&b.name));
        }
    }
    fn select(&mut self, id: String) {
        let Some(row) = self
            .projects
            .iter()
            .find(|row| row.project_id == id)
            .cloned()
        else {
            return;
        };
        self.ci.name = row.name.clone();
        self.ci.work_id = row
            .work_id
            .clone()
            .or_else(|| row.overrides.work_id.clone())
            .unwrap_or_else(|| {
                if row.legacy_config_path.is_none() {
                    format!("project-{id}")
                } else {
                    String::new()
                }
            });
        self.ci.author = row
            .overrides
            .author
            .clone()
            .unwrap_or_else(|| self.defaults.author.clone());
        self.ci.copy_id = row
            .overrides
            .copy_id
            .clone()
            .unwrap_or_else(|| self.defaults.copy_id.clone());
        self.ci.build_argv = row
            .overrides
            .build_argv
            .clone()
            .unwrap_or_else(|| self.defaults.build_argv.clone());
        self.ci.policy = row.overrides.policy.unwrap_or(self.defaults.policy);
        self.ci.rules = asset_rules(self.ci.policy, row.overrides.rules.as_deref());
        self.ci.compiler = row.compiler.clone();
        self.ci_build = serde_json::to_string(&self.ci.build_argv).unwrap_or_else(|_| "[]".into());
        self.ci.artifact_directory = PathBuf::from("target/release");
        self.ci.output_directory = PathBuf::from("dist/fileveil-ci");
        self.selected = Some(id);
        self.name = row.name;
        self.project_path = Some(row.project_root);
        self.override_policy = row.overrides.policy.is_some();
        self.policy = row.overrides.policy.unwrap_or(self.defaults.policy);
        self.overrides = row.overrides;
        self.compiler = row.compiler.unwrap_or_else(|| RegistryCompilerConfig {
            optimization: "O2".into(),
            ..Default::default()
        });
        self.compiler_args = serde_json::to_string(&self.compiler.compiler_arguments)
            .unwrap_or_else(|_| "[]".into());
        self.compiler_tests =
            serde_json::to_string(&self.compiler.test_arguments).unwrap_or_else(|_| "[[]]".into());
    }
    pub fn ui(&mut self, ui: &mut egui::Ui, language: Language, idle: bool) -> Option<JobKind> {
        let mut action = None;
        ui.label(t(language,"登记本地项目并继承作者、签名身份及策略。默认保留原件，只发布外部签名清单。","Register local projects with inherited author, signing identity and policy. Originals stay intact; external signed manifests are the default."));
        ui.add_enabled_ui(idle,|ui|{
            optional_path(ui,language,"选择项目注册表","Choose project registry",&mut self.registry_path,false);
            ui.small(t(language,"留空使用 FileVeil 私有注册表。私钥和项目索引保存在独立的本地状态目录。","Empty uses FileVeil's private registry. Keys and project indexes live in separate local state."));
            ui.horizontal_wrapped(|ui|{
                if ui.button(t(language,"读取项目列表","Load projects")).clicked(){action=Some(RegistryAction::List);}
                if ui.button(t(language,"初始化注册表","Initialize registry")).clicked(){action=Some(RegistryAction::Init);}
            });
            egui::CollapsingHeader::new(t(language,"共享身份与默认策略","Shared identity and defaults")).show(ui,|ui|{
                ui.label(t(language,"作者声明","Author declaration"));ui.text_edit_singleline(&mut self.defaults.author);
                ui.label(t(language,"默认发行副本 ID","Default copy ID"));ui.text_edit_singleline(&mut self.defaults.copy_id);
                policy_picker(ui,language,"registry_defaults_policy",&mut self.defaults.policy);
                self.identity.ui(ui,language,false);
                ui.label(t(language,"默认构建命令（JSON 参数数组）","Default build command (JSON argument array)"));ui.text_edit_multiline(&mut self.build_argv);
                if ui.button(t(language,"保存共享设置","Save shared settings")).clicked(){action=Some(RegistryAction::Configure);}
            });
            ui.separator();
            let previous=self.selected.clone();
            egui::ComboBox::from_id_salt("registered_projects").selected_text(self.projects.iter().find(|row|Some(&row.project_id)==self.selected.as_ref()).map(|row|row.name.as_str()).unwrap_or(t(language,"选择已登记项目","Choose registered project"))).show_ui(ui,|ui|{
                for row in &self.projects{ui.selectable_value(&mut self.selected,Some(row.project_id.clone()),&row.name);}
            });
            if self.selected!=previous && let Some(id)=self.selected.clone(){self.select(id);}
            if let Some(row)=self.projects.iter().find(|row|Some(&row.project_id)==self.selected.as_ref()){
                ui.small(row.source_root.display().to_string());
                if ui.small_button(t(language,"打开项目配置位置","Reveal project configuration")).clicked(){crate::app::reveal_output(&row.config_path);}
            }
            ui.horizontal_wrapped(|ui|{
                ui.checkbox(&mut self.all,t(language,"全部已登记项目","All registered projects"));
                for (operation,zh,en) in [(RegistryAction::Status,"状态","Status"),(RegistryAction::Sync,"同步并续签","Sync and renew signatures"),(RegistryAction::Verify,"验证项目","Verify projects")]{
                    if ui.add_enabled(self.all||self.selected.is_some(),egui::Button::new(t(language,zh,en))).clicked(){action=Some(operation);}
                }
            });
            ui.label(t(language,"版本（留空自动生成）","Version (empty for automatic)"));ui.text_edit_singleline(&mut self.version);
            egui::CollapsingHeader::new(t(language,"添加或编辑项目","Add or edit project")).show(ui,|ui|{
                optional_path(ui,language,"选择工程目录","Choose project folder",&mut self.project_path,true);
                ui.label(t(language,"项目名称","Project name"));ui.text_edit_singleline(&mut self.name);
                ui.checkbox(&mut self.override_policy,t(language,"为此项目覆盖共享策略","Override shared policy for this project"));
                if self.override_policy{policy_picker(ui,language,"registry_project_policy",&mut self.policy);}
                optional_path(ui,language,"单独选择资产根目录","Choose separate asset root",&mut self.overrides.source_root,true);
                optional_path(ui,language,"单独选择发行目录","Choose separate release folder",&mut self.overrides.output_directory,true);
                let policy=if self.override_policy{self.policy}else{self.defaults.policy};
                if matches!(policy,RegistryPolicy::CompilerWatermark|RegistryPolicy::Hybrid){self.compiler_ui(ui,language);}
                ui.horizontal_wrapped(|ui|{
                    if ui.add_enabled(self.project_path.is_some(),egui::Button::new(t(language,"登记新项目","Register new project"))).clicked(){action=Some(RegistryAction::Add);}
                    if ui.add_enabled(self.selected.is_some(),egui::Button::new(t(language,"保存项目覆盖项","Save project overrides"))).clicked(){action=Some(RegistryAction::Update);}
                    if ui.add_enabled(self.selected.is_some(),egui::Button::new(t(language,"移除登记引用","Remove registry reference"))).clicked(){action=Some(RegistryAction::Remove);}
                });
                egui::CollapsingHeader::new(t(language,"迁移现有 Project Mode","Migrate existing Project Mode")).show(ui,|ui|{
                    optional_path(ui,language,"选择已有项目配置","Choose existing project configuration",&mut self.legacy_config,false);
                    optional_path(ui,language,"选择已有私有状态","Choose existing private state",&mut self.legacy_state,true);
                    if ui.add_enabled(self.legacy_config.is_some(),egui::Button::new(t(language,"迁移登记并保留作品链","Migrate registration and preserve history"))).clicked(){action=Some(RegistryAction::Migrate);}
                });
            });
        });
        if self.selected.is_some() {
            self.ci_ui(ui, language);
        }
        if let Some(notice) = &self.notice {
            ui.label(crate::i18n::tr(language, notice));
        }
        let action = action?;
        match self.request(action) {
            Ok(request) => {
                self.notice = None;
                Some(JobKind::Registry {
                    request: Box::new(request),
                })
            }
            Err(message) => {
                self.notice = Some(message.into());
                None
            }
        }
    }
    fn compiler_ui(&mut self, ui: &mut egui::Ui, language: Language) {
        ui.strong(t(
            language,
            "编译器水印发行目标",
            "Compiler watermark release targets",
        ));
        let mut remove = None;
        for (index, target) in self.compiler.targets.iter_mut().enumerate() {
            ui.push_id(index, |ui| {
                let mut input = target.input.to_string_lossy().into_owned();
                let mut output = target.output.to_string_lossy().into_owned();
                ui.horizontal_wrapped(|ui| {
                    ui.label(t(language, "输入", "Input"));
                    if ui.text_edit_singleline(&mut input).changed() {
                        target.input = input.into();
                    }
                    ui.label(t(language, "输出", "Output"));
                    if ui.text_edit_singleline(&mut output).changed() {
                        target.output = output.into();
                    }
                    if ui.small_button(t(language, "移除", "Remove")).clicked() {
                        remove = Some(index);
                    }
                });
                ui.horizontal(|ui| {
                    ui.selectable_value(
                        &mut target.backend,
                        CompilerBackend::ClangSource,
                        "C / C++",
                    );
                    ui.selectable_value(&mut target.backend, CompilerBackend::LlvmIr, "LLVM IR");
                });
            });
        }
        if let Some(index) = remove {
            self.compiler.targets.remove(index);
        }
        if self.compiler.targets.len() < 32
            && ui
                .small_button(t(language, "添加发行目标", "Add release target"))
                .clicked()
        {
            self.compiler.targets.push(RegistryCompilerTarget {
                input: PathBuf::new(),
                output: PathBuf::new(),
                backend: CompilerBackend::ClangSource,
            });
        }
        optional_path(
            ui,
            language,
            "LLVM 工具目录",
            "LLVM tool directory",
            &mut self.compiler.llvm_directory,
            true,
        );
        optional_path(
            ui,
            language,
            "LLVM 插件",
            "LLVM pass plugin",
            &mut self.compiler.plugin_path,
            false,
        );
        ui.label(t(
            language,
            "额外编译参数（JSON 参数数组）",
            "Additional compiler arguments (JSON array)",
        ));
        ui.text_edit_multiline(&mut self.compiler_args);
        ui.checkbox(
            &mut self.compiler.allow_execution,
            t(
                language,
                "允许运行本次构建程序和探针",
                "Allow execution of this build and its probes",
            ),
        );
        ui.label(t(
            language,
            "功能测试参数（JSON 二维数组）",
            "Functional test arguments (JSON array of arrays)",
        ));
        ui.text_edit_multiline(&mut self.compiler_tests);
    }
    fn ci_ui(&mut self, ui: &mut egui::Ui, language: Language) {
        egui::CollapsingHeader::new(t(language, "持续集成与本地发布", "Continuous integration and local release")).show(ui, |ui| {
            ui.small(t(language,"生成工作流与本地配置。签名密钥由实际运行环境提供。","Generate a workflow and local configuration. The execution environment supplies signing keys."));
            let policy=self.effective_policy();
            ui.strong(format!("{} · {}",t(language,"生成策略","Generated policy"),policy_label(language,policy)));
            let rules=asset_rules(policy,self.overrides.rules.as_deref());
            let targets=if matches!(policy,RegistryPolicy::CompilerWatermark|RegistryPolicy::Hybrid){self.compiler.targets.len()}else{0};
            ui.small(format!("{} {} · {} {}",t(language,"资产规则","Asset rules"),rules.len(),t(language,"编译目标","Compiler targets"),targets));
            ui.small(t(language,"策略、规则和编译目标沿用当前项目设置。","Policy, rules and compiler targets use the current project settings."));
            ui.label(t(language,"作品 ID","Work ID"));
            ui.text_edit_singleline(&mut self.ci.work_id);
            ui.label(t(language,"作者声明","Author declaration"));
            ui.text_edit_singleline(&mut self.ci.author);
            ui.label(t(language,"发行副本 ID","Copy ID"));
            ui.text_edit_singleline(&mut self.ci.copy_id);
            ui.horizontal(|ui|{
                ui.label(t(language,"CI 平台","CI platform"));
                egui::ComboBox::from_id_salt("project_ci_runner").selected_text(&self.ci.runner).show_ui(ui,|ui|{
                    for runner in ["ubuntu-latest","macos-latest","windows-latest"]{ui.selectable_value(&mut self.ci.runner,runner.into(),runner);}
                });
            });
            ui.label(t(language,"构建产物相对目录","Relative build artifact directory"));
            let mut artifact=self.ci.artifact_directory.to_string_lossy().into_owned();
            if ui.text_edit_singleline(&mut artifact).changed(){self.ci.artifact_directory=artifact.into();}
            ui.label(t(language,"水印发行相对目录","Relative marked release directory"));
            let mut output=self.ci.output_directory.to_string_lossy().into_owned();
            if ui.text_edit_singleline(&mut output).changed(){self.ci.output_directory=output.into();}
            ui.label(t(language,"构建命令（JSON 参数数组）","Build command (JSON argument array)"));
            ui.text_edit_multiline(&mut self.ci_build);
            ui.label(t(language,"测试命令（JSON 参数数组）","Test command (JSON argument array)"));
            ui.text_edit_multiline(&mut self.ci_test);
            ui.horizontal_wrapped(|ui| {
                if ui.button(t(language,"生成 CI 配置","Generate CI configuration")).clicked(){
                    match self.generate_ci(){Ok(())=>self.notice=None,Err(message)=>self.notice=Some(message)}
                }
                if !self.ci_yaml.is_empty() && ui.button(t(language,"复制工作流 YAML","Copy workflow YAML")).clicked(){
                    match self.generate_ci() { Ok(()) => ui.ctx().copy_text(self.ci_yaml.clone()), Err(message) => self.notice=Some(message) }
                }
                if !self.ci_json.is_empty() && ui.button(t(language,"导出到新子目录","Export into a new subfolder")).clicked()
                    && let Some(parent)=rfd::FileDialog::new().pick_folder(){
                    match self.generate_ci().and_then(|_|self.save_ci(&parent)){
                        Ok(path)=>{
                            self.notice=Some(format!("{} {}",t(language,"已生成，尚未执行","Generated, execution pending"),path.display()));
                            crate::app::reveal_output(&path);
                        }
                        Err(message)=>self.notice=Some(message),
                    }
                }
            });
            if !self.ci_command.is_empty(){
                ui.label(t(language,"本地执行命令","Local execution command"));
                ui.monospace(&self.ci_command);
                if ui.small_button(t(language,"复制命令","Copy command")).clicked(){ui.ctx().copy_text(self.ci_command.clone());}
            }
        });
    }

    fn generate_ci(&mut self) -> Result<(), String> {
        self.ci.policy = self.effective_policy();
        self.ci.rules = asset_rules(self.ci.policy, self.overrides.rules.as_deref());
        self.ci.compiler = if matches!(
            self.ci.policy,
            RegistryPolicy::CompilerWatermark | RegistryPolicy::Hybrid
        ) {
            Some(self.configured_compiler().map_err(str::to_owned)?)
        } else {
            None
        };
        self.ci.build_argv = serde_json::from_str(&self.ci_build)
            .map_err(|_| "Build command must be a JSON array of arguments".to_owned())?;
        self.ci.test_argv = serde_json::from_str(&self.ci_test)
            .map_err(|_| "Test command must be a JSON array of arguments".to_owned())?;
        let bundle =
            fileveil_engine::project::ci::generate(&self.ci).map_err(|error| error.to_string())?;
        self.ci_yaml = bundle.workflow_yaml;
        self.ci_json = bundle.config_json;
        self.ci_command = bundle.local_command;
        Ok(())
    }

    fn save_ci(&self, parent: &std::path::Path) -> Result<PathBuf, String> {
        use std::{fs, io::Write};
        let directory = tempfile::Builder::new()
            .prefix("fileveil-ci-")
            .tempdir_in(parent)
            .map_err(|_| "Could not create new CI bundle folder".to_owned())?;
        let workflow = directory.path().join(".github/workflows");
        fs::create_dir_all(&workflow)
            .map_err(|_| "Could not create CI workflow folder".to_owned())?;
        for (path, bytes) in [
            (
                directory.path().join("fileveil-ci.json"),
                self.ci_json.as_bytes(),
            ),
            (
                workflow.join("fileveil-release.yml"),
                self.ci_yaml.as_bytes(),
            ),
        ] {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|_| "Could not create a new CI bundle file".to_owned())?;
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| "Could not write the CI bundle".to_owned())?;
        }
        Ok(directory.keep())
    }

    fn request(&self, action: RegistryAction) -> Result<RegistryRequest, &'static str> {
        let batch = self.all
            && matches!(
                action,
                RegistryAction::Status | RegistryAction::Sync | RegistryAction::Verify
            );
        let mut defaults = self.defaults.clone();
        defaults.build_argv = serde_json::from_str(&self.build_argv)
            .map_err(|_| "Build command must be a JSON array of arguments")?;
        let mut overrides = self.overrides.clone();
        overrides.policy = self.override_policy.then_some(self.policy);
        let effective = overrides.policy.unwrap_or(defaults.policy);
        let compiler = if matches!(
            effective,
            RegistryPolicy::CompilerWatermark | RegistryPolicy::Hybrid
        ) {
            Some(self.configured_compiler()?)
        } else {
            None
        };
        Ok(RegistryRequest {
            action,
            registry_path: self.registry_path.clone(),
            project_id: if matches!(
                action,
                RegistryAction::Add
                    | RegistryAction::Init
                    | RegistryAction::Migrate
                    | RegistryAction::Configure
                    | RegistryAction::List
            ) || batch
            {
                None
            } else {
                self.selected.clone()
            },
            project_path: self.project_path.clone(),
            config_path: self.legacy_config.clone(),
            name: (!self.name.trim().is_empty()).then(|| self.name.trim().into()),
            defaults: matches!(action, RegistryAction::Init | RegistryAction::Configure)
                .then_some(defaults),
            overrides: Some(overrides),
            key: self.identity.key(),
            options: SyncOptions {
                version: self.version.trim().into(),
                ..Default::default()
            },
            compiler,
            all: batch,
            legacy_state_directory: self.legacy_state.clone(),
            ..Default::default()
        })
    }

    fn effective_policy(&self) -> RegistryPolicy {
        if self.override_policy {
            self.policy
        } else {
            self.defaults.policy
        }
    }

    fn configured_compiler(&self) -> Result<RegistryCompilerConfig, &'static str> {
        let mut compiler = self.compiler.clone();
        compiler.compiler_arguments = serde_json::from_str(&self.compiler_args)
            .map_err(|_| "Compiler arguments must be a JSON array of strings")?;
        compiler.test_arguments = serde_json::from_str(&self.compiler_tests)
            .map_err(|_| "Test arguments must be a JSON array of arrays")?;
        Ok(compiler)
    }
}
fn asset_rules(policy: RegistryPolicy, rules: Option<&[ProjectRule]>) -> Vec<ProjectRule> {
    if matches!(
        policy,
        RegistryPolicy::AssetWatermark | RegistryPolicy::Hybrid
    ) {
        rules
            .map(<[ProjectRule]>::to_vec)
            .unwrap_or_else(fileveil_engine::project::ci::default_asset_rules)
    } else {
        Vec::new()
    }
}
fn policy_picker(ui: &mut egui::Ui, language: Language, id: &str, value: &mut RegistryPolicy) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(policy_label(language, *value))
        .show_ui(ui, |ui| {
            for policy in [
                RegistryPolicy::ManifestOnly,
                RegistryPolicy::AssetWatermark,
                RegistryPolicy::CompilerWatermark,
                RegistryPolicy::Hybrid,
            ] {
                ui.selectable_value(value, policy, policy_label(language, policy));
            }
        });
}
fn policy_label(language: Language, value: RegistryPolicy) -> &'static str {
    match value {
        RegistryPolicy::ManifestOnly => t(language, "外部签名清单", "External signed manifest"),
        RegistryPolicy::AssetWatermark => t(language, "资产水印", "Asset watermark"),
        RegistryPolicy::CompilerWatermark => t(language, "编译器水印", "Compiler watermark"),
        RegistryPolicy::Hybrid => t(
            language,
            "资产与编译器水印",
            "Asset and compiler watermarks",
        ),
    }
}
pub fn report_ui(ui: &mut egui::Ui, language: Language, value: &serde_json::Value) {
    ui.strong(t(language, "注册表执行结果", "Registry operation result"));
    if let Some(action) = value["action"].as_str() {
        ui.label(format!(
            "{} · {action}",
            t(language, "注册表操作", "Registry operation")
        ));
    }
    ui.label(format!(
        "{}  {}",
        t(language, "已登记项目", "Registered projects"),
        value["registered_projects"]
    ));
    if let Some(rows) = value["projects"].as_array() {
        for row in rows.iter().take(64) {
            ui.horizontal_wrapped(|ui| {
                ui.label(row["name"].as_str().unwrap_or_default());
                if let Some(report) = row.get("report") {
                    ui.monospace(report["result"].as_str().unwrap_or("not_assessed"));
                } else if let Some(result) = row["result"].as_str() {
                    ui.monospace(result);
                }
            });
        }
    }
}
fn t<'a>(language: Language, zh: &'a str, en: &'a str) -> &'a str {
    text(language, zh, en)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn batch_selection_cannot_expand_remove_or_update_scope() {
        let panel = RegistryPanel {
            selected: Some("selected-project".into()),
            all: true,
            ..Default::default()
        };
        for action in [RegistryAction::Remove, RegistryAction::Update] {
            let request = panel.request(action).unwrap();
            assert_eq!(request.project_id.as_deref(), Some("selected-project"));
            assert!(!request.all);
        }
        let request = panel.request(RegistryAction::Sync).unwrap();
        assert!(request.all && request.project_id.is_none());
    }
    #[test]
    fn ci_export_uses_a_new_complete_subdirectory() {
        let parent = tempfile::tempdir().unwrap();
        std::fs::write(parent.path().join("existing.json"), b"preserved").unwrap();
        let panel = RegistryPanel {
            ci_json: "{}\n".into(),
            ci_yaml: "name: fixture\n".into(),
            ..Default::default()
        };
        let output = panel.save_ci(parent.path()).unwrap();
        assert_eq!(
            std::fs::read(output.join("fileveil-ci.json")).unwrap(),
            b"{}\n"
        );
        assert_eq!(
            std::fs::read(output.join(".github/workflows/fileveil-release.yml")).unwrap(),
            b"name: fixture\n"
        );
        assert_eq!(
            std::fs::read(parent.path().join("existing.json")).unwrap(),
            b"preserved"
        );
    }

    #[test]
    fn ci_export_preserves_selected_policy_rules_and_compiler_targets() {
        let id = "a".repeat(32);
        let rules = vec![ProjectRule {
            pattern: "assets/**/*.png".into(),
            mode: fileveil_engine::project::ProjectFileMode::Structure,
            ..Default::default()
        }];
        let compiler = RegistryCompilerConfig {
            targets: vec![RegistryCompilerTarget {
                input: "src/main.c".into(),
                output: "target/release/demo".into(),
                backend: CompilerBackend::ClangSource,
            }],
            optimization: "O2".into(),
            compiler_arguments: vec!["-DDEMO=1".into()],
            ..Default::default()
        };
        let mut panel = RegistryPanel {
            defaults: RegistryDefaults {
                author: "Author".into(),
                ..Default::default()
            },
            projects: vec![ProjectRow {
                project_id: id.clone(),
                name: "Demo".into(),
                overrides: ProjectOverrides {
                    policy: Some(RegistryPolicy::Hybrid),
                    rules: Some(rules),
                    ..Default::default()
                },
                compiler: Some(compiler),
                ..Default::default()
            }],
            ..Default::default()
        };
        panel.select(id);
        assert_eq!(panel.ci.policy, RegistryPolicy::Hybrid);
        panel.generate_ci().unwrap();
        let config: serde_json::Value = serde_json::from_str(&panel.ci_json).unwrap();
        assert_eq!(config["policy"], "hybrid");
        assert_eq!(config["rules"][0]["pattern"], "assets/**/*.png");
        assert_eq!(config["compiler"]["targets"][0]["input"], "src/main.c");
        assert_eq!(config["compiler"]["compiler_arguments"][0], "-DDEMO=1");
        panel.policy = RegistryPolicy::ManifestOnly;
        panel.compiler_args = "irrelevant invalid JSON".into();
        panel.generate_ci().unwrap();
        let config: serde_json::Value = serde_json::from_str(&panel.ci_json).unwrap();
        assert_eq!(config["policy"], "manifest_only");
        assert!(config["rules"].as_array().unwrap().is_empty());
        assert!(config["compiler"].is_null());
    }

    #[test]
    fn ci_asset_rules_preserve_explicit_empty_overrides() {
        let id = "b".repeat(32);
        let mut panel = RegistryPanel {
            defaults: RegistryDefaults {
                author: "Author".into(),
                policy: RegistryPolicy::AssetWatermark,
                ..Default::default()
            },
            projects: vec![ProjectRow {
                project_id: id.clone(),
                name: "Assets".into(),
                overrides: ProjectOverrides {
                    rules: Some(Vec::new()),
                    ..Default::default()
                },
                ..Default::default()
            }],
            ..Default::default()
        };
        panel.select(id);
        assert!(panel.ci.rules.is_empty());
        panel.generate_ci().unwrap();
        let config: serde_json::Value = serde_json::from_str(&panel.ci_json).unwrap();
        assert_eq!(config["policy"], "asset_watermark");
        assert!(config["rules"].as_array().unwrap().is_empty());
        panel.overrides.rules = None;
        panel.generate_ci().unwrap();
        assert_eq!(
            panel.ci.rules,
            fileveil_engine::project::ci::default_asset_rules()
        );
    }
}

// FVPROV1 33812 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI5M2I2MmNkMDFlOTMxNTk1MGNmNTk2MWIxMGZkMDc0MzEzMjQyOTEyYWIyZDgxY2IxOTc2Y2IyMWJhOTAxNDg2IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvc3JjL3JlZ2lzdHJ5X3VpLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiNDBiZjVhODBjZTJkOTBhMTY3M2IxMzJiNmQ3OTVmMzg2ZTUyMjRkMDJkZWI5OTA3NWNjMDEyMWU1NjIyNmMyZmJkOTZmNjllNWM3OWM3NWQzOTU2N2JmZDczZDAzNjJhYmQzOTBmNzY0NzczMGM0ODgyYWU2NWY3ZGE4NDNhMDQifV19XQ== FVPROV1-END
