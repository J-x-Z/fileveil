// SPDX-License-Identifier: MPL-2.0
//! Private cross-project references, inherited identity and per-project policy.
use super::*;

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegistryAction {
    Init,
    Configure,
    Add,
    Update,
    Remove,
    #[default]
    List,
    Status,
    Sync,
    Verify,
    Migrate,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegistryPolicy {
    #[default]
    ManifestOnly,
    AssetWatermark,
    CompilerWatermark,
    Hybrid,
}

pub fn default_asset_rules() -> Vec<ProjectRule> {
    ["jpg", "jpeg", "png", "heic", "heif", "avif"]
        .iter()
        .map(|extension| ProjectRule {
            pattern: format!("**/*.{extension}"),
            mode: ProjectFileMode::Structure,
            ..Default::default()
        })
        .collect()
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProjectKind {
    #[default]
    Local,
    Git,
    Cargo,
    Cmake,
    Godot,
    Unreal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RegistryDefaults {
    pub author: String,
    pub copy_id: String,
    pub policy: RegistryPolicy,
    pub build_argv: Vec<String>,
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
}
impl Default for RegistryDefaults {
    fn default() -> Self {
        let project = ProjectConfig::default();
        Self {
            author: String::new(),
            copy_id: "development".into(),
            policy: RegistryPolicy::ManifestOnly,
            build_argv: Vec::new(),
            max_files: project.max_files,
            max_file_bytes: project.max_file_bytes,
            max_total_bytes: project.max_total_bytes,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectOverrides {
    pub author: Option<String>,
    pub work_id: Option<String>,
    pub copy_id: Option<String>,
    pub policy: Option<RegistryPolicy>,
    pub build_argv: Option<Vec<String>>,
    pub output_directory: Option<PathBuf>,
    pub rules: Option<Vec<ProjectRule>>,
    pub copy_external_files: Option<bool>,
    pub source_root: Option<PathBuf>,
    pub build_directory: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CompilerBackend {
    ClangSource,
    LlvmIr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryCompilerTarget {
    pub input: PathBuf,
    pub output: PathBuf,
    pub backend: CompilerBackend,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RegistryCompilerConfig {
    pub targets: Vec<RegistryCompilerTarget>,
    pub llvm_directory: Option<PathBuf>,
    pub plugin_path: Option<PathBuf>,
    pub optimization: String,
    pub target_triple: Option<String>,
    pub compiler_arguments: Vec<String>,
    pub allow_execution: bool,
    pub test_arguments: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEntry {
    pub project_id: String,
    pub name: String,
    pub kind: ProjectKind,
    pub detected_kinds: Vec<ProjectKind>,
    pub source_root: PathBuf,
    pub project_root: PathBuf,
    pub config_path: PathBuf,
    pub state_directory: PathBuf,
    pub overrides: ProjectOverrides,
    pub compiler: Option<RegistryCompilerConfig>,
    pub legacy_config_path: Option<PathBuf>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RegistryRequest {
    pub action: RegistryAction,
    pub registry_path: Option<PathBuf>,
    pub project_id: Option<String>,
    pub project_path: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub name: Option<String>,
    pub kind: Option<ProjectKind>,
    pub defaults: Option<RegistryDefaults>,
    pub overrides: Option<ProjectOverrides>,
    pub key: Option<ProjectKey>,
    pub state_directory: Option<PathBuf>,
    pub options: SyncOptions,
    pub scope: Option<ProjectScope>,
    pub compiler: Option<RegistryCompilerConfig>,
    pub all: bool,
    pub legacy_state_directory: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryAccessPlan {
    pub registry_path: PathBuf,
    pub read_paths: Vec<PathBuf>,
    pub write_directories: Vec<PathBuf>,
    pub signing_paths: Vec<PathBuf>,
    pub signing_key_refs: Vec<String>,
    pub project_requests: Vec<ProjectRequest>,
    pub source_file_count: usize,
    pub source_bytes: u64,
}

use super::files::{self, Access};
use crate::heritage::signing::{self, SigningKey};
use fileveil_core::{Error, Format, Outcome};
use serde_json::{Value, json};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    schema: String,
    registry_id: String,
    private_base: PathBuf,
    defaults: RegistryDefaults,
    projects: Vec<RegistryEntry>,
}
fn private_base() -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    let base = std::env::var_os("HOME")
        .map(|path| PathBuf::from(path).join("Library/Application Support"));
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(not(any(target_os = "macos", windows)))]
    let base = std::env::var_os("XDG_STATE_HOME")
        .filter(|path| Path::new(path).is_absolute())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|path| PathBuf::from(path).join(".local/state")));
    base.map(|path| path.join("FileVeil"))
        .ok_or_else(|| Error::Input("Select a private registry state directory".into()))
}
fn identifier() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| Error::Io("Could not generate registry identifier".into()))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}
fn encoded<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(value)
        .map_err(|_| Error::Input("Could not serialize registry metadata".into()))
}
fn registry_path(request: &RegistryRequest) -> Result<PathBuf> {
    let cwd = std::env::current_dir()
        .map_err(|_| Error::Input("Current directory is unavailable".into()))?;
    files::absolute(
        &request
            .registry_path
            .clone()
            .unwrap_or(private_base()?.join("registry.json")),
        &cwd,
    )
}
fn read_registry(access: &Access, path: &Path) -> Result<Registry> {
    let registry: Registry = serde_json::from_slice(&access.read(path, 8 * 1024 * 1024)?)
        .map_err(|_| Error::Input("Invalid strict registry JSON".into()))?;
    if registry.schema != "fileveil.project.registry.v1"
        || registry.registry_id.len() != 32
        || registry.projects.len() > 1024
    {
        return Err(Error::Input(
            "Unsupported or oversized project registry".into(),
        ));
    }
    let mut ids = std::collections::BTreeSet::new();
    for entry in &registry.projects {
        if entry.project_id.len() != 32 || !ids.insert(&entry.project_id) {
            return Err(Error::Input("Registry project identifiers collide".into()));
        }
    }
    Ok(registry)
}
fn detect(access: &Access, path: &Path) -> Result<Vec<ProjectKind>> {
    let root = access.directory(path, false, false)?;
    let names = root.list(100_000)?;
    let mut kinds = Vec::new();
    if names.iter().any(|name| {
        name.to_string_lossy()
            .to_ascii_lowercase()
            .ends_with(".uproject")
    }) {
        kinds.push(ProjectKind::Unreal);
    }
    if names.iter().any(|name| name == "project.godot") {
        kinds.push(ProjectKind::Godot);
    }
    if names.iter().any(|name| name == "Cargo.toml") {
        kinds.push(ProjectKind::Cargo);
    }
    if names.iter().any(|name| name == "CMakeLists.txt") {
        kinds.push(ProjectKind::Cmake);
    }
    if names.iter().any(|name| name == ".git") {
        kinds.push(ProjectKind::Git);
    }
    if kinds.is_empty() {
        kinds.push(ProjectKind::Local);
    }
    Ok(kinds)
}
fn selected<'a>(
    registry: &'a Registry,
    request: &RegistryRequest,
) -> Result<Vec<&'a RegistryEntry>> {
    if let Some(id) = &request.project_id {
        return registry
            .projects
            .iter()
            .find(|entry| &entry.project_id == id)
            .map(|entry| vec![entry])
            .ok_or_else(|| Error::Input("Project is not registered".into()));
    }
    if matches!(
        request.action,
        RegistryAction::Sync
            | RegistryAction::Verify
            | RegistryAction::Update
            | RegistryAction::Remove
    ) && !request.all
    {
        return Err(Error::Input(
            "Select a registered project or explicitly select all projects".into(),
        ));
    }
    if registry.projects.len() > 64
        && matches!(
            request.action,
            RegistryAction::Sync | RegistryAction::Verify
        )
    {
        return Err(files::blocked(
            "A registry operation accepts at most 64 projects",
        ));
    }
    Ok(registry.projects.iter().collect())
}
fn policy(registry: &Registry, entry: &RegistryEntry) -> RegistryPolicy {
    entry.overrides.policy.unwrap_or(registry.defaults.policy)
}
fn config(access: &Access, registry: &Registry, entry: &RegistryEntry) -> Result<ProjectConfig> {
    let config: ProjectConfig =
        serde_json::from_slice(&access.read(&entry.config_path, 512 * 1024)?)
            .map_err(|_| Error::Input("Registered project config is invalid".into()))?;
    if config.project_id != entry.project_id {
        return Err(Error::Verification(
            "Registered project identifier changed".into(),
        ));
    }
    effective_config(config, registry, entry)
}
fn effective_config(
    mut config: ProjectConfig,
    registry: &Registry,
    entry: &RegistryEntry,
) -> Result<ProjectConfig> {
    config.provenance = json!({"schema":"fileveil.registry.context.v1","policy":policy(registry,entry),"compiler":entry.compiler,"project_kind":entry.kind,"source_version":null,"scope":{"policy":"explicit_configuration","compiler":"declared_target_configuration","source_version":"not_assessed"}});
    config.source_root = files::absolute(
        &entry
            .overrides
            .source_root
            .clone()
            .unwrap_or_else(|| entry.source_root.clone()),
        &entry.project_root,
    )?;
    config.build_directory = files::absolute(
        &entry
            .overrides
            .build_directory
            .clone()
            .unwrap_or_else(|| entry.project_root.clone()),
        &entry.project_root,
    )?;
    config.author = entry
        .overrides
        .author
        .clone()
        .unwrap_or_else(|| registry.defaults.author.clone());
    if let Some(work) = &entry.overrides.work_id {
        config.work_id = work.clone();
    }
    config.copy_id = entry
        .overrides
        .copy_id
        .clone()
        .unwrap_or_else(|| registry.defaults.copy_id.clone());
    config.output_directory = files::absolute(
        &entry
            .overrides
            .output_directory
            .clone()
            .unwrap_or_else(|| entry.project_root.join("dist/fileveil-release")),
        &entry.project_root,
    )?;
    config.build_argv = entry
        .overrides
        .build_argv
        .clone()
        .unwrap_or_else(|| registry.defaults.build_argv.clone());
    config.max_file_bytes = registry.defaults.max_file_bytes;
    config.max_total_bytes = registry.defaults.max_total_bytes;
    config.max_files = registry.defaults.max_files;
    config.copy_external_files = entry.overrides.copy_external_files.unwrap_or(false);
    let generated = if entry.detected_kinds.contains(&ProjectKind::Unreal) {
        &[
            "Intermediate/**",
            "Saved/**",
            "DerivedDataCache/**",
            ".vs/**",
        ][..]
    } else if entry.detected_kinds.contains(&ProjectKind::Godot) {
        &[".godot/**"][..]
    } else {
        &[][..]
    };
    for pattern in generated {
        if !config.exclude.iter().any(|existing| existing == pattern) {
            config.exclude.push((*pattern).into());
        }
    }
    config.rules = if matches!(
        policy(registry, entry),
        RegistryPolicy::AssetWatermark | RegistryPolicy::Hybrid
    ) {
        entry
            .overrides
            .rules
            .clone()
            .unwrap_or_else(default_asset_rules)
    } else {
        Vec::new()
    };
    Ok(config)
}
fn source_version(access: &Access, entry: &RegistryEntry) -> Result<Value> {
    let candidates = [
        ("Cargo.toml", "package", "version"),
        ("project.godot", "application", "config/version"),
    ];
    for (name, section_name, key) in candidates {
        let path = entry.project_root.join(name);
        if !path.exists() {
            continue;
        }
        let bytes = access.read(&path, 512 * 1024)?;
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        let mut section = "";
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('[') && line.ends_with(']') {
                section = &line[1..line.len() - 1];
                continue;
            }
            if section != section_name {
                continue;
            }
            let Some((field, value)) = line.split_once('=') else {
                continue;
            };
            if field.trim() != key {
                continue;
            }
            // This conservative path reads a literal JSON-compatible quoted
            // string. Workspace inheritance, expressions and other TOML/Godot
            // forms remain unassessed instead of guessing their meaning.
            if let Ok(version) = serde_json::from_str::<String>(value.trim())
                && !version.is_empty()
                && version.len() <= 256
            {
                return Ok(
                    json!({"value":version,"source":name,"scope":"project_manifest_declaration","sha256":fileveil_core::digest(&bytes)}),
                );
            }
        }
    }
    Ok(Value::Null)
}
fn project_request(
    request: &RegistryRequest,
    entry: &RegistryEntry,
    action: ProjectAction,
) -> ProjectRequest {
    ProjectRequest {
        action,
        config_path: entry.config_path.clone(),
        state_directory: Some(entry.state_directory.clone()),
        key: request.key.clone(),
        options: request.options.clone(),
        scope: request.scope.clone(),
        ..Default::default()
    }
}
fn response(
    registry: &Registry,
    action: RegistryAction,
    projects: Vec<Value>,
    failed: bool,
) -> Result<Report> {
    let mut report = Report::new("registry", Format::Unknown);
    report.result = if failed {
        Outcome::Failed
    } else if projects.iter().any(|row| {
        row["result"] == "partially_verified" || row["report"]["result"] == "partially_verified"
    }) {
        Outcome::PartiallyVerified
    } else {
        Outcome::VerifiedWithinScope
    };
    report.advanced = Some(
        json!({"registry":{"schema":"fileveil.registry.report.v1","action":action,"registry_id":registry.registry_id,"defaults":registry.defaults,"projects":projects,"registered_projects":registry.projects.len(),"failed":failed,"copies_source_code":false}}),
    );
    Ok(report)
}
fn entry_value(registry: &Registry, entry: &RegistryEntry) -> Value {
    let mut value = json!(entry);
    value["effective_policy"] = json!(policy(registry, entry));
    value
}

pub fn access_plan(request: &RegistryRequest, limits: &Limits) -> Result<RegistryAccessPlan> {
    let access = Access::new(request.scope.as_ref())?;
    let path = registry_path(request)?;
    access.check(&path, false)?;
    let mut plan = RegistryAccessPlan {
        registry_path: path.clone(),
        read_paths: Vec::new(),
        write_directories: Vec::new(),
        signing_paths: Vec::new(),
        signing_key_refs: Vec::new(),
        project_requests: Vec::new(),
        source_file_count: 0,
        source_bytes: 0,
    };
    if path.exists() {
        plan.read_paths.push(path.clone());
    }
    if matches!(
        request.action,
        RegistryAction::Init
            | RegistryAction::Configure
            | RegistryAction::Add
            | RegistryAction::Update
            | RegistryAction::Remove
            | RegistryAction::Migrate
    ) {
        access.check(&path, true)?;
        plan.write_directories.push(
            path.parent()
                .ok_or_else(|| Error::Input("Registry path has no parent".into()))?
                .to_path_buf(),
        );
    }
    if request.action == RegistryAction::Init {
        if let Some(base) = &request.state_directory {
            let base = files::absolute(base, path.parent().unwrap())?;
            access.check(&base, true)?;
            plan.write_directories.push(base);
        }
        return Ok(plan);
    }
    let registry = read_registry(&access, &path)?;
    if matches!(
        request.action,
        RegistryAction::Configure
            | RegistryAction::Add
            | RegistryAction::Update
            | RegistryAction::Remove
            | RegistryAction::Migrate
            | RegistryAction::Sync
    ) {
        access.check(&registry.private_base, true)?;
        plan.write_directories.push(registry.private_base.clone());
    }
    let approved = registry.private_base.join("approved-registry.sha256");
    if approved.exists() && request.options.automatic {
        access.check(&approved, false)?;
        plan.read_paths.push(approved);
    }
    if matches!(
        request.action,
        RegistryAction::Add | RegistryAction::Migrate
    ) {
        if let Some(source) = &request.project_path {
            let source = files::absolute(source, path.parent().unwrap())?;
            access.check(&source, false)?;
            access.directory(&source, false, false)?;
        }
        if let Some(config) = &request.config_path {
            let config = files::absolute(config, path.parent().unwrap())?;
            access.check(&config, false)?;
            plan.read_paths.push(config);
        }
        access.check(&registry.private_base, true)?;
        plan.write_directories.push(registry.private_base.clone());
        match &request.key {
            Some(ProjectKey::File { path }) => {
                access.key(&ProjectKey::File { path: path.clone() })?;
                plan.signing_paths.push(path.clone());
            }
            Some(ProjectKey::System { key_id }) => {
                access.key(&ProjectKey::System {
                    key_id: key_id.clone(),
                })?;
                plan.signing_key_refs.push(key_id.clone());
            }
            None if request.scope.is_some() => {
                return Err(files::blocked(
                    "MCP registration requires an explicitly authorized existing signing key",
                ));
            }
            _ => {}
        }
        return Ok(plan);
    }
    if matches!(
        request.action,
        RegistryAction::Sync | RegistryAction::Verify | RegistryAction::Status
    ) {
        let action = match request.action {
            RegistryAction::Sync => ProjectAction::Sync,
            RegistryAction::Verify => ProjectAction::Verify,
            _ => ProjectAction::Status,
        };
        for entry in selected(&registry, request)? {
            for name in ["Cargo.toml", "project.godot"] {
                let metadata = entry.project_root.join(name);
                if metadata.exists() {
                    access.check(&metadata, false)?;
                    plan.read_paths.push(metadata);
                }
            }
            let mut project = project_request(request, entry, action);
            if request.scope.is_none() {
                project.options.git_ref = None;
            }
            let remaining = remaining_limits(
                limits,
                request.scope.is_some(),
                plan.source_file_count,
                plan.source_bytes,
            )?;
            let sub = super::access_plan(&project, &remaining)?;
            plan.source_file_count = plan.source_file_count.saturating_add(sub.source_file_count);
            plan.source_bytes = plan.source_bytes.saturating_add(sub.source_bytes);
            plan.read_paths.extend(sub.read_paths);
            plan.write_directories.extend(sub.write_directories);
            plan.signing_paths.extend(sub.signing_paths);
            plan.signing_key_refs.extend(sub.signing_key_refs);
            plan.project_requests.push(project);
            remaining_limits(
                limits,
                request.scope.is_some(),
                plan.source_file_count,
                plan.source_bytes,
            )?;
        }
        if request.scope.is_some()
            && (plan.source_file_count > limits.max_members
                || plan.source_bytes > limits.max_uncompressed_bytes)
        {
            return Err(files::blocked(
                "Registry batch exceeds the shared MCP resource budget",
            ));
        }
    }
    Ok(plan)
}

pub fn run(request: &RegistryRequest, limits: &Limits, flag: &AtomicBool) -> Result<Report> {
    files::cancelled(flag)?;
    let access = Access::new(request.scope.as_ref())?;
    let path = registry_path(request)?;
    access.check(&path, false)?;
    if request.action == RegistryAction::Init {
        if path.exists() {
            return Err(Error::Input("Registry already exists".into()));
        }
        let id = identifier()?;
        let base = files::absolute(
            &request
                .state_directory
                .clone()
                .unwrap_or(private_base()?.join("registries").join(&id)),
            path.parent().unwrap(),
        )?;
        if request.scope.is_some() && request.state_directory.is_none() {
            return Err(files::blocked(
                "MCP registry initialization requires an explicit authorized private state directory",
            ));
        }
        access.directory(&base, true, true)?;
        let registry = Registry {
            schema: "fileveil.project.registry.v1".into(),
            registry_id: id,
            private_base: base,
            defaults: request.defaults.clone().unwrap_or_default(),
            projects: Vec::new(),
        };
        access.write_new(&path, &encoded(&registry)?)?;
        registry_pin(&access, &registry, false)?;
        return response(&registry, request.action, Vec::new(), false);
    }
    let mut registry = read_registry(&access, &path)?;
    if matches!(request.action, RegistryAction::List) {
        return response(
            &registry,
            request.action,
            registry
                .projects
                .iter()
                .map(|entry| entry_value(&registry, entry))
                .collect(),
            false,
        );
    }
    let writing = matches!(
        request.action,
        RegistryAction::Configure
            | RegistryAction::Add
            | RegistryAction::Update
            | RegistryAction::Remove
            | RegistryAction::Migrate
            | RegistryAction::Sync
    );
    let _lock = if writing {
        Some(access.lock(&registry.private_base)?)
    } else {
        None
    };
    if request.action == RegistryAction::Configure {
        registry.defaults = request
            .defaults
            .clone()
            .ok_or_else(|| Error::Input("Select registry defaults".into()))?;
        access.replace(&path, &encoded(&registry)?)?;
        registry_pin(&access, &registry, false)?;
        return response(&registry, request.action, Vec::new(), false);
    }
    if matches!(
        request.action,
        RegistryAction::Add | RegistryAction::Migrate
    ) {
        return register(&access, &path, registry, request, limits, flag);
    }
    if request.action == RegistryAction::Remove {
        let ids = selected(&registry, request)?
            .iter()
            .map(|entry| entry.project_id.clone())
            .collect::<Vec<_>>();
        registry
            .projects
            .retain(|entry| !ids.contains(&entry.project_id));
        access.replace(&path, &encoded(&registry)?)?;
        registry_pin(&access, &registry, false)?;
        return response(&registry,request.action,ids.into_iter().map(|id|json!({"project_id":id,"registration_removed":true,"project_and_history_retained":true})).collect(),false);
    }
    if request.action == RegistryAction::Update {
        let id = request
            .project_id
            .as_ref()
            .ok_or_else(|| Error::Input("Select a project to update".into()))?;
        let entry = registry
            .projects
            .iter_mut()
            .find(|entry| &entry.project_id == id)
            .ok_or_else(|| Error::Input("Project is not registered".into()))?;
        if let Some(overrides) = &request.overrides {
            entry.overrides = overrides.clone();
        }
        if let Some(name) = &request.name {
            entry.name = name.clone();
        }
        if let Some(compiler) = &request.compiler {
            entry.compiler = Some(compiler.clone());
        }
        access.replace(&path, &encoded(&registry)?)?;
        registry_pin(&access, &registry, false)?;
        return response(
            &registry,
            request.action,
            vec![entry_value(
                &registry,
                registry
                    .projects
                    .iter()
                    .find(|entry| &entry.project_id == id)
                    .unwrap(),
            )],
            false,
        );
    }
    let mut results = Vec::new();
    let mut failed = false;
    let mut total_files = 0usize;
    let mut total_bytes = 0u64;
    for entry in selected(&registry, request)? {
        files::cancelled(flag)?;
        let remaining =
            remaining_limits(limits, request.scope.is_some(), total_files, total_bytes)?;
        let result = execute(&access, &registry, entry, request, &remaining, flag);
        match result {
            Ok(report) => {
                if let Some(details) = report
                    .advanced
                    .as_ref()
                    .and_then(|value| value.get("project"))
                {
                    total_files = total_files
                        .saturating_add(details["files_total"].as_u64().unwrap_or(0) as usize);
                    total_bytes =
                        total_bytes.saturating_add(details["bytes_total"].as_u64().unwrap_or(0));
                }
                failed |= matches!(
                    report.result,
                    Outcome::Failed | Outcome::Blocked | Outcome::Unsupported
                );
                results.push(json!({"project_id":entry.project_id,"name":entry.name,"policy":policy(&registry,entry),"result":report.result,"report":report}));
            }
            Err(error @ Error::Interrupted(_)) => return Err(error),
            Err(error) => {
                failed = true;
                let result = match &error {
                    Error::Blocked(_) => Outcome::Blocked,
                    Error::Unsupported(_) => Outcome::Unsupported,
                    _ => Outcome::Failed,
                };
                results.push(json!({"project_id":entry.project_id,"name":entry.name,"result":result,"published":false,"error":error.to_string()}));
            }
        }
    }
    response(&registry, request.action, results, failed)
}

fn remaining_limits(limits: &Limits, scoped: bool, files: usize, bytes: u64) -> Result<Limits> {
    let mut remaining = limits.clone();
    if scoped {
        if files > limits.max_members || bytes > limits.max_uncompressed_bytes {
            return Err(files::blocked(
                "Registry batch exceeds the shared MCP resource budget",
            ));
        }
        remaining.max_members = limits.max_members - files;
        remaining.max_uncompressed_bytes = limits.max_uncompressed_bytes - bytes;
    }
    Ok(remaining)
}

fn registry_pin(access: &Access, registry: &Registry, automatic: bool) -> Result<()> {
    let path = registry.private_base.join("approved-registry.sha256");
    let digest = fileveil_core::digest(&signing::canonical(registry)?);
    if automatic {
        let approved = access.read(&path, 128)?;
        if approved != digest.as_bytes() {
            return Err(files::blocked(
                "Automatic registry scope changed. Save registry configuration explicitly before resuming",
            ));
        }
    } else {
        access.replace(&path, digest.as_bytes())?;
    }
    Ok(())
}

fn register(
    access: &Access,
    registry_path: &Path,
    mut registry: Registry,
    request: &RegistryRequest,
    limits: &Limits,
    flag: &AtomicBool,
) -> Result<Report> {
    if registry.projects.len() >= 1024 {
        return Err(files::blocked("Registry has reached its project limit"));
    }
    let parent = registry_path.parent().unwrap();
    let requested_root = request
        .project_path
        .as_ref()
        .map(|root| files::absolute(root, parent))
        .transpose()?;
    let legacy_path = request
        .config_path
        .as_ref()
        .map(|path| files::absolute(path, parent))
        .transpose()?
        .or_else(|| {
            requested_root
                .as_ref()
                .map(|root| root.join("fileveil.project.json"))
                .filter(|path| path.exists())
        });
    let legacy = legacy_path
        .as_ref()
        .map(|path| {
            serde_json::from_slice::<ProjectConfig>(&access.read(path, 512 * 1024)?)
                .map_err(|_| Error::Input("Legacy project configuration is invalid".into()))
        })
        .transpose()?;
    if request.action == RegistryAction::Migrate && legacy.is_none() {
        return Err(Error::Input(
            "Migration requires an existing project configuration".into(),
        ));
    }
    let root = requested_root
        .or_else(|| {
            legacy_path
                .as_ref()
                .and_then(|path| path.parent().map(Path::to_path_buf))
        })
        .ok_or_else(|| Error::Input("Select a local project directory".into()))?;
    access.directory(&root, false, false)?;
    let source = if let Some(config) = &legacy {
        files::absolute(
            &config.source_root,
            legacy_path.as_ref().unwrap().parent().unwrap(),
        )?
    } else {
        root.clone()
    };
    if let Some(existing) = registry
        .projects
        .iter()
        .find(|entry| entry.project_root == root)
    {
        return response(
            &registry,
            request.action,
            vec![entry_value(&registry, existing)],
            false,
        );
    }
    let id = legacy
        .as_ref()
        .map(|config| config.project_id.clone())
        .filter(|id| !id.is_empty())
        .unwrap_or(identifier()?);
    if registry.projects.iter().any(|entry| entry.project_id == id) {
        return Err(Error::Input(
            "This project identifier is already registered".into(),
        ));
    }
    let output = legacy
        .as_ref()
        .map(|config| {
            files::absolute(
                &config.output_directory,
                legacy_path.as_ref().unwrap().parent().unwrap(),
            )
        })
        .transpose()?;
    let state = if legacy.is_some() {
        request
            .legacy_state_directory
            .as_ref()
            .map(|state| files::absolute(state, parent))
            .transpose()?
            .unwrap_or(private_base()?.join("projects").join(&id))
    } else {
        registry.private_base.join("states").join(&id)
    };
    if registry.private_base.starts_with(&source)
        || legacy_path
            .as_ref()
            .is_some_and(|path| registry.private_base.starts_with(path.parent().unwrap()))
        || output
            .as_ref()
            .is_some_and(|path| registry.private_base.starts_with(path))
    {
        return Err(Error::Input("Registry state and keys must be outside project sources, public configuration and output".into()));
    }
    let config_path = registry
        .private_base
        .join("configs")
        .join(&id)
        .join("fileveil.project.json");
    if config_path.exists() {
        return Err(Error::Input(
            "A managed config already exists for this project. Import its registration explicitly"
                .into(),
        ));
    }
    let mut overrides = request.overrides.clone().unwrap_or_default();
    if let Some(previous) = &legacy {
        overrides.author.get_or_insert(previous.author.clone());
        overrides.copy_id.get_or_insert(previous.copy_id.clone());
        overrides.work_id.get_or_insert(previous.work_id.clone());
        overrides
            .output_directory
            .get_or_insert(output.clone().unwrap());
        overrides
            .build_argv
            .get_or_insert(previous.build_argv.clone());
        overrides.build_directory.get_or_insert(files::absolute(
            &previous.build_directory,
            legacy_path.as_ref().unwrap().parent().unwrap(),
        )?);
        overrides.rules.get_or_insert(previous.rules.clone());
        overrides
            .copy_external_files
            .get_or_insert(previous.copy_external_files);
        if overrides.policy.is_none() && !previous.rules.is_empty() {
            overrides.policy = Some(RegistryPolicy::AssetWatermark);
        }
    }
    let detected = detect(access, &root)?;
    let entry = RegistryEntry {
        project_id: id.clone(),
        name: request.name.clone().unwrap_or_else(|| {
            root.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
        }),
        kind: request.kind.unwrap_or(detected[0]),
        detected_kinds: detected,
        source_root: source,
        project_root: root,
        config_path: config_path.clone(),
        state_directory: state.clone(),
        overrides,
        compiler: request.compiler.clone(),
        legacy_config_path: legacy_path,
    };
    let mut base_config = legacy.unwrap_or_default();
    base_config.project_id = id.clone();
    if base_config.work_id.is_empty() {
        base_config.work_id = format!("project-{id}");
    }
    let desired = effective_config(base_config, &registry, &entry)?;
    if desired.author.trim().is_empty() {
        return Err(Error::Input(
            "Configure a registry author or an explicit per-project author".into(),
        ));
    }
    access.directory(config_path.parent().unwrap(), true, true)?;
    let has_old_state = state.join("state.json").exists();
    let key = if has_old_state {
        request.key.clone()
    } else if let Some(key) = &request.key {
        Some(key.clone())
    } else {
        if entry.legacy_config_path.is_some() {
            return Err(files::blocked(
                "Legacy history needs its original private state or an explicitly selected original signing key",
            ));
        }
        if request.scope.is_some() {
            return Err(files::blocked(
                "MCP registration requires an existing authorized signing key",
            ));
        }
        let _key_directory = access.directory(&registry.private_base.join("keys"), true, true)?;
        let name = format!("{id}.key");
        SigningKey::generate()?.save_new(&registry.private_base.join("keys").join(&name))?;
        Some(ProjectKey::File {
            path: registry.private_base.join("keys").join(name),
        })
    };
    let mut operation = project_request(
        request,
        &entry,
        if has_old_state {
            ProjectAction::UpdateConfig
        } else {
            ProjectAction::Init
        },
    );
    operation.init = Some(desired.clone());
    operation.key = key;
    operation.options.automatic = false;
    // Imported state already binds the project. Only a metadata config copy is
    // created, while the source tree and all existing release history stay put.
    if has_old_state {
        access.write_new(&config_path, &encoded(&desired)?)?;
    }
    let result = super::run(&operation, limits, flag)?;
    if matches!(
        result.result,
        Outcome::Failed | Outcome::Blocked | Outcome::Unsupported
    ) {
        return Err(Error::Verification(
            "Project registration failed verification".into(),
        ));
    }
    registry.projects.push(entry.clone());
    access.replace(registry_path, &encoded(&registry)?)?;
    registry_pin(access, &registry, false)?;
    let mut row = entry_value(&registry, &entry);
    row["report"] = json!(result);
    response(&registry, request.action, vec![row], false)
}

fn execute(
    access: &Access,
    registry: &Registry,
    entry: &RegistryEntry,
    request: &RegistryRequest,
    limits: &Limits,
    flag: &AtomicBool,
) -> Result<Report> {
    let compiler_policy = matches!(
        policy(registry, entry),
        RegistryPolicy::CompilerWatermark | RegistryPolicy::Hybrid
    );
    if request.action == RegistryAction::Sync && compiler_policy && request.scope.is_some() {
        return Err(files::blocked(
            "MCP registry synchronization cannot execute compiler targets",
        ));
    }

    if request.options.automatic || request.action == RegistryAction::Sync {
        registry_pin(access, registry, request.options.automatic)?;
    }
    let effective = config(access, registry, entry)?;
    let stored: ProjectConfig =
        serde_json::from_slice(&access.read(&entry.config_path, 512 * 1024)?)
            .map_err(|_| Error::Input("Invalid registered configuration".into()))?;
    let pending = signing::canonical(&effective)? != signing::canonical(&stored)?;
    if pending && request.action == RegistryAction::Sync {
        if request.options.automatic {
            return Err(files::blocked(
                "Inherited project policy changed. Save registry settings explicitly before automatic synchronization",
            ));
        }
        let mut update = project_request(request, entry, ProjectAction::UpdateConfig);
        update.init = Some(effective.clone());
        update.options.automatic = false;
        update.options.git_ref = None;
        update.options.trigger = None;
        super::run(&update, limits, flag)?;
    }
    let action = match request.action {
        RegistryAction::Sync => ProjectAction::Sync,
        RegistryAction::Verify => ProjectAction::Verify,
        _ => ProjectAction::Status,
    };
    let mut operation = project_request(request, entry, action);
    operation.options.observations = json!({"source_version":source_version(access,entry)?,"scope":"observed_manifest_snapshot"});
    let mut git = None;
    if action == ProjectAction::Sync
        && (operation.options.git_ref.is_some()
            || effective.trigger == ProjectTrigger::Git
            || request.scope.is_none() && entry.detected_kinds.contains(&ProjectKind::Git))
    {
        if request.scope.is_some() {
            return Err(files::blocked(
                "MCP registry synchronization does not execute Git",
            ));
        }
        let revision = crate::worker::git_snapshot(
            &effective.build_directory,
            operation.options.git_ref.as_deref().unwrap_or("HEAD"),
            std::time::Duration::from_secs(30),
        )?;
        let git_trigger =
            operation.options.git_ref.is_some() || effective.trigger == ProjectTrigger::Git;
        operation.options.git_ref = Some(revision.commit.clone());
        if git_trigger {
            operation.options.trigger = Some(ProjectTrigger::Git);
        }
        git = Some(revision);
    }
    let mut compiled = None;
    let mut compiler_partial = false;
    if action == ProjectAction::Sync && compiler_policy {
        let compiler = entry
            .compiler
            .as_ref()
            .filter(|compiler| !compiler.targets.is_empty())
            .ok_or_else(|| {
                files::blocked("Compiler policy requires explicit source or LLVM targets")
            })?;
        let mut status = operation.clone();
        status.action = ProjectAction::Status;
        let status = super::run(&status, limits, flag)?;
        let state = &status.advanced.as_ref().ok_or_else(|| {
            Error::Verification("Project status is unavailable before compilation".into())
        })?["project"];
        let needs_compile = state["dirty"] == true
            || state["derived_artifacts_total"].as_u64() != Some(compiler.targets.len() as u64)
            || operation.options.rotate_to.is_some()
            || operation
                .options
                .copy_id
                .as_ref()
                .is_some_and(|copy| state["latest_copy_id"] != *copy)
            || !operation.options.version.is_empty()
                && state["latest_version"] != operation.options.version;
        if needs_compile {
            if operation.options.version.is_empty() {
                operation.options.version =
                    format!("r{:012}", state["revision"].as_u64().unwrap_or(0) + 1);
            }
            if operation.options.created_at.is_empty() {
                operation.options.created_at = super::compiler::asserted_time()?;
            }
            let result = super::compiler::compile(
                &effective,
                &entry.project_root,
                compiler,
                &operation,
                limits,
                flag,
            )?;
            operation.derived_artifacts = Some(result.artifacts.clone());
            operation.options.observations["compiler"] = json!(result.reports);
            compiler_partial = result.partially_verified;
            compiled = Some(result);
        } else {
            let prior = state["observations"]["compiler"].clone();
            compiler_partial = prior
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row["mark"] == "partially_verified"));
            operation.options.observations["compiler"] = prior;
        }
    } else if action == ProjectAction::Sync {
        operation.derived_artifacts = Some(Vec::new());
    }
    let mut report = super::run(&operation, limits, flag)?;
    if let Some(compiled) = compiled {
        report.advanced.as_mut().unwrap()["project"]["compiler"] = json!({"performed":true,"artifacts":compiled.reports,"scope":"authenticated_witness_and_file_hash","dependency_closure":"not_assessed"});
    } else if compiler_policy && action == ProjectAction::Sync {
        report.advanced.as_mut().unwrap()["project"]["compiler"] =
            json!({"performed":false,"scope":"unchanged_signed_derived_artifacts_reused"});
    }
    if compiler_partial && report.result == Outcome::VerifiedWithinScope {
        report.result = Outcome::PartiallyVerified;
    }
    report.advanced.as_mut().unwrap()["project"]["inherited_configuration_pending"] =
        json!(pending && request.action != RegistryAction::Sync);
    if let Some(git) = git {
        report.advanced.as_mut().unwrap()["project"]["git"] = json!(git);
    }
    Ok(report)
}

// FVPROV1 43739 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJiNTQ3NjVkOGJhMTczNTBkNDdiNTJkMjZhZjEwYTJlOTNjM2IwOGU1MDcyNmJmYmM3YzBhOWJkN2E1YTIyYWIwIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL3Byb2plY3QvcmVnaXN0cnkucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI5M2YyOTJlZDI4ZDNhMjk2NjA0MjYwNzY2MWIyMmFiYzA1MWE2ODE1OTgxN2U3YWNhZjhjZjM4YmYxYWZhOTI3MTIyYzdhNzE2NDQ5NDE1NWRjNWI2MjBjOWE4NWJiMjA5NWEwNmUyNDY5M2M4MTE0Y2MxY2EyMzUwN2VjMDAwYSJ9XX1d FVPROV1-END
