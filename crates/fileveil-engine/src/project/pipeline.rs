// SPDX-License-Identifier: MPL-2.0
use super::{
    files::{self, Access, Directory, Sample},
    *,
};
use crate::heritage::{self, custody, key_store, signing};
use fileveil_core::{Error, Format, Outcome, digest};
use serde_json::json;
use signing::{RecordBody, RecordKind, SignedRecord, SigningKey, TrustStore};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    path::Path,
    sync::atomic::AtomicBool,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_CONFIG_BYTES: u64 = 512 * 1024;
const MAX_PRIVATE_STATE_BYTES: u64 = 1024 * 1024;
const MAX_INDEX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 32 * 1024 * 1024;
const SEGMENT_RECORDS: usize = 32;
const STATE_NAME: &str = "state.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundKey {
    public: PublicKey,
    source: ProjectKey,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: String,
    project_id: String,
    initial_key: PublicKey,
    keys: Vec<BoundKey>,
    approved_config_sha256: String,
    #[serde(default)]
    index_generation: Option<String>,
    #[serde(default)]
    index_manifest_sha256: Option<String>,
    #[serde(default)]
    index_evidence_sha256: Option<String>,
    #[serde(default)]
    known_copies: Vec<String>,
    #[serde(default)]
    current_key_id: Option<String>,
    #[serde(skip)]
    index: BTreeMap<String, CachedFile>,
    #[serde(skip)]
    index_dirty: bool,
    #[serde(skip)]
    output_index: BTreeMap<String, CachedFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CachedFile {
    sha256: String,
    stamp: files::Stamp,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexCache {
    generation: String,
    manifest_sha256: String,
    files: BTreeMap<String, CachedFile>,
    #[serde(default)]
    outputs: BTreeMap<String, CachedFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    file_id: String,
    source_sha256: String,
    source_size: u64,
    #[serde(default)]
    source_executable: Option<bool>,
    mode: ProjectFileMode,
    output_sha256: Option<String>,
    output_size: Option<u64>,
    previous_source_sha256: Option<String>,
    signer_key_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    kind: String,
    path: String,
    previous_path: Option<String>,
    file_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    project_id: String,
    work_id: String,
    author: String,
    copy_id: String,
    revision: u64,
    version: String,
    created_at: String,
    trigger: ProjectTrigger,
    git_commit: Option<String>,
    config_sha256: String,
    source_fingerprint: String,
    previous_manifest_sha256: Option<String>,
    previous_generation: Option<String>,
    migration_from_work_id: Option<String>,
    segment: u64,
    files: Vec<Entry>,
    changes: Vec<Change>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    derived_artifacts: Vec<DerivedEntry>,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    observations: serde_json::Value,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DerivedEntry {
    path: String,
    sha256: String,
    size_bytes: u64,
    source_sha256: Option<String>,
    method: String,
}
struct Generation {
    name: String,
    path: PathBuf,
    manifest: Manifest,
    manifest_sha256: String,
    evidence: custody::EvidencePackage,
    evidence_sha256: String,
}
struct History {
    latest: Option<Generation>,
    initial_key: Option<PublicKey>,
    copies: BTreeSet<String>,
    count: usize,
    cached_tip: bool,
    metadata: Vec<HistoryMetadata>,
}
#[derive(Clone, Serialize)]
struct HistoryMetadata {
    generation: String,
    manifest_sha256: String,
    evidence_sha256: String,
}
fn history_metadata(generation: &Generation) -> HistoryMetadata {
    HistoryMetadata {
        generation: generation.name.clone(),
        manifest_sha256: generation.manifest_sha256.clone(),
        evidence_sha256: generation.evidence_sha256.clone(),
    }
}
struct Inventory {
    samples: BTreeMap<String, Sample>,
    fingerprint: String,
}
#[derive(Clone, Copy)]
struct Budget {
    files: usize,
    file_bytes: u64,
    total_bytes: u64,
}
struct Context {
    access: Access,
    config_path: PathBuf,
    config: ProjectConfig,
    config_sha256: String,
    source: PathBuf,
    output: PathBuf,
    state: PathBuf,
    budget: Budget,
    include: Vec<glob::Pattern>,
    exclude: Vec<glob::Pattern>,
    rules: Vec<(glob::Pattern, ProjectRule)>,
}

fn json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(value)
        .map_err(|_| Error::Input("Project data could not be serialized".into()))
}
fn read_json<T: serde::de::DeserializeOwned>(access: &Access, path: &Path, cap: u64) -> Result<T> {
    serde_json::from_slice(&access.read(path, cap)?)
        .map_err(|_| Error::Input("Invalid strict project JSON".into()))
}
fn text(value: &str, name: &str, empty: bool) -> Result<()> {
    if (!empty && value.trim().is_empty()) || value.len() > 4096 || value.contains('\0') {
        return Err(Error::Input(format!("Invalid project {name}")));
    }
    Ok(())
}
fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| Error::Io("Could not generate project identifier".into()))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}
fn validate_config(config: &ProjectConfig, allow_empty_id: bool) -> Result<()> {
    if signing::canonical(&config.provenance)?.len() > 64 * 1024 {
        return Err(Error::Input(
            "Project provenance context exceeds its limit".into(),
        ));
    }
    if config.schema != CONFIG_SCHEMA
        || !(allow_empty_id && config.project_id.is_empty())
            && (config.project_id.len() != 32
                || !config
                    .project_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    {
        return Err(Error::Input(
            "Invalid project schema or stable project identifier".into(),
        ));
    }
    for (name, value) in [
        ("work identifier", &config.work_id),
        ("author", &config.author),
        ("copy identifier", &config.copy_id),
    ] {
        text(value, name, false)?;
    }
    if config.max_files == 0
        || config.max_files > 100_000
        || config.max_file_bytes == 0
        || config.max_total_bytes < config.max_file_bytes
        || config.max_total_bytes > 1024 * 1024 * 1024 * 1024
        || config.debounce_ms > 300_000
        || !(100..=3_600_000).contains(&config.poll_interval_ms)
        || config.full_rescan_interval_ms < 1000
    {
        return Err(Error::Input(
            "Invalid project resource or watch limits".into(),
        ));
    }
    if config.include.is_empty()
        || config.include.len() > 128
        || config.exclude.len() > 128
        || config.rules.len() > 128
        || config.build_argv.len() > 128
    {
        return Err(Error::Input(
            "Project rules or build arguments exceed their limit".into(),
        ));
    }
    for value in &config.build_argv {
        text(value, "build argument", false)?;
    }
    for pattern in config
        .include
        .iter()
        .chain(&config.exclude)
        .chain(config.rules.iter().map(|rule| &rule.pattern))
    {
        if pattern.is_empty()
            || pattern.len() > 512
            || pattern.starts_with('/')
            || pattern.contains(['\0', '\\', ':'])
            || pattern.split('/').any(|part| part == "..")
        {
            return Err(Error::Input(
                "Project patterns must be bounded relative globs".into(),
            ));
        }
        glob::Pattern::new(pattern)
            .map_err(|_| Error::Input("Invalid project file pattern".into()))?;
    }
    if config
        .rules
        .iter()
        .any(|rule| !(1..=40).contains(&rule.strength))
    {
        return Err(Error::Input("Invalid project watermark strength".into()));
    }
    Ok(())
}
fn cwd() -> Result<PathBuf> {
    std::env::current_dir().map_err(|_| Error::Input("Current directory is unavailable".into()))
}
fn state_directory(project_id: &str) -> Result<PathBuf> {
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
    base.map(|path| path.join("FileVeil/projects").join(project_id))
        .ok_or_else(|| Error::Input("Select an external private project state directory".into()))
}

pub(super) fn load_configuration(
    request: &ProjectRequest,
    limits: &Limits,
) -> Result<ProjectConfig> {
    let context = Context::new(request, limits)?;
    if request.options.automatic {
        context.approved(&context.load_state()?, true)?;
    }
    Ok(context.config)
}

pub(super) fn signing_identity(request: &ProjectRequest, limits: &Limits) -> Result<ProjectKey> {
    let context = Context::new(request, limits)?;
    let state = context
        .load_state()?
        .ok_or_else(|| files::blocked("Project identity has not been initialized"))?;
    context.approved(&Some(state.clone()), request.options.automatic)?;
    let history = current_history(&context, Some(&state), false)?;
    let active = history
        .latest
        .as_ref()
        .map(|generation| active_key(generation.evidence.body.records.last().unwrap()))
        .unwrap_or(&state.initial_key.key_id);
    let (source, _key) = selected_key(&context, request, &state, active)?;
    Ok(source)
}

impl Context {
    fn new(request: &ProjectRequest, limits: &Limits) -> Result<Self> {
        if signing::canonical(&request.options.observations)?.len() > 64 * 1024 {
            return Err(Error::Input(
                "Project observed provenance exceeds its budget".into(),
            ));
        }
        if request.scope.is_some()
            && request
                .derived_artifacts
                .as_ref()
                .is_some_and(|artifacts| !artifacts.is_empty())
        {
            return Err(files::blocked(
                "MCP clients cannot inject build-derived release artifacts",
            ));
        }
        let access = Access::new(request.scope.as_ref())?;
        let config_path = files::absolute(&request.config_path, &cwd()?)?;
        access.check(&config_path, false)?;
        let parent = config_path
            .parent()
            .ok_or_else(|| Error::Input("Project config requires a containing directory".into()))?;
        let mut config = if matches!(
            request.action,
            ProjectAction::Init | ProjectAction::UpdateConfig
        ) {
            request
                .init
                .clone()
                .map(Ok)
                .unwrap_or_else(|| read_json(&access, &config_path, MAX_CONFIG_BYTES))?
        } else {
            read_json(&access, &config_path, MAX_CONFIG_BYTES)?
        };
        if request.action == ProjectAction::Init && config.project_id.is_empty() {
            config.project_id = random_id()?;
        }
        if request.action == ProjectAction::UpdateConfig {
            let previous: ProjectConfig = read_json(&access, &config_path, MAX_CONFIG_BYTES)?;
            if config.project_id.is_empty() {
                config.project_id = previous.project_id;
            } else if config.project_id != previous.project_id {
                return Err(Error::Input(
                    "Project configuration updates preserve the stable project identifier".into(),
                ));
            }
        }
        validate_config(&config, false)?;
        let source = files::absolute(&config.source_root, parent)?;
        let output = files::absolute(&config.output_directory, parent)?;
        if files::relative_to(&source, &output).is_some() {
            return Err(Error::Input(
                "Project output must be outside or below its source directory".into(),
            ));
        }
        if request.scope.is_some() && request.state_directory.is_none() {
            return Err(files::blocked(
                "MCP project access requires an explicitly authorized private state directory",
            ));
        }
        let state = files::absolute(
            &request
                .state_directory
                .clone()
                .map(Ok)
                .unwrap_or_else(|| state_directory(&config.project_id))?,
            parent,
        )?;
        if files::relative_to(&state, parent).is_some()
            || files::relative_to(&state, &source).is_some()
            || files::relative_to(&state, &output).is_some()
            || files::relative_to(&output, &state).is_some()
        {
            return Err(Error::Input(
                "Private project state must be outside project sources and distribution folders"
                    .into(),
            ));
        }
        access.check(&source, false)?;
        let writing = matches!(
            request.action,
            ProjectAction::Init | ProjectAction::UpdateConfig | ProjectAction::Sync
        );
        access.check(&output, writing)?;
        access.check(&state, writing)?;
        access.directory(&source, false, false)?;
        if matches!(
            request.action,
            ProjectAction::Init | ProjectAction::UpdateConfig
        ) {
            access.check(&config_path, true)?;
        }
        if request.scope.is_some()
            && (request.options.git_ref.is_some()
                || request.options.trigger == Some(ProjectTrigger::Git))
        {
            return Err(files::blocked(
                "MCP project sync does not execute Git or access protected Git internals",
            ));
        }
        if let Some(commit) = &request.options.git_ref
            && (!matches!(commit.len(), 40 | 64) || !commit.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(Error::Input(
                "Project Git provenance requires a resolved commit SHA".into(),
            ));
        }
        let mut budget = Budget {
            files: config.max_files,
            file_bytes: config.max_file_bytes,
            total_bytes: config.max_total_bytes,
        };
        if request.scope.is_some() {
            budget.files = budget.files.min(limits.max_members);
            budget.file_bytes = budget.file_bytes.min(limits.max_file_bytes);
            budget.total_bytes = budget.total_bytes.min(limits.max_uncompressed_bytes);
        }
        if request.options.expected_source_sha256.len() > budget.files {
            return Err(files::blocked(
                "Expected-source constraints exceed the project file budget",
            ));
        }
        for (path, expected) in &request.options.expected_source_sha256 {
            if files::relative_name(Path::new(path))? != *path || !valid_sha256(expected) {
                return Err(Error::Input("Expected-source constraints require canonical relative paths and SHA-256 digests".into()));
            }
        }
        let patterns = |values: &[String]| -> Result<Vec<glob::Pattern>> {
            values
                .iter()
                .map(|value| {
                    glob::Pattern::new(value)
                        .map_err(|_| Error::Input("Invalid project pattern".into()))
                })
                .collect()
        };
        let include = patterns(&config.include)?;
        let exclude = patterns(&config.exclude)?;
        let rules = config
            .rules
            .iter()
            .map(|rule| {
                Ok((
                    glob::Pattern::new(&rule.pattern)
                        .map_err(|_| Error::Input("Invalid project pattern".into()))?,
                    rule.clone(),
                ))
            })
            .collect::<Result<_>>()?;
        let config_sha256 = digest(&signing::canonical(&config)?);
        Ok(Self {
            access,
            config_path,
            config,
            config_sha256,
            source,
            output,
            state,
            budget,
            include,
            exclude,
            rules,
        })
    }
    fn namespace(&self) -> PathBuf {
        self.output.join(&self.config.project_id)
    }
    fn load_state(&self) -> Result<Option<State>> {
        let path = self.state.join(STATE_NAME);
        if !path.exists() {
            return Ok(None);
        }
        let state: State = read_json(&self.access, &path, MAX_PRIVATE_STATE_BYTES)?;
        if state.schema != "fileveil.project.state.v1"
            || state.project_id != self.config.project_id
            || state.keys.len() > 256
            || state.keys.iter().any(|key| key.public.key_id.is_empty())
        {
            return Err(Error::Input("Invalid private project state".into()));
        }
        Ok(Some(state))
    }
    fn approved(&self, state: &Option<State>, automatic: bool) -> Result<()> {
        if automatic
            && state
                .as_ref()
                .is_none_or(|state| state.approved_config_sha256 != self.config_sha256)
        {
            return Err(files::blocked(
                "Project configuration changed. Save or explicitly sync the selected configuration before resuming automatic processing",
            ));
        }
        Ok(())
    }
    fn mode(&self, name: &str) -> ProjectRule {
        self.rules
            .iter()
            .rev()
            .find(|(pattern, _)| {
                pattern.matches_with(
                    name,
                    glob::MatchOptions {
                        case_sensitive: false,
                        require_literal_separator: true,
                        require_literal_leading_dot: false,
                    },
                )
            })
            .map(|(_, rule)| rule.clone())
            .unwrap_or_default()
    }
    fn inventory(&self, hash_bytes: bool, flag: &AtomicBool) -> Result<Inventory> {
        self.inventory_cached(hash_bytes, None, flag)
    }
    fn inventory_cached(
        &self,
        hash_bytes: bool,
        cache: Option<&BTreeMap<String, CachedFile>>,
        flag: &AtomicBool,
    ) -> Result<Inventory> {
        let root = self.access.directory(&self.source, false, false)?;
        let mut samples = BTreeMap::new();
        let mut metadata = Vec::new();
        let mut visited = 0usize;
        let mut total = 0u64;
        self.walk(
            &root,
            Path::new(""),
            hash_bytes,
            cache,
            flag,
            &mut samples,
            &mut metadata,
            &mut visited,
            &mut total,
        )?;
        let fingerprint = if hash_bytes {
            digest(&signing::canonical(
                &samples
                    .iter()
                    .map(|(path, sample)| {
                        (
                            path,
                            &sample.sha256,
                            sample.stamp.size,
                            source_executable(sample),
                        )
                    })
                    .collect::<Vec<_>>(),
            )?)
        } else {
            digest(
                &serde_json::to_vec(&(self.config_sha256.clone(), metadata))
                    .map_err(|_| Error::Input("Could not serialize watch fingerprint".into()))?,
            )
        };
        Ok(Inventory {
            samples,
            fingerprint,
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn walk(
        &self,
        directory: &Directory,
        relative: &Path,
        hash_bytes: bool,
        cache: Option<&BTreeMap<String, CachedFile>>,
        flag: &AtomicBool,
        samples: &mut BTreeMap<String, Sample>,
        metadata: &mut Vec<(String, files::Stamp)>,
        visited: &mut usize,
        total: &mut u64,
    ) -> Result<()> {
        if relative.components().count() > 128 {
            return Err(files::blocked(
                "Project directory nesting exceeds its limit",
            ));
        }
        for name in directory.list(self.budget.files.saturating_mul(8).max(128))? {
            files::cancelled(flag)?;
            *visited += 1;
            if *visited > self.budget.files.saturating_mul(8).max(128) {
                return Err(files::blocked("Project traversal entry budget exceeded"));
            }
            let path = directory.path.join(&name);
            let child_relative = relative.join(&name);
            let label = files::relative_name(&child_relative)?;
            if name == ".git"
                || path == self.config_path
                || files::relative_to(&path, &self.output).is_some()
                || files::relative_to(&path, &self.state).is_some()
                || self.exclude.iter().any(|pattern| {
                    matches(pattern, &label) || matches(pattern, &format!("{label}/"))
                })
            {
                continue;
            }
            if self.access_scope_sensitive(&path) {
                return Err(files::blocked(
                    "A selected project file is inside a protected sensitive path",
                ));
            }
            let info = fs::symlink_metadata(directory.child_path(&name)?)
                .map_err(|_| files::blocked("Could not inspect project entry"))?;
            if info.file_type().is_symlink() || reparse(&info) {
                return Err(files::blocked(
                    "Project sources contain a symbolic link or reparse point",
                ));
            }
            if info.is_dir() {
                self.walk(
                    &directory.child(&name, false)?,
                    &child_relative,
                    hash_bytes,
                    cache,
                    flag,
                    samples,
                    metadata,
                    visited,
                    total,
                )?;
            } else {
                if !info.is_file() {
                    return Err(files::blocked(
                        "Project sources contain a special filesystem object",
                    ));
                }
                if !self.include.iter().any(|pattern| matches(pattern, &label)) {
                    continue;
                }
                if samples.len() >= self.budget.files {
                    return Err(files::blocked("Project file-count budget exceeded"));
                }
                let current_stamp = files::stamp(&self.access.open(&path)?)?;
                let sample = if hash_bytes {
                    if let Some(cached) = cache
                        .and_then(|cache| cache.get(&label))
                        .filter(|cached| cached.stamp == current_stamp)
                    {
                        Sample {
                            sha256: cached.sha256.clone(),
                            stamp: current_stamp,
                            fresh: false,
                        }
                    } else {
                        self.access.hash(&path, self.budget.file_bytes, flag)?
                    }
                } else {
                    Sample {
                        sha256: String::new(),
                        stamp: current_stamp,
                        fresh: false,
                    }
                };
                if sample.stamp.size > self.budget.file_bytes {
                    return Err(files::blocked(
                        "Project file exceeds its streaming byte budget",
                    ));
                }
                *total = total.saturating_add(sample.stamp.size);
                if *total > self.budget.total_bytes {
                    return Err(files::blocked(
                        "Project aggregate streaming budget exceeded",
                    ));
                }
                metadata.push((label.clone(), sample.stamp.clone()));
                samples.insert(label, sample);
            }
        }
        Ok(())
    }
    fn access_scope_sensitive(&self, path: &Path) -> bool {
        self.access_is_scoped() && files::sensitive(path)
    }
    fn access_is_scoped(&self) -> bool {
        self.budget.file_bytes < self.config.max_file_bytes || self.access.scoped()
    }
}
fn source_executable(sample: &Sample) -> Option<bool> {
    #[cfg(unix)]
    {
        Some(sample.stamp.executable)
    }
    #[cfg(not(unix))]
    {
        let _ = sample;
        None
    }
}
fn reparse(info: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        info.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        let _ = info;
        false
    }
}
fn matches(pattern: &glob::Pattern, path: &str) -> bool {
    pattern.matches_with(
        path,
        glob::MatchOptions {
            case_sensitive: true,
            require_literal_separator: true,
            require_literal_leading_dot: false,
        },
    )
}

fn load_generation(context: &Context, name: &str) -> Result<Generation> {
    read_generation(context, name, true)
}
fn read_generation(context: &Context, name: &str, committed: bool) -> Result<Generation> {
    if name.len() > 128 || name.contains(['/', '\\', ':']) || name.starts_with('.') {
        return Err(Error::Input("Invalid project generation name".into()));
    }
    let path = context.namespace().join(name);
    let bytes = context
        .access
        .read(&path.join("manifest.json"), MAX_MANIFEST_BYTES)?;
    let manifest_sha256 = digest(&bytes);
    if committed && context.access.read(&path.join("COMMITTED"), 128)? != manifest_sha256.as_bytes()
    {
        return Err(Error::Verification(
            "Project commit marker does not bind its manifest".into(),
        ));
    }
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .map_err(|_| Error::Input("Invalid project manifest".into()))?;
    if manifest.schema != "fileveil.project.manifest.v1"
        || manifest.project_id != context.config.project_id
        || manifest.revision == 0
        || manifest.files.len() > context.budget.files
        || manifest.changes.len() > context.budget.files.saturating_mul(2)
    {
        return Err(Error::Input(
            "Project manifest identity or file count is invalid".into(),
        ));
    }
    let evidence_bytes = context.access.read(
        &path.join("evidence.json"),
        custody::MAX_EVIDENCE_BYTES as u64,
    )?;
    let evidence = custody::parse_evidence(&evidence_bytes)?;
    let evidence_sha256 = digest(&evidence_bytes);
    let checked = custody::verify_evidence(&evidence, &TrustStore::default(), &[], None)?;
    let last = evidence
        .body
        .records
        .last()
        .ok_or_else(|| Error::Verification("Project evidence has no records".into()))?;
    if checked.package_signature != VerificationState::Valid
        || checked.custody_signer != VerificationState::Valid
        || checked.chain.signature != VerificationState::Valid
        || checked.chain.chain != VerificationState::Valid
        || !checked.asset_declarations_bound
        || last.body.content_sha256 != manifest_sha256
        || last.body.work_id != manifest.work_id
        || last.body.copy_id.as_deref() != Some(manifest.copy_id.as_str())
        || last.body.version != manifest.version
        || !evidence
            .body
            .assets
            .iter()
            .any(|asset| asset.sha256 == manifest_sha256 && asset.size_bytes == bytes.len() as u64)
    {
        return Err(Error::Verification(
            "Project manifest signature, content binding or custody chain is invalid".into(),
        ));
    }
    let mut names = BTreeSet::new();
    for entry in &manifest.files {
        if files::relative_name(Path::new(&entry.path))? != entry.path
            || !names.insert(entry.path.to_ascii_lowercase())
            || entry.file_id.len() != 32
            || entry.source_sha256.len() != 64
        {
            return Err(Error::Input(
                "Invalid or colliding project manifest path".into(),
            ));
        }
    }
    let mut derived_names = BTreeSet::new();
    if manifest
        .derived_artifacts
        .len()
        .saturating_add(manifest.files.len())
        > context.budget.files
    {
        return Err(files::blocked(
            "Project derived artifact count exceeds its budget",
        ));
    }
    for entry in &manifest.derived_artifacts {
        if files::relative_name(Path::new(&entry.path))? != entry.path
            || !derived_names.insert(entry.path.to_ascii_lowercase())
            || !valid_sha256(&entry.sha256)
            || entry
                .source_sha256
                .as_ref()
                .is_some_and(|hash| !valid_sha256(hash))
            || entry.size_bytes > context.budget.file_bytes
        {
            return Err(Error::Input("Invalid derived artifact declaration".into()));
        }
    }
    if manifest
        .files
        .iter()
        .map(|entry| entry.source_size)
        .chain(
            manifest
                .derived_artifacts
                .iter()
                .map(|entry| entry.size_bytes),
        )
        .try_fold(0u64, |total, size| total.checked_add(size))
        .is_none_or(|total| total > context.budget.total_bytes)
    {
        return Err(files::blocked(
            "Project manifest exceeds its aggregate release budget",
        ));
    }
    Ok(Generation {
        name: name.into(),
        path,
        manifest,
        manifest_sha256,
        evidence,
        evidence_sha256,
    })
}
fn generations(context: &Context) -> Result<History> {
    let namespace = context.namespace();
    let mut history = History {
        latest: None,
        initial_key: None,
        copies: BTreeSet::new(),
        count: 0,
        cached_tip: false,
        metadata: Vec::new(),
    };
    if !namespace.exists() {
        return Ok(history);
    }
    let root = context.access.directory(&namespace, false, false)?;
    let mut total = 0u64;
    for name in root.list(context.budget.files.max(128))? {
        let name = name
            .to_str()
            .ok_or_else(|| Error::Input("Invalid generation name".into()))?;
        if name.starts_with('.') {
            continue;
        }
        if !root
            .child_path(OsStr::new(name))?
            .join("COMMITTED")
            .exists()
        {
            continue;
        }
        let generation = load_generation(context, name)?;
        total = total.saturating_add(signing::canonical(&generation.evidence)?.len() as u64);
        if total > context.budget.total_bytes.min(512 * 1024 * 1024) {
            return Err(files::blocked(
                "Project history exceeds its verification budget",
            ));
        }
        let current = &generation;
        if current.name
            != format!(
                "{:012}-{}",
                current.manifest.revision,
                &current.manifest_sha256[..16]
            )
            || current.manifest.revision != history.count as u64 + 1
        {
            return Err(Error::Verification(
                "Project generation history has a gap or duplicate revision".into(),
            ));
        }
        if let Some(previous) = &history.latest {
            if current.manifest.previous_manifest_sha256.as_ref() != Some(&previous.manifest_sha256)
                || current.manifest.previous_generation.as_ref() != Some(&previous.name)
            {
                return Err(Error::Verification(
                    "Project predecessor reference is invalid".into(),
                ));
            }
            let previous_record = previous.evidence.body.records.last().unwrap();
            let active = active_key(previous_record);
            if current.manifest.segment == previous.manifest.segment {
                let old = &previous.evidence.body.records;
                if current.evidence.body.records.len() <= old.len()
                    || signing::canonical_records(&current.evidence.body.records[..old.len()])?
                        != signing::canonical_records(old)?
                {
                    return Err(Error::Verification(
                        "Project history discarded or replaced a predecessor signature".into(),
                    ));
                }
            } else {
                let first = &current.evidence.body.records[0];
                if current.manifest.segment != previous.manifest.segment + 1
                    || first.body.actor_key_id != active
                    || current
                        .manifest
                        .migration_from_work_id
                        .as_ref()
                        .is_some_and(|work| work != &previous.manifest.work_id)
                {
                    return Err(Error::Verification(
                        "Project segment transition is unauthorized".into(),
                    ));
                }
                if current.manifest.work_id == previous.manifest.work_id
                    && (first.body.content_sha256 != previous.manifest_sha256
                        || first.body.work_id != previous.manifest.work_id)
                {
                    return Err(Error::Verification(
                        "Project segment checkpoint does not bind its predecessor".into(),
                    ));
                }
                if current.manifest.work_id != previous.manifest.work_id
                    && current.manifest.migration_from_work_id.as_ref()
                        != Some(&previous.manifest.work_id)
                {
                    return Err(Error::Verification(
                        "Project work migration lacks a signed predecessor declaration".into(),
                    ));
                }
            }
        } else {
            if current.manifest.previous_generation.is_some()
                || current.manifest.previous_manifest_sha256.is_some()
                || current.manifest.segment != 0
            {
                return Err(Error::Verification(
                    "Project creation history has an unexpected predecessor".into(),
                ));
            }
            let first = &current.evidence.body.records[0];
            let signature = first
                .signatures
                .iter()
                .find(|signature| signature.key_id == first.body.actor_key_id)
                .ok_or_else(|| {
                    Error::Verification("Project creation actor signature is missing".into())
                })?;
            history.initial_key = Some(PublicKey {
                key_id: signature.key_id.clone(),
                ed25519_hex: signature.public_key_hex.clone(),
            });
        }
        history.copies.insert(current.manifest.copy_id.clone());
        history.count += 1;
        history.metadata.push(history_metadata(&generation));
        history.latest = Some(generation);
    }
    Ok(history)
}
fn active_key(record: &SignedRecord) -> &str {
    record
        .body
        .rotation_to_key_id
        .as_deref()
        .or(record.body.transfer_to_key_id.as_deref())
        .unwrap_or(&record.body.actor_key_id)
}

fn checkpoint_is_current(context: &Context, name: &str, revision: u64) -> Result<bool> {
    let namespace = context
        .access
        .directory(&context.namespace(), false, false)?;
    let mut committed = 0u64;
    for candidate in namespace.list(context.budget.files.max(128))? {
        let candidate = candidate
            .to_str()
            .ok_or_else(|| Error::Input("Invalid generation name".into()))?;
        if candidate.starts_with('.')
            || !namespace
                .child_path(OsStr::new(candidate))?
                .join("COMMITTED")
                .exists()
        {
            continue;
        }
        committed += 1;
        if candidate > name {
            return Ok(false);
        }
    }
    Ok(committed == revision)
}

fn current_history(context: &Context, state: Option<&State>, force_full: bool) -> Result<History> {
    if !force_full
        && let Some(state) = state
        && let (Some(name), Some(hash), Some(evidence_hash)) = (
            &state.index_generation,
            &state.index_manifest_sha256,
            &state.index_evidence_sha256,
        )
        && context.namespace().join(name).join("COMMITTED").exists()
    {
        let generation = load_generation(context, name)?;
        if generation.manifest_sha256 == *hash
            && generation.evidence_sha256 == *evidence_hash
            && generation.name
                == format!(
                    "{:012}-{}",
                    generation.manifest.revision,
                    &generation.manifest_sha256[..16]
                )
            && checkpoint_is_current(context, name, generation.manifest.revision)?
        {
            let count = usize::try_from(generation.manifest.revision)
                .map_err(|_| files::blocked("Project revision exceeds this platform's capacity"))?;
            let metadata = vec![history_metadata(&generation)];
            return Ok(History {
                latest: Some(generation),
                initial_key: Some(state.initial_key.clone()),
                copies: state.known_copies.iter().cloned().collect(),
                count,
                cached_tip: true,
                metadata,
            });
        }
    }
    generations(context)
}

fn normalize_key(key: &ProjectKey, base: &Path) -> Result<ProjectKey> {
    Ok(match key {
        ProjectKey::File { path } => ProjectKey::File {
            path: files::absolute(path, base)?,
        },
        ProjectKey::System { key_id } => ProjectKey::System {
            key_id: key_id.clone(),
        },
    })
}
fn load_key(context: &Context, key: &ProjectKey) -> Result<SigningKey> {
    context.access.key(key)?;
    match key {
        ProjectKey::File { path } => {
            if path.starts_with(context.config_path.parent().unwrap())
                || path.starts_with(&context.source)
                || path.starts_with(&context.output)
            {
                return Err(files::blocked(
                    "Private signing keys must be stored outside project sources and release folders",
                ));
            }
            let file = context.access.open(path)?;
            crate::access_guard::with_bound_files(vec![(path.clone(), file)], || {
                SigningKey::load(path)
            })
        }
        ProjectKey::System { key_id } => key_store::load(&key_store::KeyStoreRef {
            key_id: key_id.clone(),
        }),
    }
}
fn selected_key(
    context: &Context,
    request: &ProjectRequest,
    state: &State,
    active: &str,
) -> Result<(ProjectKey, SigningKey)> {
    if let Some(source) = &request.options.rotate_to {
        let source = normalize_key(source, context.config_path.parent().unwrap())?;
        let key = load_key(context, &source)?;
        if key.public_key().key_id == active {
            return Ok((source, key));
        }
    }
    let source = request
        .key
        .as_ref()
        .map(|source| normalize_key(source, context.config_path.parent().unwrap()))
        .transpose()?
        .or_else(|| {
            state
                .keys
                .iter()
                .find(|key| key.public.key_id == active)
                .map(|key| key.source.clone())
        });
    if let Some(source) = source {
        let key = load_key(context, &source)?;
        if key.public_key().key_id == active {
            return Ok((source, key));
        }
        return Err(files::blocked(
            "Selected key differs from the active project custodian. Select the current key or explicitly rotate to the new key",
        ));
    }
    Err(files::blocked(
        "The active project custodian key is unavailable. Select the matching local key",
    ))
}
fn validated_index(
    state: &State,
    previous: Option<&Generation>,
    force_full: bool,
) -> BTreeMap<String, CachedFile> {
    let Some(previous) = previous.filter(|previous| {
        !force_full
            && state.index_generation.as_ref() == Some(&previous.name)
            && state.index_manifest_sha256.as_ref() == Some(&previous.manifest_sha256)
    }) else {
        return BTreeMap::new();
    };
    previous
        .manifest
        .files
        .iter()
        .filter_map(|entry| {
            state
                .index
                .get(&entry.path)
                .filter(|cached| {
                    cached.sha256 == entry.source_sha256 && cached.stamp.size == entry.source_size
                })
                .map(|cached| (entry.path.clone(), cached.clone()))
        })
        .collect()
}
fn save_index(state: &mut State, inventory: &Inventory) {
    state.index = inventory
        .samples
        .iter()
        .map(|(path, sample)| {
            (
                path.clone(),
                CachedFile {
                    sha256: sample.sha256.clone(),
                    stamp: sample.stamp.clone(),
                },
            )
        })
        .collect();
    state.index_dirty = true;
}
fn load_index(context: &Context, state: &mut State) {
    let path = context.state.join("source-index.json");
    if !path.exists() {
        return;
    }
    if let Ok(cache) = read_json::<IndexCache>(&context.access, &path, MAX_INDEX_BYTES)
        && Some(&cache.generation) == state.index_generation.as_ref()
        && Some(&cache.manifest_sha256) == state.index_manifest_sha256.as_ref()
        && cache.files.len() <= context.budget.files
    {
        state.index = cache.files;
        state.output_index = cache.outputs;
    }
}
fn persist_state(context: &Context, state: &State) -> Result<()> {
    if state.index_dirty {
        let cache = IndexCache {
            generation: state.index_generation.clone().ok_or_else(|| {
                Error::Verification("Project index has no generation binding".into())
            })?,
            manifest_sha256: state.index_manifest_sha256.clone().ok_or_else(|| {
                Error::Verification("Project index has no signed manifest binding".into())
            })?,
            files: state.index.clone(),
            outputs: state.output_index.clone(),
        };
        let bytes = serde_json::to_vec(&cache)
            .map_err(|_| Error::Input("Could not encode private project index".into()))?;
        if bytes.len() as u64 > MAX_INDEX_BYTES {
            return Err(files::blocked(
                "Private project index exceeds its byte budget",
            ));
        }
        context
            .access
            .replace(&context.state.join("source-index.json"), &bytes)?;
    }
    let bytes = json_bytes(state)?;
    if bytes.len() as u64 > MAX_PRIVATE_STATE_BYTES {
        return Err(files::blocked(
            "Private project binding exceeds its byte budget",
        ));
    }
    context
        .access
        .replace(&context.state.join(STATE_NAME), &bytes)
}
fn bind_key(state: &mut State, source: ProjectKey, key: &SigningKey) -> Result<()> {
    let public = key.public_key();
    if let Some(bound) = state
        .keys
        .iter_mut()
        .find(|bound| bound.public.key_id == public.key_id)
    {
        bound.source = source;
    } else {
        if state.keys.len() >= 256 {
            return Err(files::blocked("Project key-binding limit reached"));
        }
        state.keys.push(BoundKey { public, source });
    }
    Ok(())
}
fn changes(
    inventory: &Inventory,
    previous: Option<&Generation>,
) -> Result<(Vec<Entry>, Vec<Change>, usize)> {
    let old: BTreeMap<&str, &Entry> = previous
        .map(|generation| {
            generation
                .manifest
                .files
                .iter()
                .map(|entry| (entry.path.as_str(), entry))
                .collect()
        })
        .unwrap_or_default();
    let mut removed: BTreeMap<String, Vec<&Entry>> = BTreeMap::new();
    for entry in old
        .values()
        .filter(|entry| !inventory.samples.contains_key(&entry.path))
    {
        removed
            .entry(entry.source_sha256.clone())
            .or_default()
            .push(entry);
    }
    let mut output = Vec::new();
    let mut changes = Vec::new();
    let mut unchanged = 0;
    for (path, sample) in &inventory.samples {
        let prior = old.get(path.as_str()).copied();
        let renamed = if prior.is_none() {
            removed
                .get_mut(&sample.sha256)
                .filter(|values| values.len() == 1)
                .and_then(Vec::pop)
        } else {
            None
        };
        let predecessor = prior.or(renamed);
        let file_id = predecessor
            .map(|entry| entry.file_id.clone())
            .map(Ok)
            .unwrap_or_else(random_id)?;
        let kind = if renamed.is_some() {
            "renamed"
        } else if prior.is_none() {
            "added"
        } else if prior.is_some_and(|entry| {
            entry.source_sha256 != sample.sha256
                || entry
                    .source_executable
                    .zip(source_executable(sample))
                    .is_some_and(|(old, new)| old != new)
        }) {
            "modified"
        } else {
            unchanged += 1;
            "unchanged"
        };
        if kind != "unchanged" {
            changes.push(Change {
                kind: kind.into(),
                path: path.clone(),
                previous_path: renamed.map(|entry| entry.path.clone()),
                file_id: file_id.clone(),
            });
        }
        output.push(Entry {
            path: path.clone(),
            file_id,
            source_sha256: sample.sha256.clone(),
            source_size: sample.stamp.size,
            source_executable: source_executable(sample),
            mode: ProjectFileMode::External,
            output_sha256: None,
            output_size: None,
            previous_source_sha256: predecessor.map(|entry| entry.source_sha256.clone()),
            signer_key_id: None,
        });
    }
    for entry in removed.values().flatten() {
        changes.push(Change {
            kind: "deleted".into(),
            path: entry.path.clone(),
            previous_path: None,
            file_id: entry.file_id.clone(),
        });
    }
    Ok((output, changes, unchanged))
}
struct PayloadAssessment {
    valid: bool,
    index: BTreeMap<String, CachedFile>,
}
fn payload_layout(context: &Context, generation: &Generation, flag: &AtomicBool) -> Result<bool> {
    let mut expected = BTreeSet::from(["manifest.json".to_string(), "evidence.json".to_string()]);
    if generation.path.join("COMMITTED").exists() {
        expected.insert("COMMITTED".into());
    }
    expected.extend(
        generation
            .manifest
            .files
            .iter()
            .filter(|entry| entry.output_sha256.is_some())
            .map(|entry| format!("files/{}", entry.path)),
    );
    expected.extend(
        generation
            .manifest
            .derived_artifacts
            .iter()
            .map(|entry| format!("derived/{}", entry.path)),
    );
    let root = context.access.directory(&generation.path, false, false)?;
    let mut visited = 0usize;
    payload_directory(
        &root,
        Path::new(""),
        &expected,
        &mut visited,
        context.budget.files.saturating_mul(8).max(128),
        flag,
    )
}
fn payload_directory(
    directory: &Directory,
    relative: &Path,
    expected: &BTreeSet<String>,
    visited: &mut usize,
    cap: usize,
    flag: &AtomicBool,
) -> Result<bool> {
    if relative.components().count() > 128 {
        return Ok(false);
    }
    for name in directory.list(cap)? {
        files::cancelled(flag)?;
        *visited += 1;
        if *visited > cap {
            return Err(files::blocked(
                "Release layout exceeds its traversal budget",
            ));
        }
        let relative = relative.join(&name);
        let label = files::relative_name(&relative)?;
        let info = fs::symlink_metadata(directory.child_path(&name)?)
            .map_err(|_| files::blocked("Could not inspect release layout"))?;
        if info.file_type().is_symlink() || reparse(&info) {
            return Ok(false);
        }
        if info.is_dir() {
            let prefix = format!("{label}/");
            if !expected
                .range(prefix.clone()..)
                .next()
                .is_some_and(|entry| entry.starts_with(&prefix))
                || !payload_directory(
                    &directory.child(&name, false)?,
                    &relative,
                    expected,
                    visited,
                    cap,
                    flag,
                )?
            {
                return Ok(false);
            }
        } else if !info.is_file() || !expected.contains(&label) {
            return Ok(false);
        }
    }
    Ok(true)
}
#[allow(clippy::too_many_arguments)]
fn verify_payload(
    context: &Context,
    generation: &Generation,
    inventory: &Inventory,
    limits: &Limits,
    flag: &AtomicBool,
    verify_sources: bool,
    cache: Option<&BTreeMap<String, CachedFile>>,
) -> Result<PayloadAssessment> {
    let mut index = BTreeMap::new();
    if !payload_layout(context, generation, flag)? {
        return Ok(PayloadAssessment {
            valid: false,
            index,
        });
    }
    let expected: BTreeMap<_, _> = generation
        .manifest
        .files
        .iter()
        .map(|entry| (&entry.path, entry))
        .collect();
    if verify_sources
        && (expected.len() != inventory.samples.len()
            || inventory.samples.iter().any(|(path, sample)| {
                expected.get(path).is_none_or(|entry| {
                    entry.source_sha256 != sample.sha256
                        || entry.source_size != sample.stamp.size
                        || entry
                            .source_executable
                            .zip(source_executable(sample))
                            .is_some_and(|(old, new)| old != new)
                })
            }))
    {
        return Ok(PayloadAssessment {
            valid: false,
            index,
        });
    }
    for entry in &generation.manifest.files {
        if let Some(expected) = &entry.output_sha256 {
            let path = generation.path.join("files").join(&entry.path);
            let current = files::stamp(&context.access.open(&path)?)?;
            let sample = if let Some(cached) = cache
                .and_then(|cache| cache.get(&entry.path))
                .filter(|cached| cached.sha256 == *expected && cached.stamp == current)
            {
                Sample {
                    sha256: cached.sha256.clone(),
                    stamp: current,
                    fresh: false,
                }
            } else {
                context
                    .access
                    .hash(&path, context.budget.file_bytes, flag)?
            };
            if sample.sha256 != *expected || Some(sample.stamp.size) != entry.output_size {
                return Ok(PayloadAssessment {
                    valid: false,
                    index,
                });
            }
            if entry.mode != ProjectFileMode::External && sample.fresh {
                let request = heritage::HeritageRequest {
                    action: heritage::HeritageAction::Verify,
                    ..Default::default()
                };
                let file = context.access.open(&path)?;
                let report =
                    crate::access_guard::with_bound_files(vec![(path.clone(), file)], || {
                        heritage::run(&path, None, &request, limits)
                    })?;
                let checked = &report.advanced.as_ref().ok_or_else(|| {
                    Error::Verification("Embedded release verification is absent".into())
                })?["heritage"]["verification"];
                if checked["signature"] != "valid"
                    || checked["content_binding"] != "valid"
                    || checked["chain"] != "valid"
                {
                    return Ok(PayloadAssessment {
                        valid: false,
                        index,
                    });
                }
            }
            if files::stamp(&context.access.open(&path)?)? != sample.stamp {
                return Err(files::blocked("Release output changed during verification"));
            }
            index.insert(
                entry.path.clone(),
                CachedFile {
                    sha256: sample.sha256,
                    stamp: sample.stamp,
                },
            );
        }
    }
    for entry in &generation.manifest.derived_artifacts {
        let path = generation.path.join("derived").join(&entry.path);
        let current = files::stamp(&context.access.open(&path)?)?;
        let cache_key = format!("derived/{}", entry.path);
        let sample = if let Some(cached) = cache
            .and_then(|cache| cache.get(&cache_key))
            .filter(|cached| cached.sha256 == entry.sha256 && cached.stamp == current)
        {
            Sample {
                sha256: cached.sha256.clone(),
                stamp: current,
                fresh: false,
            }
        } else {
            context
                .access
                .hash(&path, context.budget.file_bytes, flag)?
        };
        if sample.sha256 != entry.sha256 || sample.stamp.size != entry.size_bytes {
            return Ok(PayloadAssessment {
                valid: false,
                index,
            });
        }
        index.insert(
            cache_key,
            CachedFile {
                sha256: sample.sha256,
                stamp: sample.stamp,
            },
        );
    }
    Ok(PayloadAssessment { valid: true, index })
}
fn details(
    context: &Context,
    request: &ProjectRequest,
    history: &History,
    inventory: &Inventory,
    changes: &[Change],
    unchanged: usize,
    published: bool,
) -> ProjectDetails {
    let latest = history.latest.as_ref();
    let trusted = history.initial_key.as_ref().is_some_and(|key| {
        request
            .options
            .trusted_keys
            .iter()
            .any(|anchor| anchor == key)
    });
    ProjectDetails {
        schema: "fileveil.project.report.v1".into(),
        action: request.action,
        project_id: context.config.project_id.clone(),
        work_id: context.config.work_id.clone(),
        source_fingerprint: inventory.fingerprint.clone(),
        dirty: latest.is_none_or(|latest| {
            latest.manifest.source_fingerprint != inventory.fingerprint
                || latest.manifest.config_sha256 != context.config_sha256
        }),
        generation: latest.map(|latest| latest.name.clone()),
        revision: latest.map(|latest| latest.manifest.revision).unwrap_or(0),
        added: changes
            .iter()
            .filter(|change| change.kind == "added")
            .count(),
        modified: changes
            .iter()
            .filter(|change| change.kind == "modified")
            .count(),
        deleted: changes
            .iter()
            .filter(|change| change.kind == "deleted")
            .count(),
        renamed: changes
            .iter()
            .filter(|change| change.kind == "renamed")
            .count(),
        unchanged,
        published,
        manifest_sha256: latest.map(|latest| latest.manifest_sha256.clone()),
        evidence_sha256: latest.map(|latest| latest.evidence_sha256.clone()),
        integrity: VerificationState::NotAssessed,
        signature: if latest.is_some() {
            VerificationState::Valid
        } else {
            VerificationState::NotAssessed
        },
        trust: if trusted {
            VerificationState::Valid
        } else {
            VerificationState::NotAssessed
        },
        history: if latest.is_some() {
            VerificationState::Valid
        } else {
            VerificationState::NotAssessed
        },
        trust_scope: if trusted {
            "externally_pinned_project_root_key"
        } else {
            "not_assessed"
        }
        .into(),
        config: context.config.clone(),
        effective_limits: json!({"external_stream":{"max_files":context.budget.files,"max_file_bytes":context.budget.file_bytes,"max_total_bytes":context.budget.total_bytes}}),
        fresh_hash_count: inventory
            .samples
            .values()
            .filter(|sample| sample.fresh)
            .count(),
        cached_hash_count: inventory
            .samples
            .values()
            .filter(|sample| !sample.fresh && !sample.sha256.is_empty())
            .count(),
        fresh_hash_bytes: inventory
            .samples
            .values()
            .filter(|sample| sample.fresh)
            .map(|sample| sample.stamp.size)
            .sum(),
        files_total: inventory.samples.len(),
        bytes_total: inventory
            .samples
            .values()
            .map(|sample| sample.stamp.size)
            .sum(),
        source_assessment_scope: if request.action == ProjectAction::WatchProbe {
            "filesystem_metadata_trigger_only"
        } else if inventory.samples.values().any(|sample| !sample.fresh) {
            "metadata_guarded_incremental"
        } else {
            "fresh_streamed_sha256"
        }
        .into(),
    }
}
fn report(
    context: &Context,
    request: &ProjectRequest,
    mut details: ProjectDetails,
    state: Option<&State>,
    history: &History,
    limits: &Limits,
) -> Result<Report> {
    if details.trust == VerificationState::NotAssessed
        && history
            .initial_key
            .as_ref()
            .zip(state)
            .is_some_and(|(key, state)| *key == state.initial_key)
    {
        details.trust = VerificationState::Valid;
        details.trust_scope = "local_initialization_key_pin".into();
    }
    details.effective_limits["embedding"] = json!(limits);
    let mut report = Report::new("project", Format::Unknown);
    report.result = if details.integrity == VerificationState::Invalid {
        Outcome::Failed
    } else if request.action == ProjectAction::WatchProbe {
        Outcome::NotAssessed
    } else if details.signature == VerificationState::NotAssessed
        || matches!(
            request.action,
            ProjectAction::Status | ProjectAction::Verify
        ) && details.dirty
    {
        Outcome::PartiallyVerified
    } else {
        Outcome::VerifiedWithinScope
    };
    report.input_sha256 = if request.action == ProjectAction::WatchProbe {
        None
    } else {
        Some(details.source_fingerprint.clone())
    };
    report.output_sha256 = details.manifest_sha256.clone();
    report.output_name = details.generation.clone();
    let mut value = serde_json::to_value(details)
        .map_err(|_| Error::Input("Could not serialize project report".into()))?;
    value["source_sha256_assessed"] =
        json!(request.action != ProjectAction::WatchProbe && value["cached_hash_count"] == 0);
    value["fingerprint_scope"] = json!(if request.action == ProjectAction::WatchProbe {
        "filesystem_metadata_trigger_only"
    } else if value["cached_hash_count"] != 0 {
        "metadata_guarded_incremental"
    } else {
        "streamed_source_sha256"
    });
    value["historical_asset_bytes"] = json!("not_assessed");
    value["history_assessment_scope"] = json!(if history.cached_tip {
        "current_segment_and_private_checkpoint"
    } else {
        "complete_retained_manifest_chain"
    });
    value["copies"] = json!(history.copies);
    if let Some(latest) = &history.latest {
        value["files"]=json!(latest.manifest.files.iter().take(100).map(|entry|json!({"path":entry.path,"mode":entry.mode,"source_sha256":entry.source_sha256,"output_sha256":entry.output_sha256,"scope":"latest_published_manifest"})).collect::<Vec<_>>());
        value["file_results_total"] = json!(latest.manifest.files.len());
        value["derived_artifacts"] = json!(
            latest
                .manifest
                .derived_artifacts
                .iter()
                .take(100)
                .collect::<Vec<_>>()
        );
        value["derived_artifacts_total"] = json!(latest.manifest.derived_artifacts.len());
        value["observations"] = latest.manifest.observations.clone();
        value["latest_version"] = json!(latest.manifest.version);
        value["latest_copy_id"] = json!(latest.manifest.copy_id);
        value["generation_config_match"] =
            json!(latest.manifest.config_sha256 == context.config_sha256);
        value["published_declaration"] = json!({"work_id":latest.manifest.work_id,"author":latest.manifest.author,"copy_id":latest.manifest.copy_id,"version":latest.manifest.version});
        value["manifest_relative_path"] = json!(format!(
            "{}/{}/manifest.json",
            context.config.project_id, latest.name
        ));
    }
    value["git_commit"] = json!(request.options.git_ref);
    value["configuration_changed"] =
        json!(state.is_some_and(|state| state.approved_config_sha256 != context.config_sha256));
    value["history_metadata"] = json!(history.metadata);
    value["history_metadata_scope"] = json!(if request.action == ProjectAction::WatchProbe {
        "not_assessed"
    } else if history.cached_tip {
        "current_tip_only"
    } else {
        "complete_retained_manifest_chain"
    });
    report.advanced = Some(json!({"project":value}));
    report.warnings.push("Project trust pins identify signing keys. Author identity and trusted time require separate evidence.".into());
    Ok(report)
}

pub(super) fn access_plan(request: &ProjectRequest, limits: &Limits) -> Result<ProjectAccessPlan> {
    let context = Context::new(request, limits)?;
    let inventory = context.inventory(false, &AtomicBool::new(false))?;
    let state = context.load_state()?;
    context.approved(&state, request.options.automatic)?;
    let mut read_paths = vec![context.config_path.clone()];
    if request.action == ProjectAction::Init {
        read_paths.clear();
    }
    let state_path = context.state.join(STATE_NAME);
    if state_path.exists() {
        read_paths.push(state_path);
    }
    if context.state.join("source-index.json").exists() {
        read_paths.push(context.state.join("source-index.json"));
    }
    let mut source_files = Vec::new();
    for name in inventory.samples.keys() {
        source_files.push(context.source.join(name));
    }
    let mut signing_paths = Vec::new();
    let mut signing_key_refs = Vec::new();
    if matches!(request.action, ProjectAction::Init | ProjectAction::Sync) {
        let active = state.as_ref().map(|state| {
            state
                .current_key_id
                .clone()
                .unwrap_or_else(|| state.initial_key.key_id.clone())
        });
        let keys = request
            .key
            .iter()
            .chain(request.options.rotate_to.iter())
            .cloned()
            .chain(state.as_ref().into_iter().flat_map(|state| {
                state
                    .keys
                    .iter()
                    .filter(|bound| {
                        Some(&bound.public.key_id) == active.as_ref() && request.key.is_none()
                    })
                    .map(|bound| bound.source.clone())
            }));
        for key in keys {
            match normalize_key(&key, context.config_path.parent().unwrap())? {
                ProjectKey::File { path } => {
                    context
                        .access
                        .key(&ProjectKey::File { path: path.clone() })?;
                    if !signing_paths.contains(&path) {
                        signing_paths.push(path);
                    }
                }
                ProjectKey::System { key_id } => {
                    context.access.key(&ProjectKey::System {
                        key_id: key_id.clone(),
                    })?;
                    if !signing_key_refs.contains(&key_id) {
                        signing_key_refs.push(key_id);
                    }
                }
            }
        }
    }
    if context.namespace().exists() {
        let namespace = context
            .access
            .directory(&context.namespace(), false, false)?;
        for name in namespace.list(context.budget.files.max(128))? {
            let base = context.namespace().join(name);
            if base.join("COMMITTED").exists() {
                for name in ["COMMITTED", "manifest.json", "evidence.json"] {
                    read_paths.push(base.join(name));
                }
            }
        }
    }
    Ok(ProjectAccessPlan {
        config_path: context.config_path,
        source_root: context.source,
        output_directory: context.output.clone(),
        state_directory: context.state.clone(),
        source_files,
        read_paths,
        write_directories: if matches!(
            request.action,
            ProjectAction::Init | ProjectAction::Sync | ProjectAction::UpdateConfig
        ) {
            vec![context.output, context.state]
        } else {
            Vec::new()
        },
        signing_paths,
        signing_key_refs,
        source_fingerprint: inventory.fingerprint,
        config: context.config,
        source_file_count: inventory.samples.len(),
        source_bytes: inventory
            .samples
            .values()
            .map(|sample| sample.stamp.size)
            .sum(),
    })
}
pub(super) fn watch_fingerprint(request: &ProjectRequest, limits: &Limits) -> Result<String> {
    let context = Context::new(request, limits)?;
    context.approved(&context.load_state()?, request.options.automatic)?;
    Ok(context
        .inventory(false, &AtomicBool::new(false))?
        .fingerprint)
}

pub(super) fn run(request: &ProjectRequest, limits: &Limits, flag: &AtomicBool) -> Result<Report> {
    files::cancelled(flag)?;
    let context = Context::new(request, limits)?;
    if matches!(
        request.action,
        ProjectAction::Init | ProjectAction::UpdateConfig
    ) {
        return configure(context, request, limits, flag);
    }
    let mut state = context.load_state()?;
    context.approved(&state, request.options.automatic)?;
    if request.action == ProjectAction::WatchProbe {
        let inventory = context.inventory(false, flag)?;
        let history = History {
            latest: None,
            initial_key: None,
            copies: BTreeSet::new(),
            count: 0,
            cached_tip: false,
            metadata: Vec::new(),
        };
        return report(
            &context,
            request,
            details(&context, request, &history, &inventory, &[], 0, false),
            state.as_ref(),
            &history,
            limits,
        );
    }
    if request.action == ProjectAction::Sync {
        return sync(context, request, limits, flag);
    }
    let full = request.action == ProjectAction::Verify || request.options.force_full_scan;
    if !full && let Some(state) = &mut state {
        load_index(&context, state);
    }
    let history = current_history(&context, state.as_ref(), full)?;
    let cache = state
        .as_ref()
        .map(|state| validated_index(state, history.latest.as_ref(), full))
        .unwrap_or_default();
    let inventory = context.inventory_cached(true, Some(&cache), flag)?;
    let (_, changes, unchanged) = changes(&inventory, history.latest.as_ref())?;
    let mut result = details(
        &context, request, &history, &inventory, &changes, unchanged, false,
    );
    if let Some(latest) = &history.latest {
        result.integrity = if verify_payload(
            &context,
            latest,
            &inventory,
            limits,
            flag,
            request.action == ProjectAction::Verify,
            if full {
                None
            } else {
                state
                    .as_ref()
                    .filter(|state| {
                        state.index_manifest_sha256.as_ref() == Some(&latest.manifest_sha256)
                    })
                    .map(|state| &state.output_index)
            },
        )?
        .valid
        {
            if result.dirty && request.action == ProjectAction::Status {
                VerificationState::NotAssessed
            } else {
                VerificationState::Valid
            }
        } else {
            VerificationState::Invalid
        };
    }
    report(&context, request, result, state.as_ref(), &history, limits)
}

fn configure(
    context: Context,
    request: &ProjectRequest,
    limits: &Limits,
    flag: &AtomicBool,
) -> Result<Report> {
    let _lock = context.access.lock(&context.state)?;
    let _output_lock = context.access.lock(&context.namespace())?;
    let mut state = context.load_state()?;
    if request.action == ProjectAction::Init {
        if context.config_path.exists() || state.is_some() {
            return Err(Error::Input(
                "Project configuration or private binding already exists".into(),
            ));
        }
        let source = normalize_key(
            request.key.as_ref().ok_or_else(|| {
                Error::Input("Project initialization requires a selected signing key".into())
            })?,
            context.config_path.parent().unwrap(),
        )?;
        let key = load_key(&context, &source)?;
        let public = key.public_key();
        let prior = generations(&context)?;
        if prior.latest.as_ref().is_some_and(|generation| {
            active_key(generation.evidence.body.records.last().unwrap()) != public.key_id
        }) {
            return Err(files::blocked(
                "Restoring an existing project requires its current active signing key",
            ));
        }
        state = Some(State {
            schema: "fileveil.project.state.v1".into(),
            project_id: context.config.project_id.clone(),
            initial_key: prior.initial_key.unwrap_or_else(|| public.clone()),
            current_key_id: Some(public.key_id.clone()),
            keys: vec![BoundKey { public, source }],
            approved_config_sha256: context.config_sha256.clone(),
            index_generation: None,
            index_manifest_sha256: None,
            index_evidence_sha256: None,
            known_copies: prior.copies.into_iter().collect(),
            index: BTreeMap::new(),
            index_dirty: false,
            output_index: BTreeMap::new(),
        });
        persist_state(&context, state.as_ref().unwrap())?;
        context
            .access
            .write_new(&context.config_path, &json_bytes(&context.config)?)?;
    } else {
        let state = state.as_mut().ok_or_else(|| {
            Error::Input("Private project state is unavailable for configuration update".into())
        })?;
        context
            .access
            .replace(&context.config_path, &json_bytes(&context.config)?)?;
        state.approved_config_sha256 = context.config_sha256.clone();
        persist_state(&context, state)?;
    }
    let inventory = context.inventory(true, flag)?;
    let history = generations(&context)?;
    let (_, changes, unchanged) = changes(&inventory, history.latest.as_ref())?;
    report(
        &context,
        request,
        details(
            &context, request, &history, &inventory, &changes, unchanged, false,
        ),
        state.as_ref(),
        &history,
        limits,
    )
}

fn body(context: &Context, manifest: &Manifest, hash: String, key: &SigningKey) -> RecordBody {
    let mut body = RecordBody::new(
        hash,
        manifest.work_id.clone(),
        manifest.author.clone(),
        manifest.version.clone(),
        manifest.created_at.clone(),
        key.public_key().key_id,
    );
    body.schema = signing::SCHEMA_V2.into();
    body.copy_id = Some(manifest.copy_id.clone());
    body.edition = context.config.project_id.clone();
    body
}
fn sign_manifest(
    context: &Context,
    manifest: &Manifest,
    hash: &str,
    previous: Option<&Generation>,
    old_key: &SigningKey,
    new_key: Option<&SigningKey>,
) -> Result<custody::EvidencePackage> {
    let migration = previous.is_some_and(|previous| previous.manifest.work_id != manifest.work_id);
    let segment = previous.is_some_and(|previous| previous.manifest.segment != manifest.segment);
    let mut records = if migration || segment {
        Vec::new()
    } else {
        previous
            .map(|previous| previous.evidence.body.records.clone())
            .unwrap_or_default()
    };
    if records.is_empty() {
        let mut first = body(context, manifest, hash.into(), old_key);
        if segment && !migration {
            let previous = previous.unwrap();
            first.content_sha256 = previous.manifest_sha256.clone();
            first.work_id = previous.manifest.work_id.clone();
            first.author = previous.manifest.author.clone();
            first.version = previous.manifest.version.clone();
            first.copy_id = Some(previous.manifest.copy_id.clone());
        }
        records.push(signing::append_record(&[], first, &[old_key])?);
    }
    let mut active = old_key;
    if let Some(next) = new_key {
        let mut rotation = records.last().unwrap().body.clone();
        rotation.kind = RecordKind::RotateKey;
        rotation.rotation_to_key_id = Some(next.public_key().key_id);
        rotation.created_at = manifest.created_at.clone();
        rotation.actor_key_id = old_key.public_key().key_id;
        records.push(signing::append_record(
            &records,
            rotation,
            &[old_key, next],
        )?);
        active = next;
    }
    if records.last().unwrap().body.copy_id.as_deref() != Some(manifest.copy_id.as_str()) {
        let mut issue = records.last().unwrap().body.clone();
        issue.kind = RecordKind::Issue;
        issue.rotation_to_key_id = None;
        issue.transfer_to_key_id = None;
        issue.copy_id = Some(manifest.copy_id.clone());
        issue.actor_key_id = active.public_key().key_id;
        issue.created_at = manifest.created_at.clone();
        records.push(signing::append_record(&records, issue, &[active])?);
    }
    if records.last().unwrap().body.content_sha256 != hash {
        let mut modification = body(context, manifest, hash.into(), active);
        modification.kind = RecordKind::Modify;
        records.push(signing::append_record(&records, modification, &[active])?);
    }
    custody::create_evidence(
        &records,
        vec![custody::EvidenceAsset {
            version: manifest.version.clone(),
            sha256: hash.into(),
            media_type: "application/vnd.fileveil.project-manifest+json".into(),
            size_bytes: json_bytes(manifest)?.len() as u64,
        }],
        Vec::new(),
        Vec::new(),
        active,
    )
}
#[allow(clippy::too_many_arguments)]
fn mark_copy(
    context: &Context,
    entry: &Entry,
    target: &Path,
    source: &ProjectKey,
    key: &SigningKey,
    rule: &ProjectRule,
    copy_id: &str,
    version: &str,
    created_at: &str,
    limits: &Limits,
) -> Result<()> {
    let input = context.source.join(&entry.path);
    let bytes = context.access.read(&input, limits.max_file_bytes)?;
    let format = fileveil_formats::identify(&bytes, &input);
    if !matches!(
        format,
        Format::Jpeg
            | Format::Png
            | Format::Pdf
            | Format::Docx
            | Format::Xlsx
            | Format::Pptx
            | Format::Heic
            | Format::Avif
    ) || (rule.mode == ProjectFileMode::Invisible
        && !matches!(
            format,
            Format::Jpeg | Format::Png | Format::Heic | Format::Avif
        ))
    {
        return Err(Error::Unsupported(
            "Selected project embedding rule has no compatible file backend".into(),
        ));
    }
    if rule.mode == ProjectFileMode::Invisible {
        let watermark_key = key.derive_watermark_key();
        let signal =
            crate::watermark_engine::inspect(&bytes, format, Some(&*watermark_key), limits)?;
        if signal["primary"]["status"] == "detected" {
            return Err(Error::Blocked(
                "Select an unwatermarked original for project pixel embedding".into(),
            ));
        }
    }
    let parent = context
        .access
        .directory(target.parent().unwrap(), true, true)?;
    let bound_output = parent.child_path(target.file_name().unwrap())?;
    let mut request = heritage::HeritageRequest {
        action: heritage::HeritageAction::Mark,
        ..Default::default()
    };
    request.mark.work_id = format!("{}/{}", context.config.work_id, entry.file_id);
    request.mark.copy_id = copy_id.into();
    request.mark.author = context.config.author.clone();
    request.mark.version = version.into();
    request.mark.created_at = created_at.into();
    request.mark.signature_v2 = true;
    request.mark.watermark_version = 2;
    request.mark.robust = rule.mode == ProjectFileMode::Invisible;
    request.mark.strength = rule.strength;
    let mut bound = vec![(input.clone(), context.access.open(&input)?)];
    match source {
        ProjectKey::File { path } => {
            request.key_paths.push(path.clone());
            bound.push((path.clone(), context.access.open(path)?));
        }
        ProjectKey::System { key_id } => request.key_refs.push(key_store::KeyStoreRef {
            key_id: key_id.clone(),
        }),
    }
    let report = crate::access_guard::with_bound_files(bound, || {
        heritage::run(&input, Some(&bound_output), &request, limits)
    })?;
    if !matches!(
        report.result,
        Outcome::VerifiedWithinScope | Outcome::PartiallyVerified
    ) {
        return Err(Error::Verification(
            "Project embedded mark did not verify".into(),
        ));
    }
    let marked = context.access.read(target, limits.max_file_bytes)?;
    let extracted = heritage::container::extract(&marked, format)?;
    let records = signing::parse_records(
        extracted
            .manifest
            .as_deref()
            .ok_or_else(|| Error::Verification("Project embedded signature is absent".into()))?,
    )?;
    let checked =
        signing::verify_chain(&records, &digest(&extracted.base), &TrustStore::default())?;
    if checked.signature != VerificationState::Valid
        || checked.content_binding != VerificationState::Valid
        || records
            .last()
            .is_none_or(|record| record.body.actor_key_id != key.public_key().key_id)
    {
        return Err(Error::Verification(
            "Project embedded signature does not match its selected project key".into(),
        ));
    }
    Ok(())
}
fn recover_interrupted_release(
    context: &Context,
    state: &mut State,
    limits: &Limits,
    flag: &AtomicBool,
) -> Result<bool> {
    let Some(name) = &state.index_generation else {
        return Ok(false);
    };
    let path = context.namespace().join(name);
    if !path.exists() || path.join("COMMITTED").exists() {
        return Ok(false);
    }
    let pending = read_generation(context, name, false)?;
    if state.index_manifest_sha256.as_ref() != Some(&pending.manifest_sha256)
        || state.index_evidence_sha256.as_ref() != Some(&pending.evidence_sha256)
    {
        return Err(files::blocked(
            "An interrupted release does not match its private verified checkpoint",
        ));
    }
    if pending.manifest.config_sha256 != context.config_sha256 {
        return Ok(false);
    }
    let prior = generations(context)?;
    // A different authorized private state may have committed the next revision
    // while this state retained an uncommitted checkpoint. Never publish that
    // abandoned branch. Rebase only onto a fully checked chain with the same
    // pinned root and the pending checkpoint's exact committed predecessor.
    if pending.manifest.revision <= prior.count as u64 {
        let predecessor_is_retained = if pending.manifest.revision == 1 {
            pending.manifest.previous_generation.is_none()
                && pending.manifest.previous_manifest_sha256.is_none()
        } else {
            prior
                .metadata
                .get((pending.manifest.revision - 2) as usize)
                .is_some_and(|entry| {
                    Some(&entry.generation) == pending.manifest.previous_generation.as_ref()
                        && Some(&entry.manifest_sha256)
                            == pending.manifest.previous_manifest_sha256.as_ref()
                })
        };
        if prior.initial_key.as_ref() != Some(&state.initial_key) || !predecessor_is_retained {
            return Err(files::blocked(
                "An interrupted release cannot rebase onto an unrelated project chain",
            ));
        }
        state.index_generation = None;
        state.index_manifest_sha256 = None;
        state.index_evidence_sha256 = None;
        state.index.clear();
        state.output_index.clear();
        state.index_dirty = false;
        return Ok(false);
    }
    if pending.manifest.revision != prior.count as u64 + 1
        || pending.manifest.previous_generation.as_ref()
            != prior.latest.as_ref().map(|generation| &generation.name)
        || pending.manifest.previous_manifest_sha256.as_ref()
            != prior
                .latest
                .as_ref()
                .map(|generation| &generation.manifest_sha256)
    {
        return Err(files::blocked(
            "An interrupted release has an inconsistent predecessor",
        ));
    }
    let inventory = context.inventory(true, flag)?;
    let payload = verify_payload(context, &pending, &inventory, limits, flag, false, None)?;
    if !payload.valid {
        return Err(files::blocked(
            "An interrupted release contains changed or unlisted output bytes",
        ));
    }
    if !verify_payload(
        context,
        &pending,
        &inventory,
        limits,
        flag,
        true,
        Some(&payload.index),
    )?
    .valid
    {
        return Ok(false);
    }
    files::cancelled(flag)?;
    context
        .access
        .write_new(&path.join("COMMITTED"), pending.manifest_sha256.as_bytes())?;
    Ok(true)
}

fn sync(
    context: Context,
    request: &ProjectRequest,
    limits: &Limits,
    flag: &AtomicBool,
) -> Result<Report> {
    let _lock = context.access.lock(&context.state)?;
    let _output_lock = context.access.lock(&context.namespace())?;
    let mut state = context.load_state()?.ok_or_else(|| {
        files::blocked("Initialize a private project identity before synchronizing")
    })?;
    context.approved(&Some(state.clone()), request.options.automatic)?;
    let recovered = recover_interrupted_release(&context, &mut state, limits, flag)?;
    if !request.options.force_full_scan {
        load_index(&context, &mut state);
    }
    context.approved(&Some(state.clone()), request.options.automatic)?;
    let mut history = current_history(&context, Some(&state), request.options.force_full_scan)?;
    let previous = history.latest.as_ref();
    let mut cache = validated_index(&state, previous, request.options.force_full_scan);
    cache.retain(|path, _| !request.options.expected_source_sha256.contains_key(path));
    let inventory = context.inventory_cached(true, Some(&cache), flag)?;
    for (path, expected) in &request.options.expected_source_sha256 {
        if inventory
            .samples
            .get(path)
            .is_none_or(|sample| !sample.sha256.eq_ignore_ascii_case(expected))
        {
            return Err(Error::Verification(
                "A selected source differs from its required pre-signing SHA-256 snapshot".into(),
            ));
        }
    }
    let (mut entries, changes, unchanged) = changes(&inventory, previous)?;
    let mut source_names = BTreeSet::new();
    if entries
        .iter()
        .any(|entry| !source_names.insert(entry.path.to_ascii_lowercase()))
    {
        return Err(files::blocked(
            "Project source paths collide on a case-insensitive platform",
        ));
    }
    let mut derived_samples = BTreeMap::new();
    let derived = if let Some(artifacts) = &request.derived_artifacts {
        let mut names = BTreeSet::new();
        let mut output = Vec::new();
        for artifact in artifacts {
            files::cancelled(flag)?;
            let name = files::relative_name(Path::new(&artifact.relative_name))?;
            if !names.insert(name.to_ascii_lowercase())
                || !valid_sha256(&artifact.expected_sha256)
                || artifact
                    .source_sha256
                    .as_ref()
                    .is_some_and(|hash| !valid_sha256(hash))
            {
                return Err(Error::Input(
                    "Derived artifact declarations are invalid or collide".into(),
                ));
            }
            text(&artifact.method, "derived artifact method", false)?;
            let path = files::absolute(&artifact.path, context.config_path.parent().unwrap())?;
            let sample = context
                .access
                .hash(&path, context.budget.file_bytes, flag)?;
            if sample.sha256 != artifact.expected_sha256 {
                return Err(Error::Verification(
                    "A derived build artifact differs from its verified digest".into(),
                ));
            }
            output.push(DerivedEntry {
                path: name.clone(),
                sha256: sample.sha256.clone(),
                size_bytes: sample.stamp.size,
                source_sha256: artifact.source_sha256.clone(),
                method: artifact.method.clone(),
            });
            derived_samples.insert(name, (path, sample));
        }
        output.sort_by(|left, right| left.path.cmp(&right.path));
        output
    } else {
        previous
            .map(|previous| previous.manifest.derived_artifacts.clone())
            .unwrap_or_default()
    };
    if entries.len().saturating_add(derived.len()) > context.budget.files
        || inventory
            .samples
            .values()
            .map(|sample| sample.stamp.size)
            .chain(derived.iter().map(|entry| entry.size_bytes))
            .try_fold(0u64, |total, size| total.checked_add(size))
            .is_none_or(|total| total > context.budget.total_bytes)
    {
        return Err(files::blocked(
            "Project sources and derived outputs exceed the shared release budget",
        ));
    }
    let copy_id = request
        .options
        .copy_id
        .as_ref()
        .unwrap_or(&context.config.copy_id)
        .clone();
    text(&copy_id, "copy identifier", false)?;
    let active = previous
        .map(|previous| active_key(previous.evidence.body.records.last().unwrap()))
        .unwrap_or(&state.initial_key.key_id)
        .to_owned();
    let (old_source, old_key) = selected_key(&context, request, &state, &active)?;
    let rotation = request
        .options
        .rotate_to
        .as_ref()
        .map(|source| {
            let source = normalize_key(source, context.config_path.parent().unwrap())?;
            let key = load_key(&context, &source)?;
            Ok((source, key))
        })
        .transpose()?;
    let rotation = rotation.filter(|(_, key)| key.public_key().key_id != active);
    let missing_copies = previous
        .map(|previous| {
            previous
                .manifest
                .files
                .iter()
                .filter(|entry| entry.output_sha256.is_some())
                .try_fold(false, |missing, entry| {
                    match fs::symlink_metadata(previous.path.join("files").join(&entry.path)) {
                        Ok(_) => Ok(missing),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
                        Err(_) => Err(files::blocked(
                            "Could not inspect a retained project release copy",
                        )),
                    }
                })
        })
        .transpose()?
        .unwrap_or(false);
    let dirty = previous.is_none_or(|previous| {
        previous.manifest.source_fingerprint != inventory.fingerprint
            || previous.manifest.config_sha256 != context.config_sha256
            || previous.manifest.copy_id != copy_id
            || (!request.options.version.is_empty()
                && previous.manifest.version != request.options.version)
            || previous.manifest.git_commit != request.options.git_ref
            || previous.manifest.derived_artifacts != derived
            || previous.manifest.observations != request.options.observations
    }) || rotation.is_some()
        || missing_copies;
    if !dirty {
        let mut result = details(
            &context, request, &history, &inventory, &changes, unchanged, recovered,
        );
        let assessment = verify_payload(
            &context,
            previous.unwrap(),
            &inventory,
            limits,
            flag,
            true,
            if request.options.force_full_scan {
                None
            } else {
                Some(&state.output_index)
            },
        )?;
        result.integrity = if assessment.valid {
            VerificationState::Valid
        } else {
            VerificationState::Invalid
        };
        save_index(&mut state, &inventory);
        state.output_index = assessment.index;
        state.index_generation = previous.map(|previous| previous.name.clone());
        state.index_manifest_sha256 = previous.map(|previous| previous.manifest_sha256.clone());
        state.index_evidence_sha256 = previous.map(|previous| previous.evidence_sha256.clone());
        state.current_key_id = Some(active.clone());
        state.approved_config_sha256 = context.config_sha256.clone();
        persist_state(&context, &state)?;
        return report(&context, request, result, Some(&state), &history, limits);
    }
    let revision = previous
        .map(|previous| previous.manifest.revision + 1)
        .unwrap_or(1);
    let version = if request.options.version.is_empty() {
        format!("r{revision:012}")
    } else {
        request.options.version.clone()
    };
    text(&version, "version", false)?;
    if previous.is_some_and(|previous| previous.manifest.version == version) {
        return Err(Error::Input(
            "A published project version already binds different content. Select a new version"
                .into(),
        ));
    }
    let migration =
        previous.is_some_and(|previous| previous.manifest.work_id != context.config.work_id);
    if migration && request.options.automatic && !request.options.allow_work_migration {
        return Err(files::blocked(
            "Automatic work migration requires explicit authorization",
        ));
    }
    let segment = previous
        .map(|previous| {
            previous.manifest.segment
                + u64::from(migration || previous.evidence.body.records.len() + 3 > SEGMENT_RECORDS)
        })
        .unwrap_or(0);
    let created_at = if request.options.created_at.is_empty() {
        format!(
            "unix:{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Input("System time precedes the Unix epoch".into()))?
                .as_secs()
        )
    } else {
        request.options.created_at.clone()
    };
    text(&created_at, "asserted time", false)?;
    let namespace = context.access.directory(&context.namespace(), true, true)?;
    let stage = tempfile::Builder::new()
        .prefix(".stage-")
        .tempdir_in(namespace.bound_path()?)
        .map_err(|_| Error::Io("Could not create a private project stage".into()))?;
    let stage_name = stage.path().file_name().unwrap().to_os_string();
    let stage_path = context.namespace().join(&stage_name);
    let (mark_source, mark_key) = rotation
        .as_ref()
        .map(|(source, key)| (source, key))
        .unwrap_or((&old_source, &old_key));
    for entry in &mut entries {
        files::cancelled(flag)?;
        let rule = context.mode(&entry.path);
        entry.mode = rule.mode;
        let target = stage_path.join("files").join(&entry.path);
        if rule.mode != ProjectFileMode::External || context.config.copy_external_files {
            let prior = previous.and_then(|previous| {
                previous
                    .manifest
                    .files
                    .iter()
                    .find(|old| {
                        old.file_id == entry.file_id
                            && old.source_sha256 == entry.source_sha256
                            && old.mode == rule.mode
                            && old.output_sha256.is_some()
                            && (old.signer_key_id.is_none()
                                || old.signer_key_id.as_deref()
                                    == Some(mark_key.public_key().key_id.as_str()))
                            && previous.manifest.copy_id == copy_id
                    })
                    .filter(|old| {
                        fs::symlink_metadata(previous.path.join("files").join(&old.path)).is_ok()
                    })
            });
            if let Some(prior) = prior {
                let input = previous.unwrap().path.join("files").join(&prior.path);
                let sample = context
                    .access
                    .hash(&input, context.budget.file_bytes, flag)?;
                if Some(&sample.sha256) != prior.output_sha256.as_ref() {
                    return Err(Error::Verification(
                        "A reusable project release copy changed".into(),
                    ));
                }
                context.access.copy(
                    &input,
                    &target,
                    &sample,
                    context.budget.file_bytes,
                    limits,
                    flag,
                )?;
            } else if rule.mode == ProjectFileMode::External {
                context.access.copy(
                    &context.source.join(&entry.path),
                    &target,
                    &inventory.samples[&entry.path],
                    context.budget.file_bytes,
                    limits,
                    flag,
                )?;
            } else {
                mark_copy(
                    &context,
                    entry,
                    &target,
                    mark_source,
                    mark_key,
                    &rule,
                    &copy_id,
                    &version,
                    &created_at,
                    limits,
                )?;
            }
            let sample = context
                .access
                .hash(&target, context.budget.file_bytes, flag)?;
            entry.output_sha256 = Some(sample.sha256);
            entry.output_size = Some(sample.stamp.size);
            if rule.mode != ProjectFileMode::External {
                entry.signer_key_id = Some(mark_key.public_key().key_id);
            }
        }
    }
    for entry in &derived {
        let (path, sample) = if let Some((path, sample)) = derived_samples.get(&entry.path) {
            (path.clone(), sample.clone())
        } else {
            let path = previous
                .ok_or_else(|| Error::Input("Derived history is unavailable".into()))?
                .path
                .join("derived")
                .join(&entry.path);
            let sample = context
                .access
                .hash(&path, context.budget.file_bytes, flag)?;
            if sample.sha256 != entry.sha256 || sample.stamp.size != entry.size_bytes {
                return Err(Error::Verification(
                    "A retained derived artifact changed".into(),
                ));
            }
            (path, sample)
        };
        context.access.copy(
            &path,
            &stage_path.join("derived").join(&entry.path),
            &sample,
            context.budget.file_bytes,
            limits,
            flag,
        )?;
    }
    let manifest = Manifest {
        schema: "fileveil.project.manifest.v1".into(),
        project_id: context.config.project_id.clone(),
        work_id: context.config.work_id.clone(),
        author: context.config.author.clone(),
        copy_id,
        revision,
        version,
        created_at,
        trigger: request.options.trigger.unwrap_or(context.config.trigger),
        git_commit: request.options.git_ref.clone(),
        config_sha256: context.config_sha256.clone(),
        source_fingerprint: inventory.fingerprint.clone(),
        previous_manifest_sha256: previous.map(|previous| previous.manifest_sha256.clone()),
        previous_generation: previous.map(|previous| previous.name.clone()),
        migration_from_work_id: previous
            .filter(|_| migration)
            .map(|previous| previous.manifest.work_id.clone()),
        segment,
        files: entries,
        changes,
        derived_artifacts: derived,
        observations: request.options.observations.clone(),
    };
    let bytes = json_bytes(&manifest)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(files::blocked("Project manifest exceeds its byte budget"));
    }
    let hash = digest(&bytes);
    let evidence = sign_manifest(
        &context,
        &manifest,
        &hash,
        previous,
        &old_key,
        rotation.as_ref().map(|(_, key)| key),
    )?;
    context
        .access
        .write_new(&stage_path.join("manifest.json"), &bytes)?;
    let evidence_bytes = custody::canonical_evidence(&evidence)?;
    context
        .access
        .write_new(&stage_path.join("evidence.json"), &evidence_bytes)?;
    let name = format!("{revision:012}-{}", &hash[..16]);
    let mut generation = Generation {
        name: name.clone(),
        path: stage_path.clone(),
        manifest,
        manifest_sha256: hash.clone(),
        evidence,
        evidence_sha256: digest(&evidence_bytes),
    };
    let assessment = verify_payload(&context, &generation, &inventory, limits, flag, true, None)?;
    if !assessment.valid {
        return Err(Error::Verification(
            "Project staged payload failed verification".into(),
        ));
    }
    let final_metadata = context.inventory(false, flag)?;
    if final_metadata.samples.len() != inventory.samples.len()
        || final_metadata.samples.iter().any(|(path, sample)| {
            inventory
                .samples
                .get(path)
                .is_none_or(|original| original.stamp != sample.stamp)
        })
        || digest(&signing::canonical(&read_json::<ProjectConfig>(
            &context.access,
            &context.config_path,
            MAX_CONFIG_BYTES,
        )?)?)
            != context.config_sha256
    {
        return Err(files::blocked(
            "Project sources or configuration changed before publication",
        ));
    }
    bind_key(&mut state, old_source, &old_key)?;
    if let Some((source, key)) = rotation {
        bind_key(&mut state, source, &key)?;
    }
    state.approved_config_sha256 = context.config_sha256.clone();
    state.index_generation = Some(name.clone());
    state.index_manifest_sha256 = Some(hash.clone());
    state.index_evidence_sha256 = Some(generation.evidence_sha256.clone());
    state.known_copies = history
        .copies
        .iter()
        .cloned()
        .chain(std::iter::once(generation.manifest.copy_id.clone()))
        .collect();
    state.known_copies.sort();
    state.known_copies.dedup();
    state.current_key_id =
        Some(active_key(generation.evidence.body.records.last().unwrap()).to_owned());
    state.output_index = assessment.index;
    save_index(&mut state, &inventory);
    persist_state(&context, &state)?;
    files::cancelled(flag)?;
    let destination = context.namespace().join(&name);
    if destination.exists() {
        let existing_manifest = context
            .access
            .read(&destination.join("manifest.json"), MAX_MANIFEST_BYTES)?;
        let existing_evidence = context.access.read(
            &destination.join("evidence.json"),
            custody::MAX_EVIDENCE_BYTES as u64,
        )?;
        if destination.join("COMMITTED").exists()
            || existing_manifest != bytes
            || existing_evidence != custody::canonical_evidence(&generation.evidence)?
        {
            return Err(files::blocked(
                "An existing release directory cannot be recovered as the pending verified generation",
            ));
        }
        generation.path = destination.clone();
        if !verify_payload(&context, &generation, &inventory, limits, flag, true, None)?.valid {
            return Err(Error::Verification(
                "Interrupted release recovery failed payload verification".into(),
            ));
        }
    } else {
        context
            .access
            .publish_directory(&namespace, &stage_name, OsStr::new(&name))?;
        let _ = stage.keep();
        generation.path = destination;
    }
    context
        .access
        .write_new(&generation.path.join("COMMITTED"), hash.as_bytes())?;
    history.count += 1;
    history.copies.insert(generation.manifest.copy_id.clone());
    if history.initial_key.is_none() {
        history.initial_key = Some(state.initial_key.clone());
    }
    if history.cached_tip {
        history.metadata.clear();
    }
    history.metadata.push(history_metadata(&generation));
    history.latest = Some(generation);
    let latest = history.latest.as_ref().unwrap();
    let mut result = details(
        &context,
        request,
        &history,
        &inventory,
        &latest.manifest.changes,
        unchanged,
        true,
    );
    result.integrity = VerificationState::Valid;
    let mut report = report(&context, request, result, Some(&state), &history, limits)?;
    report.integrity.original_unchanged = Some(true);
    Ok(report)
}

// FVPROV1 103441 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI3ZTcxNTc4MjYyNDA0YzAwMTQ3ZWRmZjU4ZjdlMjUyMjEzYmUwMTc5MTM5NDUxODhkMThlNGQzNTlkNjFlNGQ3IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL3Byb2plY3QvcGlwZWxpbmUucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiIyM2QxMTEwOWEzYTc5MmVlM2ZmN2UxZjNlNzA0YTlmMTRjNjE3MDkzNTlhZGQ0M2M0YzFjNDg5ZmIxNzg4YTM5OWI4NDM3NjkwOTJhODFjNmY2MDRiZmI5ZjViODczM2MyMTBjYmEyYzY0NmY1NGIyNDJlYWY5NmEwZjBlZDkwOCJ9XX1d FVPROV1-END
