// SPDX-License-Identifier: MPL-2.0
//! Incremental, read-only project inputs and independently verified release generations.
use crate::heritage::signing::{PublicKey, VerificationState};
use fileveil_core::{Limits, Report, Result};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::atomic::AtomicBool};

pub mod ci;
mod compiler;
mod files;
mod pipeline;
pub mod registry;

pub const CONFIG_SCHEMA: &str = "fileveil.project.config.v1";

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProjectAction {
    Init,
    UpdateConfig,
    #[default]
    Sync,
    Status,
    Verify,
    WatchProbe,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProjectTrigger {
    #[default]
    BuildRelease,
    Git,
    Watch,
    Manual,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProjectFileMode {
    #[default]
    External,
    Structure,
    Invisible,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectRule {
    pub pattern: String,
    pub mode: ProjectFileMode,
    pub strength: u8,
}
impl Default for ProjectRule {
    fn default() -> Self {
        Self {
            pattern: "**".into(),
            mode: ProjectFileMode::External,
            strength: 12,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectConfig {
    pub schema: String,
    pub project_id: String,
    pub work_id: String,
    pub author: String,
    pub copy_id: String,
    pub source_root: PathBuf,
    pub output_directory: PathBuf,
    pub trigger: ProjectTrigger,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub rules: Vec<ProjectRule>,
    pub copy_external_files: bool,
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub debounce_ms: u64,
    pub poll_interval_ms: u64,
    pub full_rescan_interval_ms: u64,
    pub build_argv: Vec<String>,
    pub build_directory: PathBuf,
    /// Signed caller context. Observations and author declarations retain their
    /// stated verification scope inside this object.
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    pub provenance: serde_json::Value,
}
impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            schema: CONFIG_SCHEMA.into(),
            project_id: String::new(),
            work_id: String::new(),
            author: String::new(),
            copy_id: String::new(),
            source_root: ".".into(),
            output_directory: "dist/fileveil-release".into(),
            trigger: ProjectTrigger::BuildRelease,
            include: vec!["**".into()],
            exclude: vec![
                ".git/**".into(),
                "target/**".into(),
                "node_modules/**".into(),
                "work/**".into(),
            ],
            rules: Vec::new(),
            copy_external_files: false,
            max_files: 20_000,
            max_file_bytes: 1024 * 1024 * 1024,
            max_total_bytes: 8 * 1024 * 1024 * 1024,
            debounce_ms: 750,
            poll_interval_ms: 2000,
            full_rescan_interval_ms: 900_000,
            build_argv: Vec::new(),
            build_directory: ".".into(),
            provenance: serde_json::Value::Null,
        }
    }
}

/// Persisted only in the private state directory, never in the public configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProjectKey {
    File { path: PathBuf },
    System { key_id: String },
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SyncOptions {
    pub version: String,
    pub created_at: String,
    pub copy_id: Option<String>,
    pub trigger: Option<ProjectTrigger>,
    pub git_ref: Option<String>,
    pub rotate_to: Option<ProjectKey>,
    pub allow_work_migration: bool,
    /// Explicit public trust anchors. A manifest's supplied key is a declaration.
    pub trusted_keys: Vec<PublicKey>,
    /// Set by watch/Git drivers. A changed public config requires an explicit save or sync.
    pub automatic: bool,
    pub force_full_scan: bool,
    /// Bounded observed build/source metadata, signed with this generation.
    pub observations: serde_json::Value,
    /// Fresh-byte SHA-256 preconditions enforced before Sync can sign or publish.
    pub expected_source_sha256: std::collections::BTreeMap<String, String>,
}

/// Supplied by the MCP broker from its existing authorization, never by a config.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectScope {
    pub read_roots: Vec<PathBuf>,
    pub write_roots: Vec<PathBuf>,
    pub key_paths: Vec<PathBuf>,
    pub key_refs: Vec<String>,
    pub root_identities: Vec<ProjectRootIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRootIdentity {
    pub path: PathBuf,
    pub device: u64,
    pub file: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectRequest {
    pub action: ProjectAction,
    pub config_path: PathBuf,
    pub state_directory: Option<PathBuf>,
    pub init: Option<ProjectConfig>,
    pub key: Option<ProjectKey>,
    pub options: SyncOptions,
    pub scope: Option<ProjectScope>,
    /// None retains the last published derived outputs. Some(empty) clears them.
    /// This local-build channel is unavailable to raw MCP clients.
    pub derived_artifacts: Option<Vec<ProjectDerivedArtifact>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectDerivedArtifact {
    pub path: PathBuf,
    pub relative_name: String,
    pub expected_sha256: String,
    pub source_sha256: Option<String>,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectAccessPlan {
    pub config_path: PathBuf,
    pub source_root: PathBuf,
    pub output_directory: PathBuf,
    pub state_directory: PathBuf,
    pub source_files: Vec<PathBuf>,
    pub read_paths: Vec<PathBuf>,
    pub write_directories: Vec<PathBuf>,
    pub signing_paths: Vec<PathBuf>,
    pub signing_key_refs: Vec<String>,
    pub source_fingerprint: String,
    pub config: ProjectConfig,
    pub source_file_count: usize,
    pub source_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectDetails {
    pub schema: String,
    pub action: ProjectAction,
    pub project_id: String,
    pub work_id: String,
    pub source_fingerprint: String,
    pub dirty: bool,
    pub generation: Option<String>,
    pub revision: u64,
    pub added: usize,
    pub modified: usize,
    pub deleted: usize,
    pub renamed: usize,
    pub unchanged: usize,
    pub published: bool,
    pub manifest_sha256: Option<String>,
    #[serde(default)]
    pub evidence_sha256: Option<String>,
    pub integrity: VerificationState,
    pub signature: VerificationState,
    pub trust: VerificationState,
    pub history: VerificationState,
    pub trust_scope: String,
    pub config: ProjectConfig,
    pub effective_limits: serde_json::Value,
    pub fresh_hash_count: usize,
    pub cached_hash_count: usize,
    pub fresh_hash_bytes: u64,
    pub files_total: usize,
    pub bytes_total: u64,
    pub source_assessment_scope: String,
}

pub fn access_plan(request: &ProjectRequest, limits: &Limits) -> Result<ProjectAccessPlan> {
    pipeline::access_plan(request, limits)
}

pub fn run(request: &ProjectRequest, limits: &Limits, cancelled: &AtomicBool) -> Result<Report> {
    pipeline::run(request, limits, cancelled)
}

/// A bounded metadata trigger. Sync and Verify independently stream SHA-256.
pub fn watch_fingerprint(request: &ProjectRequest, limits: &Limits) -> Result<String> {
    pipeline::watch_fingerprint(request, limits)
}

pub fn load_configuration(request: &ProjectRequest, limits: &Limits) -> Result<ProjectConfig> {
    pipeline::load_configuration(request, limits)
}

// FVPROV1 8378 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJmOTNmMmQ1M2JmNDZmYTZkMWI4M2E3ZmNjYzQ4MGQ0MGE2Njk4YzVkNWViYzY0ZDc5ZjdmYjM2NmNiM2ZjNjg1IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL3Byb2plY3QvbW9kLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiZWY5N2M3YzE0YzRhM2VlNDgyOTY2YTNiZmU2NTVkOWFkNzk1ZjhiYWExMDY1MjVjODRmZTA1OTFhZDZmODc2ZjFlZDRhM2Y1NjkyM2EwZTExZmI2YmNiZTIyZjVkYTYyZmVkNzY5OGIwY2JmYTY4YmM3OTAwNDk1ZjIzZTUxMGUifV19XQ== FVPROV1-END
