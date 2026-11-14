// SPDX-License-Identifier: MPL-2.0
//! Explicit software-watermark experiments and bounded executable forensics.
use crate::heritage::signing::PublicKey;
use crate::project::ProjectKey;
use fileveil_core::{Limits, Report, Result};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::atomic::AtomicBool};

mod container;
mod forensics;
mod packet;
mod pipeline;
mod source;
mod tools;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareAction {
    #[default]
    Inspect,
    Detect,
    Mark,
    Clean,
    Verify,
    Compare,
    BuildPlugin,
    Lab,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftwareMode {
    #[default]
    Compiler,
    Ir,
    Source,
    Structure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SoftwareRequest {
    pub action: SoftwareAction,
    pub mode: SoftwareMode,
    pub input_path: PathBuf,
    pub output_path: Option<PathBuf>,
    /// Unmarked source/IR for controlled rebuilds or a second binary for comparison.
    pub reference_path: Option<PathBuf>,
    pub key: Option<ProjectKey>,
    pub work_id: String,
    pub copy_id: String,
    pub author: String,
    pub version: String,
    pub created_at: String,
    pub llvm_directory: Option<PathBuf>,
    pub plugin_path: Option<PathBuf>,
    pub optimization: String,
    pub target_triple: Option<String>,
    pub compiler_arguments: Vec<String>,
    /// Program execution requires this explicit local opt-in.
    pub allow_execution: bool,
    pub test_arguments: Vec<Vec<String>>,
    pub trusted_keys: Vec<PublicKey>,
    pub disclose_private: bool,
    pub timeout_seconds: u64,
}

impl Default for SoftwareRequest {
    fn default() -> Self {
        Self {
            action: SoftwareAction::Inspect,
            mode: SoftwareMode::Compiler,
            input_path: PathBuf::new(),
            output_path: None,
            reference_path: None,
            key: None,
            work_id: String::new(),
            copy_id: String::new(),
            author: String::new(),
            version: String::new(),
            created_at: String::new(),
            llvm_directory: None,
            plugin_path: None,
            optimization: "O2".into(),
            target_triple: None,
            compiler_arguments: Vec::new(),
            allow_execution: false,
            test_arguments: Vec::new(),
            trusted_keys: Vec::new(),
            disclose_private: false,
            timeout_seconds: 120,
        }
    }
}

pub fn run(request: &SoftwareRequest, limits: &Limits, cancelled: &AtomicBool) -> Result<Report> {
    pipeline::run(request, limits, cancelled)
}

pub fn publish_staged(
    input: &std::path::Path,
    staged: &std::path::Path,
    output: &std::path::Path,
    report: &mut Report,
    limits: &Limits,
    request: &SoftwareRequest,
) -> Result<()> {
    pipeline::publish_staged(input, staged, output, report, limits, request)
}
