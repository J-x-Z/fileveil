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

// FVPROV1 3113 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIyZTgzMzcyYTNlNWI0NjFjNjRkZWQ0MzY5YTgzNTBkMjNmZTIwM2NjZWJlY2FlZTI0YWY3NTkzYjM3ZTcyZWM1IiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL3NvZnR3YXJlL21vZC5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjliNTgyMTA3ZjM2MzlhMmQxZmIyNTY5YzdhYzFiMjBiNzg5MmE4NGFlMmFhY2I2NzI2NGUxYmY0ZmQxNThjNzYwNWNmNmQ5NjE1ZDAxMWNmYzU2Y2U5NjVlODdjNTc3ZTVmOTMyZTNlMmUwOGNiZjUzMjBmMjA3NDAyOTE1ZTBkIn1dfV0= FVPROV1-END
