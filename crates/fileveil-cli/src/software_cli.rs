// SPDX-License-Identifier: MPL-2.0
//! Explicit local software-watermark experiments through the confined worker.
use clap::{Args, Subcommand, ValueEnum};
use fileveil_core::{Error, Limits, Result};
use fileveil_engine::software::{SoftwareAction, SoftwareMode, SoftwareRequest};
use std::{io::Read, path::PathBuf, sync::atomic::AtomicBool};

#[derive(Debug, Subcommand)]
pub enum SoftwareCommand {
    /// Inspect executable containers and watermark carriers without running them
    Inspect(SoftwareArguments),
    /// Detect known software watermark packets and structural evidence
    Detect(SoftwareArguments),
    /// Compile or transform an explicitly selected source or IR into a marked copy
    Mark(SoftwareArguments),
    /// Remove a known structural carrier or rebuild from an unmarked reference
    Clean(SoftwareArguments),
    /// Verify signatures and content binding without executing the input
    Verify(SoftwareArguments),
    /// Compare two binaries or explicitly opt into controlled execution tests
    Compare(SoftwareArguments),
    /// Build the FileVeil LLVM pass plugin using a local toolchain
    BuildPlugin(SoftwareArguments),
    /// Run a local controlled watermark experiment
    Lab(SoftwareArguments),
    #[command(name = "__run", hide = true)]
    Worker {
        #[arg(skip)]
        execution: Option<Box<SoftwareRequest>>,
    },
}

#[derive(Debug, Args)]
pub struct SoftwareArguments {
    #[arg(default_value = ".")]
    input: PathBuf,
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[arg(long)]
    reference: Option<PathBuf>,
    #[arg(long, value_enum)]
    mode: Option<Mode>,
    #[arg(long, conflicts_with = "key_ref")]
    key: Option<PathBuf>,
    #[arg(long, conflicts_with = "key")]
    key_ref: Option<String>,
    #[arg(long, default_value = "")]
    work_id: String,
    #[arg(long, default_value = "")]
    copy_id: String,
    #[arg(long, default_value = "")]
    author: String,
    #[arg(long, default_value = "")]
    version: String,
    #[arg(long, default_value = "")]
    created_at: String,
    #[arg(long)]
    llvm_directory: Option<PathBuf>,
    #[arg(long)]
    plugin: Option<PathBuf>,
    #[arg(long, default_value = "O2")]
    optimization: String,
    #[arg(long)]
    target: Option<String>,
    #[arg(
        long,
        help = "Compiler argument array as JSON, executed directly without a shell"
    )]
    compiler_arguments_json: Option<String>,
    #[arg(long, help = "Explicitly permit running selected local test binaries")]
    allow_execution: bool,
    #[arg(
        long,
        help = "Test argument arrays as JSON, requires --allow-execution"
    )]
    test_arguments_json: Option<String>,
    #[arg(long, help = "JSON array of independently trusted public signing keys")]
    trusted_keys: Option<PathBuf>,
    #[arg(long)]
    disclose_private: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Mode {
    Compiler,
    Ir,
    Source,
    Structure,
}
impl From<Mode> for SoftwareMode {
    fn from(mode: Mode) -> Self {
        match mode {
            Mode::Compiler => Self::Compiler,
            Mode::Ir => Self::Ir,
            Mode::Source => Self::Source,
            Mode::Structure => Self::Structure,
        }
    }
}

pub fn worker_payload(command: &SoftwareCommand) -> Result<Vec<u8>> {
    let SoftwareCommand::Worker {
        execution: Some(request),
    } = command
    else {
        return Err(Error::Input(
            "Software worker payload is unavailable".into(),
        ));
    };
    let bytes = serde_json::to_vec(request)
        .map_err(|_| Error::Input("Software request could not be serialized".into()))?;
    if bytes.len() > 256 * 1024 {
        return Err(Error::Blocked("Software request exceeds 256 KiB".into()));
    }
    Ok(bytes)
}

pub fn run(command: &SoftwareCommand, cli: &super::Cli, limits: &Limits) -> Result<i32> {
    if matches!(command, SoftwareCommand::Worker { .. }) {
        if !cli.worker || std::env::var_os("FILEVEIL_WORKER_HANDSHAKE").is_none() {
            return Err(Error::Blocked(
                "Software worker requires the parent handshake".into(),
            ));
        }
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(256 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Io("Software request could not be read".into()))?;
        if bytes.len() > 256 * 1024 {
            return Err(Error::Blocked(
                "Software request exceeds its byte budget".into(),
            ));
        }
        let request: SoftwareRequest = serde_json::from_slice(&bytes)
            .map_err(|_| Error::Input("Invalid software worker request".into()))?;
        let report = fileveil_engine::software::run(&request, limits, &AtomicBool::new(false))?;
        super::print_report(&report, true);
        return Ok(super::project_cli::report_code(&report));
    }
    let (action, arguments) = match command {
        SoftwareCommand::Inspect(args) => (SoftwareAction::Inspect, args),
        SoftwareCommand::Detect(args) => (SoftwareAction::Detect, args),
        SoftwareCommand::Mark(args) => (SoftwareAction::Mark, args),
        SoftwareCommand::Clean(args) => (SoftwareAction::Clean, args),
        SoftwareCommand::Verify(args) => (SoftwareAction::Verify, args),
        SoftwareCommand::Compare(args) => (SoftwareAction::Compare, args),
        SoftwareCommand::BuildPlugin(args) => (SoftwareAction::BuildPlugin, args),
        SoftwareCommand::Lab(args) => (SoftwareAction::Lab, args),
        SoftwareCommand::Worker { .. } => unreachable!(),
    };
    let request = SoftwareRequest {
        action,
        mode: arguments.mode.map(Into::into).unwrap_or_else(|| {
            if matches!(
                action,
                SoftwareAction::Mark | SoftwareAction::BuildPlugin | SoftwareAction::Lab
            ) {
                SoftwareMode::Compiler
            } else {
                SoftwareMode::Structure
            }
        }),
        input_path: super::project_cli::absolute(&arguments.input)?,
        output_path: arguments
            .output
            .as_deref()
            .map(super::project_cli::absolute)
            .transpose()?,
        reference_path: arguments
            .reference
            .as_deref()
            .map(super::project_cli::absolute)
            .transpose()?,
        key: super::project_cli::key(arguments.key.as_ref(), arguments.key_ref.as_ref())?,
        work_id: arguments.work_id.clone(),
        copy_id: arguments.copy_id.clone(),
        author: arguments.author.clone(),
        version: arguments.version.clone(),
        created_at: arguments.created_at.clone(),
        llvm_directory: arguments
            .llvm_directory
            .as_deref()
            .map(super::project_cli::absolute)
            .transpose()?,
        plugin_path: arguments
            .plugin
            .as_deref()
            .map(super::project_cli::absolute)
            .transpose()?,
        optimization: arguments.optimization.clone(),
        target_triple: arguments.target.clone(),
        compiler_arguments: arguments
            .compiler_arguments_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| Error::Input("Compiler arguments must be a JSON string array".into()))?
            .unwrap_or_default(),
        allow_execution: arguments.allow_execution,
        test_arguments: arguments
            .test_arguments_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| {
                Error::Input("Test arguments must be a JSON array of string arrays".into())
            })?
            .unwrap_or_default(),
        trusted_keys: super::project_cli::trusted_keys(arguments.trusted_keys.as_ref())?,
        disclose_private: arguments.disclose_private,
        timeout_seconds: cli.timeout_seconds,
    };
    super::supervise(&super::Cli {
        command: super::Command::Software {
            command: SoftwareCommand::Worker {
                execution: Some(Box::new(request)),
            },
        },
        json: cli.json,
        max_file_mib: cli.max_file_mib,
        timeout_seconds: cli.timeout_seconds,
        worker: false,
    })
}

// FVPROV1 8319 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI1MDgwNWI0OWViNjNkZGJjY2YxNDc3OGE4M2JmZDUzYzlmNjE2YjQ3MzFiNDljMTZkMWQ2Zjg5ZDUzNjlmYTllIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1jbGkvc3JjL3NvZnR3YXJlX2NsaS5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6Ijk3NDRlMGY5NzY4NDY4NjAxZGQyOWU2MDkxZDNhNzFkZGVkMmQ5Njc3MTk5MGY3N2IxMzkzOGE0OWJjMmNiNmRkMmU0NGQxNmQ0ZWM2ZmYxMzU4ZjkxZDRmOTA2YzRhNTJlN2UzMjRjNzk2MTM1YjU4OTM2ZGY5NTNiYjhiZTBmIn1dfV0= FVPROV1-END
