// SPDX-License-Identifier: MPL-2.0
use clap::{Parser, Subcommand, ValueEnum};
use fileveil_core::{
    Error, Format, ImageProcessMode, ImageProcessOptions, Limits, Outcome, Policy, Report, Result,
    SanitizeOptions,
};
use fileveil_engine::heritage::{HeritageAction, HeritageRequest};
use fileveil_engine::worker::{WorkerGuard, configure_command};
mod project_cli;
mod registry_cli;
mod software_cli;
use project_cli::ProjectCommand;
use registry_cli::RegistryCommand;
use software_cli::SoftwareCommand;
use std::{
    path::PathBuf,
    process::{Command as Process, ExitCode, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Parser, Debug)]
#[command(
    name = "fileveil",
    version,
    about = "Offline file privacy audit and verified sanitization"
)]
struct Cli {
    #[arg(long, global = true, help = "Emit a versioned, redacted JSON report")]
    json: bool,
    #[arg(long, global = true, default_value_t = 64, value_parser = clap::value_parser!(u64).range(1..=512))]
    max_file_mib: u64,
    #[arg(long, global = true, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..=3600))]
    timeout_seconds: u64,
    #[arg(long, global = true, hide = true)]
    worker: bool,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand, Debug)]
enum Command {
    /// Experimental, streaming Philox initialization-layout comparison (never executes a model)
    Compute {
        path: PathBuf,
        #[arg(long)]
        tensor: String,
        #[arg(long, value_delimiter = ',', num_args = 1..=64)]
        rows: Vec<u64>,
        #[arg(long, value_delimiter = ',', num_args = 1..=16)]
        seeds: Vec<u64>,
        #[arg(long, value_delimiter = ',', default_value = "108,132,148,152", num_args = 1..=256)]
        sm_counts: Vec<u32>,
        #[arg(long, default_value_t = 0)]
        philox_offset: u64,
        #[arg(long)]
        rows_per_shard: Option<u64>,
        #[arg(long, default_value_t = 0)]
        seed_per_rank: u64,
    },
    /// Manage the unified local project registry
    Registry {
        #[command(subcommand)]
        command: RegistryCommand,
    },
    /// Inspect, mark and verify compiled software using explicit local experiments
    Software {
        #[command(subcommand)]
        command: SoftwareCommand,
    },
    /// Configure and maintain signed project release generations
    Project {
        #[command(subcommand)]
        command: ProjectCommand,
    },
    #[command(flatten)]
    Watermarks(WatermarkCommand),
    /// Read-only audit of one explicitly selected regular file
    Scan { path: PathBuf },
    /// Create a new, independently verified copy. Existing paths are protected
    Sanitize {
        path: PathBuf,
        #[arg(long, value_enum, default_value = "safe")]
        profile: Profile,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, help = "Explicit SanitizeOptions JSON, shared with GUI and MCP")]
        options_json: Option<String>,
    },
    /// Reparse an original and output and compare preserved content
    Verify {
        original: PathBuf,
        output: Option<PathBuf>,
        #[arg(long)]
        watermark_key: Option<PathBuf>,
        #[arg(long)]
        trust_policy: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "safe")]
        profile: Profile,
        #[arg(long)]
        options_json: Option<String>,
    },
    /// Detect named public image watermark protocols offline
    DetectWatermark { path: PathBuf },
    /// Compare 2 to 8 explicitly selected image control samples
    Lab {
        #[arg(num_args = 1..=8)]
        paths: Vec<PathBuf>,
        #[arg(
            long,
            help = "Optional reference groups JSON with labels and zero-based sample_indices"
        )]
        groups_json: Option<String>,
        #[arg(long)]
        watermark_key: Option<PathBuf>,
    },
    /// Validate embedded C2PA credentials offline and report AI detector availability
    Provenance {
        path: PathBuf,
        #[arg(long, help = "Explicit local PEM trust roots, read offline")]
        trust_roots: Option<PathBuf>,
    },
    /// Process image signals into a new PNG copy and report the measured pixel changes
    ProcessImage {
        path: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[command(flatten)]
        options: ImageOptions,
    },
    /// Verify a processed image against its original and the same processing parameters
    VerifyImage {
        original: PathBuf,
        output: PathBuf,
        #[command(flatten)]
        options: ImageOptions,
    },
    /// Audit, mark, clean, verify or trace local file-reference records offline
    Heritage {
        #[arg(value_enum)]
        action: HeritageMode,
        path: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[command(flatten)]
        options: HeritageOptions,
    },
    /// Create a new owner-only local Ed25519 key without overwriting a file
    HeritageKeygen {
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Show implemented adapters, platform support and resource limits
    Capabilities,
}
#[derive(Debug, Subcommand)]
enum WatermarkCommand {
    /// Embed a versioned watermark and signed copyright record
    Mark {
        path: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[command(flatten)]
        options: HeritageOptions,
    },
    /// Clean standard metadata and recognized structural marks into a verified copy
    Clean {
        path: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[command(flatten)]
        options: HeritageOptions,
    },
    /// Verify signed versions, dual-party transfers and external checkpoints
    Trace {
        path: PathBuf,
        #[command(flatten)]
        options: HeritageOptions,
    },
    /// Export or verify a portable copyright evidence package or timestamp
    Evidence {
        #[arg(value_enum)]
        action: EvidenceMode,
        path: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[command(flatten)]
        options: HeritageOptions,
    },
    /// Explicit current-user system key storage. Secrets stay in the native backend
    KeyStore {
        #[arg(value_enum)]
        action: KeyStoreMode,
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long)]
        id: Option<String>,
    },
}
#[derive(Debug, Clone, Copy, ValueEnum)]
enum EvidenceMode {
    Export,
    Verify,
    Checkpoint,
    TimestampQuery,
    TimestampVerify,
    PrepareTransfer,
    AcceptTransfer,
}
#[derive(Debug, Clone, Copy, ValueEnum)]
enum KeyStoreMode {
    Generate,
    Import,
    Public,
}

impl Cli {
    fn normalize(&mut self) -> Result<()> {
        let make =
            |action: HeritageMode,
             path: &PathBuf,
             output: &Option<PathBuf>,
             mut request: HeritageRequest|
             -> Result<Command> {
                request.action = action.engine_action();
                Ok(Command::Heritage {
                    action,
                    path: path.clone(),
                    output: output.clone(),
                    options: HeritageOptions {
                        options_json: Some(serde_json::to_string(&request).map_err(|_| {
                            Error::Input("Could not encode watermark options".into())
                        })?),
                        ..Default::default()
                    },
                })
            };
        let replacement = match &self.command {
            Command::Watermarks(WatermarkCommand::Mark {
                path,
                output,
                options,
            }) => {
                let mut request = options.engine_request(HeritageMode::Mark, output.is_some())?;
                request.mark.signature_v2 = true;
                let encoded: serde_json::Value = options
                    .options_json
                    .as_deref()
                    .map(serde_json::from_str)
                    .transpose()
                    .map_err(|_| Error::Input("Invalid watermark options".into()))?
                    .unwrap_or_default();
                if options.watermark_version.is_none()
                    && encoded["mark"].get("watermark_version").is_none()
                {
                    request.mark.watermark_version = 2;
                }
                if options.strength.is_none()
                    && encoded["mark"].get("strength").is_none()
                    && request.mark.watermark_version == 2
                {
                    request.mark.strength = fileveil_engine::heritage::robust_v2::DEFAULT_STRENGTH;
                }
                if request.mark.copy_id.is_empty() {
                    request.mark.copy_id = "original".into();
                }
                let mode = if request.certificate.is_some() || request.private_key.is_some() {
                    HeritageMode::C2paMark
                } else {
                    HeritageMode::Mark
                };
                Some(make(mode, path, output, request)?)
            }
            Command::Watermarks(WatermarkCommand::Clean {
                path,
                output,
                options,
            }) => {
                let mut request = options.engine_request(HeritageMode::Clean, output.is_some())?;
                request.clean_metadata = true;
                Some(make(HeritageMode::Clean, path, output, request)?)
            }
            Command::Watermarks(WatermarkCommand::Trace { path, options }) => Some(make(
                HeritageMode::Trace,
                path,
                &None,
                options.engine_request(HeritageMode::Trace, false)?,
            )?),
            Command::Watermarks(WatermarkCommand::Evidence {
                action,
                path,
                output,
                options,
            }) => {
                let mode = match action {
                    EvidenceMode::Export => HeritageMode::EvidenceExport,
                    EvidenceMode::Verify => HeritageMode::EvidenceVerify,
                    EvidenceMode::Checkpoint => HeritageMode::Checkpoint,
                    EvidenceMode::TimestampQuery => HeritageMode::TimestampQuery,
                    EvidenceMode::TimestampVerify => HeritageMode::TimestampVerify,
                    EvidenceMode::PrepareTransfer => HeritageMode::TransferPrepare,
                    EvidenceMode::AcceptTransfer => HeritageMode::TransferAccept,
                };
                Some(make(
                    mode,
                    path,
                    output,
                    options.engine_request(mode, output.is_some())?,
                )?)
            }
            Command::Verify {
                original,
                output: None,
                options_json,
                watermark_key,
                trust_policy,
                ..
            } => {
                let options = HeritageOptions {
                    options_json: options_json.clone(),
                    watermark_key: watermark_key.clone(),
                    trust_policy: trust_policy.clone(),
                    ..Default::default()
                };
                Some(make(
                    HeritageMode::Verify,
                    original,
                    &None,
                    options.engine_request(HeritageMode::Verify, false)?,
                )?)
            }
            Command::Lab {
                paths,
                watermark_key,
                ..
            } if paths.len() == 1 => {
                let request = HeritageRequest {
                    action: HeritageAction::Lab,
                    watermark_key: watermark_key.clone(),
                    ..Default::default()
                };
                Some(make(HeritageMode::Lab, &paths[0], &None, request)?)
            }
            _ => None,
        };
        if let Some(command) = replacement {
            self.command = command;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Profile {
    Safe,
    Deep,
    Research,
}
fn sanitize_options(profile: Profile, encoded: Option<&str>) -> Result<SanitizeOptions> {
    let mut options: SanitizeOptions = encoded
        .map(serde_json::from_str)
        .transpose()
        .map_err(|_| Error::Input("Invalid SanitizeOptions JSON".into()))?
        .unwrap_or_default();
    options.policy = match profile {
        Profile::Safe => Policy::Safe,
        Profile::Deep => Policy::Deep,
        Profile::Research => Policy::Research,
    };
    Ok(options)
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ImageMode {
    LowBits,
    Signal,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum HeritageMode {
    Detect,
    Mark,
    Clean,
    Verify,
    Trace,
    Lab,
    C2paMark,
    Checkpoint,
    EvidenceExport,
    EvidenceVerify,
    TimestampQuery,
    TimestampVerify,
    TransferPrepare,
    TransferAccept,
}

impl HeritageMode {
    fn engine_action(self) -> HeritageAction {
        match self {
            Self::Detect => HeritageAction::Detect,
            Self::Mark => HeritageAction::Mark,
            Self::Clean => HeritageAction::Clean,
            Self::Verify => HeritageAction::Verify,
            Self::Trace => HeritageAction::Trace,
            Self::Lab => HeritageAction::Lab,
            Self::C2paMark => HeritageAction::C2paMark,
            Self::Checkpoint => HeritageAction::Checkpoint,
            Self::EvidenceExport => HeritageAction::EvidenceExport,
            Self::EvidenceVerify => HeritageAction::EvidenceVerify,
            Self::TimestampQuery => HeritageAction::TimestampQuery,
            Self::TimestampVerify => HeritageAction::TimestampVerify,
            Self::TransferPrepare => HeritageAction::TransferPrepare,
            Self::TransferAccept => HeritageAction::TransferAccept,
        }
    }

    fn argument(self) -> &'static str {
        match self {
            Self::Detect => "detect",
            Self::Mark => "mark",
            Self::Clean => "clean",
            Self::Verify => "verify",
            Self::Trace => "trace",
            Self::Lab => "lab",
            Self::C2paMark => "c2pa-mark",
            Self::Checkpoint => "checkpoint",
            Self::EvidenceExport => "evidence-export",
            Self::EvidenceVerify => "evidence-verify",
            Self::TimestampQuery => "timestamp-query",
            Self::TimestampVerify => "timestamp-verify",
            Self::TransferPrepare => "transfer-prepare",
            Self::TransferAccept => "transfer-accept",
        }
    }

    fn writes_file(self) -> bool {
        matches!(
            self,
            Self::Mark
                | Self::Clean
                | Self::C2paMark
                | Self::Checkpoint
                | Self::EvidenceExport
                | Self::TimestampQuery
                | Self::TransferPrepare
                | Self::TransferAccept
        )
    }
}

#[derive(Debug, Clone, Default, clap::Args)]
struct HeritageOptions {
    #[arg(long, help = "Explicit HeritageRequest JSON, shared with GUI and MCP")]
    options_json: Option<String>,
    #[arg(
        long = "key",
        help = "Explicit local Ed25519 key; repeat for multiple signers"
    )]
    key_paths: Vec<PathBuf>,
    #[arg(long = "key-ref")]
    key_refs: Vec<String>,
    #[arg(long)]
    watermark_key: Option<PathBuf>,
    #[arg(long)]
    watermark_key_ref: Option<String>,
    #[arg(long)]
    certificate: Option<PathBuf>,
    #[arg(long)]
    private_key: Option<PathBuf>,
    #[arg(long)]
    copy_id: Option<String>,
    #[arg(long, value_parser=clap::value_parser!(u8).range(1..=2))]
    watermark_version: Option<u8>,
    #[arg(long)]
    strength: Option<u8>,
    #[arg(long)]
    pixel: bool,
    #[arg(long)]
    reference: Option<PathBuf>,
    #[arg(long)]
    trust_policy: Option<PathBuf>,
    #[arg(long = "checkpoint")]
    checkpoints: Vec<PathBuf>,
    #[arg(long)]
    checkpoint_anchors: Option<PathBuf>,
    #[arg(long)]
    timestamp_response: Option<PathBuf>,
    #[arg(long)]
    timestamp_query: Option<PathBuf>,
    #[arg(long)]
    timestamp_roots: Option<PathBuf>,
    #[arg(long, help = "Public work reference; overrides the JSON mark.work_id")]
    work_id: Option<String>,
    #[arg(long, help = "Declared author; overrides the JSON mark.author")]
    author: Option<String>,
    #[arg(
        long,
        help = "User-asserted creation time; overrides the JSON mark.created_at"
    )]
    created_at: Option<String>,
}

impl HeritageOptions {
    fn engine_request(&self, action: HeritageMode, has_output: bool) -> Result<HeritageRequest> {
        if has_output && !action.writes_file() {
            return Err(Error::Input(
                "--output requires Heritage mark, clean or c2pa-mark".into(),
            ));
        }
        let mut request: HeritageRequest = self
            .options_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| Error::Input("Invalid HeritageRequest JSON".into()))?
            .unwrap_or_default();
        request.action = action.engine_action();
        request.key_paths.extend(self.key_paths.iter().cloned());
        request.key_refs.extend(
            self.key_refs
                .iter()
                .cloned()
                .map(|key_id| fileveil_engine::heritage::key_store::KeyStoreRef { key_id }),
        );
        if let Some(path) = &self.watermark_key {
            request.watermark_key = Some(path.clone());
        }
        if let Some(key_id) = &self.watermark_key_ref {
            request.watermark_key_ref = Some(fileveil_engine::heritage::key_store::KeyStoreRef {
                key_id: key_id.clone(),
            });
        }
        if let Some(copy) = &self.copy_id {
            request.mark.copy_id = copy.clone();
        }
        if let Some(version) = self.watermark_version {
            request.mark.watermark_version = version;
        }
        if let Some(strength) = self.strength {
            request.mark.strength = strength;
        }
        if let Some(path) = &self.certificate {
            request.certificate = Some(path.clone());
        }
        if let Some(path) = &self.private_key {
            request.private_key = Some(path.clone());
        }
        if self.pixel {
            if matches!(
                request.action,
                HeritageAction::Mark | HeritageAction::C2paMark
            ) {
                request.mark.robust = true;
            } else if request.action == HeritageAction::Clean {
                request.clean_signal = true;
            }
        }
        if let Some(path) = &self.reference {
            request.reference = Some(path.clone());
        }
        if let Some(path) = &self.trust_policy {
            request.trust_store = Some(path.clone());
        }
        request.checkpoints.extend(self.checkpoints.iter().cloned());
        if let Some(path) = &self.checkpoint_anchors {
            request.checkpoint_anchors = Some(path.clone());
        }
        if let Some(path) = &self.timestamp_response {
            request.timestamp_response = Some(path.clone());
        }
        if let Some(path) = &self.timestamp_query {
            request.timestamp_query = Some(path.clone());
        }
        if let Some(path) = &self.timestamp_roots {
            request.timestamp_roots = Some(path.clone());
        }
        if let Some(work_id) = &self.work_id {
            request.mark.work_id.clone_from(work_id);
        }
        if let Some(author) = &self.author {
            request.mark.author.clone_from(author);
        }
        if let Some(created_at) = &self.created_at {
            request.mark.created_at.clone_from(created_at);
        }
        Ok(request)
    }
}

#[derive(Debug, clap::Args)]
struct ImageOptions {
    #[arg(long, value_enum, default_value = "low-bits")]
    mode: ImageMode,
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..=3))]
    bits: u8,
}
impl ImageOptions {
    fn engine_options(&self) -> ImageProcessOptions {
        ImageProcessOptions {
            mode: match self.mode {
                ImageMode::LowBits => ImageProcessMode::LowBits,
                ImageMode::Signal => ImageProcessMode::Signal,
            },
            low_bits: self.bits,
        }
    }
    fn worker_arguments(&self, command: &mut Process) {
        command.arg("--mode").arg(match self.mode {
            ImageMode::LowBits => "low-bits",
            ImageMode::Signal => "signal",
        });
        command.arg("--bits").arg(self.bits.to_string());
    }
}
impl Command {
    fn output_target(&self) -> Option<(&std::path::Path, Option<&std::path::Path>)> {
        match self {
            Self::Sanitize { path, output, .. } | Self::ProcessImage { path, output, .. } => {
                Some((path, output.as_deref()))
            }
            Self::Heritage {
                action,
                path,
                output,
                ..
            } if action.writes_file() => Some((path, output.as_deref())),
            _ => None,
        }
    }
}

fn print_report(report: &Report, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(report).expect("serializable report")
        );
        return;
    }
    println!(
        "FileVeil {} · {} · {:?}",
        report.operation, report.input_format, report.result
    );
    for finding in &report.findings {
        println!(
            "  [{:?}] {} · {} · {}",
            finding.state, finding.code, finding.location, finding.summary
        );
    }
    if let Some(details) = report
        .advanced
        .as_ref()
        .and_then(|value| value.get("heritage"))
    {
        if let Some(key) = details.get("public_key") {
            println!(
                "  Ed25519 public key · {}",
                key["key_id"].as_str().unwrap_or_default()
            );
            println!(
                "  Public bytes · {}",
                key["ed25519_hex"].as_str().unwrap_or_default()
            );
        }
        if let Some(legacy) = details.get("legacy") {
            println!(
                "  Legacy structures · {}",
                legacy["status"].as_str().unwrap_or("not_assessed")
            );
            if let Some(locations) = legacy["locations"].as_array() {
                for location in locations {
                    println!(
                        "    {} · offset {} · bytes {} · records {}",
                        location["kind"].as_str().unwrap_or_default(),
                        location["offset"],
                        location["bytes"],
                        location["record_count"]
                    );
                }
            }
        }
        for section in ["verification", "reference_verification"] {
            if let Some(verification) = details.get(section) {
                for field in ["signature", "content_binding", "chain", "trust"] {
                    println!(
                        "  {section} {field} · {}",
                        verification[field].as_str().unwrap_or("not_assessed")
                    );
                }
            }
        }
        for section in ["records", "reference_records"] {
            if let Some(records) = details[section].as_array() {
                for record in records {
                    println!(
                        "  Signed record {} · {} · version {} · actor {}",
                        record["sequence"],
                        record["kind"].as_str().unwrap_or_default(),
                        record["version"].as_str().unwrap_or_default(),
                        record["actor_key_id"].as_str().unwrap_or_default()
                    );
                }
            }
        }
        if let Some(value) = details["trace_reference_match"].as_bool() {
            println!("  Signed reference match · {value}");
        }
        if let Some(lab) = details.get("lab") {
            println!(
                "  Lab detected variants · {} / {}",
                lab["detected_variants"], lab["tested_variants"]
            );
        }
    }
    if let Some(credentials) = &report.provenance {
        for field in ["signature", "asset_binding", "trust"] {
            if let Some(value) = credentials[field].as_str() {
                println!("  C2PA {field} · {value}");
            }
        }
    }
    if let Some(advanced) = &report.advanced {
        if let Some(project) = advanced.get("project") {
            println!(
                "  Project revision {} · added {} · modified {} · renamed {} · deleted {} · unchanged {}",
                project["revision"],
                project["added"],
                project["modified"],
                project["renamed"],
                project["deleted"],
                project["unchanged"]
            );
            println!(
                "  Integrity {} · signature {} · trust {} · history {}",
                project["integrity"].as_str().unwrap_or("not_assessed"),
                project["signature"].as_str().unwrap_or("not_assessed"),
                project["trust"].as_str().unwrap_or("not_assessed"),
                project["history"].as_str().unwrap_or("not_assessed")
            );
        }
        if let Some(registry) = advanced.get("registry") {
            println!(
                "  Registered projects · {}",
                registry["registered_projects"]
            );
            if let Some(projects) = registry["projects"].as_array() {
                for project in projects {
                    println!(
                        "  {} · {} · {}",
                        project["project_id"].as_str().unwrap_or_default(),
                        project["name"].as_str().unwrap_or_default(),
                        project["result"]
                            .as_str()
                            .or_else(|| project["effective_policy"].as_str())
                            .unwrap_or("not_assessed")
                    );
                }
            }
        }
        if let Some(software) = advanced.get("software") {
            println!(
                "  Software {} · mode {}",
                software["action"].as_str().unwrap_or_default(),
                software["mode"].as_str().unwrap_or_default()
            );
            if let Some(packets) = software["binary"]["packets"].as_array() {
                println!("  Recognized packets · {}", packets.len());
                for packet in packets {
                    println!(
                        "  Signature {} · decoded {}",
                        packet["signature"].as_str().unwrap_or("not_assessed"),
                        packet["decoded"].as_bool().unwrap_or(false)
                    );
                }
            }
            if let Some(packet) = software.get("packet") {
                println!(
                    "  Signature {} · decoded {}",
                    packet["signature"].as_str().unwrap_or("not_assessed"),
                    packet["decoded"].as_bool().unwrap_or(false)
                );
            }
        }
        if let Some(heritage) = advanced.get("heritage") {
            if let Some(action) = heritage["action"].as_str() {
                println!("  Heritage {action}");
            }
            for field in ["signature", "content_binding", "chain", "trust"] {
                if let Some(value) = heritage["verification"][field].as_str() {
                    println!("  Heritage {field} · {value}");
                }
            }
            if let Some(status) = heritage["robust"]["status"].as_str() {
                println!("  FileVeil DCT · {status}");
            }
        }
        if let Some(detections) = advanced
            .get("detections")
            .or_else(|| advanced.get("watermark_detections"))
            .and_then(serde_json::Value::as_array)
        {
            for detection in detections {
                println!(
                    "  {} · {}",
                    detection["method_id"].as_str().unwrap_or("unknown"),
                    detection["status"].as_str().unwrap_or("not_assessed")
                );
            }
        }
        if let Some(samples) = advanced["lab"]["samples"].as_array() {
            println!("  Compared {} image controls", samples.len());
        }
    }
    if let Some(name) = &report.output_name {
        println!("Saved {}", name.escape_debug());
    }
    for warning in &report.warnings {
        println!("  {}", warning);
    }
}
fn print_error(error: &Error, json: bool, operation: &str) {
    if json {
        let mut report = Report::new(operation, Format::Unknown);
        report.result = match error {
            Error::Unsupported(_) => Outcome::Unsupported,
            Error::Blocked(_) => Outcome::Blocked,
            _ => Outcome::Failed,
        };
        report.warnings.push(error.to_string());
        print_report(&report, true);
    } else {
        eprintln!("FileVeil error {} · {}", error.exit_code(), error);
    }
}
fn operation(command: &Command) -> &'static str {
    match command {
        Command::Compute { .. } => "compute_fingerprint",
        Command::Project { .. } => "project",
        Command::Registry { .. } => "registry",
        Command::Software { .. } => "software",
        Command::Watermarks(_) => "heritage",
        Command::Scan { .. } => "scan",
        Command::Sanitize { .. } | Command::ProcessImage { .. } => "sanitize",
        Command::Verify { .. } | Command::VerifyImage { .. } => "verify",
        Command::DetectWatermark { .. } => "detect_watermark",
        Command::Lab { .. } => "lab",
        Command::Provenance { .. } => "provenance",
        Command::Heritage { .. } => "heritage",
        Command::HeritageKeygen { .. } => "heritage_keygen",
        Command::Capabilities => "capabilities",
    }
}
fn execute(cli: &Cli, limits: &Limits) -> Result<i32> {
    let report = match &cli.command {
        Command::Compute {
            path,
            tensor,
            rows,
            seeds,
            sm_counts,
            philox_offset,
            rows_per_shard,
            seed_per_rank,
        } => fileveil_engine::compute::report(
            &fileveil_engine::compute::ComputeRequest {
                path: path.clone(),
                tensor: tensor.clone(),
                rows: rows.clone(),
                seeds: seeds.clone(),
                sm_counts: sm_counts.clone(),
                philox_offset: *philox_offset,
                rows_per_shard: *rows_per_shard,
                seed_per_rank: *seed_per_rank,
            },
            &AtomicBool::new(false),
        )?,
        Command::Project { .. } | Command::Registry { .. } | Command::Software { .. } => {
            return Err(Error::Input(
                "Project command requires its project dispatcher".into(),
            ));
        }
        Command::Watermarks(WatermarkCommand::KeyStore { action, key, id }) => {
            use fileveil_engine::heritage::{key_store, signing::SigningKey};
            let (reference, public) = match action {
                KeyStoreMode::Generate => key_store::generate()?,
                KeyStoreMode::Import => {
                    let key =
                        SigningKey::load(key.as_deref().ok_or_else(|| {
                            Error::Input("key-store import requires --key".into())
                        })?)?;
                    (key_store::store(&key)?, key.public_key())
                }
                KeyStoreMode::Public => {
                    let reference = key_store::KeyStoreRef {
                        key_id: id
                            .clone()
                            .ok_or_else(|| Error::Input("key-store public requires --id".into()))?,
                    };
                    let key = key_store::load(&reference)?;
                    (reference, key.public_key())
                }
            };
            let mut report = Report::new("heritage_keygen", Format::Unknown);
            report.result = Outcome::VerifiedWithinScope;
            report.advanced = Some(
                serde_json::json!({"heritage":{"public_key":public,"system_key_ref":reference,"backend":key_store::backend_name()}}),
            );
            report
        }
        Command::Watermarks(_) => {
            return Err(Error::Input(
                "Public watermark command was not normalized".into(),
            ));
        }
        Command::Scan { path } => fileveil_engine::scan(path, limits)?,
        Command::Sanitize {
            path,
            output,
            profile,
            options_json,
        } => {
            let options = sanitize_options(*profile, options_json.as_deref())?;
            if options.policy == Policy::Research {
                if options.any() {
                    return Err(Error::Input(
                        "Research image processing accepts its explicit process-image parameters"
                            .into(),
                    ));
                }
                fileveil_engine::process_image_in(
                    path,
                    output.as_deref(),
                    &ImageProcessOptions::default(),
                    limits,
                    None,
                )?
            } else if options.policy == Policy::Safe && !options.any() {
                fileveil_engine::sanitize_in(path, output.as_deref(), limits, None)?
            } else {
                fileveil_engine::advanced::sanitize_with_options(
                    path,
                    output.as_deref(),
                    limits,
                    &options,
                )?
            }
        }
        Command::Verify {
            original,
            output,
            profile,
            options_json,
            ..
        } => {
            let options = sanitize_options(*profile, options_json.as_deref())?;
            if options.policy == Policy::Safe && !options.any() {
                fileveil_engine::verify(
                    original,
                    output.as_deref().expect("normalized comparison output"),
                    limits,
                )?
            } else if options.policy == Policy::Research {
                fileveil_engine::verify_processed_image(
                    original,
                    output.as_deref().expect("normalized comparison output"),
                    &ImageProcessOptions::default(),
                    limits,
                )?
            } else {
                fileveil_engine::advanced::verify_with_options(
                    original,
                    output.as_deref().expect("normalized comparison output"),
                    limits,
                    &options,
                )?
            }
        }
        Command::DetectWatermark { path } => {
            fileveil_engine::audits::detect_watermark(path, limits)?
        }
        Command::Lab {
            paths, groups_json, ..
        } => {
            let groups: Vec<fileveil_engine::lab::SampleGroup> = groups_json
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(|_| Error::Input("Invalid sample groups JSON".into()))?
                .unwrap_or_default();
            fileveil_engine::audits::lab_with_groups(paths, &groups, limits)?
        }
        Command::Provenance { path, trust_roots } => {
            fileveil_engine::audits::provenance(path, trust_roots.as_deref(), limits)?
        }
        Command::ProcessImage {
            path,
            output,
            options,
        } => fileveil_engine::image_processing::process_image_in(
            path,
            output.as_deref(),
            &options.engine_options(),
            limits,
            None,
        )?,
        Command::VerifyImage {
            original,
            output,
            options,
        } => fileveil_engine::image_processing::verify_processed_image(
            original,
            output,
            &options.engine_options(),
            limits,
        )?,
        Command::Heritage {
            action,
            path,
            output,
            options,
        } => {
            let request = options.engine_request(*action, output.is_some())?;
            fileveil_engine::heritage::run(path, output.as_deref(), &request, limits)?
        }
        Command::HeritageKeygen { output } => fileveil_engine::heritage::keygen(output)?,
        Command::Capabilities => {
            let value = fileveil_engine::capabilities(limits);
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).expect("serializable capability table")
                );
            } else {
                println!(
                    "FileVeil {} · offline · safe profile",
                    env!("CARGO_PKG_VERSION")
                );
                println!("JPEG / PNG / DOCX / XLSX / PPTX · scan, sanitize, verify");
                println!("UTF-8 text / Markdown / HTML · explicit selective copies");
                println!("PDF · qpdf full rewrite with independent validation when available");
                println!(
                    "C2PA · offline cryptographic verification and explicit local trust roots"
                );
                println!("Synthetic watermark detection and image difference lab · available");
                println!(
                    "Image signal processing · low-bit clearing and experimental resampling · new PNG copy"
                );
                println!("Use capabilities --json for detailed limits and restrictions.");
            }
            return Ok(0);
        }
    };
    let code = match report.result {
        Outcome::Unsupported => 3,
        Outcome::Blocked => 5,
        Outcome::Failed => 4,
        Outcome::PartiallyVerified if !matches!(cli.command, Command::Scan { .. }) => 4,
        _ => 0,
    };
    print_report(&report, cli.json);
    Ok(code)
}
fn supervise(cli: &Cli) -> Result<i32> {
    let cancelled = cancellation_flag()?;
    supervise_with_cancellation(cli, &cancelled)
}
fn cancellation_flag() -> Result<Arc<AtomicBool>> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&cancelled);
    ctrlc::set_handler(move || {
        signal.store(true, Ordering::SeqCst);
    })
    .map_err(|_| Error::Io("Could not install cancellation handler".into()))?;
    Ok(cancelled)
}
fn supervise_with_cancellation(cli: &Cli, cancelled: &AtomicBool) -> Result<i32> {
    if let Command::Heritage {
        action,
        output,
        options,
        ..
    } = &cli.command
    {
        options.engine_request(*action, output.is_some())?;
    }
    let scratch = tempfile::Builder::new()
        .prefix(".fileveil-scratch-")
        .tempdir()
        .map_err(|_| Error::Io("Could not create private worker scratch directory".into()))?;
    let staging = if let Some((path, output)) = cli.command.output_target() {
        Some(
            tempfile::Builder::new()
                .prefix(".fileveil-job-")
                .tempdir_in(fileveil_engine::output_directory(path, output))
                .map_err(|_| {
                    Error::Io(
                        "Could not create private staging directory in the output filesystem"
                            .into(),
                    )
                })?,
        )
    } else {
        None
    };
    let mut command = Process::new(
        std::env::current_exe().map_err(|_| Error::Io("Could not locate CLI worker".into()))?,
    );
    command
        .arg("--worker")
        .arg("--json")
        .arg("--max-file-mib")
        .arg(cli.max_file_mib.to_string())
        .arg("--timeout-seconds")
        .arg(cli.timeout_seconds.to_string())
        .env("FILEVEIL_PDF_STAGING", scratch.path())
        .env("FILEVEIL_WORKER_HANDSHAKE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let staged_output = staging
        .as_ref()
        .map(|directory| directory.path().join("verified-artifact.png"));
    match &cli.command {
        Command::Compute {
            path,
            tensor,
            rows,
            seeds,
            sm_counts,
            philox_offset,
            rows_per_shard,
            seed_per_rank,
        } => {
            command
                .arg("compute")
                .arg("--tensor")
                .arg(tensor)
                .arg("--rows")
                .arg(
                    rows.iter()
                        .map(u64::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                )
                .arg("--seeds")
                .arg(
                    seeds
                        .iter()
                        .map(u64::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                )
                .arg("--sm-counts")
                .arg(
                    sm_counts
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                )
                .arg("--philox-offset")
                .arg(philox_offset.to_string())
                .arg("--seed-per-rank")
                .arg(seed_per_rank.to_string());
            if let Some(rows) = rows_per_shard {
                command.arg("--rows-per-shard").arg(rows.to_string());
            }
            command.arg("--").arg(path);
        }
        Command::Project { .. } => {
            command.arg("project").arg("__run");
        }
        Command::Registry { .. } => {
            command.arg("registry").arg("__run");
        }
        Command::Software { .. } => {
            command.arg("software").arg("__run");
        }
        Command::Watermarks(_) => {
            return Err(Error::Input(
                "Public watermark command was not normalized".into(),
            ));
        }
        Command::Scan { path } => {
            command.arg("scan").arg("--").arg(path);
        }
        Command::Sanitize {
            path,
            profile,
            options_json,
            ..
        } => {
            let profile = match profile {
                Profile::Safe => "safe",
                Profile::Deep => "deep",
                Profile::Research => "research",
            };
            command.arg("sanitize").arg("--profile").arg(profile);
            if let Some(options) = options_json {
                command.arg("--options-json").arg(options);
            }
            command
                .arg("--output")
                .arg(staged_output.as_ref().expect("sanitization staging path"))
                .arg("--")
                .arg(path);
        }
        Command::Verify {
            original,
            output,
            profile,
            options_json,
            ..
        } => {
            command.arg("verify").arg("--profile").arg(match profile {
                Profile::Safe => "safe",
                Profile::Deep => "deep",
                Profile::Research => "research",
            });
            if let Some(options) = options_json {
                command.arg("--options-json").arg(options);
            }
            command
                .arg("--")
                .arg(original)
                .arg(output.as_ref().expect("normalized comparison output"));
        }
        Command::DetectWatermark { path } => {
            command.arg("detect-watermark").arg("--").arg(path);
        }
        Command::Lab {
            paths, groups_json, ..
        } => {
            command.arg("lab");
            if let Some(groups) = groups_json {
                command.arg("--groups-json").arg(groups);
            }
            command.arg("--").args(paths);
        }
        Command::Provenance { path, trust_roots } => {
            command.arg("provenance");
            if let Some(roots) = trust_roots {
                command.arg("--trust-roots").arg(roots);
            }
            command.arg("--").arg(path);
        }
        Command::ProcessImage { path, options, .. } => {
            command.arg("process-image");
            options.worker_arguments(&mut command);
            command
                .arg("--output")
                .arg(
                    staged_output
                        .as_ref()
                        .expect("image processing staging path"),
                )
                .arg("--")
                .arg(path);
        }
        Command::VerifyImage {
            original,
            output,
            options,
        } => {
            command.arg("verify-image");
            options.worker_arguments(&mut command);
            command.arg("--").arg(original).arg(output);
        }
        Command::Heritage {
            action,
            path,
            output,
            options,
        } => {
            let request = options.engine_request(*action, output.is_some())?;
            command
                .arg("heritage")
                .arg(action.argument())
                .arg("--options-json")
                .arg(
                    serde_json::to_string(&request)
                        .map_err(|_| Error::Input("Could not serialize Heritage request".into()))?,
                );
            if action.writes_file() {
                command.arg("--output").arg(
                    staged_output
                        .as_ref()
                        .expect("Heritage private staging path"),
                );
            }
            command.arg("--").arg(path);
        }
        Command::HeritageKeygen { output } => {
            command.arg("heritage-keygen").arg("--output").arg(output);
        }
        Command::Capabilities => unreachable!("capabilities runs in the parent"),
    }
    configure_command(&mut command);
    let mut child = WorkerGuard::new(
        command
            .spawn()
            .map_err(|_| Error::Io("Could not start isolated CLI worker".into()))?,
    )?;
    {
        use std::io::Write;
        let mut stdin = child
            .child
            .stdin
            .take()
            .ok_or_else(|| Error::Io("Worker startup pipe unavailable".into()))?;
        stdin
            .write_all(b"FILEVEIL_START\n")
            .map_err(|_| Error::Io("Could not start confined worker".into()))?;
        let payload = match &cli.command {
            Command::Project { command } => Some(project_cli::worker_payload(command)?),
            Command::Registry { command } => Some(registry_cli::worker_payload(command)?),
            Command::Software { command } => Some(software_cli::worker_payload(command)?),
            _ => None,
        };
        if let Some(payload) = payload {
            stdin
                .write_all(&payload)
                .map_err(|_| Error::Io("Could not send operation worker request".into()))?;
        }
    }
    let stdout = child
        .child
        .stdout
        .take()
        .ok_or_else(|| Error::Io("Could not capture worker report".into()))?;
    let reader = std::thread::spawn(move || {
        use std::io::Read;
        let mut bytes = Vec::new();
        stdout
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let started = Instant::now();
    loop {
        if cancelled.load(Ordering::SeqCst)
            || started.elapsed() >= Duration::from_secs(cli.timeout_seconds)
        {
            child.terminate();
            let error = Error::Interrupted(if cancelled.load(Ordering::SeqCst) {
                "Operation cancelled; worker reaped and private staging cleaned".into()
            } else {
                "Operation timed out; worker reaped and private staging cleaned".into()
            });
            print_error(&error, cli.json, operation(&cli.command));
            return Ok(6);
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|_| Error::Io("Could not inspect CLI worker".into()))?
        {
            let code = match status.code() {
                Some(code @ (0 | 2..=6)) => code,
                _ => return Err(Error::Blocked("CLI worker terminated abnormally".into())),
            };
            let bytes = reader
                .join()
                .map_err(|_| Error::Io("Could not collect worker report".into()))?
                .map_err(|_| Error::Io("Could not read worker report".into()))?;
            let mut report: Report = serde_json::from_slice(&bytes).map_err(|_| {
                Error::Blocked("Worker returned an invalid or oversized report".into())
            })?;
            if let (Some((path, output)), Some(staged)) =
                (cli.command.output_target(), &staged_output)
                && matches!(code, 0 | 4)
                && matches!(
                    report.result,
                    Outcome::VerifiedWithinScope | Outcome::PartiallyVerified
                )
            {
                if cancelled.load(Ordering::SeqCst)
                    || started.elapsed() >= Duration::from_secs(cli.timeout_seconds)
                {
                    return Err(Error::Interrupted(
                        "Operation ended before artifact publication; staging cleaned".into(),
                    ));
                }
                let limits = Limits {
                    max_file_bytes: cli.max_file_mib * 1024 * 1024,
                    ..Limits::default()
                };
                if let Command::Heritage {
                    action, options, ..
                } = &cli.command
                {
                    let request = options.engine_request(*action, output.is_some())?;
                    fileveil_engine::heritage::publish_staged(
                        path,
                        staged,
                        output,
                        &request,
                        &mut report,
                        &limits,
                    )?;
                } else if matches!(
                    cli.command,
                    Command::ProcessImage { .. }
                        | Command::Sanitize {
                            profile: Profile::Research,
                            ..
                        }
                ) {
                    fileveil_engine::image_processing::publish_processed_staged(
                        path,
                        staged,
                        output,
                        &mut report,
                        &limits,
                    )?;
                } else if let Command::Sanitize {
                    profile,
                    options_json,
                    ..
                } = &cli.command
                {
                    let options = sanitize_options(*profile, options_json.as_deref())?;
                    if options.policy != Policy::Safe || options.any() {
                        fileveil_engine::advanced::publish_advanced_staged(
                            path,
                            staged,
                            output,
                            &mut report,
                            &limits,
                            &options,
                        )?;
                    } else {
                        fileveil_engine::publish_staged(
                            path,
                            staged,
                            output,
                            &mut report,
                            &limits,
                        )?;
                    }
                } else {
                    fileveil_engine::publish_staged(path, staged, output, &mut report, &limits)?;
                }
            }
            print_report(&report, cli.json);
            return Ok(code);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn main() -> ExitCode {
    let mut cli = Cli::parse();
    if let Err(error) = cli.normalize() {
        print_error(&error, cli.json, operation(&cli.command));
        return ExitCode::from(error.exit_code() as u8);
    }
    if cli.worker && std::env::var_os("FILEVEIL_WORKER_HANDSHAKE").is_some() {
        use std::io::Read;
        let mut token = [0u8; 15];
        if std::io::stdin().read_exact(&mut token).is_err() || &token != b"FILEVEIL_START\n" {
            return ExitCode::from(5);
        }
    }
    let limits = Limits {
        max_file_bytes: cli.max_file_mib * 1024 * 1024,
        ..Limits::default()
    };
    let result = if let Command::Project { command } = &cli.command {
        project_cli::run(command, &cli, &limits)
    } else if let Command::Registry { command } = &cli.command {
        registry_cli::run(command, &cli, &limits)
    } else if let Command::Software { command } = &cli.command {
        software_cli::run(command, &cli, &limits)
    } else if cli.worker
        || matches!(
            cli.command,
            Command::Capabilities | Command::Watermarks(WatermarkCommand::KeyStore { .. })
        )
    {
        execute(&cli, &limits)
    } else {
        supervise(&cli)
    };
    let code = match result {
        Ok(code) => code,
        Err(error) => {
            print_error(&error, cli.json, operation(&cli.command));
            error.exit_code()
        }
    };
    ExitCode::from(code as u8)
}
