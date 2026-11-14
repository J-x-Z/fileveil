// SPDX-License-Identifier: MPL-2.0
//! Project commands and debounced automation through the confined CLI worker.
use clap::{Args, Subcommand, ValueEnum};
use fileveil_core::{Error, Limits, Outcome, Report, Result};
use fileveil_engine::project::{
    ProjectAction, ProjectConfig, ProjectKey, ProjectRequest, ProjectTrigger, SyncOptions,
};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

#[derive(Debug, Subcommand)]
pub enum ProjectCommand {
    /// Create a version-controlled configuration and separate private local state
    Init {
        #[command(flatten)]
        common: ProjectPaths,
        #[arg(
            long,
            help = "Approve the current edited configuration and update private project settings"
        )]
        update: bool,
        #[arg(
            long,
            conflicts_with = "update",
            help = "Bounded public ProjectConfig JSON used as the base for a new project"
        )]
        template: Option<PathBuf>,
        #[arg(long, required_unless_present_any = ["update", "template"])]
        work_id: Option<String>,
        #[arg(long, required_unless_present_any = ["update", "template"])]
        author: Option<String>,
        #[arg(long)]
        copy_id: Option<String>,
        #[arg(long)]
        source: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(
            long,
            help = "Build working directory, relative to the configuration directory"
        )]
        build_directory: Option<PathBuf>,
        #[arg(long, value_enum)]
        trigger: Option<Trigger>,
        #[arg(long = "include")]
        include: Vec<String>,
        #[arg(long = "exclude")]
        exclude: Vec<String>,
        #[arg(
            long,
            help = "ProjectRule array JSON for explicit structural or invisible marking"
        )]
        rules_json: Option<String>,
        #[arg(long, num_args = 0..=1, default_missing_value = "true", help = "Copy externally signed files into each release generation")]
        copy_files: Option<bool>,
        #[arg(
            long,
            help = "Saved build program and arguments as a JSON string array"
        )]
        build_argv_json: Option<String>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=100_000))]
        max_files: Option<u32>,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=16_384))]
        max_project_file_mib: Option<u64>,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=65_536))]
        max_total_mib: Option<u64>,
    },
    /// Mark and verify changed files into a new atomic release generation
    Sync {
        #[command(flatten)]
        common: ProjectPaths,
        #[command(flatten)]
        options: SyncArguments,
        #[arg(
            long,
            conflicts_with = "after",
            help = "Execute saved build_argv successfully before synchronization"
        )]
        build: bool,
        #[arg(long, num_args = 1.., allow_hyphen_values = true, help = "Explicit build program and arguments. Put this option last")]
        after: Vec<String>,
    },
    /// Debounce filesystem or Git changes and synchronize verified generations
    Watch {
        #[command(flatten)]
        common: ProjectPaths,
        #[command(flatten)]
        options: SyncArguments,
        #[arg(long, value_parser = clap::value_parser!(u64).range(100..=60_000))]
        poll_ms: Option<u64>,
        #[arg(long, value_parser = clap::value_parser!(u64).range(50..=60_000))]
        debounce_ms: Option<u64>,
        #[arg(long, value_parser = clap::value_parser!(u64).range(60..=86_400))]
        full_rescan_seconds: Option<u64>,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..), help = "Stop after this many synchronization attempts, including the initial pass")]
        max_runs: Option<u64>,
    },
    /// Verify release integrity, signatures, trust and project history separately
    Verify {
        #[command(flatten)]
        common: ProjectPaths,
        #[arg(long, help = "JSON array of independently trusted public keys")]
        trusted_keys: Option<PathBuf>,
    },
    /// Read current differences and effective project resource limits
    Status {
        #[command(flatten)]
        common: ProjectPaths,
    },
    #[command(name = "__run", hide = true)]
    Worker {
        #[arg(skip)]
        execution: Option<Box<ProjectExecution>>,
    },
}

#[derive(Debug, Args)]
pub struct ProjectPaths {
    #[arg(default_value = "fileveil.project.json")]
    config: PathBuf,
    #[arg(long)]
    state_directory: Option<PathBuf>,
    #[arg(long, conflicts_with = "key_ref")]
    key: Option<PathBuf>,
    #[arg(long, conflicts_with = "key")]
    key_ref: Option<String>,
}

#[derive(Debug, Args)]
pub struct SyncArguments {
    #[arg(
        long,
        help = "Stream SHA-256 for every source instead of reusing metadata-guarded cache entries"
    )]
    full_rescan: bool,
    #[arg(
        long,
        help = "JSON object binding source-relative paths to required SHA-256 digests"
    )]
    expected_sources_json: Option<String>,
    #[arg(long, default_value = "")]
    version: String,
    #[arg(long, default_value = "")]
    created_at: String,
    #[arg(long)]
    copy_id: Option<String>,
    #[arg(
        long,
        help = "Resolve an existing local commit or tag after a successful build"
    )]
    git_ref: Option<String>,
    #[arg(long, conflicts_with = "rotate_key_ref")]
    rotate_key: Option<PathBuf>,
    #[arg(long, conflicts_with = "rotate_key")]
    rotate_key_ref: Option<String>,
    #[arg(long)]
    allow_work_migration: bool,
    #[arg(long, help = "JSON array of independently trusted public keys")]
    trusted_keys: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Trigger {
    BuildRelease,
    Git,
    Watch,
    Manual,
}
impl From<Trigger> for ProjectTrigger {
    fn from(value: Trigger) -> Self {
        match value {
            Trigger::BuildRelease => Self::BuildRelease,
            Trigger::Git => Self::Git,
            Trigger::Watch => Self::Watch,
            Trigger::Manual => Self::Manual,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectExecution {
    pub request: ProjectRequest,
    pub after: Option<Vec<String>>,
}

pub(super) fn absolute(path: &Path) -> Result<PathBuf> {
    std::path::absolute(path).map_err(|_| Error::Input("Project path could not be resolved".into()))
}

pub(super) fn key(
    path: Option<&PathBuf>,
    reference: Option<&String>,
) -> Result<Option<ProjectKey>> {
    if let Some(path) = path {
        return Ok(Some(ProjectKey::File {
            path: absolute(path)?,
        }));
    }
    if let Some(reference) = reference {
        return Ok(Some(ProjectKey::System {
            key_id: reference.clone(),
        }));
    }
    Ok(None)
}

fn request(paths: &ProjectPaths, action: ProjectAction) -> Result<ProjectRequest> {
    Ok(ProjectRequest {
        action,
        config_path: absolute(&paths.config)?,
        state_directory: paths.state_directory.as_deref().map(absolute).transpose()?,
        key: key(paths.key.as_ref(), paths.key_ref.as_ref())?,
        ..Default::default()
    })
}

pub(super) fn trusted_keys(
    path: Option<&PathBuf>,
) -> Result<Vec<fileveil_engine::heritage::signing::PublicKey>> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| Error::Input("Trusted-key file is unavailable".into()))?;
    if !metadata.is_file() || metadata.len() > 64 * 1024 {
        return Err(Error::Input(
            "Trusted-key file must be a regular JSON file of at most 64 KiB".into(),
        ));
    }
    let file = std::fs::File::open(path)
        .map_err(|_| Error::Input("Trusted-key file is unavailable".into()))?;
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Input("Trusted-key file could not be read".into()))?;
    if bytes.len() > 64 * 1024 {
        return Err(Error::Input(
            "Trusted-key file exceeds its byte budget".into(),
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| Error::Input("Expected an array of public signing keys".into()))
}

fn read_template(path: &Path) -> Result<ProjectConfig> {
    const MAX_BYTES: u64 = 256 * 1024;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| Error::Input("Project template is unavailable".into()))?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES {
        return Err(Error::Input(
            "Project template must be a regular JSON file of at most 256 KiB".into(),
        ));
    }
    let file = std::fs::File::open(path)
        .map_err(|_| Error::Input("Project template is unavailable".into()))?;
    let opened = file
        .metadata()
        .map_err(|_| Error::Input("Project template metadata is unavailable".into()))?;
    if !opened.is_file() || opened.len() > MAX_BYTES {
        return Err(Error::Input(
            "Project template must be a bounded regular JSON file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.dev() != opened.dev() || metadata.ino() != opened.ino() {
            return Err(Error::Input(
                "Project template changed identity while opening".into(),
            ));
        }
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Input("Project template could not be read".into()))?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(Error::Input("Project template exceeds 256 KiB".into()));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| Error::Input("Invalid public ProjectConfig template JSON".into()))
}

pub(super) fn sync_options(arguments: &SyncArguments) -> Result<SyncOptions> {
    Ok(SyncOptions {
        version: arguments.version.clone(),
        created_at: arguments.created_at.clone(),
        copy_id: arguments.copy_id.clone(),
        git_ref: arguments.git_ref.clone(),
        trigger: arguments.git_ref.as_ref().map(|_| ProjectTrigger::Git),
        rotate_to: key(
            arguments.rotate_key.as_ref(),
            arguments.rotate_key_ref.as_ref(),
        )?,
        allow_work_migration: arguments.allow_work_migration,
        trusted_keys: trusted_keys(arguments.trusted_keys.as_ref())?,
        force_full_scan: arguments.full_rescan,
        expected_source_sha256: arguments
            .expected_sources_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| {
                Error::Input(
                    "Expected sources must be a JSON object mapping paths to SHA-256 strings"
                        .into(),
                )
            })?
            .unwrap_or_default(),
        ..Default::default()
    })
}

pub fn worker_payload(command: &ProjectCommand) -> Result<Vec<u8>> {
    let ProjectCommand::Worker {
        execution: Some(execution),
    } = command
    else {
        return Err(Error::Input("Project worker payload is unavailable".into()));
    };
    let bytes = serde_json::to_vec(execution)
        .map_err(|_| Error::Input("Project request could not be serialized".into()))?;
    if bytes.len() > 256 * 1024 {
        return Err(Error::Blocked("Project request exceeds 256 KiB".into()));
    }
    Ok(bytes)
}

fn supervised(
    execution: ProjectExecution,
    cli: &super::Cli,
    cancelled: &AtomicBool,
) -> Result<i32> {
    let worker = super::Cli {
        json: cli.json,
        max_file_mib: cli.max_file_mib,
        timeout_seconds: cli.timeout_seconds,
        worker: false,
        command: super::Command::Project {
            command: ProjectCommand::Worker {
                execution: Some(Box::new(execution)),
            },
        },
    };
    super::supervise_with_cancellation(&worker, cancelled)
}

fn execute_worker(cli: &super::Cli, limits: &Limits) -> Result<i32> {
    if !cli.worker || std::env::var_os("FILEVEIL_WORKER_HANDSHAKE").is_none() {
        return Err(Error::Blocked(
            "Project worker requires the parent handshake".into(),
        ));
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(256 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Io("Project worker request could not be read".into()))?;
    if bytes.len() > 256 * 1024 {
        return Err(Error::Blocked(
            "Project worker request exceeds its byte budget".into(),
        ));
    }
    let execution: ProjectExecution = serde_json::from_slice(&bytes)
        .map_err(|_| Error::Input("Project worker request is invalid".into()))?;
    let report = fileveil_engine::worker::run_project_operation(
        execution.request,
        execution.after.as_deref(),
        limits,
        Duration::from_secs(cli.timeout_seconds),
    )?;
    let code = report_code(&report);
    super::print_report(&report, true);
    Ok(code)
}

pub(super) fn report_code(report: &Report) -> i32 {
    match report.result {
        Outcome::VerifiedWithinScope => 0,
        Outcome::PartiallyVerified => 4,
        Outcome::Unsupported => 3,
        Outcome::Blocked => 5,
        Outcome::Failed => 4,
        Outcome::NotAssessed => 4,
    }
}

pub fn run(command: &ProjectCommand, cli: &super::Cli, limits: &Limits) -> Result<i32> {
    if matches!(command, ProjectCommand::Worker { .. }) {
        return execute_worker(cli, limits);
    }
    let cancelled = super::cancellation_flag()?;
    let (mut request, after) = match command {
        ProjectCommand::Init {
            common,
            update,
            template,
            work_id,
            author,
            copy_id,
            source,
            output,
            build_directory,
            trigger,
            include,
            exclude,
            rules_json,
            copy_files,
            build_argv_json,
            max_files,
            max_project_file_mib,
            max_total_mib,
        } => {
            let mut request = request(
                common,
                if *update {
                    ProjectAction::UpdateConfig
                } else {
                    ProjectAction::Init
                },
            )?;
            let mut config = if *update {
                fileveil_engine::project::load_configuration(&request, limits)?
            } else if let Some(path) = template {
                read_template(path)?
            } else {
                ProjectConfig {
                    copy_id: "original".into(),
                    ..Default::default()
                }
            };
            if let Some(value) = work_id {
                config.work_id = value.clone();
            }
            if let Some(value) = author {
                config.author = value.clone();
            }
            if let Some(value) = copy_id {
                config.copy_id = value.clone();
            }
            if let Some(value) = source {
                config.source_root = value.clone();
            }
            if let Some(value) = output {
                config.output_directory = value.clone();
            }
            if let Some(value) = build_directory {
                config.build_directory = value.clone();
            }
            if let Some(value) = trigger {
                config.trigger = (*value).into();
            }
            if let Some(value) = copy_files {
                config.copy_external_files = *value;
            }
            if let Some(value) = max_files {
                config.max_files = *value as usize;
            }
            if let Some(value) = max_project_file_mib {
                config.max_file_bytes = value * 1024 * 1024;
            }
            if let Some(value) = max_total_mib {
                config.max_total_bytes = value * 1024 * 1024;
            }
            if !include.is_empty() {
                config.include = include.clone();
            }
            config.exclude.extend(exclude.iter().cloned());
            if let Some(encoded) = rules_json {
                config.rules = serde_json::from_str(encoded)
                    .map_err(|_| Error::Input("Invalid project rules JSON".into()))?;
            }
            if let Some(encoded) = build_argv_json {
                config.build_argv = serde_json::from_str(encoded).map_err(|_| {
                    Error::Input("Build command must be a JSON string array".into())
                })?;
            }
            request.init = Some(config);
            (request, None)
        }
        ProjectCommand::Sync {
            common,
            options,
            build,
            after,
        } => {
            let mut request = request(common, ProjectAction::Sync)?;
            request.options = sync_options(options)?;
            let after = if *build {
                let mut configuration_request = request.clone();
                configuration_request.options.git_ref = None;
                let config =
                    fileveil_engine::project::load_configuration(&configuration_request, limits)?;
                if config.build_argv.is_empty() {
                    return Err(Error::Input(
                        "The project has no saved build command".into(),
                    ));
                }
                Some(config.build_argv)
            } else {
                (!after.is_empty()).then(|| after.clone())
            };
            (request, after)
        }
        ProjectCommand::Verify {
            common,
            trusted_keys: anchors,
        } => {
            let mut request = request(common, ProjectAction::Verify)?;
            request.options.trusted_keys = trusted_keys(anchors.as_ref())?;
            (request, None)
        }
        ProjectCommand::Status { common } => (request(common, ProjectAction::Status)?, None),
        ProjectCommand::Watch {
            common,
            options,
            poll_ms,
            debounce_ms,
            full_rescan_seconds,
            max_runs,
        } => {
            let mut request = request(common, ProjectAction::Sync)?;
            request.options = sync_options(options)?;
            return watch(
                request,
                cli,
                limits,
                &cancelled,
                *poll_ms,
                *debounce_ms,
                *full_rescan_seconds,
                *max_runs,
            );
        }
        ProjectCommand::Worker { .. } => unreachable!(),
    };
    if after.is_some() {
        request.options.trigger = Some(ProjectTrigger::BuildRelease);
    }
    supervised(ProjectExecution { request, after }, cli, &cancelled)
}

#[allow(clippy::too_many_arguments)]
fn watch(
    mut request: ProjectRequest,
    cli: &super::Cli,
    limits: &Limits,
    cancelled: &AtomicBool,
    poll_override: Option<u64>,
    debounce_override: Option<u64>,
    full_rescan_override: Option<u64>,
    maximum_runs: Option<u64>,
) -> Result<i32> {
    request.options.automatic = true;
    let requested_reference = request.options.git_ref.take();
    let config = fileveil_engine::project::load_configuration(&request, limits)?;
    let configuration_directory = request.config_path.parent().unwrap_or(Path::new("."));
    let git_directory = if config.build_directory.is_absolute() {
        config.build_directory.clone()
    } else {
        configuration_directory.join(&config.build_directory)
    };
    let git = requested_reference.is_some() || config.trigger == ProjectTrigger::Git;
    let git_reference = requested_reference.unwrap_or_else(|| "HEAD".into());
    if git {
        request.options.trigger = Some(ProjectTrigger::Git);
    } else {
        request.options.trigger = Some(ProjectTrigger::Watch);
    }
    let poll = Duration::from_millis(poll_override.unwrap_or(config.poll_interval_ms).max(100));
    let debounce = Duration::from_millis(debounce_override.unwrap_or(config.debounce_ms).max(50));
    let full_interval = full_rescan_override
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_millis(config.full_rescan_interval_ms.max(60_000)));
    let mut runs = 0u64;
    let mut strong_duration = Duration::ZERO;
    let mut last_strong = Instant::now();
    let mut previous = String::new();
    let mut pending = None;
    loop {
        if cancelled.load(Ordering::SeqCst) {
            return Ok(6);
        }
        let started = Instant::now();
        let fingerprint = fileveil_engine::project::watch_fingerprint(&request, limits)?;
        let fingerprint = if git {
            let revision = fileveil_engine::worker::git_snapshot(
                &git_directory,
                &git_reference,
                Duration::from_secs(10),
            )?;
            format!("{fingerprint}:{}", revision.commit)
        } else {
            fingerprint
        };
        let probe_duration = started.elapsed();
        if fingerprint != previous {
            previous = fingerprint;
            pending = Some(Instant::now());
        }
        let periodic =
            last_strong.elapsed() >= full_interval.max(strong_duration.saturating_mul(2));
        let changed = pending.is_some_and(|time| time.elapsed() >= debounce);
        if runs == 0 || changed || periodic {
            let strong = Instant::now();
            let mut synchronization = request.clone();
            synchronization.options.force_full_scan =
                runs == 0 || periodic || request.options.force_full_scan;
            if git {
                synchronization.options.git_ref = Some(git_reference.clone());
            }
            let code = supervised(
                ProjectExecution {
                    request: synchronization,
                    after: None,
                },
                cli,
                cancelled,
            )?;
            strong_duration = strong.elapsed();
            last_strong = Instant::now();
            pending = None;
            runs += 1;
            if code == 6 || maximum_runs.is_some_and(|maximum| runs >= maximum) {
                return Ok(code);
            }
        }
        let wait = poll.max(probe_duration.saturating_mul(2));
        let until = Instant::now() + wait;
        while Instant::now() < until {
            if cancelled.load(Ordering::SeqCst) {
                return Ok(6);
            }
            std::thread::sleep(
                Duration::from_millis(50).min(until.saturating_duration_since(Instant::now())),
            );
        }
    }
}
