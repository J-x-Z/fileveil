// SPDX-License-Identifier: MPL-2.0
//! Central project registration through the same bounded CLI worker transport.
use clap::{Args, Subcommand, ValueEnum};
use fileveil_core::{Error, Limits, Result};
use fileveil_engine::project::registry::{
    ProjectKind, ProjectOverrides, RegistryAction, RegistryCompilerConfig, RegistryDefaults,
    RegistryPolicy, RegistryRequest,
};
use std::{io::Read, path::PathBuf, sync::atomic::AtomicBool};

#[derive(Debug, Args)]
pub struct RegistryPaths {
    #[arg(long)]
    registry: Option<PathBuf>,
    #[arg(long, help = "Private registry data directory")]
    state_directory: Option<PathBuf>,
    #[arg(long, conflicts_with = "key_ref")]
    key: Option<PathBuf>,
    #[arg(long, conflicts_with = "key")]
    key_ref: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum RegistryCommand {
    /// Generate secret-free local and GitHub Actions release configuration
    Ci {
        #[arg(long, default_value = "Project copyright")]
        name: String,
        #[arg(long)]
        work_id: String,
        #[arg(long)]
        author: String,
        #[arg(long, default_value = "release")]
        copy_id: String,
        #[arg(long, default_value = "dist")]
        artifacts: PathBuf,
        #[arg(long, default_value = "fileveil-release")]
        output: PathBuf,
        #[arg(long, default_value = "[]")]
        build_argv_json: String,
        #[arg(long, default_value = "[]")]
        test_argv_json: String,
        #[arg(long, value_enum, default_value = "manifest-only")]
        policy: Policy,
        #[arg(long)]
        rules_json: Option<String>,
        #[arg(long)]
        compiler_json: Option<String>,
        #[arg(long, default_value = "main")]
        engine_ref: String,
        #[arg(long, default_value = "ubuntu-latest")]
        runner: String,
        #[arg(
            long,
            help = "Create a new directory containing the generated configuration and workflow"
        )]
        write_directory: Option<PathBuf>,
    },
    /// Initialize shared identity and policy defaults
    Init {
        #[command(flatten)]
        paths: RegistryPaths,
        #[arg(long)]
        author: String,
        #[arg(long)]
        defaults_json: Option<String>,
    },
    /// Replace shared defaults with explicit RegistryDefaults JSON
    Configure {
        #[command(flatten)]
        paths: RegistryPaths,
        #[arg(long)]
        defaults_json: String,
    },
    /// Register and identify a local, Git, Cargo, CMake, Godot or Unreal project
    Add {
        project: PathBuf,
        #[command(flatten)]
        paths: RegistryPaths,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, value_enum)]
        kind: Option<Kind>,
        #[command(flatten)]
        overrides: Overrides,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(
            long,
            help = "RegistryCompilerConfig JSON selecting real source or LLVM targets"
        )]
        compiler_json: Option<String>,
    },
    /// Update one registered project's policy and identity overrides
    Update {
        project_id: String,
        #[command(flatten)]
        paths: RegistryPaths,
        #[command(flatten)]
        overrides: Overrides,
        #[arg(long)]
        compiler_json: Option<String>,
    },
    /// Import existing project metadata and preserve its original configuration
    Migrate {
        config: PathBuf,
        #[command(flatten)]
        paths: RegistryPaths,
        #[arg(long)]
        project: Option<PathBuf>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        legacy_state_directory: Option<PathBuf>,
    },
    /// Remove a registration reference
    Remove {
        project_id: String,
        #[command(flatten)]
        paths: RegistryPaths,
    },
    /// List registered projects and shared defaults
    List {
        #[command(flatten)]
        paths: RegistryPaths,
    },
    /// Inspect registered project status
    Status {
        project_id: Option<String>,
        #[command(flatten)]
        paths: RegistryPaths,
        #[arg(long, conflicts_with = "project_id")]
        all: bool,
    },
    /// Synchronize one selected project or an explicitly selected registry batch
    Sync {
        #[arg(required_unless_present = "all")]
        project_id: Option<String>,
        #[command(flatten)]
        paths: RegistryPaths,
        #[arg(long, conflicts_with = "project_id")]
        all: bool,
        #[command(flatten)]
        options: super::project_cli::SyncArguments,
    },
    /// Verify integrity, signatures and history across registered generations
    Verify {
        #[arg(required_unless_present = "all")]
        project_id: Option<String>,
        #[command(flatten)]
        paths: RegistryPaths,
        #[arg(long, conflicts_with = "project_id")]
        all: bool,
        #[command(flatten)]
        options: super::project_cli::SyncArguments,
    },
    #[command(name = "__run", hide = true)]
    Worker {
        #[arg(skip)]
        execution: Option<Box<RegistryRequest>>,
    },
}

#[derive(Debug, Args)]
pub struct Overrides {
    #[arg(long)]
    author: Option<String>,
    #[arg(long)]
    work_id: Option<String>,
    #[arg(long)]
    copy_id: Option<String>,
    #[arg(long, value_enum)]
    policy: Option<Policy>,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long)]
    source: Option<PathBuf>,
    #[arg(long)]
    build_directory: Option<PathBuf>,
    #[arg(long,num_args=0..=1,default_missing_value="true")]
    copy_files: Option<bool>,
    #[arg(long)]
    build_argv_json: Option<String>,
    #[arg(long)]
    rules_json: Option<String>,
}
impl Overrides {
    fn value(&self) -> Result<ProjectOverrides> {
        Ok(ProjectOverrides {
            author: self.author.clone(),
            work_id: self.work_id.clone(),
            copy_id: self.copy_id.clone(),
            policy: self.policy.map(Into::into),
            output_directory: self.output.clone(),
            source_root: self.source.clone(),
            build_directory: self.build_directory.clone(),
            copy_external_files: self.copy_files,
            build_argv: self
                .build_argv_json
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(|_| Error::Input("Build arguments must be a JSON string array".into()))?,
            rules: self
                .rules_json
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(|_| Error::Input("Project rules must be a JSON array".into()))?,
        })
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Policy {
    ManifestOnly,
    AssetWatermark,
    CompilerWatermark,
    Hybrid,
}
impl From<Policy> for RegistryPolicy {
    fn from(policy: Policy) -> Self {
        match policy {
            Policy::ManifestOnly => Self::ManifestOnly,
            Policy::AssetWatermark => Self::AssetWatermark,
            Policy::CompilerWatermark => Self::CompilerWatermark,
            Policy::Hybrid => Self::Hybrid,
        }
    }
}
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Kind {
    Local,
    Git,
    Cargo,
    Cmake,
    Godot,
    Unreal,
}
impl From<Kind> for ProjectKind {
    fn from(kind: Kind) -> Self {
        match kind {
            Kind::Local => Self::Local,
            Kind::Git => Self::Git,
            Kind::Cargo => Self::Cargo,
            Kind::Cmake => Self::Cmake,
            Kind::Godot => Self::Godot,
            Kind::Unreal => Self::Unreal,
        }
    }
}

fn request(paths: &RegistryPaths, action: RegistryAction) -> Result<RegistryRequest> {
    Ok(RegistryRequest {
        action,
        registry_path: paths
            .registry
            .as_deref()
            .map(super::project_cli::absolute)
            .transpose()?,
        state_directory: paths
            .state_directory
            .as_deref()
            .map(super::project_cli::absolute)
            .transpose()?,
        key: super::project_cli::key(paths.key.as_ref(), paths.key_ref.as_ref())?,
        ..Default::default()
    })
}
fn compiler(value: Option<&String>) -> Result<Option<RegistryCompilerConfig>> {
    value
        .map(|value| {
            serde_json::from_str(value)
                .map_err(|_| Error::Input("Invalid registry compiler configuration JSON".into()))
        })
        .transpose()
}

pub fn worker_payload(command: &RegistryCommand) -> Result<Vec<u8>> {
    let RegistryCommand::Worker {
        execution: Some(execution),
    } = command
    else {
        return Err(Error::Input(
            "Registry worker payload is unavailable".into(),
        ));
    };
    let bytes = serde_json::to_vec(execution)
        .map_err(|_| Error::Input("Registry request could not be serialized".into()))?;
    if bytes.len() > 256 * 1024 {
        return Err(Error::Blocked("Registry request exceeds 256 KiB".into()));
    }
    Ok(bytes)
}
pub fn run(command: &RegistryCommand, cli: &super::Cli, limits: &Limits) -> Result<i32> {
    if let RegistryCommand::Ci {
        name,
        work_id,
        author,
        copy_id,
        artifacts,
        output,
        build_argv_json,
        test_argv_json,
        policy,
        rules_json,
        compiler_json,
        engine_ref,
        runner,
        write_directory,
    } = command
    {
        let bundle =
            fileveil_engine::project::ci::generate(&fileveil_engine::project::ci::CiConfig {
                name: name.clone(),
                work_id: work_id.clone(),
                author: author.clone(),
                copy_id: copy_id.clone(),
                artifact_directory: artifacts.clone(),
                output_directory: output.clone(),
                build_argv: serde_json::from_str(build_argv_json).map_err(|_| {
                    Error::Input("Build arguments must be a JSON string array".into())
                })?,
                test_argv: serde_json::from_str(test_argv_json).map_err(|_| {
                    Error::Input("Test arguments must be a JSON string array".into())
                })?,
                engine_ref: engine_ref.clone(),
                runner: runner.clone(),
                policy: (*policy).into(),
                rules: rules_json
                    .as_deref()
                    .map(serde_json::from_str)
                    .transpose()
                    .map_err(|_| Error::Input("Project rules must be a JSON array".into()))?
                    .unwrap_or_else(fileveil_engine::project::ci::default_asset_rules),
                compiler: compiler(compiler_json.as_ref())?,
            })?;
        if let Some(path) = write_directory {
            write_ci_bundle(path, &bundle)?;
        }
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&bundle)
                    .map_err(|_| Error::Input("CI bundle could not be serialized".into()))?
            );
        } else {
            println!("{}", bundle.local_command);
            println!("{}", bundle.workflow_yaml);
            println!("{}", bundle.config_json);
        }
        return Ok(0);
    }
    if matches!(command, RegistryCommand::Worker { .. }) {
        if !cli.worker || std::env::var_os("FILEVEIL_WORKER_HANDSHAKE").is_none() {
            return Err(Error::Blocked(
                "Registry worker requires the parent handshake".into(),
            ));
        }
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(256 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Io("Registry request could not be read".into()))?;
        if bytes.len() > 256 * 1024 {
            return Err(Error::Blocked(
                "Registry request exceeds its byte budget".into(),
            ));
        }
        let request: RegistryRequest = serde_json::from_slice(&bytes)
            .map_err(|_| Error::Input("Invalid registry worker request".into()))?;
        let report =
            fileveil_engine::project::registry::run(&request, limits, &AtomicBool::new(false))?;
        super::print_report(&report, true);
        return Ok(super::project_cli::report_code(&report));
    }
    let request = match command {
        RegistryCommand::Init {
            paths,
            author,
            defaults_json,
        } => {
            let mut request = request(paths, RegistryAction::Init)?;
            let mut defaults: RegistryDefaults = defaults_json
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(|_| Error::Input("Invalid RegistryDefaults JSON".into()))?
                .unwrap_or_default();
            defaults.author = author.clone();
            request.defaults = Some(defaults);
            request
        }
        RegistryCommand::Configure {
            paths,
            defaults_json,
        } => {
            let mut request = request(paths, RegistryAction::Configure)?;
            request.defaults = Some(
                serde_json::from_str(defaults_json)
                    .map_err(|_| Error::Input("Invalid RegistryDefaults JSON".into()))?,
            );
            request
        }
        RegistryCommand::Add {
            project,
            paths,
            name,
            kind,
            overrides,
            config,
            compiler_json,
        } => {
            let mut request = request(paths, RegistryAction::Add)?;
            request.project_path = Some(super::project_cli::absolute(project)?);
            request.name = name.clone();
            request.kind = kind.map(Into::into);
            request.overrides = Some(overrides.value()?);
            request.config_path = config
                .as_deref()
                .map(super::project_cli::absolute)
                .transpose()?;
            request.compiler = compiler(compiler_json.as_ref())?;
            request
        }
        RegistryCommand::Update {
            project_id,
            paths,
            overrides,
            compiler_json,
        } => {
            let mut request = request(paths, RegistryAction::Update)?;
            request.project_id = Some(project_id.clone());
            request.overrides = Some(overrides.value()?);
            request.compiler = compiler(compiler_json.as_ref())?;
            request
        }
        RegistryCommand::Migrate {
            config,
            paths,
            project,
            name,
            legacy_state_directory,
        } => {
            let mut request = request(paths, RegistryAction::Migrate)?;
            request.legacy_state_directory = legacy_state_directory
                .as_deref()
                .map(super::project_cli::absolute)
                .transpose()?;
            request.config_path = Some(super::project_cli::absolute(config)?);
            request.project_path = project
                .as_deref()
                .map(super::project_cli::absolute)
                .transpose()?;
            request.name = name.clone();
            request
        }
        RegistryCommand::Remove { project_id, paths } => {
            let mut request = request(paths, RegistryAction::Remove)?;
            request.project_id = Some(project_id.clone());
            request
        }
        RegistryCommand::List { paths } => request(paths, RegistryAction::List)?,
        RegistryCommand::Status {
            project_id,
            paths,
            all,
        } => {
            let mut request = request(paths, RegistryAction::Status)?;
            request.project_id = project_id.clone();
            request.all = *all || project_id.is_none();
            request
        }
        RegistryCommand::Sync {
            project_id,
            paths,
            all,
            options,
        }
        | RegistryCommand::Verify {
            project_id,
            paths,
            all,
            options,
        } => {
            let mut request = request(
                paths,
                if matches!(command, RegistryCommand::Sync { .. }) {
                    RegistryAction::Sync
                } else {
                    RegistryAction::Verify
                },
            )?;
            request.project_id = project_id.clone();
            request.all = *all;
            request.options = super::project_cli::sync_options(options)?;
            request
        }
        RegistryCommand::Worker { .. } | RegistryCommand::Ci { .. } => unreachable!(),
    };
    let cancelled = super::cancellation_flag()?;
    let worker = super::Cli {
        json: cli.json,
        max_file_mib: cli.max_file_mib,
        timeout_seconds: cli.timeout_seconds,
        worker: false,
        command: super::Command::Registry {
            command: RegistryCommand::Worker {
                execution: Some(Box::new(request)),
            },
        },
    };
    super::supervise_with_cancellation(&worker, &cancelled)
}

fn write_ci_bundle(
    path: &std::path::Path,
    bundle: &fileveil_engine::project::ci::CiBundle,
) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(not(unix))]
    let builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|_| {
        Error::Input("CI output must name a new directory under an existing parent".into())
    })?;
    let workflow_directory = path.join(".github/workflows");
    std::fs::create_dir_all(&workflow_directory)
        .map_err(|_| Error::Io("Could not create the CI workflow directory".into()))?;
    for (destination, text) in [
        (path.join("fileveil-ci.json"), &bundle.config_json),
        (
            workflow_directory.join("fileveil-release.yml"),
            &bundle.workflow_yaml,
        ),
    ] {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)
            .map_err(|_| Error::Io("Could not create a new CI configuration file".into()))?;
        file.write_all(text.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::Io("Could not flush the CI configuration file".into()))?;
    }
    Ok(())
}

// FVPROV1 18454 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJjZDY1ODI2OWIxZjhlZGNjY2ZkMDY2MGFhOGRlNGM1NDJhOWUwOGQ2MzZhMGFmZTkyNTFkOWI1ODQ0YjI0NmE2IiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1jbGkvc3JjL3JlZ2lzdHJ5X2NsaS5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6ImJkZTM3ZmJkYTI0Y2YwMTc1MmZjMjFiYjQxZDk5ZDIzZGE5OTdmMzcxODRhMTdkZDA3MDdhZjNjMjZjNWI3YTdiNDg2NjQxOTdlN2JhNDc3MDlhODIzZDFjNjkzMWE2MjlhMTdmNjU1NDMwMmU0OTdlZjNmOGEzYzk4ODFjMzBjIn1dfV0= FVPROV1-END
