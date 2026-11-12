// SPDX-License-Identifier: MPL-2.0
use clap::{Parser, Subcommand, ValueEnum};
use fileveil_core::{
    Error, Format, ImageProcessMode, ImageProcessOptions, Limits, Outcome, Policy, Report, Result,
    SanitizeOptions,
};
use fileveil_engine::worker::{WorkerGuard, configure_command};
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
        output: PathBuf,
        #[arg(long, value_enum, default_value = "safe")]
        profile: Profile,
        #[arg(long)]
        options_json: Option<String>,
    },
    /// Detect a named, reproducible synthetic image watermark protocol
    DetectWatermark { path: PathBuf },
    /// Compare 2 to 8 explicitly selected image control samples
    Lab {
        #[arg(num_args = 2..=8)]
        paths: Vec<PathBuf>,
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
    /// Show implemented adapters, platform support and resource limits
    Capabilities,
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
        Command::Scan { .. } => "scan",
        Command::Sanitize { .. } | Command::ProcessImage { .. } => "sanitize",
        Command::Verify { .. } | Command::VerifyImage { .. } => "verify",
        Command::DetectWatermark { .. } => "detect_watermark",
        Command::Lab { .. } => "lab",
        Command::Provenance { .. } => "provenance",
        Command::Capabilities => "capabilities",
    }
}
fn execute(cli: &Cli, limits: &Limits) -> Result<i32> {
    let report = match &cli.command {
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
        } => {
            let options = sanitize_options(*profile, options_json.as_deref())?;
            if options.policy == Policy::Safe && !options.any() {
                fileveil_engine::verify(original, output, limits)?
            } else if options.policy == Policy::Research {
                fileveil_engine::verify_processed_image(
                    original,
                    output,
                    &ImageProcessOptions::default(),
                    limits,
                )?
            } else {
                fileveil_engine::advanced::verify_with_options(original, output, limits, &options)?
            }
        }
        Command::DetectWatermark { path } => {
            fileveil_engine::audits::detect_watermark(path, limits)?
        }
        Command::Lab { paths } => fileveil_engine::audits::lab(paths, limits)?,
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
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&cancelled);
    ctrlc::set_handler(move || {
        signal.store(true, Ordering::SeqCst);
    })
    .map_err(|_| Error::Io("Could not install cancellation handler".into()))?;
    let mut command = Process::new(
        std::env::current_exe().map_err(|_| Error::Io("Could not locate CLI worker".into()))?,
    );
    command
        .arg("--worker")
        .arg("--json")
        .arg("--max-file-mib")
        .arg(cli.max_file_mib.to_string())
        .env("FILEVEIL_PDF_STAGING", scratch.path())
        .env("FILEVEIL_WORKER_HANDSHAKE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let staged_output = staging
        .as_ref()
        .map(|directory| directory.path().join("verified-artifact.png"));
    match &cli.command {
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
        } => {
            command.arg("verify").arg("--profile").arg(match profile {
                Profile::Safe => "safe",
                Profile::Deep => "deep",
                Profile::Research => "research",
            });
            if let Some(options) = options_json {
                command.arg("--options-json").arg(options);
            }
            command.arg("--").arg(original).arg(output);
        }
        Command::DetectWatermark { path } => {
            command.arg("detect-watermark").arg("--").arg(path);
        }
        Command::Lab { paths } => {
            command.arg("lab").arg("--").args(paths);
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
        child
            .child
            .stdin
            .take()
            .ok_or_else(|| Error::Io("Worker startup pipe unavailable".into()))?
            .write_all(b"FILEVEIL_START\n")
            .map_err(|_| Error::Io("Could not start confined worker".into()))?;
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
            .child
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
                if matches!(
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
    let cli = Cli::parse();
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
    let result = if cli.worker || matches!(cli.command, Command::Capabilities) {
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
