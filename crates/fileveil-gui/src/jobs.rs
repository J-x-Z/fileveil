// SPDX-License-Identifier: MPL-2.0
//! Isolated GUI jobs backed by the same engine and reports as the CLI.
//!
//! A supervisor owns each private staging directory. The worker writes its
//! verified artifact there. The supervisor commits that artifact after the
//! worker exits and checks the report-bound file snapshots again.
use crate::mcp_access::{AuthorizedJob, BINDINGS_ENV, PrivateStaging};
use fileveil_core::{Error, Format, ImageProcessOptions, Limits, Outcome, Report, SanitizeOptions};
use fileveil_engine::worker::{WorkerGuard, configure_command};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
        mpsc::{self, Receiver},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const RUNNING: u8 = 0;
const CANCELLED: u8 = 1;
const COMMITTING: u8 = 2;
const FINISHED: u8 = 3;
const MAX_REQUEST_BYTES: u64 = 256 * 1024;
const MAX_REPORT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum JobKind {
    Compute {
        request: Box<fileveil_engine::compute::ComputeRequest>,
    },
    Registry {
        request: Box<fileveil_engine::project::registry::RegistryRequest>,
    },
    Software {
        request: Box<fileveil_engine::software::SoftwareRequest>,
    },
    Project {
        request: Box<fileveil_engine::project::ProjectRequest>,
        #[serde(default)]
        after: Option<Vec<String>>,
    },
    Heritage {
        path: PathBuf,
        output: Option<PathBuf>,
        request: Box<fileveil_engine::heritage::HeritageRequest>,
    },
    SystemKeygen,
    HeritageKeygen {
        output: PathBuf,
    },
    SanitizeAdvanced {
        input: PathBuf,
        output: Option<PathBuf>,
        options: SanitizeOptions,
    },
    VerifyAdvanced {
        original: PathBuf,
        output: PathBuf,
        options: SanitizeOptions,
    },
    DetectWatermark {
        path: PathBuf,
    },
    Lab {
        paths: Vec<PathBuf>,
    },
    LabGrouped {
        paths: Vec<PathBuf>,
        groups: Vec<fileveil_engine::lab::SampleGroup>,
    },
    Provenance {
        path: PathBuf,
        trust_roots: Option<PathBuf>,
    },
    Scan {
        path: PathBuf,
    },
    Sanitize {
        input: PathBuf,
        output: Option<PathBuf>,
    },
    ProcessImage {
        input: PathBuf,
        output: Option<PathBuf>,
        options: ImageProcessOptions,
    },
    Verify {
        original: PathBuf,
        output: PathBuf,
    },
    VerifyImage {
        original: PathBuf,
        output: PathBuf,
        options: ImageProcessOptions,
    },
}
impl JobKind {
    pub fn operation(&self) -> &'static str {
        match self {
            Self::Compute { .. } => "compute_fingerprint",
            Self::Project { .. } => "project",
            Self::Registry { .. } => "registry",
            Self::Software { .. } => "software",
            Self::Heritage { .. } => "heritage",
            Self::HeritageKeygen { .. } | Self::SystemKeygen => "heritage_keygen",
            Self::Scan { .. } => "scan",
            Self::Sanitize { .. } | Self::ProcessImage { .. } | Self::SanitizeAdvanced { .. } => {
                "sanitize"
            }
            Self::Verify { .. } | Self::VerifyImage { .. } | Self::VerifyAdvanced { .. } => {
                "verify"
            }
            Self::DetectWatermark { .. } => "detect_watermark",
            Self::Lab { .. } | Self::LabGrouped { .. } => "lab",
            Self::Provenance { .. } => "provenance",
        }
    }

    fn output_target(&self) -> Option<(&Path, Option<&Path>)> {
        match self {
            Self::Software { request }
                if request.action == fileveil_engine::software::SoftwareAction::Clean
                    && request.mode == fileveil_engine::software::SoftwareMode::Structure =>
            {
                Some((&request.input_path, request.output_path.as_deref()))
            }
            Self::Heritage {
                path,
                output,
                request,
            } if request.writes_file() => Some((path, output.as_deref())),
            Self::Sanitize { input, output }
            | Self::ProcessImage { input, output, .. }
            | Self::SanitizeAdvanced { input, output, .. } => Some((input, output.as_deref())),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRequest {
    pub kind: JobKind,
    pub limits: Limits,
    pub timeout_seconds: u64,
}
impl JobRequest {
    pub fn new(kind: JobKind) -> Self {
        Self {
            kind,
            limits: Limits::default(),
            timeout_seconds: 120,
        }
    }
    fn validate(&self) -> fileveil_core::Result<()> {
        if !(1..=512 * 1024 * 1024).contains(&self.limits.max_file_bytes)
            || !(1..=1024 * 1024 * 1024).contains(&self.limits.max_uncompressed_bytes)
            || !(1..=100_000).contains(&self.limits.max_members)
            || !(1..=16 * 1024 * 1024).contains(&self.limits.max_metadata_bytes)
            || !(1..=10_000).contains(&self.limits.max_compression_ratio)
            || !(1..=64_000_000).contains(&self.limits.max_pixels)
            || !(1..=3600).contains(&self.timeout_seconds)
        {
            return Err(Error::Input(
                "Requested resource limits exceed the desktop worker budget".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct JobResult {
    pub report: Report,
    pub exit_code: i32,
    pub output_path: Option<PathBuf>,
}
impl JobResult {
    fn failure(kind: &JobKind, error: Error) -> Self {
        let mut report = Report::new(kind.operation(), Format::Unknown);
        report.result = match error {
            Error::Unsupported(_) => Outcome::Unsupported,
            Error::Blocked(_) => Outcome::Blocked,
            _ => Outcome::Failed,
        };
        let exit_code = error.exit_code();
        report.warnings.push(error.to_string());
        Self {
            report,
            exit_code,
            output_path: None,
        }
    }
}

/// One active job. Dropping this handle cancels and reaps its worker.
#[derive(Debug)]
pub struct JobHandle {
    receiver: Receiver<JobResult>,
    phase: Arc<AtomicU8>,
    thread: Option<JoinHandle<()>>,
}
impl JobHandle {
    pub fn spawn(request: JobRequest, notify: Arc<dyn Fn() + Send + Sync>) -> Self {
        match std::env::current_exe() {
            Ok(executable) => Self::spawn_with_executable(request, executable, notify),
            Err(_) => {
                let (sender, receiver) = mpsc::channel();
                let result = JobResult::failure(
                    &request.kind,
                    Error::Io("Could not locate GUI worker executable".into()),
                );
                let _ = sender.send(result);
                notify();
                Self {
                    receiver,
                    phase: Arc::new(AtomicU8::new(FINISHED)),
                    thread: None,
                }
            }
        }
    }

    /// Explicit executable selection also exercises the packaged worker in tests.
    pub fn spawn_with_executable(
        request: JobRequest,
        executable: PathBuf,
        notify: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self::spawn_inner(request, executable, notify, None)
    }

    pub(crate) fn spawn_authorized(
        authorization: AuthorizedJob,
        notify: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        let request = authorization.request.clone();
        match std::env::current_exe() {
            Ok(executable) => Self::spawn_inner(request, executable, notify, Some(authorization)),
            Err(_) => Self::spawn_inner(request, PathBuf::new(), notify, Some(authorization)),
        }
    }

    fn spawn_inner(
        request: JobRequest,
        executable: PathBuf,
        notify: Arc<dyn Fn() + Send + Sync>,
        authorization: Option<AuthorizedJob>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel();
        let phase = Arc::new(AtomicU8::new(RUNNING));
        let task_phase = Arc::clone(&phase);
        let fallback_sender = sender.clone();
        let fallback_notify = Arc::clone(&notify);
        let fallback_kind = request.kind.clone();
        let thread = thread::Builder::new()
            .name("fileveil-job".into())
            .spawn(move || {
                let operation = request.kind.clone();
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if let Some(authorization) = &authorization {
                        fileveil_engine::access_guard::with_bound_files(
                            authorization.bindings()?,
                            || supervise(&request, &executable, &task_phase, Some(authorization)),
                        )
                    } else {
                        supervise(&request, &executable, &task_phase, None)
                    }
                }));
                let mut result = match outcome {
                    Ok(Ok(result)) => result,
                    Ok(Err(error)) => JobResult::failure(&operation, error),
                    Err(_) => JobResult::failure(
                        &operation,
                        Error::Blocked("GUI job supervisor ended unexpectedly".into()),
                    ),
                };
                // Once this transition succeeds, cancellation has reached its commit boundary.
                if task_phase
                    .compare_exchange(RUNNING, COMMITTING, Ordering::SeqCst, Ordering::SeqCst)
                    .is_err()
                    && task_phase.load(Ordering::SeqCst) == CANCELLED
                    && result.exit_code != 6
                {
                    result = JobResult::failure(
                        &operation,
                        Error::Interrupted(
                            "Operation cancelled and private staging cleaned".into(),
                        ),
                    );
                }
                let _ = sender.send(result);
                task_phase.store(FINISHED, Ordering::SeqCst);
                notify();
            });
        let thread = match thread {
            Ok(thread) => Some(thread),
            Err(_) => {
                let _ = fallback_sender.send(JobResult::failure(
                    &fallback_kind,
                    Error::Io("Could not start GUI job supervisor".into()),
                ));
                phase.store(FINISHED, Ordering::SeqCst);
                fallback_notify();
                None
            }
        };
        Self {
            receiver,
            phase,
            thread,
        }
    }

    pub fn try_recv(&self) -> Option<JobResult> {
        let result = self.receiver.try_recv().ok();
        if result.is_some() {
            self.phase.store(FINISHED, Ordering::SeqCst);
        }
        result
    }

    /// Returns whether cancellation was accepted before output publication began.
    pub fn cancel(&self) -> bool {
        self.phase
            .compare_exchange(RUNNING, CANCELLED, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    pub fn is_finished(&self) -> bool {
        self.phase.load(Ordering::SeqCst) == FINISHED
    }
}
impl Drop for JobHandle {
    fn drop(&mut self) {
        self.cancel();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn supervise(
    request: &JobRequest,
    executable: &Path,
    phase: &AtomicU8,
    authorization: Option<&AuthorizedJob>,
) -> fileveil_core::Result<JobResult> {
    request.validate()?;
    if let Some(authorization) = authorization {
        authorization.revalidate()?;
    }
    if phase.load(Ordering::SeqCst) == CANCELLED {
        return Err(Error::Interrupted(
            "Operation cancelled before worker startup".into(),
        ));
    }
    let started = Instant::now();
    // Backend snapshots belong to the supervisor so killing a worker also
    // removes sensitive helper inputs. Helpers receive ordinary private paths.
    let helper_staging = tempfile::Builder::new()
        .prefix(".fileveil-backend-job-")
        .tempdir()
        .map_err(|_| Error::Io("Could not create private backend scratch directory".into()))?;
    let helper_staging_path = helper_staging
        .path()
        .canonicalize()
        .map_err(|_| Error::Io("Could not resolve private backend scratch directory".into()))?;
    let mut private_staging = None;
    let staging = if let Some((input, output)) = request.kind.output_target() {
        if let Some(path) = output {
            ensure_new_path(path)?;
        }
        if let Some(authorization) = authorization {
            private_staging = Some(authorization.create_staging()?);
            None
        } else {
            Some(
                tempfile::Builder::new()
                    .prefix(".fileveil-gui-job-")
                    .tempdir_in(fileveil_engine::output_directory(input, output))
                    .map_err(|_| {
                        Error::Io(
                            "Could not create private staging directory in the output filesystem"
                                .into(),
                        )
                    })?,
            )
        }
    } else {
        None
    };
    let staged_directory = private_staging
        .as_ref()
        .map(PrivateStaging::path)
        .or_else(|| staging.as_ref().map(tempfile::TempDir::path));
    let staged_output = staged_directory.map(|directory| directory.join("verified-artifact.png"));
    let mut worker_request = request.clone();
    if let Some(staged) = &staged_output {
        match &mut worker_request.kind {
            JobKind::Software { request } => {
                request.output_path = Some(staged.clone());
            }
            JobKind::Heritage { output, .. }
            | JobKind::Sanitize { output, .. }
            | JobKind::ProcessImage { output, .. }
            | JobKind::SanitizeAdvanced { output, .. } => {
                *output = Some(staged.clone());
            }
            _ => {}
        }
    }
    let request_bytes = serde_json::to_vec(&worker_request)
        .map_err(|_| Error::Input("Selected paths cannot be encoded for the worker".into()))?;
    if request_bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(Error::Input(
            "Selected paths exceed the worker request limit".into(),
        ));
    }
    let mut command = Command::new(executable);
    command
        .arg("--fileveil-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command.env_remove(BINDINGS_ENV);
    command.env("FILEVEIL_PDF_STAGING", &helper_staging_path);
    configure_command(&mut command);
    if let Some(authorization) = authorization {
        authorization.configure_worker(&mut command, private_staging.as_ref())?;
    }
    let mut worker = WorkerGuard::new(
        command
            .spawn()
            .map_err(|_| Error::Io("Could not start isolated GUI worker".into()))?,
    )?;
    let mut stdin = worker
        .child
        .stdin
        .take()
        .ok_or_else(|| Error::Io("Could not open worker request pipe".into()))?;
    let stdout = worker
        .child
        .stdout
        .take()
        .ok_or_else(|| Error::Io("Could not open worker report pipe".into()))?;
    let writer = thread::spawn(move || stdin.write_all(&request_bytes));
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_REPORT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let status = wait_for_worker(&mut worker, phase, started, request.timeout_seconds);
    // Reaping closes both pipes before joining their bounded reader and writer.
    drop(worker);
    let written = writer
        .join()
        .map_err(|_| Error::Io("Could not complete worker request pipe".into()))?;
    let read = reader
        .join()
        .map_err(|_| Error::Io("Could not collect worker report".into()))?;
    let status = status?;
    written.map_err(|_| Error::Io("Could not send worker request".into()))?;
    let bytes = read.map_err(|_| Error::Io("Could not read worker report".into()))?;
    if bytes.len() as u64 > MAX_REPORT_BYTES {
        return Err(Error::Blocked(
            "Worker report exceeds the desktop report budget".into(),
        ));
    }
    let mut report: Report = serde_json::from_slice(&bytes)
        .map_err(|_| Error::Blocked("Worker returned an invalid report".into()))?;
    if report.schema_version != fileveil_core::SCHEMA_VERSION
        || report.tool != "FileVeil"
        || report.operation != request.kind.operation()
    {
        return Err(Error::Blocked(
            "Worker report contract does not match the requested operation".into(),
        ));
    }
    let exit_code = status
        .code()
        .ok_or_else(|| Error::Blocked("GUI worker ended abnormally".into()))?;
    if !matches!(exit_code, 0 | 2..=6) {
        return Err(Error::Blocked("GUI worker ended abnormally".into()));
    }
    if !status_matches_report(&request.kind, &report, exit_code) {
        return Err(Error::Blocked(
            "Worker exit status disagrees with its report".into(),
        ));
    }
    if let Some(authorization) = authorization {
        authorization.revalidate()?;
    }
    if matches!(
        report.result,
        Outcome::VerifiedWithinScope | Outcome::PartiallyVerified
    ) {
        let requested_processing = match &request.kind {
            JobKind::ProcessImage { options, .. } | JobKind::VerifyImage { options, .. } => {
                Some(options)
            }
            _ => None,
        };
        let contract_matches = match (requested_processing, report.image_processing.as_ref()) {
            (Some(options), Some(processing)) => {
                report.policy == fileveil_core::Policy::Research
                    && processing.mode == options.mode
                    && processing.low_bits
                        == (options.mode == fileveil_core::ImageProcessMode::LowBits)
                            .then_some(options.low_bits)
                    && report.result == Outcome::PartiallyVerified
            }
            (None, None) => match &request.kind {
                JobKind::Registry { request } => report.advanced.as_ref().is_some_and(|details| {
                    details["registry"]["action"]
                        == serde_json::to_value(request.action).unwrap_or_default()
                }),
                JobKind::Software { request } => report.advanced.as_ref().is_some_and(|details| {
                    details["software"]["action"]
                        == serde_json::to_value(request.action).unwrap_or_default()
                }),
                JobKind::Project { request, .. } => {
                    report.policy == fileveil_core::Policy::Safe
                        && report.advanced.as_ref().is_some_and(|details| {
                            details["project"]["action"]
                                == serde_json::to_value(request.action).unwrap_or_default()
                        })
                }
                JobKind::Heritage { request, .. } => {
                    report.policy == request.policy()
                        && report.advanced.as_ref().is_some_and(|details| {
                            details["heritage"]["request_sha256"]
                                == request.digest().unwrap_or_default()
                        })
                }
                JobKind::SanitizeAdvanced { options, .. }
                | JobKind::VerifyAdvanced { options, .. } => {
                    report.policy == options.policy
                        && report.advanced.as_ref().is_some_and(|details| {
                            details["options"] == serde_json::to_value(options).unwrap_or_default()
                        })
                }
                _ => report.policy == fileveil_core::Policy::Safe,
            },
            _ => false,
        };
        if !contract_matches {
            return Err(Error::Blocked(
                "Worker processing parameters disagree with the requested operation".into(),
            ));
        }
    }
    if let (Some((input, output)), Some(staged)) = (request.kind.output_target(), &staged_output)
        && matches!(
            report.result,
            Outcome::VerifiedWithinScope | Outcome::PartiallyVerified
        )
    {
        if started.elapsed() >= Duration::from_secs(request.timeout_seconds) {
            return Err(Error::Interrupted(
                "Operation timed out before artifact publication and staging was cleaned".into(),
            ));
        }
        if phase
            .compare_exchange(RUNNING, COMMITTING, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(Error::Interrupted(
                "Operation cancelled before artifact publication and staging was cleaned".into(),
            ));
        }
        if let JobKind::Software { request: options } = &request.kind {
            let output = output.ok_or_else(|| {
                Error::Input("Software clean requires an explicit new output path".into())
            })?;
            fileveil_engine::software::publish_staged(
                input,
                staged,
                output,
                &mut report,
                &request.limits,
                options,
            )?;
        } else if let JobKind::Heritage {
            request: options, ..
        } = &request.kind
        {
            fileveil_engine::heritage::publish_staged(
                input,
                staged,
                output,
                options,
                &mut report,
                &request.limits,
            )?;
        } else if matches!(request.kind, JobKind::ProcessImage { .. }) {
            fileveil_engine::image_processing::publish_processed_staged(
                input,
                staged,
                output,
                &mut report,
                &request.limits,
            )?;
        } else if let JobKind::SanitizeAdvanced { options, .. } = &request.kind {
            fileveil_engine::advanced::publish_advanced_staged(
                input,
                staged,
                output,
                &mut report,
                &request.limits,
                options,
            )?;
        } else {
            fileveil_engine::publish_staged(input, staged, output, &mut report, &request.limits)?;
        }
        let output_path = report.output_name.as_ref().map(|name| {
            authorization
                .and_then(|authorization| authorization.external_output(name))
                .unwrap_or_else(|| fileveil_engine::output_directory(input, output).join(name))
        });
        return Ok(JobResult {
            report,
            exit_code,
            output_path,
        });
    }
    Ok(JobResult {
        report,
        exit_code,
        output_path: None,
    })
}

fn ensure_new_path(path: &Path) -> fileveil_core::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(Error::Input(
            "Output already exists. Choose a new path".into(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Error::Input("Output path could not be inspected".into())),
    }
}
fn wait_for_worker(
    worker: &mut WorkerGuard,
    phase: &AtomicU8,
    started: Instant,
    timeout_seconds: u64,
) -> fileveil_core::Result<ExitStatus> {
    loop {
        if phase.load(Ordering::SeqCst) == CANCELLED {
            return Err(Error::Interrupted(
                "Operation cancelled and private staging cleaned".into(),
            ));
        }
        if started.elapsed() >= Duration::from_secs(timeout_seconds) {
            return Err(Error::Interrupted(
                "Operation timed out and private staging cleaned".into(),
            ));
        }
        if let Some(status) = worker
            .try_wait()
            .map_err(|_| Error::Io("Could not inspect GUI worker".into()))?
        {
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(20));
    }
}
fn status_matches_report(kind: &JobKind, report: &Report, exit_code: i32) -> bool {
    if report.result == Outcome::Failed {
        matches!(exit_code, 2 | 4 | 6)
    } else {
        exit_code == report_exit_code(kind, report)
    }
}
fn report_exit_code(kind: &JobKind, report: &Report) -> i32 {
    match report.result {
        Outcome::Unsupported => 3,
        Outcome::Blocked => 5,
        Outcome::Failed => 4,
        Outcome::PartiallyVerified if !matches!(kind, JobKind::Scan { .. }) => 4,
        _ => 0,
    }
}

/// Run before initializing eframe or fonts when `--fileveil-worker` is present.
pub fn worker_main() -> i32 {
    let mut bytes = Vec::new();
    let read = std::io::stdin()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes);
    let request = if read.is_ok() && bytes.len() as u64 <= MAX_REQUEST_BYTES {
        serde_json::from_slice::<JobRequest>(&bytes)
            .map_err(|_| Error::Input("Invalid GUI worker request".into()))
    } else {
        Err(Error::Input(
            "Could not read bounded GUI worker request".into(),
        ))
    };
    let result = match request {
        Ok(request) => {
            let operation = request.kind.clone();
            match execute_worker(&request) {
                Ok(report) => JobResult {
                    exit_code: report_exit_code(&operation, &report),
                    report,
                    output_path: None,
                },
                Err(error) => JobResult::failure(&operation, error),
            }
        }
        Err(error) => JobResult::failure(
            &JobKind::Scan {
                path: PathBuf::new(),
            },
            error,
        ),
    };
    let mut stdout = std::io::stdout().lock();
    if serde_json::to_writer(&mut stdout, &result.report).is_err()
        || stdout.write_all(b"\n").is_err()
    {
        return 2;
    }
    result.exit_code
}
fn execute_worker(request: &JobRequest) -> fileveil_core::Result<Report> {
    let bindings = crate::mcp_access::worker_bindings()?;
    fileveil_engine::access_guard::with_bound_files(bindings, || execute_bound_worker(request))
}
fn execute_bound_worker(request: &JobRequest) -> fileveil_core::Result<Report> {
    request.validate()?;
    match &request.kind {
        JobKind::Compute { request: options } => {
            fileveil_engine::compute::report(options, &std::sync::atomic::AtomicBool::new(false))
        }
        JobKind::Registry { request: options } => fileveil_engine::project::registry::run(
            options,
            &request.limits,
            &std::sync::atomic::AtomicBool::new(false),
        ),
        JobKind::Software { request: options } => fileveil_engine::software::run(
            options,
            &request.limits,
            &std::sync::atomic::AtomicBool::new(false),
        ),
        JobKind::Project {
            request: options,
            after,
        } => fileveil_engine::worker::run_project_operation(
            options.as_ref().clone(),
            after.as_deref(),
            &request.limits,
            Duration::from_secs(request.timeout_seconds),
        ),
        JobKind::Heritage {
            path,
            output,
            request: options,
        } => {
            if options.writes_file() && output.is_none() {
                return Err(Error::Input(
                    "Heritage worker requires a private staging output".into(),
                ));
            }
            fileveil_engine::heritage::run(path, output.as_deref(), options, &request.limits)
        }
        JobKind::HeritageKeygen { output } => fileveil_engine::heritage::keygen(output),
        JobKind::SystemKeygen => {
            let (reference, public) = fileveil_engine::heritage::key_store::generate()?;
            let mut report = Report::new("heritage_keygen", Format::Unknown);
            report.result = Outcome::VerifiedWithinScope;
            report.advanced = Some(
                serde_json::json!({"heritage":{"public_key":public,"system_key_ref":reference,"backend":fileveil_engine::heritage::key_store::backend_name()}}),
            );
            Ok(report)
        }
        JobKind::SanitizeAdvanced {
            input,
            output,
            options,
        } => {
            if output.is_none() {
                return Err(Error::Input(
                    "Worker requires a private staging output".into(),
                ));
            }
            fileveil_engine::advanced::sanitize_with_options(
                input,
                output.as_deref(),
                &request.limits,
                options,
            )
        }
        JobKind::VerifyAdvanced {
            original,
            output,
            options,
        } => fileveil_engine::advanced::verify_with_options(
            original,
            output,
            &request.limits,
            options,
        ),
        JobKind::DetectWatermark { path } => {
            fileveil_engine::audits::detect_watermark(path, &request.limits)
        }
        JobKind::Lab { paths } => fileveil_engine::audits::lab(paths, &request.limits),
        JobKind::LabGrouped { paths, groups } => {
            fileveil_engine::audits::lab_with_groups(paths, groups, &request.limits)
        }
        JobKind::Provenance { path, trust_roots } => {
            fileveil_engine::audits::provenance(path, trust_roots.as_deref(), &request.limits)
        }
        JobKind::Scan { path } => fileveil_engine::scan(path, &request.limits),
        JobKind::Sanitize { input, output } => {
            if output.is_none() {
                return Err(Error::Input(
                    "GUI worker requires a private staging output".into(),
                ));
            }
            fileveil_engine::sanitize(input, output.as_deref(), &request.limits)
        }
        JobKind::Verify { original, output } => {
            fileveil_engine::verify(original, output, &request.limits)
        }
        JobKind::ProcessImage {
            input,
            output,
            options,
        } => {
            if output.is_none() {
                return Err(Error::Input(
                    "GUI worker requires a private staging output".into(),
                ));
            }
            fileveil_engine::image_processing::process_image_in(
                input,
                output.as_deref(),
                options,
                &request.limits,
                None,
            )
        }
        JobKind::VerifyImage {
            original,
            output,
            options,
        } => fileveil_engine::image_processing::verify_processed_image(
            original,
            output,
            options,
            &request.limits,
        ),
    }
}

// FVPROV1 31384 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJhOGNlZGNjYjk5ODhmMmQ0OGUzMWUyNTQyNzYzOTA2MjZmNjM4YTBmZjY5MjZjOWY3ZTVkM2M4NmM1NGY2ZmE2IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvc3JjL2pvYnMucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiIzNWFmNDM0OTc4MGJkNDNhZmRjZGY3ODRhZjIzZDc4OGEwNWI2YTY5NmQ4MDc5NTMyMGU3YjFhOTZjNWJlMjhmNmQwZjM5ZDU3N2YyYzJmMTE2MjYzM2UzODU2YjJlZGE0NzIzOGM5NmU0YmI1MjA0Njg4MDJiZjllMmU2MDAwOSJ9XX1d FVPROV1-END
