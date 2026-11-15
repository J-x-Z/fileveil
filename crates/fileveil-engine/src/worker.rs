// SPDX-License-Identifier: MPL-2.0
//! Own a worker process tree through cancellation, timeout and ordinary exit.
use std::process::{Child, Command, ExitStatus};

/// Execute an explicitly requested build from an already confined FileVeil
/// worker. Children inherit the worker's process group or Windows Job Object.
/// Build output stays separate from the worker's JSON report channel.
pub fn run_build_command(
    arguments: &[String],
    directory: &std::path::Path,
    timeout: std::time::Duration,
) -> fileveil_core::Result<serde_json::Value> {
    use fileveil_core::Error;
    use std::{process::Stdio, time::Instant};
    if arguments.is_empty()
        || arguments.len() > 256
        || arguments.iter().map(String::len).sum::<usize>() > 64 * 1024
        || arguments.iter().any(|value| value.contains('\0'))
    {
        return Err(Error::Input(
            "Build command requires a bounded program and argument list".into(),
        ));
    }
    let mut child = Command::new(&arguments[0])
        .args(&arguments[1..])
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error::Io("Could not start the configured build program".into()))?;
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| Error::Io("Could not inspect the build process".into()))?
        {
            if !status.success() {
                return Err(Error::Blocked(format!(
                    "Build failed with exit code {}",
                    status
                        .code()
                        .map_or_else(|| "signal".into(), |code| code.to_string())
                )));
            }
            return Ok(serde_json::json!({
                "program":std::path::Path::new(&arguments[0]).file_name().unwrap_or_default().to_string_lossy(),
                "exit_code":0,
                "elapsed_ms":started.elapsed().as_millis(),
            }));
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Interrupted("Build step timed out".into()));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GitRevision {
    pub reference: String,
    pub commit: String,
    pub tracked_worktree_dirty: Option<bool>,
}

/// Shared GUI/CLI entry inside a confined worker. Public project configuration
/// never executes a build unless the caller supplies an explicit argument list.
pub fn run_project_operation(
    mut request: crate::project::ProjectRequest,
    after: Option<&[String]>,
    limits: &fileveil_core::Limits,
    timeout: std::time::Duration,
) -> fileveil_core::Result<fileveil_core::Report> {
    use crate::project::{ProjectAction, ProjectTrigger};
    use fileveil_core::Error;
    let directory = request
        .config_path
        .parent()
        .ok_or_else(|| Error::Input("Project configuration needs a parent directory".into()))?;
    if after.is_some() && (request.scope.is_some() || request.action != ProjectAction::Sync) {
        return Err(Error::Blocked(
            "Build commands require an explicit GUI or CLI project synchronization".into(),
        ));
    }
    if request.scope.is_some()
        && (request.options.git_ref.is_some()
            || request.options.trigger == Some(ProjectTrigger::Git))
    {
        return Err(Error::Blocked(
            "MCP project synchronization cannot inspect Git internals".into(),
        ));
    }
    let config = if request.action == ProjectAction::Sync {
        let mut configuration_request = request.clone();
        configuration_request.options.git_ref = None;
        Some(crate::project::load_configuration(
            &configuration_request,
            limits,
        )?)
    } else {
        None
    };
    let build_directory = config
        .as_ref()
        .map(|config| {
            if config.build_directory.is_absolute() {
                config.build_directory.clone()
            } else {
                directory.join(&config.build_directory)
            }
        })
        .unwrap_or_else(|| directory.to_path_buf());
    let build = after
        .map(|arguments| run_build_command(arguments, &build_directory, timeout))
        .transpose()?;
    let mut git = None;
    if let Some(config) = config {
        let trigger = request.options.trigger.unwrap_or(config.trigger);
        if trigger == ProjectTrigger::Git || request.options.git_ref.is_some() {
            if request.scope.is_some() {
                return Err(Error::Blocked(
                    "MCP project synchronization cannot inspect Git internals".into(),
                ));
            }
            let revision = git_snapshot(
                &build_directory,
                request.options.git_ref.as_deref().unwrap_or("HEAD"),
                std::time::Duration::from_secs(10),
            )?;
            request.options.git_ref = Some(revision.commit.clone());
            git = Some(revision);
        }
    }
    let mut report =
        crate::project::run(&request, limits, &std::sync::atomic::AtomicBool::new(false))?;
    let advanced = report.advanced.get_or_insert_with(|| serde_json::json!({}));
    advanced["project"]["build_assessed"] = serde_json::json!(build.is_some());
    if let Some(build) = build {
        advanced["project"]["build"] = build;
    }
    if let Some(git) = git {
        advanced["project"]["git"] = serde_json::to_value(git)
            .map_err(|_| Error::Input("Git evidence could not be serialized".into()))?;
    }
    Ok(report)
}

/// Resolve a local revision without hooks, fsmonitor, pagers, external diffs,
/// submodule recursion, index updates or network operations.
pub fn git_snapshot(
    directory: &std::path::Path,
    reference: &str,
    timeout: std::time::Duration,
) -> fileveil_core::Result<GitRevision> {
    use fileveil_core::Error;
    if reference.is_empty() || reference.len() > 256 || reference.contains('\0') {
        return Err(Error::Input(
            "Git reference must contain 1 to 256 bytes".into(),
        ));
    }
    let program = git_program(directory)?;
    let make_command = || {
        let mut command = Command::new(&program);
        command.current_dir(directory).args([
            "--no-pager",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.pager=",
            "-c",
            "diff.external=",
        ]);
        for (name, _) in std::env::vars_os() {
            if name.to_str().is_some_and(|name| name.starts_with("GIT_")) {
                command.env_remove(name);
            }
        }
        command.env("GIT_TERMINAL_PROMPT", "0");
        command
    };
    let mut resolve = make_command();
    resolve.args([
        "rev-parse",
        "--verify",
        "--end-of-options",
        &format!("{reference}^{{commit}}"),
    ]);
    let (status, bytes) = capture_local_command(resolve, timeout, 4096)?;
    let commit = String::from_utf8(bytes)
        .map_err(|_| Error::Blocked("Git returned an invalid commit identifier".into()))?;
    let commit = commit.trim().to_owned();
    if !status.success()
        || !matches!(commit.len(), 40 | 64)
        || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(Error::Input(
            "The selected local Git reference does not resolve to a commit".into(),
        ));
    }
    // Project manifests bind actual source hashes separately. Avoid worktree
    // conversion here because repository clean filters can execute programs.
    Ok(GitRevision {
        reference: reference.into(),
        commit,
        tracked_worktree_dirty: None,
    })
}

fn git_program(directory: &std::path::Path) -> fileveil_core::Result<std::path::PathBuf> {
    use std::path::PathBuf;
    let mut candidates = Vec::new();
    #[cfg(unix)]
    candidates.extend([PathBuf::from("/usr/bin/git"), PathBuf::from("/bin/git")]);
    #[cfg(windows)]
    for variable in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
        if let Some(root) = std::env::var_os(variable) {
            let root = PathBuf::from(root);
            candidates.push(root.join("Git/cmd/git.exe"));
            candidates.push(root.join("Programs/Git/cmd/git.exe"));
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        candidates.extend(
            std::env::split_paths(&paths)
                .filter(|path| path.is_absolute())
                .map(|path| path.join(if cfg!(windows) { "git.exe" } else { "git" })),
        );
    }
    let selected = directory
        .canonicalize()
        .unwrap_or_else(|_| directory.to_path_buf());
    candidates
        .into_iter()
        .filter_map(|path| path.canonicalize().ok())
        .find(|path| path.is_file() && !path.starts_with(&selected))
        .ok_or_else(|| {
            fileveil_core::Error::Unsupported(
                "A local Git installation outside the project directory is required".into(),
            )
        })
}

fn capture_local_command(
    mut command: Command,
    timeout: std::time::Duration,
    maximum: u64,
) -> fileveil_core::Result<(ExitStatus, Vec<u8>)> {
    use fileveil_core::Error;
    use std::{io::Read, process::Stdio, time::Instant};
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|_| Error::Io("Could not start local Git".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::Io("Could not read local Git output".into()))?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(maximum + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(std::time::Duration::from_millis(20))
            }
            Ok(None) => break Err(Error::Interrupted("Local Git inspection timed out".into())),
            Err(_) => break Err(Error::Io("Could not inspect local Git process".into())),
        }
    };
    if status.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    drop(child);
    let bytes = reader
        .join()
        .map_err(|_| Error::Io("Could not collect local Git output".into()))?
        .map_err(|_| Error::Io("Could not read local Git output".into()))?;
    if bytes.len() as u64 > maximum {
        return Err(Error::Blocked(
            "Local Git output exceeds its byte budget".into(),
        ));
    }
    Ok((status?, bytes))
}

/// Configure a dedicated process group before spawning an isolated worker.
/// Windows callers must construct `WorkerGuard` before sending the request.
pub fn configure_command(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
}

/// The child must have been created by `configure_command` and must wait for
/// its request until `new` returns, allowing Windows Job Object assignment.
pub struct WorkerGuard {
    /// Access worker pipes here and collect completion through `Self::try_wait`.
    pub child: Child,
    terminated: bool,
    #[cfg(windows)]
    job: windows_job::Job,
}
impl WorkerGuard {
    pub fn new(child: Child) -> fileveil_core::Result<Self> {
        #[cfg(windows)]
        {
            let mut child = child;
            let job = match windows_job::Job::assign(&child) {
                Ok(job) => job,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
            };
            Ok(Self {
                child,
                job,
                terminated: false,
            })
        }
        #[cfg(not(windows))]
        {
            #[cfg(unix)]
            if unsafe { libc::getpgid(child.id() as i32) } != child.id() as i32 {
                let mut child = child;
                let _ = child.kill();
                let _ = child.wait();
                return Err(fileveil_core::Error::Blocked(
                    "Worker does not own its process group".into(),
                ));
            }
            Ok(Self {
                child,
                terminated: false,
            })
        }
    }
    /// Collect completion after stopping the owned process tree. Unix retains
    /// the leader's PID until the group has been signalled, preventing reuse.
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        if self.terminated {
            return self.child.try_wait();
        }
        #[cfg(unix)]
        {
            let information = loop {
                let mut information: libc::siginfo_t = unsafe { std::mem::zeroed() };
                let result = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        self.child.id() as libc::id_t,
                        &mut information,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                };
                if result == 0 {
                    break information;
                }
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    if error.raw_os_error() == Some(libc::ECHILD) {
                        self.terminated = true;
                    }
                    return Err(error);
                }
            };
            if unsafe { information.si_pid() } == 0 {
                return Ok(None);
            }
            self.terminate();
            self.child.wait().map(Some)
        }
        #[cfg(not(unix))]
        {
            let status = self.child.try_wait()?;
            if status.is_some() {
                self.terminate();
            }
            Ok(status)
        }
    }
    pub fn terminate(&mut self) {
        if std::mem::replace(&mut self.terminated, true) {
            return;
        }
        #[cfg(unix)]
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        #[cfg(windows)]
        self.job.terminate();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(windows)]
mod windows_job {
    use fileveil_core::{Error, Result};
    use std::{mem::size_of, os::windows::io::AsRawHandle, process::Child};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject, TerminateJobObject,
        },
    };
    pub(super) struct Job(HANDLE);
    impl Job {
        pub(super) fn assign(child: &Child) -> Result<Self> {
            let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if handle.is_null() {
                return Err(Error::Blocked(
                    "Could not create the worker process-tree job".into(),
                ));
            }
            let job = Self(handle);
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if unsafe {
                SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    &limits as *const _ as *const _,
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            } == 0
                || unsafe { AssignProcessToJobObject(handle, child.as_raw_handle()) } == 0
            {
                return Err(Error::Blocked(
                    "Could not confine the worker process tree".into(),
                ));
            }
            Ok(job)
        }
        pub(super) fn terminate(&self) {
            unsafe {
                TerminateJobObject(self.0, 6);
            }
        }
    }
    impl Drop for Job {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

// FVPROV1 17027 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJhZTZlY2RmOWMzOTFiZjQzMzBhNjViNWU1MDE0MDc2NWUwNWU3ZjcyYjdjNWI2OTU2MTIwMTEyNjU1Y2Q0NzNhIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL3dvcmtlci5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjhjYjQyMWZmN2NlZTQ1YzI1ZmM1MzJjNTNmNWU4YWViZDMyNDc4MDM1MDk3OTcyZTVmODcxMjA1Yzg1ZTIwNGY0OWE3ZDAwMTMyOTc3MjYyNDlhOGNkOGRjZTkzNmE5ZDlhZDQ3NzJjOGFiYTM2MTQzMmZjZjRhMjBjZjE5MTAzIn1dfV0= FVPROV1-END
