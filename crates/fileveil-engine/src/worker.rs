// SPDX-License-Identifier: MPL-2.0
//! Own a worker process tree through cancellation, timeout and ordinary exit.
use std::process::{Child, Command, ExitStatus};

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
