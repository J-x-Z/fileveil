// SPDX-License-Identifier: MPL-2.0
//! Trusted local LLVM tools with bounded logs and inherited worker confinement.
use fileveil_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub(super) struct Toolchain {
    pub directory: PathBuf,
    pub clang: PathBuf,
    pub opt: PathBuf,
    pub objdump: PathBuf,
    pub strip: PathBuf,
    pub version: String,
    pub major: u32,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum PassExecutionKind {
    #[default]
    Plugin,
    StandaloneDriver,
}

#[derive(Debug, Deserialize)]
struct PluginMetadata {
    schema: String,
    llvm_major: u32,
    plugin: String,
    platform: String,
    architecture: String,
    #[serde(default)]
    execution_kind: PassExecutionKind,
}

#[derive(Debug)]
pub(super) struct Plugin {
    pub path: PathBuf,
    pub execution_kind: PassExecutionKind,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(super) struct Metrics {
    pub wall_seconds: f64,
    pub cpu_seconds: Option<f64>,
    pub peak_rss_bytes: Option<u64>,
}

#[derive(Debug)]
pub(super) struct Output {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub metrics: Metrics,
    pub exit_code: Option<i32>,
}

pub(super) fn check_cancel(cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::Relaxed) {
        Err(Error::Interrupted("Software operation cancelled".into()))
    } else {
        Ok(())
    }
}

fn read_log(file: &mut File) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| Error::Io("Could not rewind software tool log".into()))?;
    let mut bytes = Vec::new();
    file.take(MAX_LOG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Io("Could not read software tool log".into()))?;
    if bytes.len() as u64 > MAX_LOG_BYTES {
        return Err(Error::Blocked("Software tool output exceeded 2 MiB".into()));
    }
    Ok(bytes)
}

pub(super) fn run(
    program: &Path,
    arguments: &[OsString],
    directory: &Path,
    environment: &[(&str, &OsStr)],
    timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<Output> {
    run_inner(
        program,
        arguments,
        directory,
        environment,
        timeout,
        cancelled,
        false,
        None,
    )
}

pub(super) fn run_test(
    program: &Path,
    arguments: &[OsString],
    directory: &Path,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<Output> {
    run_inner(
        program,
        arguments,
        directory,
        &[],
        timeout,
        cancelled,
        true,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run_producing(
    program: &Path,
    arguments: &[OsString],
    directory: &Path,
    environment: &[(&str, &OsStr)],
    timeout: Duration,
    cancelled: &AtomicBool,
    output: &Path,
    max_output_bytes: u64,
) -> Result<Output> {
    run_inner(
        program,
        arguments,
        directory,
        environment,
        timeout,
        cancelled,
        false,
        Some((output, max_output_bytes)),
    )
}

#[allow(clippy::too_many_arguments)]
fn run_inner(
    program: &Path,
    arguments: &[OsString],
    directory: &Path,
    environment: &[(&str, &OsStr)],
    timeout: Duration,
    cancelled: &AtomicBool,
    accept_nonzero: bool,
    artifact_limit: Option<(&Path, u64)>,
) -> Result<Output> {
    check_cancel(cancelled)?;
    if arguments.len() > 512
        || arguments.iter().map(|value| value.len()).sum::<usize>() > 128 * 1024
        || arguments
            .iter()
            .any(|value| value.to_string_lossy().contains('\0'))
    {
        return Err(Error::Input(
            "Software tool arguments exceed their bounded contract".into(),
        ));
    }
    let mut stdout = tempfile::tempfile_in(directory)
        .map_err(|_| Error::Io("Could not create private software tool log".into()))?;
    let mut stderr = tempfile::tempfile_in(directory)
        .map_err(|_| Error::Io("Could not create private software tool log".into()))?;
    let mut time_log = tempfile::NamedTempFile::new_in(directory)
        .map_err(|_| Error::Io("Could not create private software timing log".into()))?;
    let timer = cfg!(unix) && Path::new("/usr/bin/time").is_file();
    let mut command = if timer {
        let mut command = Command::new("/usr/bin/time");
        command.arg("-o").arg(time_log.path());
        command.arg(if cfg!(target_os = "macos") {
            "-l"
        } else {
            "-v"
        });
        command.arg(program);
        command
    } else {
        Command::new(program)
    };
    command
        .args(arguments)
        .current_dir(directory)
        .env("LC_ALL", "C")
        .env_remove("FILEVEIL_SOFTWARE_PACKET")
        .env_remove("FILEVEIL_SOFTWARE_MODULE")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout.try_clone().map_err(|_| {
            Error::Io("Could not bind software stdout".into())
        })?))
        .stderr(Stdio::from(stderr.try_clone().map_err(|_| {
            Error::Io("Could not bind software stderr".into())
        })?));
    for (key, value) in environment {
        command.env(key, value);
    }
    // Keep the parent worker's process group and Windows Job Object. A new group
    // would let compiler/linker descendants survive the supervisor's cancellation.
    let mut child = command.spawn().map_err(|_| {
        Error::Unsupported(format!(
            "Could not start software tool {}",
            program.file_name().unwrap_or_default().to_string_lossy()
        ))
    })?;
    let started = Instant::now();
    let status = loop {
        let artifact_exceeded = artifact_limit.is_some_and(|(path, limit)| {
            fs::symlink_metadata(path)
                .is_ok_and(|metadata| !metadata.is_file() || metadata.len() > limit)
        });
        let exceeded = artifact_exceeded
            || stdout
                .metadata()
                .map(|value| value.len() > MAX_LOG_BYTES)
                .unwrap_or(true)
            || stderr
                .metadata()
                .map(|value| value.len() > MAX_LOG_BYTES)
                .unwrap_or(true);
        let interruption = if cancelled.load(Ordering::Relaxed) {
            Some("Software operation cancelled")
        } else if started.elapsed() >= timeout {
            Some("Software tool timed out")
        } else if artifact_exceeded {
            Some("Generated software artifact exceeded the configured file byte limit")
        } else if exceeded {
            Some("Software tool output exceeded 2 MiB")
        } else {
            None
        };
        if let Some(message) = interruption {
            let _ = child.kill();
            let _ = child.wait();
            return Err(if exceeded {
                Error::Blocked(message.into())
            } else {
                Error::Interrupted(message.into())
            });
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::Io("Could not inspect software tool progress".into()));
            }
        }
    };
    let bytes_out = read_log(&mut stdout)?;
    let bytes_err = read_log(&mut stderr)?;
    if !status.success() && !accept_nonzero {
        // Source/metadata values can appear in compiler diagnostics. Keep the
        // ordinary report value-free while naming the failing tool and status.
        return Err(Error::Blocked(format!(
            "Software tool {} failed with {}",
            program.file_name().unwrap_or_default().to_string_lossy(),
            status
                .code()
                .map_or_else(|| "a signal".into(), |value| format!("exit code {value}")),
        )));
    }
    let mut metrics = Metrics {
        wall_seconds: started.elapsed().as_secs_f64(),
        ..Default::default()
    };
    if timer {
        metrics_from_time(
            &String::from_utf8_lossy(&read_log(time_log.as_file_mut())?),
            &mut metrics,
        );
    }
    Ok(Output {
        stdout: bytes_out,
        stderr: bytes_err,
        metrics,
        exit_code: status.code(),
    })
}

fn metrics_from_time(text: &str, metrics: &mut Metrics) {
    let mut user = None;
    let mut system = None;
    for line in text.lines() {
        let trimmed = line.trim();
        let words: Vec<_> = trimmed.split_whitespace().collect();
        if cfg!(target_os = "macos") {
            if words.len() == 6 && words[1] == "real" && words[3] == "user" && words[5] == "sys" {
                user = words[2].parse::<f64>().ok();
                system = words[4].parse::<f64>().ok();
            }
            if trimmed.ends_with("maximum resident set size") {
                metrics.peak_rss_bytes = words.first().and_then(|value| value.parse().ok());
            }
        } else {
            if let Some(value) = trimmed.strip_prefix("User time (seconds):") {
                user = value.trim().parse::<f64>().ok();
            }
            if let Some(value) = trimmed.strip_prefix("System time (seconds):") {
                system = value.trim().parse::<f64>().ok();
            }
            if let Some(value) = trimmed.strip_prefix("Maximum resident set size (kbytes):") {
                metrics.peak_rss_bytes = value
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .and_then(|value| value.checked_mul(1024));
            }
        }
    }
    metrics.cpu_seconds = user.zip(system).map(|(user, system)| user + system);
}

fn executable(directory: &Path, name: &str) -> PathBuf {
    directory
        .join("bin")
        .join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

pub(super) fn discover(
    requested: Option<&Path>,
    scratch: &Path,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<Toolchain> {
    let mut candidates = Vec::new();
    if let Some(directory) = requested {
        candidates.push(directory.to_path_buf());
    } else if let Some(directory) = std::env::var_os("FILEVEIL_LLVM_DIR") {
        candidates.push(PathBuf::from(directory));
    } else {
        for directory in [
            "/opt/homebrew/opt/llvm",
            "/usr/local/opt/llvm",
            "/usr/lib/llvm-23",
            "/usr/lib/llvm-22",
            "/usr/lib/llvm-21",
            "/usr",
        ] {
            candidates.push(PathBuf::from(directory));
        }
        #[cfg(windows)]
        if let Some(program_files) = std::env::var_os("ProgramFiles") {
            candidates.push(PathBuf::from(program_files).join("LLVM"));
        }
    }
    for candidate in candidates {
        let Ok(directory) = fs::canonicalize(&candidate) else {
            continue;
        };
        let clang = executable(&directory, "clang");
        let opt = executable(&directory, "opt");
        let objdump = executable(&directory, "llvm-objdump");
        let strip = executable(&directory, "llvm-strip");
        if ![&clang, &opt, &objdump].iter().all(|path| path.is_file()) {
            continue;
        }
        let output = run(
            &opt,
            &["--version".into()],
            scratch,
            &[],
            timeout.min(Duration::from_secs(10)),
            cancelled,
        )?;
        let version = String::from_utf8_lossy(&output.stdout)
            .lines()
            .find(|line| line.contains("LLVM version"))
            .and_then(|line| line.split("LLVM version").nth(1))
            .map(|value| {
                value
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            })
            .ok_or_else(|| Error::Unsupported("Could not identify the LLVM opt version".into()))?;
        let major = version
            .split('.')
            .next()
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or_else(|| Error::Unsupported("Invalid LLVM opt major version".into()))?;
        let output = run(
            &clang,
            &["--version".into()],
            scratch,
            &[],
            timeout.min(Duration::from_secs(10)),
            cancelled,
        )?;
        let clang_version = String::from_utf8_lossy(&output.stdout);
        let clang_major = clang_version
            .split("clang version")
            .nth(1)
            .and_then(|value| value.trim().split('.').next())
            .and_then(|value| value.parse::<u32>().ok());
        if clang_major != Some(major) {
            return Err(Error::Blocked(
                "clang and opt must use the same LLVM major version".into(),
            ));
        }
        return Ok(Toolchain {
            directory,
            clang,
            opt,
            objdump,
            strip,
            version,
            major,
        });
    }
    Err(Error::Unsupported(
        "A complete local LLVM toolchain with clang, opt and llvm-objdump is unavailable".into(),
    ))
}

pub(super) fn plugin(path: Option<&Path>, toolchain: &Toolchain) -> Result<Plugin> {
    let chosen = path
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("FILEVEIL_SOFTWARE_PLUGIN").map(PathBuf::from))
        .ok_or_else(|| {
            Error::Unsupported("Build or select the FileVeil LLVM pass plugin first".into())
        })?;
    let canonical = fs::canonicalize(chosen)
        .map_err(|_| Error::Unsupported("The LLVM pass plugin is unavailable".into()))?;
    if !canonical.is_file() {
        return Err(Error::Input(
            "The LLVM pass plugin must be a regular file".into(),
        ));
    }
    let metadata = canonical
        .parent()
        .unwrap_or(Path::new("."))
        .join("fileveil-plugin.json");
    let file = File::open(metadata).map_err(|_| {
        Error::Blocked("The LLVM pass plugin needs its generated ABI metadata".into())
    })?;
    let mut data = Vec::new();
    file.take(16 * 1024 + 1)
        .read_to_end(&mut data)
        .map_err(|_| Error::Io("Could not read LLVM plugin ABI metadata".into()))?;
    if data.len() > 16 * 1024 {
        return Err(Error::Blocked(
            "LLVM plugin metadata exceeds its size limit".into(),
        ));
    }
    let value: PluginMetadata = serde_json::from_slice(&data)
        .map_err(|_| Error::Input("Invalid LLVM plugin ABI metadata".into()))?;
    if value.schema != "fileveil.software.llvm-plugin.v1"
        || value.llvm_major != toolchain.major
        || Some(value.plugin.as_str()) != canonical.file_name().and_then(OsStr::to_str)
    {
        return Err(Error::Blocked(
            "LLVM pass plugin and selected toolchain have incompatible ABI metadata".into(),
        ));
    }
    let platform = if cfg!(target_os = "macos") {
        "Darwin"
    } else if cfg!(windows) {
        "Windows"
    } else {
        "Linux"
    };
    let architecture = value.architecture.as_str();
    let architecture_matches = match std::env::consts::ARCH {
        "aarch64" => matches!(architecture, "aarch64" | "arm64" | "ARM64"),
        "x86_64" => matches!(architecture, "x86_64" | "AMD64" | "amd64"),
        native => architecture == native,
    };
    if value.platform != platform || !architecture_matches {
        return Err(Error::Blocked(
            "LLVM pass plugin platform or architecture differs from this host".into(),
        ));
    }
    Ok(Plugin {
        path: canonical,
        execution_kind: value.execution_kind,
    })
}

pub(super) fn native_flags(
    scratch: &Path,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> Result<Vec<OsString>> {
    #[cfg(target_os = "macos")]
    {
        let output = run(
            Path::new("/usr/bin/xcrun"),
            &["--show-sdk-path".into()],
            scratch,
            &[],
            timeout.min(Duration::from_secs(10)),
            cancelled,
        )?;
        let path = String::from_utf8(output.stdout)
            .map_err(|_| Error::Unsupported("Invalid macOS SDK path".into()))?;
        let sdk = PathBuf::from(path.trim());
        if !sdk.is_absolute() || !sdk.is_dir() {
            return Err(Error::Unsupported(
                "A valid macOS SDK is unavailable".into(),
            ));
        }
        Ok(vec![
            "-isysroot".into(),
            sdk.into_os_string(),
            "-mmacosx-version-min=11.0".into(),
        ])
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (scratch, timeout, cancelled);
        Ok(Vec::new())
    }
}

pub(super) fn optimization(value: &str) -> Result<OsString> {
    match value {
        "O0" | "O1" | "O2" | "O3" | "Os" | "Oz" => Ok(format!("-{value}").into()),
        "LTO" => Ok("-O3".into()),
        _ => Err(Error::Input(
            "Optimization must be O0, O1, O2, O3, Os, Oz or LTO".into(),
        )),
    }
}

pub(super) fn target_flags(target: Option<&str>) -> Result<Vec<OsString>> {
    match target {
        None => Ok(Vec::new()),
        Some(target)
            if !target.is_empty()
                && target.len() <= 128
                && target.bytes().all(|value| {
                    value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_' | b'.')
                }) =>
        {
            Ok(vec!["-target".into(), target.into()])
        }
        _ => Err(Error::Input(
            "Target triple contains unsupported characters".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_metadata_defaults_to_plugin_and_selects_standalone_driver() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pass-fixture");
        fs::write(&path, b"unexecuted pass fixture").unwrap();
        let toolchain = Toolchain {
            directory: directory.path().to_path_buf(),
            clang: "clang".into(),
            opt: "opt".into(),
            objdump: "llvm-objdump".into(),
            strip: "llvm-strip".into(),
            version: "23.1.5".into(),
            major: 23,
        };
        let mut metadata = serde_json::json!({
            "schema":"fileveil.software.llvm-plugin.v1", "llvm_major":23,
            "plugin":"pass-fixture", "architecture":std::env::consts::ARCH,
            "platform":if cfg!(windows) { "Windows" } else if cfg!(target_os="macos") { "Darwin" } else { "Linux" }
        });
        for (kind, expected) in [
            (None, PassExecutionKind::Plugin),
            (Some("plugin"), PassExecutionKind::Plugin),
            (
                Some("standalone_driver"),
                PassExecutionKind::StandaloneDriver,
            ),
        ] {
            if let Some(kind) = kind {
                metadata["execution_kind"] = kind.into();
            }
            fs::write(
                directory.path().join("fileveil-plugin.json"),
                serde_json::to_vec(&metadata).unwrap(),
            )
            .unwrap();
            let selected = plugin(Some(&path), &toolchain).unwrap();
            assert_eq!(selected.execution_kind, expected);
            assert_eq!(selected.path, path.canonicalize().unwrap());
        }
        metadata["execution_kind"] = "unknown_backend".into();
        fs::write(
            directory.path().join("fileveil-plugin.json"),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            plugin(Some(&path), &toolchain),
            Err(Error::Input(_))
        ));
    }

    #[test]
    #[cfg(unix)]
    fn generated_artifact_budget_is_enforced_before_success() {
        let work = tempfile::tempdir().unwrap();
        let output = work.path().join("oversized.bin");
        let arguments = vec![
            "if=/dev/zero".into(),
            format!("of={}", output.display()).into(),
            "bs=4096".into(),
            "count=32".into(),
        ];
        let result = run_producing(
            Path::new("/usr/bin/dd"),
            &arguments,
            work.path(),
            &[],
            Duration::from_secs(10),
            &AtomicBool::new(false),
            &output,
            1024,
        );
        assert!(matches!(result, Err(Error::Blocked(_))));
    }
}

// FVPROV1 20697 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI5NGVhZTFiOTMyZTU1ZDJjMDEyNWMxOTYzYmQwMjQ2NTdlZTFkMjIzYTMyMDljNzIxMzdjMjYxOWIwNjBmNmIxIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL3NvZnR3YXJlL3Rvb2xzLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiMWUzNDhkNWE2ZTIxZmNkOGRkMWEzYWNlYjYwODlmYWNhODAzNWRkNDlhZmIwNjVkM2ViNWY4MjcwNjA1ODUyMDkyNmE0NmQ5MDQ0MjRjNGY2ODA2M2U5N2JiODc1ZWM0YTgxMzJmM2FkODRmOGMwMTFiOTg2NjYxZTlkOTA3MDgifV19XQ== FVPROV1-END
