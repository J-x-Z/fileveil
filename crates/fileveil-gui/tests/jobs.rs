// SPDX-License-Identifier: MPL-2.0
use fileveil_core::{Limits, Outcome, Report, digest};
use fileveil_gui::jobs::{JobHandle, JobKind, JobRequest, JobResult};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}
fn executable() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_fileveil-gui"))
}
fn start(request: JobRequest) -> JobHandle {
    JobHandle::spawn_with_executable(request, executable(), Arc::new(|| {}))
}
fn wait(handle: &JobHandle) -> JobResult {
    let started = Instant::now();
    loop {
        if let Some(result) = handle.try_recv() {
            return result;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "GUI worker exceeded integration-test deadline"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
fn copy_fixture(name: &str, directory: &Path) -> PathBuf {
    let path = directory.join(name);
    fs::copy(fixtures().join(name), &path).unwrap();
    path
}
fn assert_no_staging(directory: &Path) {
    assert!(!fs::read_dir(directory).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".fileveil")
    }));
}

#[test]
fn packaged_worker_uses_core_scan_and_emits_redacted_report() {
    let input = fixtures().join("jpeg_exif_gps_author.jpg");
    let request = JobRequest::new(JobKind::Scan {
        path: input.clone(),
    });
    let mut process = Command::new(executable())
        .arg("--fileveil-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    process
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&request).unwrap())
        .unwrap();
    let output = process.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Report = serde_json::from_slice(&output.stdout).unwrap();
    let expected = fileveil_engine::scan(&input, &Limits::default()).unwrap();
    assert_eq!(
        serde_json::to_value(report).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout)
            .contains(input.parent().unwrap().to_str().unwrap())
    );
}

#[test]
fn image_processing_jobs_publish_and_verify_both_modes_without_overwriting() {
    use fileveil_core::{ImageProcessMode, ImageProcessOptions};
    for mode in [ImageProcessMode::LowBits, ImageProcessMode::Signal] {
        let directory = tempfile::tempdir().unwrap();
        let input = copy_fixture("png_clean.png", directory.path());
        let original_hash = digest(&fs::read(&input).unwrap());
        let output = directory.path().join("processed.png");
        let options = ImageProcessOptions { mode, low_bits: 2 };
        let result = wait(&start(JobRequest::new(JobKind::ProcessImage {
            input: input.clone(),
            output: Some(output.clone()),
            options: options.clone(),
        })));
        assert_eq!(result.exit_code, 4, "{:?}", result.report);
        assert_eq!(result.output_path, Some(output.clone()));
        assert_eq!(result.report.result, Outcome::PartiallyVerified);
        let processing = result.report.image_processing.as_ref().unwrap();
        assert_eq!(processing.mode, mode);
        assert_eq!(processing.detector_status, "not_assessed");
        if mode == ImageProcessMode::LowBits {
            assert_eq!(processing.verified_low_bits, Some(true));
            assert!(processing.max_delta <= 3);
        }
        let verified = wait(&start(JobRequest::new(JobKind::VerifyImage {
            original: input.clone(),
            output: output.clone(),
            options: options.clone(),
        })));
        assert_eq!(verified.exit_code, 4, "{:?}", verified.report);
        assert_eq!(verified.report.output_sha256, result.report.output_sha256);
        let hash = digest(&fs::read(&output).unwrap());
        let collision = wait(&start(JobRequest::new(JobKind::ProcessImage {
            input: input.clone(),
            output: Some(output.clone()),
            options,
        })));
        assert_eq!(collision.exit_code, 2);
        assert_eq!(digest(&fs::read(&output).unwrap()), hash);
        assert_eq!(digest(&fs::read(&input).unwrap()), original_hash);
        assert_no_staging(directory.path());
    }
}

#[test]
fn gui_supervisor_completes_five_format_round_trips() {
    for name in [
        "jpeg_exif_gps_author.jpg",
        "png_itxt_exif_icc.png",
        "docx_author_comments_rels.docx",
        "xlsx_author_custom_formula.xlsx",
        "pptx_author_media.pptx",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let input = copy_fixture(name, directory.path());
        let hash = digest(&fs::read(&input).unwrap());
        let output = directory.path().join(format!("verified-{name}"));
        let handle = start(JobRequest::new(JobKind::Sanitize {
            input: input.clone(),
            output: Some(output.clone()),
        }));
        let result = wait(&handle);
        assert!(
            matches!(result.exit_code, 0 | 4),
            "{name} {:?}",
            result.report
        );
        assert!(matches!(
            result.report.result,
            Outcome::VerifiedWithinScope | Outcome::PartiallyVerified
        ));
        assert_eq!(result.output_path.as_ref(), Some(&output));
        assert_eq!(result.report.integrity.content_equal, Some(true));
        assert_eq!(result.report.integrity.original_unchanged, Some(true));
        assert_eq!(digest(&fs::read(&input).unwrap()), hash);
        assert!(
            !handle.cancel(),
            "A completed job cannot accept cancellation"
        );
        assert!(handle.is_finished());
        let verification = start(JobRequest::new(JobKind::Verify {
            original: input,
            output,
        }));
        let verified = wait(&verification);
        assert_eq!(verified.exit_code, result.exit_code);
        assert_eq!(verified.report.integrity.content_equal, Some(true));
        assert_no_staging(directory.path());
    }
}

#[test]
fn input_errors_unsupported_and_malformed_files_keep_stable_reports() {
    let pdf_failure = if fileveil_engine::pdf::capabilities()["available"] == true {
        ("pdf_corrupt.pdf", 5, Outcome::Blocked)
    } else {
        ("pdf_corrupt.pdf", 3, Outcome::Unsupported)
    };
    for (name, exit_code, outcome) in [
        ("missing-input.png", 2, Outcome::Failed),
        pdf_failure,
        ("png_bad_crc.png", 5, Outcome::Blocked),
    ] {
        let handle = start(JobRequest::new(JobKind::Scan {
            path: fixtures().join(name),
        }));
        let result = wait(&handle);
        assert_eq!(result.exit_code, exit_code, "{name} {:?}", result.report);
        assert_eq!(result.report.result, outcome);
        assert!(result.output_path.is_none());
    }
    let directory = tempfile::tempdir().unwrap();
    let input = copy_fixture("png_itxt_exif_icc.png", directory.path());
    let before = fs::read(&input).unwrap();
    let result = wait(&start(JobRequest::new(JobKind::Sanitize {
        input: input.clone(),
        output: Some(input.clone()),
    })));
    assert_eq!(result.exit_code, 2);
    assert_eq!(fs::read(input).unwrap(), before);
    assert_no_staging(directory.path());
}

#[test]
fn unicode_and_control_character_paths_round_trip_through_stdin_protocol() {
    let directory = tempfile::tempdir().unwrap();
    let name = if cfg!(windows) {
        "合成 文件.png"
    } else {
        "合成 文件\n原件.png"
    };
    let input = directory.path().join(name);
    fs::copy(fixtures().join("png_itxt_exif_icc.png"), &input).unwrap();
    let output = directory.path().join("净化 副本.png");
    let result = wait(&start(JobRequest::new(JobKind::Sanitize {
        input,
        output: Some(output.clone()),
    })));
    assert_eq!(result.exit_code, 0, "{:?}", result.report);
    assert_eq!(result.output_path, Some(output));
    assert_eq!(result.report.integrity.pixel_equal, Some(true));
    assert_no_staging(directory.path());
}

#[test]
fn simultaneous_default_outputs_are_published_without_clobbering() {
    let directory = tempfile::tempdir().unwrap();
    let input = copy_fixture("png_itxt_exif_icc.png", directory.path());
    let first = start(JobRequest::new(JobKind::Sanitize {
        input: input.clone(),
        output: None,
    }));
    let second = start(JobRequest::new(JobKind::Sanitize {
        input,
        output: None,
    }));
    let first = wait(&first);
    let second = wait(&second);
    assert_eq!(first.exit_code, 0);
    assert_eq!(second.exit_code, 0);
    assert_ne!(first.output_path, second.output_path);
    assert!(first.output_path.unwrap().is_file());
    assert!(second.output_path.unwrap().is_file());
    assert_no_staging(directory.path());
}

#[test]
fn invalid_limits_finish_without_spawning_a_worker() {
    let directory = tempfile::tempdir().unwrap();
    let mut request = JobRequest::new(JobKind::Scan {
        path: fixtures().join("png_clean.png"),
    });
    request.timeout_seconds = 0;
    let handle = JobHandle::spawn_with_executable(
        request,
        directory.path().join("absent-worker"),
        Arc::new(|| {}),
    );
    let result = wait(&handle);
    assert_eq!(result.exit_code, 2);
    assert!(result.report.warnings[0].contains("resource limits"));
    assert!(handle.is_finished());
}

#[cfg(unix)]
fn sleeping_worker(directory: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let executable = directory.join("sleeping-worker");
    fs::write(
        &executable,
        br##"#!/bin/sh
pid_file=${0%/*}/worker.pid
/bin/sleep 30 &
printf '%s' "$!" > "${0%/*}/grandchild.pid"
printf '%s' "$FILEVEIL_PDF_STAGING" > "${0%/*}/scratch.path"
printf 'private backend input' > "$FILEVEIL_PDF_STAGING/snapshot.pdf"
printf '%s' "$$" > "$pid_file"
exec /bin/sleep 30
"##,
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    executable
}
#[cfg(any(unix, windows))]
fn wait_for_pid(directory: &Path) -> String {
    let started = Instant::now();
    loop {
        if let Ok(pid) = fs::read_to_string(directory.join("worker.pid"))
            && pid.parse::<u32>().is_ok_and(|value| value > 0)
        {
            return pid;
        }
        assert!(started.elapsed() < Duration::from_secs(5));
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(windows)]
fn assert_windows_stopped(pid: &str) {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, GetLastError, STILL_ACTIVE},
        System::Threading::{GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
    };
    let pid = pid.parse::<u32>().unwrap();
    let started = Instant::now();
    loop {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            assert_eq!(unsafe { GetLastError() }, ERROR_INVALID_PARAMETER);
            return;
        }
        let mut code = STILL_ACTIVE as u32;
        let checked = unsafe { GetExitCodeProcess(handle, &mut code) };
        unsafe {
            CloseHandle(handle);
        }
        assert_ne!(checked, 0);
        if code != STILL_ACTIVE as u32 {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "Owned Windows process remained alive"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(windows)]
#[test]
fn windows_job_object_stops_native_worker_and_grandchild_through_all_exit_paths() {
    let directory = tempfile::tempdir().unwrap();
    let worker = directory.path().join("process-tree-worker.exe");
    let status = Command::new("rustc")
        .arg("--edition=2024")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/process_tree_worker.rs"))
        .arg("-o")
        .arg(&worker)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "Native Windows worker fixture compilation failed"
    );
    let normal_worker = directory.path().join("normal-exit-worker.exe");
    fs::copy(&worker, &normal_worker).unwrap();
    let input = copy_fixture("png_clean.png", directory.path());
    let original = fs::read(&input).unwrap();
    for mode in ["timeout", "cancel", "drop", "normal"] {
        let output = directory.path().join(format!("{mode}.png"));
        let mut request = JobRequest::new(JobKind::Sanitize {
            input: input.clone(),
            output: Some(output.clone()),
        });
        request.timeout_seconds = if mode == "timeout" { 2 } else { 30 };
        let executable = if mode == "normal" {
            &normal_worker
        } else {
            &worker
        };
        let handle = JobHandle::spawn_with_executable(request, executable.clone(), Arc::new(|| {}));
        let pid = wait_for_pid(directory.path());
        let descendant = fs::read_to_string(directory.path().join("grandchild.pid")).unwrap();
        if mode == "drop" {
            drop(handle);
        } else {
            if mode == "cancel" {
                assert!(handle.cancel());
            }
            // The normal-exit fixture deliberately supplies no business report.
            let expected = if mode == "normal" { 5 } else { 6 };
            assert_eq!(wait(&handle).exit_code, expected);
            drop(handle);
        }
        assert_windows_stopped(&pid);
        assert_windows_stopped(&descendant);
        let scratch = fs::read_to_string(directory.path().join("scratch.path")).unwrap();
        assert!(!Path::new(&scratch).exists());
        assert!(!output.exists());
        assert_no_staging(directory.path());
        assert_eq!(fs::read(&input).unwrap(), original);
        for name in ["worker.pid", "grandchild.pid", "scratch.path"] {
            fs::remove_file(directory.path().join(name)).unwrap();
        }
    }
}
#[cfg(unix)]
fn assert_reaped(pid: &str) {
    let status = Command::new("/bin/kill")
        .args(["-0", pid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success(), "Owned worker process remained alive");
}

#[cfg(unix)]
fn assert_descendant_stopped_and_scratch_removed(directory: &Path) {
    let pid = fs::read_to_string(directory.join("grandchild.pid")).unwrap();
    let started = Instant::now();
    loop {
        let output = Command::new("/bin/ps")
            .args(["-o", "stat=", "-p", &pid])
            .output()
            .unwrap();
        let state = String::from_utf8_lossy(&output.stdout);
        if !output.status.success() || state.trim().is_empty() || state.trim().starts_with('Z') {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "Owned worker descendant remained live"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let scratch = fs::read_to_string(directory.join("scratch.path")).unwrap();
    assert!(
        !Path::new(&scratch).exists(),
        "Private PDF snapshot staging remained after the worker ended"
    );
}

#[cfg(unix)]
#[test]
fn timeout_reaps_worker_and_discards_private_staging() {
    let directory = tempfile::tempdir().unwrap();
    let input = copy_fixture("png_itxt_exif_icc.png", directory.path());
    let output = directory.path().join("must-not-exist.png");
    let mut request = JobRequest::new(JobKind::Sanitize {
        input,
        output: Some(output.clone()),
    });
    request.timeout_seconds = 1;
    let handle = JobHandle::spawn_with_executable(
        request,
        sleeping_worker(directory.path()),
        Arc::new(|| {}),
    );
    let pid = wait_for_pid(directory.path());
    let result = wait(&handle);
    assert_eq!(result.exit_code, 6);
    assert!(
        result
            .report
            .warnings
            .iter()
            .any(|warning| warning.contains("timed out"))
    );
    assert!(!output.exists());
    assert_no_staging(directory.path());
    assert_reaped(&pid);
    assert_descendant_stopped_and_scratch_removed(directory.path());
}

#[cfg(unix)]
#[test]
fn accepted_cancellation_and_drop_reap_owned_workers() {
    for drop_handle in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let input = copy_fixture("png_itxt_exif_icc.png", directory.path());
        let output = directory.path().join("must-not-exist.png");
        let request = JobRequest::new(JobKind::Sanitize {
            input,
            output: Some(output.clone()),
        });
        let handle = JobHandle::spawn_with_executable(
            request,
            sleeping_worker(directory.path()),
            Arc::new(|| {}),
        );
        let pid = wait_for_pid(directory.path());
        if drop_handle {
            drop(handle);
        } else {
            assert!(handle.cancel());
            let result = wait(&handle);
            assert_eq!(result.exit_code, 6);
        }
        assert!(!output.exists());
        assert_no_staging(directory.path());
        assert_reaped(&pid);
        assert_descendant_stopped_and_scratch_removed(directory.path());
    }
}

// FVPROV1 17587 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI2NGVmYWQ1YzJlZGRmNzAwOWY3ZTJlYmU1Nzc2ZDRkOTZmM2EzNTA2ODliNDg5NzNlZjFiZDczNzhjNmZlZmFjIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4zIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMyIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvdGVzdHMvam9icy5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjI2MDM3MGIyNjg2OTVmY2E4ZTQyN2MwNTBlNWNkZjExOTI5MDZiYjA4ZmVmNTc5OWYzMjgwMjczZjg4NWNmYzk5MzVhZWE3MzRkY2Q0MWY0YTI0M2RiNGRmMjUxYjdjNGM3MTEwZDY4YTdiZWUxNDRmMGY2OTA2MzAyZDNlMDAyIn1dfV0= FVPROV1-END
