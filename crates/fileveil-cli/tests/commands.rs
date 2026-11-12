// SPDX-License-Identifier: MPL-2.0
use std::{
    path::{Path, PathBuf},
    process::Command,
};
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}
fn run(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_fileveil"))
        .args(arguments)
        .output()
        .unwrap()
}
#[test]
fn capabilities_and_help_use_normal_entry_points() {
    let output = run(&["capabilities", "--json"]);
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], "0.3");
    assert_eq!(value["offline"], true);
    assert_eq!(value["profiles"]["deep"], "selective");
    assert!(run(&["--help"]).status.success());
}
#[test]
fn unknown_format_has_explicit_unsupported_json_and_exit_code() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("unknown.bin");
    std::fs::write(&input, b"fictional unknown format").unwrap();
    let output = run(&["scan", input.to_str().unwrap(), "--json"]);
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["result"], "unsupported");
}
#[test]
fn image_command_round_trip_accepts_unicode_spaces_and_newline_paths() {
    let directory = tempfile::tempdir().unwrap();
    let name = if cfg!(windows) {
        "合成 图像 原件.png"
    } else {
        "合成 图像\n原件.png"
    };
    let input = directory.path().join(name);
    let clean = directory.path().join("净化 副本.png");
    std::fs::copy(fixtures().join("png_itxt_exif_icc.png"), &input).unwrap();
    let output = run(&[
        "sanitize",
        input.to_str().unwrap(),
        "--output",
        clean.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["integrity"]["pixel_equal"], true);
    assert_eq!(value["integrity"]["original_unchanged"], true);
    assert_eq!(value["result"], "verified_within_scope");
    let verified = run(&[
        "verify",
        input.to_str().unwrap(),
        clean.to_str().unwrap(),
        "--json",
    ]);
    assert!(verified.status.success());
    let overwrite = run(&[
        "sanitize",
        input.to_str().unwrap(),
        "--output",
        clean.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(overwrite.status.code(), Some(2));
    assert!(!std::fs::read_dir(directory.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".fileveil")
    }));
}
#[test]
fn deep_profile_and_malformed_file_have_stable_exit_codes() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("original.png");
    std::fs::copy(fixtures().join("png_clean.png"), &input).unwrap();
    assert_eq!(
        run(&[
            "sanitize",
            input.to_str().unwrap(),
            "--profile",
            "deep",
            "--json"
        ])
        .status
        .code(),
        Some(0)
    );
    let malformed = fixtures().join("png_bad_crc.png");
    assert_eq!(
        run(&["scan", malformed.to_str().unwrap(), "--json"])
            .status
            .code(),
        Some(5)
    );
    assert_eq!(
        run(&["scan", "missing", "--max-file-mib", "0"])
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn worker_preserves_option_terminator_for_dash_prefixed_names() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::copy(
        fixtures().join("jpeg_clean.jpg"),
        directory.path().join("-sample.jpg"),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fileveil"))
        .current_dir(directory.path())
        .args(["scan", "--json", "--", "-sample.jpg"])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["operation"], "scan");
}

#[test]
fn image_signal_commands_use_supervised_workers_and_report_pixel_changes() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("图像 原件.png");
    std::fs::copy(fixtures().join("png_clean.png"), &input).unwrap();
    for mode in ["low-bits", "signal"] {
        let output = directory.path().join(format!("{mode}.png"));
        let processed = run(&[
            "process-image",
            input.to_str().unwrap(),
            "--mode",
            mode,
            "--output",
            output.to_str().unwrap(),
            "--json",
        ]);
        assert_eq!(
            processed.status.code(),
            Some(4),
            "{}",
            String::from_utf8_lossy(&processed.stdout)
        );
        let report: serde_json::Value = serde_json::from_slice(&processed.stdout).unwrap();
        assert_eq!(report["result"], "partially_verified");
        assert_eq!(
            report["image_processing"]["detector_status"],
            "not_assessed"
        );
        assert_eq!(report["integrity"]["original_unchanged"], true);
        let verified = run(&[
            "verify-image",
            input.to_str().unwrap(),
            output.to_str().unwrap(),
            "--mode",
            mode,
            "--json",
        ]);
        assert_eq!(
            verified.status.code(),
            Some(4),
            "{}",
            String::from_utf8_lossy(&verified.stdout)
        );
        let verified: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
        assert_eq!(report["output_sha256"], verified["output_sha256"]);
    }
}

#[test]
fn mobile_media_commands_complete_scan_sanitize_verify_without_overwriting_originals() {
    let directory = tempfile::tempdir().unwrap();
    for (name, mime) in [
        ("heic_exif_gps.heic", "image/heif"),
        ("avif_exif_gps.avif", "image/avif"),
        ("mp4_container_times.mp4", "video/mp4"),
        ("mp4_av_source.mp4", "video/mp4"),
        ("mov_model_metadata.mov", "video/quicktime"),
    ] {
        let input = directory.path().join(format!("原件 {name}"));
        let output = directory.path().join(format!("副本 {name}"));
        std::fs::copy(fixtures().join(name), &input).unwrap();
        let original = std::fs::read(&input).unwrap();
        let scanned = run(&["scan", input.to_str().unwrap(), "--json"]);
        assert!(matches!(scanned.status.code(), Some(0 | 4)));
        let scanned: serde_json::Value = serde_json::from_slice(&scanned.stdout).unwrap();
        assert_eq!(scanned["input_format"], mime);
        assert_eq!(scanned["integrity"]["parseable"], true);
        let sanitized = run(&[
            "sanitize",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--json",
        ]);
        assert!(
            matches!(sanitized.status.code(), Some(0 | 4)),
            "{}",
            String::from_utf8_lossy(&sanitized.stdout)
        );
        let sanitized: serde_json::Value = serde_json::from_slice(&sanitized.stdout).unwrap();
        assert_eq!(sanitized["integrity"]["original_unchanged"], true);
        assert_eq!(sanitized["integrity"]["content_equal"], true);
        assert!(sanitized["integrity"]["pixel_equal"].is_null());
        let verified = run(&[
            "verify",
            input.to_str().unwrap(),
            output.to_str().unwrap(),
            "--json",
        ]);
        assert!(matches!(verified.status.code(), Some(0 | 4)));
        let verified: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
        assert_eq!(verified["integrity"]["content_equal"], true);
        assert_eq!(verified["output_sha256"], sanitized["output_sha256"]);
        let cleaned = std::fs::read(&output).unwrap();
        assert_eq!(
            run(&[
                "sanitize",
                input.to_str().unwrap(),
                "--output",
                output.to_str().unwrap(),
                "--json",
            ])
            .status
            .code(),
            Some(2)
        );
        assert_eq!(std::fs::read(&input).unwrap(), original);
        assert_eq!(std::fs::read(&output).unwrap(), cleaned);
    }
}
