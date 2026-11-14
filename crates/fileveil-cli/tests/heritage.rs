// SPDX-License-Identifier: MPL-2.0
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fileveil"))
        .args(arguments)
        .output()
        .unwrap()
}

fn report(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}: {} / {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn successful(output: &Output) -> Value {
    let report = report(output);
    assert!(matches!(output.status.code(), Some(0 | 4)), "{}", report);
    assert!(
        matches!(
            report["result"].as_str(),
            Some("verified_within_scope" | "partially_verified")
        ),
        "{}",
        report
    );
    report
}

fn png(directory: &Path) -> PathBuf {
    let input = directory.join("自然 图片 原件.png");
    std::fs::copy(
        root().join("crates/fileveil-engine/tests/fixtures/watermark/astronaut.png"),
        &input,
    )
    .unwrap();
    input
}

#[test]
fn supervised_keygen_mark_verify_trace_and_clean_preserve_original_and_protect_outputs() {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("私有签名.key");
    let generated = successful(&run(&[
        "heritage-keygen",
        "--output",
        key.to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(generated["operation"], "heritage_keygen");
    assert!(key.is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(
        run(&["heritage-keygen", "-o", key.to_str().unwrap(), "--json"])
            .status
            .code(),
        Some(2)
    );
    let input = png(directory.path());
    let original = std::fs::read(&input).unwrap();
    let marked = directory.path().join("作品标记.png");
    let declared = "Unverified Author 参考声明";
    let created = "2026-11-12T18:00:00Z";
    let options =
        json!({"action":"clean","mark":{"robust":true},"disclose_claims":false}).to_string();
    let mark = successful(&run(&[
        "heritage",
        "mark",
        input.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "--work-id",
        "public-work-2026",
        "--author",
        declared,
        "--created-at",
        created,
        "--options-json",
        &options,
        "--output",
        marked.to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(mark["operation"], "heritage");
    assert_eq!(mark["advanced"]["heritage"]["action"], "mark");
    assert_eq!(mark["advanced"]["heritage"]["robust"]["status"], "detected");
    assert_eq!(mark["integrity"]["original_unchanged"], true);
    assert_eq!(mark["output_name"], "作品标记.png");
    assert!(
        !String::from_utf8_lossy(
            &run(&["heritage", "detect", marked.to_str().unwrap(), "--json"]).stdout
        )
        .contains(declared)
    );
    let verified = successful(&run(&[
        "heritage",
        "verify",
        marked.to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(
        verified["advanced"]["heritage"]["verification"]["signature"],
        "valid"
    );
    assert_eq!(
        verified["advanced"]["heritage"]["verification"]["content_binding"],
        "valid"
    );
    let reference = json!({"reference": marked}).to_string();
    let traced = successful(&run(&[
        "heritage",
        "trace",
        marked.to_str().unwrap(),
        "--options-json",
        &reference,
        "--json",
    ]));
    assert_eq!(
        traced["advanced"]["heritage"]["trace_reference_match"],
        true
    );
    let cleaned = directory.path().join("净化作品.png");
    let clean_options = json!({"clean_signal":true}).to_string();
    let clean = successful(&run(&[
        "heritage",
        "clean",
        marked.to_str().unwrap(),
        "--options-json",
        &clean_options,
        "-o",
        cleaned.to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(
        clean["advanced"]["heritage"]["robust_recheck"]["frame_valid"],
        false
    );
    assert_eq!(
        clean["advanced"]["heritage"]["modern_manifest_removed"],
        true
    );
    assert_eq!(std::fs::read(&input).unwrap(), original);
    let cleaned_bytes = std::fs::read(&cleaned).unwrap();
    assert_eq!(
        run(&[
            "heritage",
            "clean",
            marked.to_str().unwrap(),
            "-o",
            cleaned.to_str().unwrap(),
            "--json"
        ])
        .status
        .code(),
        Some(2)
    );
    assert_eq!(std::fs::read(&cleaned).unwrap(), cleaned_bytes);
    assert!(!std::fs::read_dir(directory.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".fileveil")
    }));
}

#[test]
fn typed_options_validation_help_and_read_only_output_errors_use_normal_entry_points() {
    let directory = tempfile::tempdir().unwrap();
    let input = png(directory.path());
    assert!(run(&["heritage", "--help"]).status.success());
    for action in ["detect", "verify", "trace", "lab"] {
        let unwanted = directory.path().join(format!("{action}.png"));
        let output = run(&[
            "heritage",
            action,
            input.to_str().unwrap(),
            "--output",
            unwanted.to_str().unwrap(),
            "--json",
        ]);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(report(&output)["operation"], "heritage");
        assert!(!unwanted.exists());
    }
    for options in [
        "{",
        "{\"unknown_field\":true}",
        "{\"mark\":{\"robust\":\"yes\"}}",
    ] {
        let output = run(&[
            "heritage",
            "detect",
            input.to_str().unwrap(),
            "--options-json",
            options,
            "--json",
        ]);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(report(&output)["result"], "failed");
    }
}

#[test]
fn dash_prefixed_heritage_inputs_keep_the_option_terminator_across_workers() {
    let directory = tempfile::tempdir().unwrap();
    let input = png(directory.path());
    std::fs::rename(&input, directory.path().join("-original.png")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fileveil"))
        .current_dir(directory.path())
        .args(["heritage", "detect", "--json", "--", "-original.png"])
        .output()
        .unwrap();
    let detected = successful(&output);
    assert_eq!(detected["operation"], "heritage");
    assert_eq!(detected["integrity"]["original_unchanged"], true);
}

#[test]
fn human_trace_prints_signature_binding_and_custody_records() {
    let directory = tempfile::tempdir().unwrap();
    let input = png(directory.path());
    let key = directory.path().join("owner.key");
    let marked = directory.path().join("marked.png");
    successful(&run(&[
        "heritage-keygen",
        "-o",
        key.to_str().unwrap(),
        "--json",
    ]));
    successful(&run(&[
        "heritage",
        "mark",
        input.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "--work-id",
        "human-trace-work",
        "-o",
        marked.to_str().unwrap(),
        "--json",
    ]));
    let output = run(&["heritage", "trace", marked.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(4));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("signature · valid"));
    assert!(text.contains("content_binding · valid"));
    assert!(text.contains("Signed record 0 · create · version 1"));
}

#[test]
fn public_v2_commands_keep_copy_identity_key_scope_and_verified_cleaning() {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("owner.key");
    let wrong = directory.path().join("other.key");
    for path in [&key, &wrong] {
        successful(&run(&[
            "heritage-keygen",
            "-o",
            path.to_str().unwrap(),
            "--json",
        ]));
    }
    let input = png(directory.path());
    let original = std::fs::read(&input).unwrap();
    let marked = directory.path().join("copy-a.png");
    let other = directory.path().join("copy-b.png");
    for (output, copy) in [(&marked, "copy-a"), (&other, "copy-b")] {
        let value = successful(&run(&[
            "mark",
            input.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--pixel",
            "--copy-id",
            copy,
            "--work-id",
            "same-public-work",
            "--created-at",
            "2026-11-13T00:00:00Z",
            "--json",
        ]));
        assert_eq!(
            value["advanced"]["heritage"]["robust"]["authenticated"],
            true
        );
        assert_eq!(value["integrity"]["original_unchanged"], true);
    }
    let verified = successful(&run(&[
        "verify",
        marked.to_str().unwrap(),
        "--watermark-key",
        key.to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(
        verified["advanced"]["heritage"]["robust"]["frame_valid"],
        true
    );
    let wrong_key = successful(&run(&[
        "verify",
        marked.to_str().unwrap(),
        "--watermark-key",
        wrong.to_str().unwrap(),
        "--json",
    ]));
    assert_ne!(
        wrong_key["advanced"]["heritage"]["robust"]["frame_valid"],
        true
    );
    let trace = successful(&run(&[
        "trace",
        marked.to_str().unwrap(),
        "--watermark-key",
        key.to_str().unwrap(),
        "--reference",
        other.to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(trace["advanced"]["heritage"]["work_digest_match"], true);
    assert_eq!(trace["advanced"]["heritage"]["copy_digest_match"], false);
    assert_eq!(
        trace["advanced"]["heritage"]["trace_reference_match"],
        false
    );
    let cleaned = directory.path().join("clean.png");
    let clean = successful(&run(&[
        "clean",
        marked.to_str().unwrap(),
        "-o",
        cleaned.to_str().unwrap(),
        "--pixel",
        "--watermark-key",
        key.to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(
        clean["advanced"]["heritage"]["modern_manifest_removed"],
        true
    );
    assert_ne!(
        clean["advanced"]["heritage"]["robust_recheck"]["frame_valid"],
        true
    );
    assert_eq!(clean["integrity"]["original_unchanged"], true);
    assert_eq!(std::fs::read(input).unwrap(), original);
    assert_eq!(
        run(&[
            "clean",
            marked.to_str().unwrap(),
            "-o",
            cleaned.to_str().unwrap(),
            "--json"
        ])
        .status
        .code(),
        Some(2),
    );
}

#[test]
fn public_clean_targets_deployed_sd_payload_and_reports_encoded_recheck() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("sdxl.png");
    let output = directory.path().join("sdxl-clean.png");
    std::fs::copy(
        root().join("crates/fileveil-engine/tests/fixtures/watermark/astronaut-sdxl.png"),
        &input,
    )
    .unwrap();
    let original = std::fs::read(&input).unwrap();
    let value = successful(&run(&[
        "clean",
        input.to_str().unwrap(),
        "-o",
        output.to_str().unwrap(),
        "--pixel",
        "--json",
    ]));
    let evidence = &value["advanced"]["heritage"];
    assert!(
        evidence["signal_processing"]["processed_methods"]
            .as_array()
            .unwrap()
            .iter()
            .any(|method| method == "stable_diffusion_xl_dwt_dct")
    );
    assert!(
        evidence["robust_recheck"]["detections"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["status"] != "detected")
    );
    assert_eq!(value["integrity"]["original_unchanged"], true);
    assert_eq!(std::fs::read(input).unwrap(), original);
}

// FVPROV1 12424 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJhNjc0Y2YzZTdlNDIzMGQyOTU1ZTE4MjRlNTk4ZTAzZTVlMGUzM2M4Y2YyYTI3YzhmYjlhYzA5MTRkOWYyNzA2IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4yIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMiIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1jbGkvdGVzdHMvaGVyaXRhZ2UucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI5OTE2NzIxMmM2NWZiNjBhNDU3MjVkOWMwN2U4MDM2YWYxNDY1NTJhZjQxZGVkM2EyZjI1ZmRjMjM4NzI1ZjMxZjhiNDM1Zjc3ZWNmMDA5ZGZiNDJmZjcyNDNmODliYWQzZTM2ZDIzOTI1MmExNGMyYTBiZjM1MGVjYmQ1MzcwNCJ9XX1d FVPROV1-END
