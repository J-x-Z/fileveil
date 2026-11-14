// SPDX-License-Identifier: MPL-2.0
//! Source comment carriers use the existing normal file operations and signatures.
use fileveil_core::{Format, Limits, Outcome, Report, digest};
use fileveil_engine::heritage::{self, HeritageAction, HeritageRequest, MarkSettings, container};
use serde_json::Value;
use std::{fs, path::Path};

fn details(report: &Report) -> &Value {
    &report.advanced.as_ref().unwrap()["heritage"]
}

fn mark_request(key: &Path) -> HeritageRequest {
    HeritageRequest {
        action: HeritageAction::Mark,
        key_paths: vec![key.to_path_buf()],
        mark: MarkSettings {
            work_id: "fileveil-source-test".into(),
            copy_id: "alpha-source".into(),
            signature_v2: true,
            author: "Synthetic Source Author".into(),
            created_at: "2026-11-14T00:00:00Z".into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn supported_source_languages_mark_verify_trace_clean_without_changing_source_bytes() {
    for (name, code) in [
        ("sample.rs", "fn main() { println!(\"你好\"); }"),
        ("sample.py", "{'dict': 'at beginning'}\nprint('hello')\n"),
        ("Cargo.toml", "[package]\nname = 'source-test'\n"),
        ("ci.yml", "steps:\n  - run: |\n      echo hello\n"),
        ("script.sh", "#!/bin/sh\nprintf '%s\\n' 'hello'\n"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join(name);
        let marked = directory.path().join(format!("marked-{name}"));
        let clean = directory.path().join(format!("clean-{name}"));
        let key = directory.path().join("owner.key");
        heritage::keygen(&key).unwrap();
        fs::write(&input, code).unwrap();
        let original = digest(code.as_bytes());
        let report = heritage::run(
            &input,
            Some(&marked),
            &mark_request(&key),
            &Limits::default(),
        )
        .unwrap();
        assert_ne!(report.result, Outcome::Failed);
        assert_eq!(report.input_format, Format::Text.mime());
        assert_eq!(details(&report)["verification"]["signature"], "valid");
        assert_eq!(details(&report)["verification"]["content_binding"], "valid");
        assert_eq!(report.integrity.original_unchanged, Some(true));
        let bytes = fs::read(&marked).unwrap();
        assert_eq!(
            container::extract(&bytes, Format::Text).unwrap().base,
            code.as_bytes()
        );
        for action in [
            HeritageAction::Detect,
            HeritageAction::Verify,
            HeritageAction::Trace,
        ] {
            let request = HeritageRequest {
                action,
                reference: Some(marked.clone()),
                ..Default::default()
            };
            let report = heritage::run(&marked, None, &request, &Limits::default()).unwrap();
            assert_ne!(report.result, Outcome::Failed);
            assert_eq!(details(&report)["verification"]["signature"], "valid");
            assert_eq!(details(&report)["verification"]["content_binding"], "valid");
            assert_eq!(details(&report)["trace_reference_match"], true);
            assert_eq!(details(&report)["copy_digest_match"], true);
        }
        let clean_report = heritage::run(
            &marked,
            Some(&clean),
            &HeritageRequest {
                action: HeritageAction::Clean,
                clean_metadata: true,
                ..Default::default()
            },
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(details(&clean_report)["modern_manifest_removed"], true);
        assert_eq!(details(&clean_report)["source_content_preserved"], true);
        assert_eq!(fs::read(&clean).unwrap(), code.as_bytes());
        assert_eq!(digest(&fs::read(&input).unwrap()), original);
        let rechecked = heritage::run(
            &clean,
            None,
            &HeritageRequest::default(),
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(details(&rechecked)["manifest_present"], false);
        let renamed = directory.path().join("source-copy.txt");
        fs::write(&renamed, &bytes).unwrap();
        let renamed_clean = directory.path().join("source-copy.clean.txt");
        let report = heritage::run(
            &renamed,
            Some(&renamed_clean),
            &HeritageRequest {
                action: HeritageAction::Clean,
                clean_metadata: true,
                ..Default::default()
            },
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(details(&report)["source_content_preserved"], true);
        assert_eq!(fs::read(renamed_clean).unwrap(), code.as_bytes());
    }
}

#[test]
fn source_base_tamper_fails_binding_and_existing_outputs_remain_protected() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("sample.rs");
    let marked = directory.path().join("marked.rs");
    let key = directory.path().join("owner.key");
    heritage::keygen(&key).unwrap();
    fs::write(&input, "fn main() { let value = 1; }\n").unwrap();
    let request = mark_request(&key);
    heritage::run(&input, Some(&marked), &request, &Limits::default()).unwrap();
    let before = fs::read(&marked).unwrap();
    assert!(heritage::run(&input, Some(&marked), &request, &Limits::default()).is_err());
    assert_eq!(fs::read(&marked).unwrap(), before);
    let mut tampered = before;
    let position = tampered.iter().position(|&byte| byte == b'1').unwrap();
    tampered[position] = b'2';
    fs::write(&marked, tampered).unwrap();
    let report = heritage::run(
        &marked,
        None,
        &HeritageRequest {
            action: HeritageAction::Verify,
            ..Default::default()
        },
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(report.result, Outcome::Failed);
    assert_eq!(details(&report)["verification"]["signature"], "valid");
    assert_eq!(
        details(&report)["verification"]["content_binding"],
        "invalid"
    );
}

#[test]
fn source_copyright_evidence_export_and_asset_verification_use_normal_entry() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("sample.py");
    let marked = directory.path().join("marked.py");
    let evidence = directory.path().join("copyright.json");
    let key = directory.path().join("owner.key");
    heritage::keygen(&key).unwrap();
    fs::write(&input, "print('source evidence')\n").unwrap();
    heritage::run(
        &input,
        Some(&marked),
        &mark_request(&key),
        &Limits::default(),
    )
    .unwrap();
    heritage::run(
        &marked,
        Some(&evidence),
        &HeritageRequest {
            action: HeritageAction::EvidenceExport,
            key_paths: vec![key],
            ..Default::default()
        },
        &Limits::default(),
    )
    .unwrap();
    let report = heritage::run(
        &evidence,
        None,
        &HeritageRequest {
            action: HeritageAction::EvidenceVerify,
            reference: Some(marked),
            ..Default::default()
        },
        &Limits::default(),
    )
    .unwrap();
    assert_ne!(report.result, Outcome::Failed);
    assert_eq!(report.integrity.original_unchanged, Some(true));
}

// FVPROV1 7356 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI2ZTZhMTRiZmJjM2JhNjUzOTE1ZmQzZGNmOTEwY2VhYTM4MGY1Mjg3Y2YxYWUwNWRkZTI0NzdmYzc1NTQzYWUyIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4zIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMyIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvdGVzdHMvaGVyaXRhZ2Vfc291cmNlLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiMDQwMmVjZGIxYTM1YzI2MTQyYjI5Njc1YTkwMWIyOGVjNGVmZWVhMmJiYjlmYzdlZGQ3ZTdlZGE1NzQxMWQ4MzY5OGFiYTRlMDNmZmRmODRkZDk3NmJhNjVmNGNmMmI0NGQzOTkwMjYxNGFlODA0Y2Q4M2MzYzJiZTk5MmE1MGYifV19XQ== FVPROV1-END
