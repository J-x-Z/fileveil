// SPDX-License-Identifier: MPL-2.0
use fileveil_core::{Limits, Outcome, digest};
use std::{fs, path::Path};

#[test]
fn invalid_credentials_fail_the_audit_and_preserve_the_original() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/provenance");
    let bytes = fs::read(fixtures.join("signed.png")).unwrap();
    let mut manifest = c2pa::jumbf_io::load_jumbf_from_memory("image/png", &bytes).unwrap();
    let marker = b"PRIVATE_GENERATOR";
    let offset = manifest
        .windows(marker.len())
        .position(|part| part == marker)
        .unwrap();
    manifest[offset] ^= 1;
    let bytes = c2pa::jumbf_io::save_jumbf_to_memory("image/png", &bytes, &manifest).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("invalid.png");
    fs::write(&input, &bytes).unwrap();
    let report = fileveil_engine::audits::provenance(&input, None, &Limits::default()).unwrap();
    assert_eq!(report.result, Outcome::Failed);
    assert_eq!(report.provenance.as_ref().unwrap()["signature"], "invalid");
    assert_eq!(digest(&bytes), digest(&fs::read(input).unwrap()));
}

#[test]
fn unsupported_detector_input_is_explicitly_unsupported() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("notes.txt");
    fs::write(&input, "synthetic clean text").unwrap();
    let report = fileveil_engine::audits::detect_watermark(&input, &Limits::default()).unwrap();
    assert_eq!(report.result, Outcome::Unsupported);
    assert_eq!(
        report.advanced.unwrap()["detection"]["status"],
        "not_assessed"
    );
    assert_eq!(report.integrity.original_unchanged, Some(true));
}

#[test]
fn lab_rejects_invalid_groups_before_opening_inputs() {
    let inputs = ["missing-first.png".into(), "missing-second.png".into()];
    let groups = [fileveil_engine::lab::SampleGroup {
        label: "control".into(),
        sample_indices: vec![0, 9],
    }];
    let error =
        fileveil_engine::audits::lab_with_groups(&inputs, &groups, &Limits::default()).unwrap_err();
    assert!(error.to_string().contains("indices"));
}

#[test]
fn lab_enforces_remaining_snapshot_budget_before_reading_the_next_file() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first.png");
    let second = directory.path().join("second.png");
    let bytes = include_bytes!("../../../tests/fixtures/png_clean.png");
    fs::write(&first, bytes).unwrap();
    fs::write(&second, bytes).unwrap();
    let limits = Limits {
        max_uncompressed_bytes: bytes.len() as u64,
        ..Default::default()
    };
    let error = fileveil_engine::audits::lab(&[first, second], &limits).unwrap_err();
    assert!(error.to_string().contains("file byte limit"));
}

// FVPROV1 2792 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI4MDI3Yjg1N2U4YWI3NTU3YzkxZGYxNDYxMGIxNzAwN2ViODhmYjg0ZGFjYWYxZTMxMDdhMjA4NzBjOTdmYjdmIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4zIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMyIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvdGVzdHMvYXVkaXRzLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiY2FhZmI2ZGVhZmI5YTFhZWQ3ODg0YmVlODNkMTUzOTBiNjY3Mjk2ZWVmZTRjMzQ5MWJmN2Q4NWI3MDc2ZTUzZGIwYWFkOGJhYmEyM2M5ODUxODhlZTBjOThiYWM4YzRmZmQ1ZmE1YTBiYWQ2MjVhMjYyMzk3ZTk3NmYxNTRiMDAifV19XQ== FVPROV1-END
