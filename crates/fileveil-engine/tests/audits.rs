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
