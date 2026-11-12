// SPDX-License-Identifier: MPL-2.0
use fileveil_core::{FindingState, Limits, Outcome, Policy, SanitizeOptions, TextOptions};
use fileveil_engine::{advanced, provenance, scan};
use std::{fs, path::PathBuf};
fn fixture(name: &str) -> Vec<u8> {
    fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/provenance")
            .join(name),
    )
    .unwrap()
}
fn removal() -> SanitizeOptions {
    SanitizeOptions {
        policy: Policy::Deep,
        remove_provenance: true,
        ..Default::default()
    }
}
#[test]
fn signed_pdf_normal_entry_points_protect_default_and_verify_explicit_removal() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("original.pdf");
    let output = directory.path().join("clean.pdf");
    let source = fixture("signed.pdf");
    fs::write(&input, &source).unwrap();
    let summary = fileveil_engine::pdf::credential_summary(&source, &Limits::default()).unwrap();
    assert_eq!(summary.store_count, 1);
    assert!(!summary.digital_signatures_present);
    let report = scan(&input, &Limits::default()).unwrap();
    assert_eq!(report.result, Outcome::Blocked);
    assert_eq!(report.provenance.as_ref().unwrap()["signature"], "valid");
    assert!(fileveil_engine::sanitize(&input, Some(&output), &Limits::default()).is_err());
    assert!(!output.exists());
    let report =
        advanced::sanitize_with_options(&input, Some(&output), &Limits::default(), &removal())
            .unwrap();
    assert_eq!(report.result, Outcome::PartiallyVerified);
    assert_eq!(report.integrity.original_unchanged, Some(true));
    assert_eq!(report.integrity.content_equal, None);
    assert_eq!(report.pdf.as_ref().unwrap()["c2pa_store_count"], 0);
    assert_eq!(report.pdf.as_ref().unwrap()["attachment_structures"], 0);
    let attachments: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.code == "pdf.attachments")
        .collect();
    assert_eq!(attachments.len(), 1);
    assert_eq!(attachments[0].state, FindingState::RemovedVerified);
    if fileveil_engine::pdf::capabilities()["independent_validation_available"] == true {
        assert_eq!(report.pdf.as_ref().unwrap()["independent_text_equal"], true);
        assert_eq!(
            report.pdf.as_ref().unwrap()["independent_render_equal"],
            true
        );
    } else {
        let checks = [
            &report.pdf.as_ref().unwrap()["independent_page_count_equal"],
            &report.pdf.as_ref().unwrap()["independent_text_equal"],
            &report.pdf.as_ref().unwrap()["independent_render_equal"],
        ];
        assert!(
            checks
                .iter()
                .all(|check| check.is_null() || **check == true)
        );
        assert!(checks.iter().any(|check| check.is_null()));
    }
    assert!(
        provenance::inspect_mime(
            &fs::read(&output).unwrap(),
            "application/pdf",
            &Limits::default(),
            None
        )
        .unwrap()
        .is_none()
    );
    advanced::verify_with_options(&input, &output, &Limits::default(), &removal()).unwrap();
    let clean_report = scan(&output, &Limits::default()).unwrap();
    assert_eq!(
        clean_report.pdf.as_ref().unwrap()["attachment_structures"],
        0
    );
    assert!(
        !clean_report
            .findings
            .iter()
            .any(|finding| finding.code == "pdf.attachments")
    );
    assert_eq!(fs::read(&input).unwrap(), source);
}
#[test]
fn signed_plaintext_and_markdown_preserve_exact_body_and_default_protection() {
    for (name, mime) in [("signed.txt", "text/plain"), ("signed.md", "text/markdown")] {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join(name);
        let output = directory.path().join("clean.txt");
        let source = fixture(name);
        fs::write(&input, &source).unwrap();
        let report = scan(&input, &Limits::default()).unwrap();
        assert_eq!(report.result, Outcome::Blocked);
        assert_eq!(report.provenance.as_ref().unwrap()["signature"], "valid");
        let safe = SanitizeOptions {
            text: TextOptions {
                remove_bom: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            advanced::sanitize_with_options(&input, Some(&output), &Limits::default(), &safe)
                .is_err()
        );
        assert!(!output.exists());
        let expected = provenance::strip_text_wrappers(&source, mime, &Limits::default()).unwrap();
        let report =
            advanced::sanitize_with_options(&input, Some(&output), &Limits::default(), &removal())
                .unwrap();
        assert_eq!(report.result, Outcome::PartiallyVerified);
        assert_eq!(report.integrity.content_equal, Some(true));
        assert_eq!(fs::read(&output).unwrap(), expected);
        assert_eq!(fs::read(&input).unwrap(), source);
        advanced::verify_with_options(&input, &output, &Limits::default(), &removal()).unwrap();
    }
}
#[test]
fn non_nfc_body_keeps_original_utf8_bytes_after_explicit_wrapper_removal() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("decomposed.txt");
    let output = directory.path().join("clean.txt");
    let source = String::from_utf8(fixture("signed.txt"))
        .unwrap()
        .replace("café", "cafe\u{301}");
    fs::write(&input, source.as_bytes()).unwrap();
    let report =
        advanced::sanitize_with_options(&input, Some(&output), &Limits::default(), &removal())
            .unwrap();
    assert!(
        String::from_utf8(fs::read(&output).unwrap())
            .unwrap()
            .contains("cafe\u{301}")
    );
    assert_eq!(
        report.provenance.as_ref().unwrap()["asset_binding_scope"],
        "nfc_normalization_required_not_performed"
    );
    assert_eq!(fs::read(&input).unwrap(), source.as_bytes());
}
