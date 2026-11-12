// SPDX-License-Identifier: MPL-2.0
//! Synthetic PDF fixtures exercise qpdf rewrites and independent Poppler comparisons.
use fileveil_core::{Action, Error, FindingState, Limits, Outcome, digest};
use fileveil_engine::pdf;
use std::{fs, path::PathBuf, process::Command};

fn stream(dictionary: &str, bytes: &[u8]) -> Vec<u8> {
    let mut result = format!("<< {dictionary} /Length {} >>\nstream\n", bytes.len()).into_bytes();
    result.extend_from_slice(bytes);
    result.extend_from_slice(b"\nendstream");
    result
}
fn assemble(objects: &[Vec<u8>], trailer: &str) -> Vec<u8> {
    let mut data = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
    let mut offsets = vec![0];
    for (index, object) in objects.iter().enumerate() {
        offsets.push(data.len());
        data.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
        data.extend_from_slice(object);
        data.extend_from_slice(b"\nendobj\n");
    }
    let xref = data.len();
    data.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for offset in &offsets[1..] {
        data.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    data.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R {trailer} >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    data
}
fn fixture(visible_text: &str, catalog_extra: &str, extra: Vec<Vec<u8>>) -> Vec<u8> {
    fixture_page(visible_text, catalog_extra, "", extra)
}
fn fixture_page(
    visible_text: &str,
    catalog_extra: &str,
    page_extra: &str,
    extra: Vec<Vec<u8>>,
) -> Vec<u8> {
    let mut objects = vec![
        format!("<< /Type /Catalog /Pages 2 0 R /Metadata 7 0 R {catalog_extra} >>").into_bytes(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R {page_extra} >>").into_bytes(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
        stream("", format!("BT /F1 12 Tf 20 200 Td ({visible_text}) Tj ET").as_bytes()),
        b"<< /Author (SYNTHETIC_PRIVATE_AUTHOR) /CreationDate (D:20260101010101) /PrivateField (SYNTHETIC_PRIVATE_CUSTOM) >>".to_vec(),
        stream("/Type /Metadata /Subtype /XML", b"<x:xmpmeta>SYNTHETIC_PRIVATE_XMP</x:xmpmeta>"),
    ];
    objects.extend(extra);
    assemble(&objects, "/Info 6 0 R /ID [<1234><1234>]")
}
fn has_bytes(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}
fn require_backend() {
    assert_eq!(
        pdf::capabilities()["available"],
        true,
        "Install qpdf or configure an absolute FILEVEIL_QPDF executable"
    );
}

#[test]
fn safe_rewrite_removes_metadata_and_preserves_visible_content() {
    require_backend();
    let limits = Limits::default();
    let original = fixture("Synthetic visible text", "", Vec::new());
    let hash_before = digest(&original);
    let inspection = pdf::inspect(&original, &limits).unwrap();
    assert_eq!(inspection.details["pages"], 1);
    assert_eq!(inspection.details["document_info_fields"], 3);
    assert_eq!(inspection.details["custom_info_fields"], 1);
    assert_eq!(inspection.details["metadata_objects"], 1);
    assert!(inspection.blockers.is_empty());
    let clean = pdf::sanitize(&original, &limits).unwrap();
    assert!(!has_bytes(&clean, b"SYNTHETIC_PRIVATE_"));
    assert_eq!(digest(&original), hash_before);
    let after = pdf::inspect(&clean, &limits).unwrap();
    assert_eq!(after.details["metadata_objects"], 0);
    assert_eq!(after.details["document_info_fields"], 0);
    assert_eq!(inspection.content_digest, after.content_digest);
    let verified = pdf::verify(&original, &clean, &limits).unwrap();
    assert!(verified.integrity.parseable);
    assert!(
        verified
            .findings
            .iter()
            .any(|f| f.code == "pdf.xmp" && f.state == FindingState::RemovedVerified)
    );
    if pdf::capabilities()["independent_validation_available"] == true {
        assert_eq!(verified.integrity.content_equal, Some(true));
        assert_eq!(verified.details["independent_page_count_equal"], true);
        assert_eq!(verified.details["independent_text_equal"], true);
        assert_eq!(verified.details["independent_render_equal"], true);
        assert_eq!(verified.result, Outcome::VerifiedWithinScope);
    } else {
        assert_eq!(verified.integrity.content_equal, None);
        assert_eq!(verified.result, Outcome::PartiallyVerified);
    }
    let report = serde_json::to_string(&verified.details).unwrap();
    let findings = serde_json::to_string(&verified.findings).unwrap();
    assert!(!report.contains("SYNTHETIC_PRIVATE"));
    assert!(!findings.contains("SYNTHETIC_PRIVATE"));
}

#[test]
fn complete_rewrite_discards_incremental_old_metadata() {
    require_backend();
    let limits = Limits::default();
    let mut original = fixture("Revision content", "", Vec::new());
    let text = String::from_utf8_lossy(&original);
    let previous = text
        .rsplit("startxref\n")
        .next()
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let object_offset = original.len();
    original.extend_from_slice(b"8 0 obj\n<< /Author (NEW_PRIVATE_AUTHOR) >>\nendobj\n");
    let xref = original.len();
    original.extend_from_slice(format!("xref\n8 1\n{object_offset:010} 00000 n \ntrailer\n<< /Size 9 /Root 1 0 R /Info 8 0 R /Prev {previous} >>\nstartxref\n{xref}\n%%EOF\n").as_bytes());
    let inspection = pdf::inspect(&original, &limits).unwrap();
    assert_eq!(inspection.details["has_previous_xref"], true);
    assert_eq!(inspection.details["incremental_marker_count"], 2);
    let clean = pdf::sanitize(&original, &limits).unwrap();
    assert!(!has_bytes(&clean, b"PRIVATE_AUTHOR"));
    assert!(!has_bytes(&clean, b"PRIVATE_CUSTOM"));
    assert_eq!(
        pdf::inspect(&clean, &limits).unwrap().details["has_previous_xref"],
        false
    );
    pdf::verify(&original, &clean, &limits).unwrap();
}

#[test]
fn signatures_are_reported_unassessed_and_block_rewriting() {
    require_backend();
    let original = fixture("Signed content", "/AcroForm << /Fields [8 0 R] >>", vec![
        b"<< /FT /Sig /V 9 0 R /T (SyntheticSignature) >>".to_vec(),
        b"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /ByteRange [0 1 2 3] /Contents <00> >>".to_vec(),
    ]);
    let inspection = pdf::inspect(&original, &Limits::default()).unwrap();
    assert!(!inspection.blockers.is_empty());
    assert_eq!(inspection.details["signature_validation"], "not_assessed");
    assert!(
        inspection
            .findings
            .iter()
            .any(|f| f.code == "pdf.digital_signature" && f.state == FindingState::NotAssessed)
    );
    assert!(matches!(
        pdf::sanitize(&original, &Limits::default()),
        Err(Error::Blocked(_))
    ));
}

#[test]
fn safe_preserves_attachments_and_active_actions_with_residual_report() {
    require_backend();
    let original = fixture(
        "Attachment content",
        "/Names << /EmbeddedFiles << /Names [(fixture.txt) 8 0 R] >> >> /OpenAction 10 0 R",
        vec![
            b"<< /Type /Filespec /F (fixture.txt) /EF << /F 9 0 R >> >>".to_vec(),
            stream("/Type /EmbeddedFile", b"Synthetic embedded private payload"),
            br"<< /S /JavaScript /JS (app.alert\(synthetic\)) >>".to_vec(),
        ],
    );
    let limits = Limits::default();
    let inspection = pdf::inspect(&original, &limits).unwrap();
    assert!(
        inspection
            .findings
            .iter()
            .any(|f| f.code == "pdf.attachments" && f.action == Action::AskUser)
    );
    assert!(
        inspection
            .findings
            .iter()
            .any(|f| f.code == "pdf.active_content")
    );
    let clean = pdf::sanitize(&original, &limits).unwrap();
    assert!(has_bytes(&clean, b"Synthetic embedded private payload"));
    let verified = pdf::verify(&original, &clean, &limits).unwrap();
    assert_eq!(verified.result, Outcome::PartiallyVerified);
    assert!(
        verified
            .findings
            .iter()
            .any(|f| f.code == "pdf.attachments")
    );
}

#[test]
fn altered_visible_content_fails_verification() {
    require_backend();
    let limits = Limits::default();
    let original = fixture("Original visible content", "", Vec::new());
    let changed = fixture("Changed visible content", "", Vec::new());
    let clean_changed = pdf::sanitize(&changed, &limits).unwrap();
    assert!(matches!(
        pdf::verify(&original, &clean_changed, &limits),
        Err(Error::Verification(_))
    ));
}

#[test]
fn corrupt_and_over_budget_inputs_fail_safely() {
    require_backend();
    assert!(matches!(
        pdf::inspect(b"%PDF-1.7\nnot a PDF", &Limits::default()),
        Err(Error::Blocked(_))
    ));
    let original = fixture("Budget fixture", "", Vec::new());
    let limits = Limits {
        max_members: 2,
        ..Limits::default()
    };
    assert!(matches!(
        pdf::inspect(&original, &limits),
        Err(Error::Blocked(_))
    ));
    let limits = Limits {
        max_file_bytes: 16,
        ..Limits::default()
    };
    assert!(matches!(
        pdf::inspect(&original, &limits),
        Err(Error::Blocked(_))
    ));
}

#[test]
fn independent_render_budget_is_reported_as_partial() {
    require_backend();
    let limits = Limits {
        max_pixels: 1,
        ..Limits::default()
    };
    let original = fixture("Render budget", "", Vec::new());
    let clean = pdf::sanitize(&original, &limits).unwrap();
    let verified = pdf::verify(&original, &clean, &limits).unwrap();
    assert_eq!(verified.integrity.content_equal, None);
    assert_eq!(
        verified.details["independent_render_equal"],
        serde_json::Value::Null
    );
    assert_eq!(verified.result, Outcome::PartiallyVerified);
}

#[test]
fn encrypted_document_is_blocked_even_with_empty_user_password() {
    require_backend();
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("original.pdf");
    let output = directory.path().join("encrypted.pdf");
    fs::write(&input, fixture("Encrypted content", "", Vec::new())).unwrap();
    let executable = std::env::var_os("FILEVEIL_QPDF")
        .map(PathBuf::from)
        .or_else(|| {
            [
                "/opt/homebrew/bin/qpdf",
                "/usr/local/bin/qpdf",
                "/usr/bin/qpdf",
            ]
            .iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
        })
        .unwrap();
    assert!(
        Command::new(executable)
            .args(["--encrypt", "", "synthetic-owner", "256", "--"])
            .arg(input)
            .arg(&output)
            .status()
            .unwrap()
            .success()
    );
    let bytes = fs::read(output).unwrap();
    assert!(matches!(
        pdf::inspect(&bytes, &Limits::default()),
        Err(Error::Blocked(_))
    ));
}

/// An independently produced PDF can be supplied without copying private fixtures into Git.
#[test]
#[ignore = "requires FILEVEIL_TEST_REAL_PDF pointing to a local PDF"]
fn independently_produced_pdf_roundtrip() {
    require_backend();
    let input = std::env::var_os("FILEVEIL_TEST_REAL_PDF")
        .expect("Provide a local independent PDF fixture");
    let original = fs::read(&input).unwrap();
    let original_hash = digest(&original);
    let limits = Limits::default();
    let clean = pdf::sanitize(&original, &limits).unwrap();
    let verified = pdf::verify(&original, &clean, &limits).unwrap();
    assert_eq!(digest(&fs::read(input).unwrap()), original_hash);
    assert_eq!(verified.integrity.content_equal, Some(true));
    println!(
        "{}",
        serde_json::json!({"original_sha256":original_hash,"output_sha256":digest(&clean),"original_bytes":original.len(),"output_bytes":clean.len(),"pdf":verified.details,"result":verified.result})
    );
}

#[test]
fn explicit_deep_removes_attachments_and_javascript_preserving_navigation() {
    use fileveil_core::PdfOptions;
    require_backend();
    let original = fixture(
        "Deep retained page text",
        "/Names << /EmbeddedFiles << /Names [(fixture.txt) 8 0 R] >> /JavaScript << /Names [(script) 10 0 R] >> >> /OpenAction [3 0 R /Fit]",
        vec![
            b"<< /Type /Filespec /F (PRIVATE_FILENAME) /EF << /F 9 0 R >> >>".to_vec(),
            stream("/Type /EmbeddedFile", b"PRIVATE_ATTACHMENT_PAYLOAD"),
            b"<< /S /JavaScript /JS (PRIVATE_JAVASCRIPT) >>".to_vec(),
        ],
    );
    let options = PdfOptions {
        remove_attachments: true,
        remove_javascript: true,
        ..Default::default()
    };
    let output = pdf::sanitize_with_options(&original, &Limits::default(), &options).unwrap();
    assert!(!has_bytes(&output, b"PRIVATE_"));
    let inspection = pdf::inspect(&output, &Limits::default()).unwrap();
    assert_eq!(inspection.details["attachment_structures"], 0);
    assert_eq!(inspection.details["javascript_actions"], 0);
    assert_eq!(inspection.details["automatic_actions"], 1);
    let verified = pdf::verify_scoped(&original, &output, &Limits::default(), &options).unwrap();
    assert_eq!(verified.result, Outcome::PartiallyVerified);
    assert_eq!(verified.integrity.content_equal, None);
    assert!(
        verified
            .findings
            .iter()
            .any(|f| f.code == "pdf.javascript" && f.state == FindingState::RemovedVerified)
    );
    if pdf::capabilities()["independent_validation_available"] == true {
        assert_eq!(verified.details["independent_text_equal"], true);
        assert_eq!(verified.details["independent_render_equal"], true);
    }
    assert!(matches!(
        pdf::verify(&original, &output, &Limits::default()),
        Err(Error::Verification(_))
    ));
}

#[test]
fn explicit_annotation_removal_records_intentional_visible_change() {
    use fileveil_core::PdfOptions;
    require_backend();
    let original=fixture_page("Keep page content","","/Annots [8 0 R]",vec![b"<< /Type /Annot /Subtype /Square /Rect [20 20 100 100] /C [1 0 0] /BS << /W 3 >> /T (PRIVATE_ANNOTATION_AUTHOR) /Contents (PRIVATE_ANNOTATION_CONTENT) >>".to_vec()]);
    let options = PdfOptions {
        remove_annotations: true,
        ..Default::default()
    };
    let output = pdf::sanitize_with_options(&original, &Limits::default(), &options).unwrap();
    assert!(!has_bytes(&output, b"PRIVATE_ANNOTATION"));
    let verified = pdf::verify_scoped(&original, &output, &Limits::default(), &options).unwrap();
    assert_eq!(verified.details["annotation_structures"], 0);
    assert_eq!(verified.result, Outcome::PartiallyVerified);
    assert_eq!(verified.integrity.content_equal, None);
    if pdf::capabilities()["independent_validation_available"] == true {
        assert_eq!(verified.details["independent_page_count_equal"], true);
        assert_eq!(verified.details["independent_text_equal"], true);
        assert_eq!(verified.details["independent_render_equal"], false);
        assert_eq!(verified.integrity.decodeable, Some(true));
    }
}

#[test]
fn annotation_cleanup_protects_interactive_form_widgets() {
    use fileveil_core::PdfOptions;
    require_backend();
    let original = fixture_page(
        "Form page",
        "/AcroForm << /Fields [8 0 R] >>",
        "/Annots [8 0 R]",
        vec![
            b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (SyntheticField) /Rect [10 10 100 30] >>"
                .to_vec(),
        ],
    );
    assert!(matches!(
        pdf::sanitize_with_options(
            &original,
            &Limits::default(),
            &PdfOptions {
                remove_annotations: true,
                ..Default::default()
            }
        ),
        Err(Error::Blocked(_))
    ));
}

#[test]
fn mixed_javascript_action_chains_are_protected() {
    use fileveil_core::PdfOptions;
    require_backend();
    let options = PdfOptions {
        remove_javascript: true,
        ..Default::default()
    };
    for (extra, objects) in [
        (
            "/OpenAction 8 0 R",
            vec![
                b"<< /S /JavaScript /JS (synthetic) /Next << /S /GoTo /D [3 0 R /Fit] >> >>"
                    .to_vec(),
            ],
        ),
        (
            "/OpenAction << /S /JavaScript /JS (synthetic) /Next << /S /GoTo /D [3 0 R /Fit] >> >>",
            vec![],
        ),
    ] {
        let original = fixture("Action chain page", extra, objects);
        assert!(matches!(
            pdf::sanitize_with_options(&original, &Limits::default(), &options),
            Err(Error::Blocked(_))
        ));
    }
}

#[test]
fn deep_selection_does_not_allow_unrelated_page_content_changes() {
    use fileveil_core::PdfOptions;
    require_backend();
    let original = fixture("Original retained page", "", vec![]);
    let changed = fixture("Tampered retained page", "", vec![]);
    let options = PdfOptions {
        remove_javascript: true,
        ..Default::default()
    };
    let output = pdf::sanitize_with_options(&changed, &Limits::default(), &options).unwrap();
    assert!(matches!(
        pdf::verify_scoped(&original, &output, &Limits::default(), &options),
        Err(Error::Verification(_))
    ));
}

#[test]
fn structural_c2pa_summary_deduplicates_streams_and_preserves_default_protection() {
    require_backend();
    let source=fixture("Visible c2pa and jumb words are ordinary page content","/AF [8 0 R 8 0 R] /Names << /EmbeddedFiles << /Names [(credentials) 8 0 R] >> >>",vec![
        b"<< /Type /Filespec /Subtype /application#2Fc2pa /AFRelationship /C2PA_Manifest /EF << /F 9 0 R >> >>".to_vec(),
        stream("/Type /EmbeddedFile /Subtype /application#2Fc2pa",b"synthetic structured credential payload"),
    ]);
    let summary = pdf::credential_summary(&source, &Limits::default()).unwrap();
    assert_eq!(summary.store_count, 1);
    assert_eq!(summary.unresolved_credential_entries, 0);
    assert!(!summary.digital_signatures_present);
    assert!(matches!(
        pdf::sanitize(&source, &Limits::default()),
        Err(Error::Blocked(_))
    ));
    let selected = pdf::inspect_for_provenance_removal(&source, &Limits::default()).unwrap();
    assert!(selected.blockers.is_empty());
    let ordinary = fixture(
        "Visible c2pa and jumb words are ordinary page content",
        "",
        vec![],
    );
    assert_eq!(
        pdf::credential_summary(&ordinary, &Limits::default())
            .unwrap()
            .store_count,
        0
    );
    assert!(
        pdf::inspect(&ordinary, &Limits::default())
            .unwrap()
            .blockers
            .is_empty()
    );
}

#[test]
fn credential_cleanup_keeps_ordinary_attachment_finding_present() {
    require_backend();
    let source = fixture(
        "Visible retained content",
        "/AF [8 0 R 10 0 R] /Names << /EmbeddedFiles << /Names [(credentials) 8 0 R (ordinary) 10 0 R] >> >>",
        vec![
            b"<< /Type /Filespec /AFRelationship /C2PA_Manifest /EF << /F 9 0 R >> >>".to_vec(),
            stream(
                "/Type /EmbeddedFile /Subtype /application#2Fc2pa",
                b"credential payload",
            ),
            b"<< /Type /Filespec /F (ordinary.txt) /EF << /F 11 0 R >> >>".to_vec(),
            stream("/Type /EmbeddedFile", b"retained ordinary attachment"),
        ],
    );
    let limits = Limits::default();
    let options = Default::default();
    let clean = pdf::sanitize_with_provenance_removal(&source, &limits, &options).unwrap();
    let verified = pdf::verify_with_provenance_removal(&source, &clean, &limits, &options).unwrap();
    assert_eq!(verified.details["c2pa_store_count"], 0);
    assert!(verified.details["attachment_structures"].as_u64().unwrap() > 0);
    let attachments: Vec<_> = verified
        .findings
        .iter()
        .filter(|finding| finding.code == "pdf.attachments")
        .collect();
    assert_eq!(attachments.len(), 1);
    assert_eq!(attachments[0].state, FindingState::Present);
    assert_eq!(attachments[0].action, Action::AskUser);
    assert!(has_bytes(&clean, b"retained ordinary attachment"));
}

#[test]
fn malformed_c2pa_descriptors_are_protected_and_native_pdf_signatures_stay_blocked() {
    require_backend();
    let source = fixture(
        "Protected source",
        "/AF [8 0 R]",
        vec![b"<< /Type /Filespec /AFRelationship /C2PA_Manifest >>".to_vec()],
    );
    let summary = pdf::credential_summary(&source, &Limits::default()).unwrap();
    assert_eq!(summary.store_count, 0);
    assert_eq!(summary.unresolved_credential_entries, 1);
    assert!(matches!(
        pdf::sanitize(&source, &Limits::default()),
        Err(Error::Blocked(_))
    ));
    let signed = fixture(
        "Native signature source",
        "/AcroForm << /Fields [8 0 R] >>",
        vec![b"<< /Type /Sig /ByteRange [0 1 2 3] /Contents <00> >>".to_vec()],
    );
    assert!(
        pdf::credential_summary(&signed, &Limits::default())
            .unwrap()
            .digital_signatures_present
    );
    assert!(
        !pdf::inspect_for_provenance_removal(&signed, &Limits::default())
            .unwrap()
            .blockers
            .is_empty()
    );
    assert!(matches!(
        pdf::sanitize_with_provenance_removal(&signed, &Limits::default(), &Default::default()),
        Err(Error::Blocked(_))
    ));
}

#[test]
fn protected_pdf_scan_completes_with_a_separate_rewrite_restriction() {
    require_backend();
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("signed.pdf");
    let output = directory.path().join("copy.pdf");
    let bytes = fixture(
        "Native signature source",
        "/AcroForm << /Fields [8 0 R] >>",
        vec![b"<< /Type /Sig /ByteRange [0 1 2 3] /Contents <00> >>".to_vec()],
    );
    fs::write(&input, &bytes).unwrap();
    let report = fileveil_engine::scan(&input, &Limits::default()).unwrap();
    assert_eq!(report.result, Outcome::PartiallyVerified);
    assert!(report.integrity.parseable);
    let details = report.pdf.unwrap();
    assert_eq!(details["scan_status"], "complete");
    assert_eq!(details["safe_rewrite_allowed"], false);
    assert!(
        !details["rewrite_restrictions"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(fileveil_engine::sanitize(&input, Some(&output), &Limits::default()).is_err());
    assert!(!output.exists());
    assert_eq!(fs::read(&input).unwrap(), bytes);
}

#[test]
fn shared_metadata_and_page_content_stream_is_blocked_before_any_deletion() {
    require_backend();
    let source=assemble(&[
        b"<< /Type /Catalog /Pages 2 0 R /Metadata 4 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << >> /Contents 4 0 R >>".to_vec(),
        stream("/Type /Metadata /Subtype /XML",b"0 0 1 rg 20 20 100 100 re f"),
    ],"");
    let inspected = pdf::inspect(&source, &Limits::default()).unwrap();
    assert!(
        inspected
            .findings
            .iter()
            .any(|finding| finding.code == "pdf.shared_metadata")
    );
    assert!(
        inspected
            .blockers
            .iter()
            .any(|reason| reason.contains("Shared PDF metadata"))
    );
    for result in [
        pdf::sanitize(&source, &Limits::default()),
        pdf::sanitize_with_provenance_removal(&source, &Limits::default(), &Default::default()),
    ] {
        assert!(
            matches!(result,Err(Error::Blocked(ref message))if message.contains("Shared PDF metadata"))
        );
    }
}
