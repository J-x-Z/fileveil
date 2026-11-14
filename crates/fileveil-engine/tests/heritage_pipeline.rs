// SPDX-License-Identifier: MPL-2.0
//! Normal-entry integration checks for verified, non-overwriting Heritage copies.
use fileveil_core::{Format, Limits, Outcome, Report, digest};
use fileveil_engine::heritage::{
    self, HeritageAction, HeritageRequest, MarkSettings, container,
    signing::{self, PublicKey, RecordKind, SignMode, SigningKey, TrustStore},
};
use serde_json::Value;
use std::{
    fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
};
use zip::ZipArchive;

const WORK: &str = "integration-work-2026";
const AUTHOR: &str = "Synthetic Heritage Author";

fn fixture(name: &str) -> Vec<u8> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name),
    )
    .unwrap()
}

fn pixels(size: u32, changed: bool) -> Vec<u8> {
    let mut image = image::RgbImage::from_fn(size, size, |x, y| {
        image::Rgb([
            (x.wrapping_mul(13) % 256) as u8,
            (y.wrapping_mul(7) % 256) as u8,
            113,
        ])
    });
    if changed {
        image.put_pixel(0, 0, image::Rgb([255, 0, 0]));
    }
    let mut encoded = Cursor::new(Vec::new());
    image
        .write_to(&mut encoded, image::ImageFormat::Png)
        .unwrap();
    encoded.into_inner()
}

fn new_key(directory: &Path, name: &str) -> (PathBuf, PublicKey) {
    let path = directory.join(name);
    let report = heritage::keygen(&path).unwrap();
    assert_eq!(report.result, Outcome::VerifiedWithinScope);
    assert_eq!(
        report.advanced.as_ref().unwrap()["heritage"]["private_key_saved"],
        true
    );
    let key = SigningKey::load(&path).unwrap().public_key();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o077, 0);
    }
    (path, key)
}

fn mark_request(keys: Vec<PathBuf>) -> HeritageRequest {
    HeritageRequest {
        action: HeritageAction::Mark,
        key_paths: keys,
        mark: MarkSettings {
            work_id: WORK.into(),
            author: AUTHOR.into(),
            version: "1".into(),
            created_at: "2026-11-12T00:00:00Z".into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn details(report: &Report) -> &Value {
    &report.advanced.as_ref().unwrap()["heritage"]
}

fn run(input: &Path, output: Option<&Path>, request: &HeritageRequest) -> Report {
    heritage::run(input, output, request, &Limits::default()).unwrap()
}

fn assert_verified_chain(report: &Report, records: usize) {
    assert_ne!(report.result, Outcome::Failed, "{report:?}");
    let verified = &details(report)["verification"];
    assert_eq!(verified["signature"], "valid");
    assert_eq!(verified["chain"], "valid");
    assert_eq!(verified["content_binding"], "valid");
    assert_eq!(verified["record_count"], records);
    assert_eq!(report.integrity.original_unchanged, Some(true));
}

fn zip_members(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
    (0..archive.len())
        .map(|index| {
            let mut file = archive.by_index(index).unwrap();
            let name = file.name().unwrap().into_owned();
            let mut content = Vec::new();
            file.read_to_end(&mut content).unwrap();
            (name, content)
        })
        .collect()
}

fn roundtrip(name: &str, format: Format, source: &[u8]) {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join(name);
    let marked = directory.path().join(format!("marked-{name}"));
    let cleaned = directory.path().join(format!("cleaned-{name}"));
    fs::write(&input, source).unwrap();
    let input_sha = digest(source);
    let (key, _) = new_key(directory.path(), "owner.key");
    let mark = run(&input, Some(&marked), &mark_request(vec![key]));
    assert_verified_chain(&mark, 1);
    assert_eq!(mark.input_sha256.as_deref(), Some(input_sha.as_str()));
    assert_eq!(mark.integrity.security_markers_preserved, Some(true));
    let marked_bytes = fs::read(&marked).unwrap();
    assert_eq!(
        mark.output_sha256.as_deref(),
        Some(digest(&marked_bytes).as_str())
    );
    assert_eq!(
        container::extract(&marked_bytes, format).unwrap().base,
        source
    );
    if format.is_office() {
        assert_eq!(zip_members(source), zip_members(&marked_bytes));
    }
    if format == Format::Pdf {
        let before = fileveil_engine::pdf::inspect(source, &Limits::default()).unwrap();
        let after = fileveil_engine::pdf::inspect(&marked_bytes, &Limits::default()).unwrap();
        assert_eq!(before.details["pages"], after.details["pages"]);
        assert_pdf_display_scope(&mark);
    }
    for action in [
        HeritageAction::Detect,
        HeritageAction::Verify,
        HeritageAction::Trace,
    ] {
        let report = run(
            &marked,
            None,
            &HeritageRequest {
                action,
                ..Default::default()
            },
        );
        assert_verified_chain(&report, 1);
        assert_eq!(details(&report)["manifest_present"], true);
        let public_report = serde_json::to_string(&report).unwrap();
        assert!(!public_report.contains(AUTHOR));
        assert!(!public_report.contains(WORK));
        assert!(!public_report.contains(directory.path().to_str().unwrap()));
    }
    let clean = run(
        &marked,
        Some(&cleaned),
        &HeritageRequest {
            action: HeritageAction::Clean,
            ..Default::default()
        },
    );
    assert_ne!(clean.result, Outcome::Failed);
    assert_eq!(details(&clean)["modern_manifest_removed"], true);
    if format == Format::Pdf {
        assert_pdf_display_scope(&clean);
    }
    assert_eq!(fs::read(&cleaned).unwrap(), source);
    assert_eq!(digest(&fs::read(&input).unwrap()), input_sha);
    assert_eq!(fs::read(&marked).unwrap(), marked_bytes);
}

fn assert_pdf_display_scope(report: &Report) {
    let display = &details(report)["pdf_display"];
    if fileveil_engine::pdf::capabilities()["independent_validation_available"] == true {
        assert_eq!(display["independent_page_count_equal"], true);
        assert_eq!(display["independent_text_equal"], true);
        assert_eq!(display["independent_render_equal"], true);
        assert_eq!(display["result"], "verified_within_scope");
    } else {
        assert_eq!(display["result"], "partially_verified");
    }
}

#[test]
fn jpeg_normal_entry_mark_detect_verify_clean_restores_original_bytes() {
    roundtrip(
        "source.jpg",
        Format::Jpeg,
        &fixture("jpeg_exif_gps_author.jpg"),
    );
}

#[test]
fn png_normal_entry_mark_detect_verify_clean_restores_original_bytes() {
    roundtrip("source.png", Format::Png, &fixture("png_itxt_exif_icc.png"));
}

#[test]
fn docx_normal_entry_preserves_every_package_member_and_original_bytes() {
    roundtrip(
        "source.docx",
        Format::Docx,
        &fixture("docx_author_comments_rels.docx"),
    );
}

#[test]
fn xlsx_normal_entry_preserves_formulas_and_original_package_bytes() {
    roundtrip(
        "source.xlsx",
        Format::Xlsx,
        &fixture("xlsx_author_custom_formula.xlsx"),
    );
}

#[test]
fn pptx_normal_entry_preserves_media_and_original_package_bytes() {
    roundtrip(
        "source.pptx",
        Format::Pptx,
        &fixture("pptx_author_media.pptx"),
    );
}

fn pdf() -> Vec<u8> {
    let content = b"BT /F1 12 Tf 20 200 Td (Heritage visible text) Tj ET";
    let mut stream = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
    stream.extend_from_slice(content);
    stream.extend_from_slice(b"\nendstream");
    let objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>".to_vec(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(), stream,
    ];
    let mut bytes = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
    let mut offsets = Vec::new();
    for (index, object) in objects.iter().enumerate() {
        offsets.push(bytes.len());
        bytes.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
        bytes.extend_from_slice(object);
        bytes.extend_from_slice(b"\nendobj\n");
    }
    let xref = bytes.len();
    bytes.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for offset in offsets {
        bytes.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    bytes.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    bytes
}

#[test]
fn pdf_normal_entry_preserves_parseable_pages_and_exact_original_bytes() {
    assert_eq!(fileveil_engine::pdf::capabilities()["available"], true);
    roundtrip("source.pdf", Format::Pdf, &pdf());
}

#[test]
fn nati_two_distinct_keys_and_local_threshold_trust_remain_separate() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("source.png");
    let marked = directory.path().join("marked.png");
    fs::write(&input, pixels(32, false)).unwrap();
    let (a, public_a) = new_key(directory.path(), "issuer-a.key");
    let (b, public_b) = new_key(directory.path(), "issuer-b.key");
    let mut request = mark_request(vec![a, b]);
    request.mark.mode = SignMode::NatiSign;
    request.mark.issuer_threshold = 2;
    let trust = directory.path().join("trust.json");
    fs::write(
        &trust,
        serde_json::to_vec(&TrustStore {
            trusted_issuers: vec![public_a.clone(), public_b],
            minimum_issuer_signatures: 2,
        })
        .unwrap(),
    )
    .unwrap();
    request.trust_store = Some(trust.clone());
    let marked_report = run(&input, Some(&marked), &request);
    assert_verified_chain(&marked_report, 1);
    assert_eq!(details(&marked_report)["verification"]["trust"], "valid");
    let verify = HeritageRequest {
        action: HeritageAction::Verify,
        trust_store: Some(trust.clone()),
        ..Default::default()
    };
    assert_eq!(
        details(&run(&marked, None, &verify))["verification"]["trust"],
        "valid"
    );
    fs::write(
        &trust,
        serde_json::to_vec(&TrustStore {
            trusted_issuers: vec![public_a],
            minimum_issuer_signatures: 2,
        })
        .unwrap(),
    )
    .unwrap();
    let untrusted = run(&marked, None, &verify);
    assert_verified_chain(&untrusted, 1);
    assert_eq!(details(&untrusted)["verification"]["trust"], "untrusted");
}

#[test]
fn previous_asset_can_extend_a_modified_version_and_transfer_custody() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original.png");
    let first = directory.path().join("first.png");
    let transferred = directory.path().join("transferred.png");
    let modified_source = directory.path().join("modified-source.png");
    let modified = directory.path().join("modified.png");
    fs::write(&original, pixels(32, false)).unwrap();
    fs::write(&modified_source, pixels(32, true)).unwrap();
    let before_original = digest(&fs::read(&original).unwrap());
    let before_modified = digest(&fs::read(&modified_source).unwrap());
    let (owner, _) = new_key(directory.path(), "owner.key");
    let (recipient, public_recipient) = new_key(directory.path(), "recipient.key");
    run(&original, Some(&first), &mark_request(vec![owner.clone()]));
    let mut transfer = mark_request(vec![owner.clone()]);
    transfer.mark.kind = RecordKind::Transfer;
    transfer.mark.transfer_to_key_id = Some(public_recipient.key_id);
    assert_verified_chain(&run(&first, Some(&transferred), &transfer), 2);
    let mut modify = mark_request(vec![recipient]);
    modify.mark.kind = RecordKind::Modify;
    modify.mark.version = "2".into();
    modify.previous = Some(transferred.clone());
    let result = run(&modified_source, Some(&modified), &modify);
    assert_verified_chain(&result, 3);
    assert_eq!(details(&result)["records"][2]["parent_version"], "1");
    let verify = run(
        &modified,
        None,
        &HeritageRequest {
            action: HeritageAction::Verify,
            ..Default::default()
        },
    );
    assert_verified_chain(&verify, 3);
    modify.key_paths = vec![owner];
    let rejected = directory.path().join("old-owner-must-fail.png");
    assert!(
        heritage::run(
            &modified_source,
            Some(&rejected),
            &modify,
            &Limits::default()
        )
        .is_err()
    );
    assert!(!rejected.exists());
    assert_eq!(digest(&fs::read(&original).unwrap()), before_original);
    assert_eq!(
        digest(&fs::read(&modified_source).unwrap()),
        before_modified
    );
}

#[test]
fn tampered_claim_and_signature_bytes_fail_normal_entry_signature_verification() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.png");
    let marked = directory.path().join("marked.png");
    fs::write(&input, pixels(32, false)).unwrap();
    let (key, _) = new_key(directory.path(), "owner.key");
    run(&input, Some(&marked), &mark_request(vec![key]));
    let extracted = container::extract(&fs::read(&marked).unwrap(), Format::Png).unwrap();
    let original_records = signing::parse_records(extracted.manifest.as_deref().unwrap()).unwrap();
    for change_claim in [true, false] {
        let mut records = original_records.clone();
        if change_claim {
            records[0].body.author = "Tampered unsigned author".into();
        } else {
            let signature = &mut records[0].signatures[0].signature_hex;
            let replacement = if signature.starts_with('0') { "1" } else { "0" };
            signature.replace_range(..1, replacement);
        }
        let tampered = directory.path().join(if change_claim {
            "tampered-claim.png"
        } else {
            "tampered-signature.png"
        });
        fs::write(
            &tampered,
            container::embed(
                &extracted.base,
                Format::Png,
                &signing::canonical_records(&records).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let report = run(
            &tampered,
            None,
            &HeritageRequest {
                action: HeritageAction::Verify,
                ..Default::default()
            },
        );
        assert_eq!(report.result, Outcome::Failed);
        assert_eq!(details(&report)["verification"]["signature"], "invalid");
    }
}

#[test]
fn changed_pixels_keep_signature_math_but_fail_content_binding() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.png");
    let marked = directory.path().join("marked.png");
    fs::write(&input, pixels(32, false)).unwrap();
    let (key, _) = new_key(directory.path(), "owner.key");
    run(&input, Some(&marked), &mark_request(vec![key]));
    let extracted = container::extract(&fs::read(&marked).unwrap(), Format::Png).unwrap();
    let tampered = directory.path().join("changed-pixels.png");
    fs::write(
        &tampered,
        container::embed(
            &pixels(32, true),
            Format::Png,
            extracted.manifest.as_deref().unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let report = run(
        &tampered,
        None,
        &HeritageRequest {
            action: HeritageAction::Verify,
            ..Default::default()
        },
    );
    assert_eq!(report.result, Outcome::Failed);
    assert_eq!(details(&report)["verification"]["signature"], "valid");
    assert_eq!(
        details(&report)["verification"]["content_binding"],
        "invalid"
    );
}

#[test]
fn existing_outputs_and_original_path_are_never_replaced() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.png");
    let output = directory.path().join("existing.png");
    let source = pixels(32, false);
    fs::write(&input, &source).unwrap();
    fs::write(&output, b"EXISTING-USER-DATA").unwrap();
    let (key, _) = new_key(directory.path(), "owner.key");
    let request = mark_request(vec![key]);
    assert!(heritage::run(&input, Some(&output), &request, &Limits::default()).is_err());
    assert_eq!(fs::read(&output).unwrap(), b"EXISTING-USER-DATA");
    assert!(heritage::run(&input, Some(&input), &request, &Limits::default()).is_err());
    assert_eq!(fs::read(&input).unwrap(), source);
}

#[test]
fn fake_pdf_fails_before_publishing_any_copy() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("fake.pdf");
    let output = directory.path().join("output.pdf");
    let malformed = b"%PDF-1.7\nstartxref\n0\n%%EOF\n";
    fs::write(&input, malformed).unwrap();
    let (key, _) = new_key(directory.path(), "owner.key");
    assert!(
        heritage::run(
            &input,
            Some(&output),
            &mark_request(vec![key]),
            &Limits::default()
        )
        .is_err()
    );
    assert!(!output.exists());
    assert_eq!(fs::read(&input).unwrap(), malformed);
}

#[test]
fn small_images_support_signature_verification_with_explicit_signal_not_assessed() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("small.png");
    let marked = directory.path().join("marked.png");
    fs::write(&input, pixels(32, false)).unwrap();
    let (key, _) = new_key(directory.path(), "owner.key");
    run(&input, Some(&marked), &mark_request(vec![key]));
    let report = run(
        &marked,
        None,
        &HeritageRequest {
            action: HeritageAction::Verify,
            ..Default::default()
        },
    );
    assert_verified_chain(&report, 1);
    assert_eq!(details(&report)["robust"]["status"], "not_assessed");
}

#[test]
fn pixel_marking_and_protocol_cleaning_complete_through_the_normal_entry() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("photo.png");
    let marked = directory.path().join("marked.png");
    let cleaned = directory.path().join("cleaned.png");
    let source = include_bytes!("fixtures/watermark/astronaut.png");
    fs::write(&input, source).unwrap();
    let (key, _) = new_key(directory.path(), "owner.key");
    let mut mark = mark_request(vec![key]);
    mark.mark.robust = true;
    let marked_report = run(&input, Some(&marked), &mark);
    assert_verified_chain(&marked_report, 1);
    assert_eq!(details(&marked_report)["robust"]["frame_valid"], true);
    assert_eq!(marked_report.integrity.pixel_equal, Some(false));
    assert_eq!(marked_report.policy, fileveil_core::Policy::Research);
    let verify = run(
        &marked,
        None,
        &HeritageRequest {
            action: HeritageAction::Verify,
            ..Default::default()
        },
    );
    assert_verified_chain(&verify, 1);
    assert_eq!(details(&verify)["robust"]["frame_valid"], true);
    let clean = run(
        &marked,
        Some(&cleaned),
        &HeritageRequest {
            action: HeritageAction::Clean,
            clean_signal: true,
            ..Default::default()
        },
    );
    assert_eq!(details(&clean)["robust_recheck"]["frame_valid"], false);
    assert_eq!(details(&clean)["modern_manifest_removed"], true);
    let after = run(&cleaned, None, &HeritageRequest::default());
    assert_eq!(details(&after)["manifest_present"], false);
    assert_eq!(details(&after)["robust"]["frame_valid"], false);
    assert_eq!(fs::read(&input).unwrap().as_slice(), source);
}

#[test]
fn repeated_keygen_never_overwrites_an_existing_private_key() {
    let directory = tempfile::tempdir().unwrap();
    let (key, _) = new_key(directory.path(), "owner.key");
    let before = fs::read(&key).unwrap();
    assert!(heritage::keygen(&key).is_err());
    assert_eq!(fs::read(&key).unwrap(), before);
}

#[cfg(unix)]
#[test]
fn normal_entry_preserves_source_attributes_on_both_new_copies() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.png");
    let marked = directory.path().join("marked.png");
    let cleaned = directory.path().join("cleaned.png");
    fs::write(&input, pixels(32, false)).unwrap();
    xattr::set(
        &input,
        "user.fileveil.heritage-test",
        b"SYNTHETIC-ATTRIBUTE",
    )
    .unwrap();
    let (key, _) = new_key(directory.path(), "owner.key");
    run(&input, Some(&marked), &mark_request(vec![key]));
    run(
        &marked,
        Some(&cleaned),
        &HeritageRequest {
            action: HeritageAction::Clean,
            ..Default::default()
        },
    );
    for path in [&input, &marked, &cleaned] {
        assert_eq!(
            xattr::get(path, "user.fileveil.heritage-test")
                .unwrap()
                .as_deref(),
            Some(b"SYNTHETIC-ATTRIBUTE".as_slice())
        );
    }
}

// FVPROV1 21207 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI1NjkwYzRhMTdiYTBjODg5NDMyMThjMDgxZTJjNTc3YjBhNmU1Yjg1ZjNjMDk4NDU2ZDc5ZWZmMDRmYjc2NjZiIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvdGVzdHMvaGVyaXRhZ2VfcGlwZWxpbmUucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiIxNGRkNmRjOTg3NzgxNjY1NzYzMjg4ZjM4ZDFkZDQwNjMyMjFmYWFiOWQ4NWJkYWE4YzU5ZTc1ZGE1YmNiOGIyNDc3ZDk5NGMwNTY2YThkZDlmMDM4ZTNhYTZiOTAwNjMwM2NhN2Y1ODIyYzI3YzNhOTQ0NDBjMTYyOTU1NTMwYyJ9XX1d FVPROV1-END
