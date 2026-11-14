// SPDX-License-Identifier: MPL-2.0
use fileveil_core::{Format, Limits};
use fileveil_engine::heritage::{
    self, HeritageAction, HeritageRequest, MarkSettings, container, signing,
};
use image::{ImageDecoder, ImageEncoder, ImageReader, codecs::jpeg::JpegEncoder};
use serde_json::Value;
use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
};

const PHOTO: &[u8] = include_bytes!("fixtures/watermark/astronaut.png");

fn key(directory: &Path) -> PathBuf {
    let path = directory.join("local.key");
    heritage::keygen(&path).unwrap();
    path
}

fn request(key: PathBuf) -> HeritageRequest {
    HeritageRequest {
        action: HeritageAction::Mark,
        key_paths: vec![key],
        mark: MarkSettings {
            work_id: "audit-public-work".into(),
            robust: true,
            created_at: "2026-11-12".into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn chunks(data: &[u8]) -> Vec<([u8; 4], Vec<u8>)> {
    let mut position = 8;
    let mut chunks = Vec::new();
    while position < data.len() {
        let length = u32::from_be_bytes(data[position..position + 4].try_into().unwrap()) as usize;
        let end = position + length + 12;
        chunks.push((
            data[position + 4..position + 8].try_into().unwrap(),
            data[position..end].to_vec(),
        ));
        position = end;
    }
    chunks
}

fn chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut data = (payload.len() as u32).to_be_bytes().to_vec();
    data.extend_from_slice(kind);
    data.extend_from_slice(payload);
    data.extend_from_slice(&crc32fast::hash(&data[4..]).to_be_bytes());
    data
}

fn profile(data: &[u8]) -> Option<Vec<u8>> {
    ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .unwrap()
        .into_decoder()
        .unwrap()
        .icc_profile()
        .unwrap()
}

#[test]
fn robust_png_and_jpeg_preserve_icc_and_png_display_records_through_mark_and_clean() {
    let limits = Limits::default();
    let directory = tempfile::tempdir().unwrap();
    let keys = key(directory.path());
    let mut source = PHOTO.to_vec();
    source.splice(33..33, chunk(b"gAMA", &45455_u32.to_be_bytes()));
    let expected_profile = profile(&source).unwrap();
    let display = |bytes: &[u8]| {
        chunks(bytes)
            .into_iter()
            .filter(|(kind, _)| matches!(kind, b"iCCP" | b"gAMA" | b"pHYs"))
            .collect::<Vec<_>>()
    };
    let expected_display = display(&source);
    for (name, source) in [
        ("png", source),
        ("jpg", {
            let mut bytes = Vec::new();
            let mut encoder = JpegEncoder::new_with_quality(&mut bytes, 95);
            encoder.set_icc_profile(expected_profile.clone()).unwrap();
            encoder
                .encode_image(&image::load_from_memory(PHOTO).unwrap().to_rgb8())
                .unwrap();
            bytes
        }),
    ] {
        let input = directory.path().join(format!("source.{name}"));
        let marked = directory.path().join(format!("marked.{name}"));
        let cleaned = directory.path().join(format!("cleaned.{name}"));
        fs::write(&input, &source).unwrap();
        heritage::run(&input, Some(&marked), &request(keys.clone()), &limits).unwrap();
        let marked_bytes = fs::read(&marked).unwrap();
        assert_eq!(profile(&marked_bytes), Some(expected_profile.clone()));
        let clean_request = HeritageRequest {
            action: HeritageAction::Clean,
            clean_signal: true,
            ..Default::default()
        };
        heritage::run(&marked, Some(&cleaned), &clean_request, &limits).unwrap();
        let cleaned_bytes = fs::read(cleaned).unwrap();
        assert_eq!(profile(&cleaned_bytes), Some(expected_profile.clone()));
        if name == "png" {
            assert_eq!(display(&marked_bytes), expected_display);
            assert_eq!(display(&cleaned_bytes), expected_display);
        }
        assert_eq!(fs::read(input).unwrap(), source);
    }
}

#[test]
fn trace_separates_public_digest_match_from_invalid_reference_signature() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("source.png");
    let marked = directory.path().join("marked.png");
    let signal_only = directory.path().join("signal.png");
    let invalid_reference = directory.path().join("invalid-reference.png");
    fs::write(&input, PHOTO).unwrap();
    heritage::run(
        &input,
        Some(&marked),
        &request(key(directory.path())),
        &Limits::default(),
    )
    .unwrap();
    let extracted = container::extract(&fs::read(&marked).unwrap(), Format::Png).unwrap();
    fs::write(&signal_only, &extracted.base).unwrap();
    let mut history = signing::parse_records(extracted.manifest.as_deref().unwrap()).unwrap();
    let first = history[0].signatures[0].signature_hex.remove(0);
    history[0].signatures[0]
        .signature_hex
        .insert(0, if first == '0' { '1' } else { '0' });
    let invalid = container::embed(
        &extracted.base,
        Format::Png,
        &signing::canonical_records(&history).unwrap(),
    )
    .unwrap();
    fs::write(&invalid_reference, invalid).unwrap();
    let mut trace = HeritageRequest {
        action: HeritageAction::Trace,
        reference: Some(marked),
        ..Default::default()
    };
    let valid = heritage::run(&signal_only, None, &trace, &Limits::default()).unwrap();
    assert_eq!(
        valid.advanced.as_ref().unwrap()["heritage"]["trace_reference_match"],
        true
    );
    trace.reference = Some(invalid_reference);
    let report = heritage::run(&signal_only, None, &trace, &Limits::default()).unwrap();
    let detail = &report.advanced.as_ref().unwrap()["heritage"];
    assert_eq!(detail["work_digest_match"], true);
    assert_eq!(detail["trace_reference_match"], false);
    assert_eq!(detail["reference_verification"]["signature"], "invalid");
}

#[test]
fn lab_keeps_unsupported_controls_out_of_assessed_denominators() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.png");
    let small = directory.path().join("small.png");
    fs::write(&source, PHOTO).unwrap();
    image::RgbImage::from_pixel(32, 32, image::Rgb([127; 3]))
        .save(&small)
        .unwrap();
    let request = HeritageRequest {
        action: HeritageAction::Lab,
        controls: vec![small, source.clone()],
        ..Default::default()
    };
    let report = heritage::run(&source, None, &request, &Limits::default()).unwrap();
    let lab = &report.advanced.as_ref().unwrap()["heritage"]["lab"];
    assert_eq!(lab["control_count"], 2);
    assert_eq!(lab["assessed_controls"], 1);
    assert_eq!(lab["controls"][0]["status"], "not_assessed");
    assert_eq!(lab["control_positive_count"], 0);
    assert_eq!(lab["tested_variants"], 7);
    assert!(
        lab["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["robust"]["status"] != Value::Null)
    );
}

#[test]
fn common_safe_cleaning_preserves_marker_but_reports_changed_binding_and_protected_rows() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("source.png");
    let marked = directory.path().join("marked.png");
    let image = image::load_from_memory(PHOTO).unwrap();
    let (pixels, _) =
        heritage::robust::embed(&image, "audit-public-work", 32, &Limits::default()).unwrap();
    let mut encoded = Cursor::new(Vec::new());
    pixels
        .write_to(&mut encoded, image::ImageFormat::Png)
        .unwrap();
    let mut source = encoded.into_inner();
    source.splice(
        33..33,
        chunk(b"tEXt", b"Author\0Synthetic metadata privacy control"),
    );
    fs::write(&input, source).unwrap();
    let mut mark_request = request(key(directory.path()));
    mark_request.mark.robust = false;
    heritage::run(&input, Some(&marked), &mark_request, &Limits::default()).unwrap();
    let lab_request = HeritageRequest {
        action: HeritageAction::Lab,
        ..Default::default()
    };
    let report = heritage::run(&marked, None, &lab_request, &Limits::default()).unwrap();
    let lab = &report.advanced.as_ref().unwrap()["heritage"]["lab"];
    let rows = lab["rows"].as_array().unwrap();
    let cleaned = rows
        .iter()
        .find(|row| row["operation"] == "safe_metadata_clean")
        .unwrap();
    assert_eq!(cleaned["structural_manifest_present"], true);
    assert_eq!(cleaned["signature"], "valid");
    assert_eq!(cleaned["content_binding"], "invalid");
    assert_ne!(cleaned["trust"], "valid");
    assert_eq!(cleaned["robust"]["frame_valid"], true);
    assert!(
        rows.iter()
            .all(|row| row.get("structural_manifest_present").is_some())
    );
    assert_eq!(lab["tested_variants"], 8);
    let protected = directory.path().join("c2pa.png");
    fs::write(&protected, include_bytes!("fixtures/provenance/signed.png")).unwrap();
    let report = heritage::run(&protected, None, &lab_request, &Limits::default()).unwrap();
    let rows = report.advanced.as_ref().unwrap()["heritage"]["lab"]["rows"]
        .as_array()
        .unwrap();
    let blocked = rows
        .iter()
        .find(|row| row["operation"] == "safe_metadata_clean")
        .unwrap();
    assert_eq!(blocked["result"], "blocked");
    assert_eq!(blocked["robust"]["status"], "not_assessed");
    assert_eq!(blocked["variant_generated"], false);
    assert_eq!(rows.len(), 7);
    assert!(rows.iter().any(|row| row["operation"] == "jpeg_70"));
}

#[test]
fn c2pa_pdf_clean_reuses_the_verified_full_rewrite_and_keeps_original() {
    let directory = tempfile::tempdir().unwrap();
    let source = include_bytes!("fixtures/provenance/signed.pdf");
    let input = directory.path().join("signed.pdf");
    let output = directory.path().join("cleaned.pdf");
    fs::write(&input, source).unwrap();
    let limits = Limits::default();
    let report = heritage::run(
        &input,
        Some(&output),
        &HeritageRequest {
            action: HeritageAction::Clean,
            remove_c2pa: true,
            ..Default::default()
        },
        &limits,
    )
    .unwrap();
    assert_eq!(fs::read(&input).unwrap(), source);
    let clean = fs::read(&output).unwrap();
    assert!(
        fileveil_engine::provenance::inspect(&clean, Format::Pdf, &limits)
            .unwrap()
            .is_none()
    );
    let details = &report.advanced.as_ref().unwrap()["heritage"];
    assert_eq!(details["c2pa_removed"], true);
    assert_eq!(
        fileveil_engine::pdf::inspect(&clean, &limits)
            .unwrap()
            .details["has_previous_xref"],
        false
    );
    assert_eq!(report.integrity.original_unchanged, Some(true));
}

#[test]
fn heritage_verify_rechecks_c2pa_png_and_pdf_with_explicit_pem_trust() {
    let directory = tempfile::tempdir().unwrap();
    for (name, bytes, root) in [
        (
            "signed.png",
            include_bytes!("fixtures/provenance/signed.png").as_slice(),
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/provenance/root.pem"),
        ),
        (
            "signed.pdf",
            include_bytes!("fixtures/provenance/signed.pdf").as_slice(),
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/provenance/document-root.pem"),
        ),
    ] {
        let input = directory.path().join(name);
        fs::write(&input, bytes).unwrap();
        let mut request = HeritageRequest {
            action: HeritageAction::Verify,
            ..Default::default()
        };
        let report = heritage::run(&input, None, &request, &Limits::default()).unwrap();
        let credentials = report.provenance.unwrap();
        assert_eq!(credentials["signature"], "valid");
        assert_eq!(credentials["asset_binding"], "valid");
        assert_eq!(credentials["trust"], "not_assessed");
        request.c2pa_trust_roots = Some(root);
        let report = heritage::run(&input, None, &request, &Limits::default()).unwrap();
        assert_eq!(report.provenance.unwrap()["trust"], "trusted");
        assert_eq!(fs::read(&input).unwrap(), bytes);
    }
}

// FVPROV1 12235 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI4NjYzZWEyZGJlMThlNzRhYmM2YWJjNzA5ZTQ5OTVkNzNiZjllY2FhNmVmNGE1NzY5NjA3OTdkMjhmYmQ3MWNjIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4zIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMyIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvdGVzdHMvaGVyaXRhZ2VfcGlwZWxpbmVfYXVkaXQucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiIzM2UyYjYxNzVkZTgxMjJkMjhlNWNhYzM1ZmNiM2Q5MjYxNDBmMGVhZTI3OGNiODVkYTIzYThmMmE3ZjQ1MWU4OTViNzhlZDBiZTEyNTBkMTFjMmM0Y2Y4NmE3OGFkZGRlZjFmZGY4MGM0MTk5OTkwMWUzNWFmYTkzZWQwNTIwYyJ9XX1d FVPROV1-END
