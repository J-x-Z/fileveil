// SPDX-License-Identifier: MPL-2.0
use std::{fs, io::Cursor, path::PathBuf};

use fileveil_core::{Format, Limits, digest};
use fileveil_engine::provenance::{self, CheckStatus, ManifestPresence, TrustStatus};
use image::{DynamicImage, ImageFormat};

fn fixture(name: &str) -> Vec<u8> {
    fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/provenance")
            .join(name),
    )
    .expect("committed public synthetic C2PA fixture")
}

#[test]
fn provider_availability_matches_configured_backends() {
    let capabilities = provenance::capabilities();
    assert_eq!(
        capabilities
            .iter()
            .filter(|item| item.status == "available")
            .count(),
        3
    );
    assert!(capabilities.iter().all(|item| !item.network_enabled));
    assert!(
        capabilities
            .iter()
            .filter(
                |item| !["c2pa", "stable_diffusion_v1", "stable_diffusion_xl"]
                    .contains(&item.provider_id.as_str())
            )
            .all(|item| item.verified_formats.is_empty() && item.status == "unavailable")
    );
}

#[test]
fn signed_documents_validate_crypto_binding_and_explicit_trust_offline() {
    let limits = Limits::default();
    let root = String::from_utf8(fixture("document-root.pem")).unwrap();
    for (name, mime) in [
        ("signed.pdf", "application/pdf"),
        ("signed.txt", "text/plain"),
        ("signed.md", "text/markdown"),
    ] {
        let source = fixture(name);
        let original_hash = digest(&source);
        let report = provenance::inspect_mime(&source, mime, &limits, Some(&root))
            .unwrap()
            .unwrap();
        assert_eq!(report.presence, ManifestPresence::Embedded, "{name}");
        assert_eq!(report.signature, CheckStatus::Valid, "{name}");
        assert_eq!(report.asset_binding, CheckStatus::Valid, "{name}");
        assert_eq!(report.manifest_validation, CheckStatus::Valid, "{name}");
        assert_eq!(report.trust, TrustStatus::Trusted, "{name}");
        assert!(report.offline);
        assert_eq!(digest(&source), original_hash);
        let serialized = serde_json::to_string(&report).unwrap();
        for value in ["PRIVATE_SYNTHETIC", "PRIVATE_GENERATOR", "Synthetic Signer"] {
            assert!(!serialized.contains(value));
        }
    }
}

#[test]
fn document_store_removal_preserves_raw_text_and_leaves_pdf_content_verifiable() {
    let limits = Limits::default();
    for (name, mime) in [("signed.txt", "text/plain"), ("signed.md", "text/markdown")] {
        let source = fixture(name);
        let scope = provenance::text_scope(&source, mime, &limits).unwrap();
        assert_eq!(scope.wrapper_count, 1);
        assert!(scope.removal_supported);
        let clean = provenance::remove_store(&source, mime, &limits).unwrap();
        assert_eq!(digest(&clean), scope.visible_sha256);
        assert!(
            provenance::inspect_mime(&clean, mime, &limits, None)
                .unwrap()
                .is_none()
        );
        assert!(
            clean
                .windows("❤️".len())
                .any(|part| part == "❤️".as_bytes())
        );
        assert!(clean.windows(2).any(|part| part == b"\r\n"));
    }
    let source = fixture("signed.pdf");
    let clean = provenance::remove_store(&source, "application/pdf", &limits).unwrap();
    assert!(
        provenance::inspect_mime(&clean, "application/pdf", &limits, None)
            .unwrap()
            .is_none()
    );
    let inspection = fileveil_engine::pdf::inspect(&clean, &limits).unwrap();
    assert_eq!(inspection.details["pages"], 1);
    assert!(inspection.blockers.is_empty());
}

#[test]
fn non_nfc_plaintext_binding_is_unverifiable_and_removal_keeps_source_bytes() {
    let source = String::from_utf8(fixture("signed.txt"))
        .unwrap()
        .replace("café", "cafe\u{301}");
    let limits = Limits::default();
    let scope = provenance::text_scope(source.as_bytes(), "text/plain", &limits).unwrap();
    assert!(!scope.is_nfc);
    let report = provenance::inspect_mime(source.as_bytes(), "text/plain", &limits, None)
        .unwrap()
        .unwrap();
    assert_eq!(report.signature, CheckStatus::Valid);
    assert_eq!(report.asset_binding, CheckStatus::Unverifiable);
    assert_eq!(
        report.manifest_validation,
        CheckStatus::Unverifiable,
        "{:?}",
        report.validation_codes
    );
    assert_eq!(
        report.asset_binding_scope,
        "nfc_normalization_required_not_performed"
    );
    let clean = provenance::remove_store(source.as_bytes(), "text/plain", &limits).unwrap();
    assert_eq!(digest(&clean), scope.visible_sha256);
    assert!(String::from_utf8(clean).unwrap().contains("cafe\u{301}"));
    let original = fixture("signed.txt");
    let mut manifest = c2pa::jumbf_io::load_jumbf_from_memory("text/plain", &original).unwrap();
    let marker = b"PRIVATE_GENERATOR";
    let offset = manifest
        .windows(marker.len())
        .position(|part| part == marker)
        .unwrap();
    manifest[offset] ^= 1;
    let tampered =
        c2pa::jumbf_io::save_jumbf_to_memory("text/plain", &original, &manifest).unwrap();
    let tampered = String::from_utf8(tampered)
        .unwrap()
        .replace("café", "cafe\u{301}");
    let report = provenance::inspect_mime(tampered.as_bytes(), "text/plain", &limits, None)
        .unwrap()
        .unwrap();
    assert_eq!(report.signature, CheckStatus::Invalid);
    assert_eq!(report.manifest_validation, CheckStatus::Invalid);
    let markdown = String::from_utf8(fixture("signed.md"))
        .unwrap()
        .replace("Café", "Cafe\u{301}");
    let report = provenance::inspect_mime(markdown.as_bytes(), "text/markdown", &limits, None)
        .unwrap()
        .unwrap();
    assert!(!report.text_scope.as_ref().unwrap().is_nfc);
    assert_eq!(report.signature, CheckStatus::Valid);
    assert_eq!(report.asset_binding, CheckStatus::Invalid);
    assert_eq!(report.manifest_validation, CheckStatus::Invalid);
    assert_eq!(report.asset_binding_scope, "declared_hash_ranges");
}

#[test]
fn multiple_and_malformed_plaintext_frames_are_present_without_false_validation() {
    let limits = Limits::default();
    let signed = fixture("signed.txt");
    let scope = provenance::text_scope(&signed, "text/plain", &limits).unwrap();
    let [start, end] = scope.ranges[0];
    let mut duplicate = signed.clone();
    duplicate.extend_from_slice(&signed[start..end]);
    let report = provenance::inspect_mime(&duplicate, "text/plain", &limits, None)
        .unwrap()
        .unwrap();
    assert_eq!(report.signature, CheckStatus::Unverifiable);
    assert_eq!(report.text_scope.unwrap().wrapper_count, 2);
    let mut malformed = b"C2PATXT\0".to_vec();
    malformed.extend_from_slice(&[1, 0, 0, 0, 99, 65]);
    let encoded = plain_frame(&malformed);
    let scope = provenance::text_scope(encoded.as_bytes(), "text/plain", &limits).unwrap();
    assert!(!scope.removal_supported);
    assert!(provenance::remove_store(encoded.as_bytes(), "text/plain", &limits).is_err());
    assert!(
        provenance::inspect_mime(encoded.as_bytes(), "text/plain", &limits, None)
            .unwrap()
            .is_some()
    );
    let small = Limits {
        max_metadata_bytes: 8,
        ..limits
    };
    assert!(provenance::text_scope(&signed, "text/plain", &small).is_err());
}

fn plain_frame(frame: &[u8]) -> String {
    let mut encoded = "\u{feff}".to_string();
    encoded.extend(frame.iter().map(|&byte| {
        char::from_u32(if byte < 16 {
            0xfe00 + u32::from(byte)
        } else {
            0xe0100 + u32::from(byte) - 16
        })
        .unwrap()
    }));
    encoded
}

#[test]
fn markdown_ambiguous_contexts_are_preserved_and_remote_references_stay_offline() {
    let limits = Limits::default();
    let signed = String::from_utf8(fixture("signed.md")).unwrap();
    for source in [
        format!("Prose {signed}"),
        format!("```markdown\n{signed}\n```\n"),
        format!("    {signed}"),
        format!("<script>const value = `{signed}`;</script>"),
        format!("---\n{signed}---\nBody\n"),
    ] {
        let scope = provenance::text_scope(source.as_bytes(), "text/markdown", &limits).unwrap();
        assert!(!scope.removal_supported);
        assert!(
            provenance::strip_text_wrappers(source.as_bytes(), "text/markdown", &limits).is_err()
        );
        let report = provenance::inspect_mime(source.as_bytes(), "text/markdown", &limits, None)
            .unwrap()
            .unwrap();
        assert_eq!(report.signature, CheckStatus::Unverifiable);
    }
    let remote = b"<!-- -----BEGIN C2PA MANIFEST----- https://example.invalid/private.c2pa -----END C2PA MANIFEST----- -->\r\nVisible body\r\n";
    let report = provenance::inspect_mime(remote, "text/markdown", &limits, None)
        .unwrap()
        .unwrap();
    assert_eq!(report.presence, ManifestPresence::RemoteReference);
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("example.invalid")
    );
    assert_eq!(
        provenance::remove_store(remote, "text/markdown", &limits).unwrap(),
        b"Visible body\r\n"
    );
}

#[test]
fn ordinary_format_characters_and_prose_examples_are_retained_exactly() {
    let limits = Limits::default();
    let plain = "\u{feff}Emoji ❤️ 👩\u{200d}🔬, فارسی\u{200c}متن, \u{2067}العربية\u{2069}.\r\n";
    assert!(
        provenance::inspect_mime(plain.as_bytes(), "text/plain", &limits, None)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        provenance::strip_text_wrappers(plain.as_bytes(), "text/plain", &limits).unwrap(),
        plain.as_bytes()
    );
    let markdown =
        b"Explain -----BEGIN C2PA MANIFEST----- ordinary prose -----END C2PA MANIFEST----- here.\n";
    assert_eq!(
        provenance::text_scope(markdown, "text/markdown", &limits)
            .unwrap()
            .wrapper_count,
        0
    );
    assert_eq!(
        provenance::strip_text_wrappers(markdown, "text/markdown", &limits).unwrap(),
        markdown
    );
    assert!(provenance::inspect_mime(b"<html/>", "text/html", &limits, None).is_err());
}

#[test]
fn document_claim_and_visible_body_tampering_are_reported_separately() {
    let limits = Limits::default();
    for (name, mime) in [
        ("signed.pdf", "application/pdf"),
        ("signed.txt", "text/plain"),
        ("signed.md", "text/markdown"),
    ] {
        let source = fixture(name);
        let mut manifest = c2pa::jumbf_io::load_jumbf_from_memory(mime, &source).unwrap();
        let marker = b"PRIVATE_GENERATOR";
        let offset = manifest
            .windows(marker.len())
            .position(|part| part == marker)
            .unwrap();
        manifest[offset] ^= 1;
        let changed = c2pa::jumbf_io::save_jumbf_to_memory(mime, &source, &manifest).unwrap();
        let report = provenance::inspect_mime(&changed, mime, &limits, None)
            .unwrap()
            .unwrap();
        assert_eq!(report.signature, CheckStatus::Invalid, "{name}");
        let mut changed_body = source.clone();
        let offset = changed_body
            .windows(7)
            .position(|part| part == b"Visible")
            .unwrap();
        changed_body[offset] ^= 1;
        let report = provenance::inspect_mime(&changed_body, mime, &limits, None)
            .unwrap()
            .unwrap();
        assert_eq!(report.signature, CheckStatus::Valid, "{name}");
        assert_eq!(report.asset_binding, CheckStatus::Invalid, "{name}");
    }
}

#[test]
fn pdf_multiple_and_incomplete_store_structures_are_protected_before_sdk_first_store_selection() {
    let limits = Limits::default();
    let stream = b"<< /Type /EmbeddedFile /Subtype /application#2fc2pa /Length 4 >>\nstream\ntest\nendstream".to_vec();
    let multiple = document_pdf_extra(
        "/AF [6 0 R 8 0 R]",
        vec![
            b"<< /Type /Filespec /AFRelationship /C2PA_Manifest /EF << /F 7 0 R >> >>".to_vec(),
            stream.clone(),
            b"<< /Type /Filespec /AFRelationship /C2PA_Manifest /EF << /F 9 0 R >> >>".to_vec(),
            stream,
        ],
    );
    let report = provenance::inspect_mime(&multiple, "application/pdf", &limits, None)
        .unwrap()
        .unwrap();
    assert_eq!(report.signature, CheckStatus::Unverifiable);
    assert_eq!(report.manifest_count, 2);
    assert!(
        report
            .validation_codes
            .iter()
            .any(|code| code == "fileveil.c2pa.multiple_pdf_stores")
    );
    let incomplete = document_pdf_extra(
        "/AF [6 0 R]",
        vec![b"<< /Type /Filespec /AFRelationship /C2PA_Manifest >>".to_vec()],
    );
    let report = provenance::inspect_mime(&incomplete, "application/pdf", &limits, None)
        .unwrap()
        .unwrap();
    assert_eq!(report.signature, CheckStatus::Unverifiable);
    assert!(
        report
            .validation_codes
            .iter()
            .any(|code| code == "fileveil.c2pa.pdf_store_structure_unresolved")
    );
    assert!(
        provenance::inspect_mime(&document_pdf(), "application/pdf", &limits, None)
            .unwrap()
            .is_none()
    );
    assert!(
        provenance::inspect_mime(b"%PDF-1.7\nbroken", "application/pdf", &limits, None).is_err()
    );
    let source = fixture("signed.pdf");
    let marker = source
        .windows(9)
        .rposition(|part| part == b"startxref")
        .unwrap()
        + 9;
    let previous_xref = std::str::from_utf8(&source[marker..])
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap();
    let mut revision = source.clone();
    let object_offset = revision.len();
    revision.extend_from_slice(b"100 0 obj\n<< /Author (PRIVATE_OLD_REVISION) >>\nendobj\n");
    let xref = revision.len();
    revision.extend_from_slice(format!("xref\n100 1\n{object_offset:010} 00000 n \ntrailer\n<< /Size 101 /Root 1 0 R /Info 100 0 R /Prev {previous_xref} >>\nstartxref\n{xref}\n%%EOF\n").as_bytes());
    let report = provenance::inspect_mime(&revision, "application/pdf", &limits, None)
        .unwrap()
        .unwrap();
    assert_eq!(report.signature, CheckStatus::Valid);
    assert_ne!(report.manifest_validation, CheckStatus::Valid);
    assert!(
        report
            .validation_codes
            .iter()
            .any(|code| code == "fileveil.c2pa.pdf_incremental_history_not_fully_validated")
    );
}

#[test]
fn signed_wav_validates_offline_and_container_rewriting_remains_protected() {
    let limits = Limits::default();
    let source = fixture("signed.wav");
    let root = String::from_utf8(fixture("audio-root.pem")).unwrap();
    let original_hash = digest(&source);
    let report = provenance::inspect_mime(&source, "audio/wav", &limits, Some(&root))
        .unwrap()
        .unwrap();
    assert_eq!(report.signature, CheckStatus::Valid);
    assert_eq!(report.asset_binding, CheckStatus::Valid);
    assert_eq!(report.trust, TrustStatus::Trusted);
    assert!(report.offline);
    let inspection = fileveil_formats::audio::inspect(&source, Format::Wav, &limits).unwrap();
    assert!(!inspection.blockers.is_empty());
    assert!(fileveil_formats::audio::sanitize(&source, Format::Wav, &limits).is_err());
    assert!(provenance::remove_store(&source, "audio/wav", &limits).is_err());
    let mut tampered = source.clone();
    let samples = source.windows(4).position(|part| part == b"data").unwrap() + 8;
    tampered[samples] ^= 1;
    let report = provenance::inspect(&tampered, Format::Wav, &limits)
        .unwrap()
        .unwrap();
    assert_eq!(report.signature, CheckStatus::Valid);
    assert_eq!(report.asset_binding, CheckStatus::Invalid);
    let mut duplicate = source.clone();
    duplicate.extend_from_slice(b"C2PA\x04\0\0\0test");
    let length = (duplicate.len() - 8) as u32;
    duplicate[4..8].copy_from_slice(&length.to_le_bytes());
    let report = provenance::inspect(&duplicate, Format::Wav, &limits)
        .unwrap()
        .unwrap();
    assert_eq!(report.signature, CheckStatus::Unverifiable);
    assert_eq!(report.manifest_count, 2);
    assert!(
        provenance::inspect(&document_wav(), Format::Wav, &limits)
            .unwrap()
            .is_none()
    );
    assert_eq!(digest(&source), original_hash);
}

#[test]
fn native_bmff_media_validate_credentials_and_reject_claim_and_media_tampering() {
    let limits = Limits::default();
    let root = String::from_utf8(fixture("media-root.pem")).unwrap();
    for (extension, mime, format) in [
        ("heic", "image/heic", Format::Heic),
        ("avif", "image/avif", Format::Avif),
        ("mp4", "video/mp4", Format::Mp4),
        ("mov", "video/quicktime", Format::Mov),
    ] {
        let source = fixture(&format!("signed.{extension}"));
        let original_hash = digest(&source);
        let report = provenance::inspect_with_trust(&source, format, &limits, Some(&root))
            .unwrap()
            .unwrap();
        assert_eq!(report.signature, CheckStatus::Valid, "{extension}");
        assert_eq!(report.asset_binding, CheckStatus::Valid, "{extension}");
        assert_eq!(
            report.manifest_validation,
            CheckStatus::Valid,
            "{extension}"
        );
        assert_eq!(report.trust, TrustStatus::Trusted, "{extension}");
        assert!(report.offline);
        assert!(!serde_json::to_string(&report).unwrap().contains("PRIVATE_"));
        let mut manifest = c2pa::jumbf_io::load_jumbf_from_memory(mime, &source).unwrap();
        let marker = b"PRIVATE_GENERATOR";
        let index = manifest
            .windows(marker.len())
            .position(|part| part == marker)
            .unwrap();
        manifest[index] ^= 1;
        let tampered = c2pa::jumbf_io::save_jumbf_to_memory(mime, &source, &manifest).unwrap();
        let report = provenance::inspect(&tampered, format, &limits)
            .unwrap()
            .unwrap();
        assert_eq!(report.signature, CheckStatus::Invalid, "{extension}");
        let mut tampered = source.clone();
        let payload = bmff_payload_offset(&source);
        tampered[payload] ^= 1;
        let report = provenance::inspect(&tampered, format, &limits)
            .unwrap()
            .unwrap();
        assert_eq!(report.signature, CheckStatus::Valid, "{extension}");
        assert_eq!(report.asset_binding, CheckStatus::Invalid, "{extension}");
        assert_eq!(digest(&source), original_hash);
    }
}

fn bmff_payload_offset(data: &[u8]) -> usize {
    let mut offset = 0;
    while offset + 8 <= data.len() {
        let size = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        let (size, header) = if size == 1 {
            (
                u64::from_be_bytes(data[offset + 8..offset + 16].try_into().unwrap()) as usize,
                16,
            )
        } else {
            (size, 8)
        };
        assert!(size >= header && offset + size <= data.len());
        if &data[offset + 4..offset + 8] == b"mdat" {
            assert!(size > header);
            return offset + header;
        }
        offset += size;
    }
    panic!("codec-produced synthetic BMFF fixture has no media-data box")
}

#[test]
fn official_private_copy_removal_clears_signed_and_remote_credentials_without_pixel_changes() {
    for (name, format) in [
        ("signed.png", Format::Png),
        ("signed.jpg", Format::Jpeg),
        ("remote.png", Format::Png),
    ] {
        let source = fixture(name);
        let original_hash = digest(&source);
        let before = image::load_from_memory(&source).unwrap();
        let output = provenance::remove(&source, format, &Limits::default()).unwrap();
        assert!(
            provenance::inspect(&output, format, &Limits::default())
                .unwrap()
                .is_none()
        );
        let after = image::load_from_memory(&output).unwrap();
        assert_eq!(before.color(), after.color());
        assert_eq!(before.as_bytes(), after.as_bytes());
        assert_eq!(digest(&source), original_hash);
    }
}

fn png(value: u8) -> Vec<u8> {
    let image = DynamicImage::ImageRgb8(image::RgbImage::from_pixel(
        4,
        4,
        image::Rgb([value, 64, 128]),
    ));
    let mut output = Cursor::new(Vec::new());
    image.write_to(&mut output, ImageFormat::Png).unwrap();
    output.into_inner()
}

#[test]
fn signed_png_checks_crypto_and_binding_without_assuming_trust() {
    let data = fixture("signed.png");
    let before = digest(&data);
    let report = provenance::inspect(&data, Format::Png, &Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(report.presence, ManifestPresence::Embedded);
    assert_eq!(report.manifest_count, 1);
    assert_eq!(report.signature, CheckStatus::Valid);
    assert_eq!(report.asset_binding, CheckStatus::Valid);
    assert_eq!(report.manifest_validation, CheckStatus::Valid);
    assert_eq!(report.trust, TrustStatus::NotAssessed);
    assert_eq!(report.revocation, CheckStatus::NotAssessed);
    assert_eq!(report.timestamp, CheckStatus::NotAssessed);
    assert!(report.offline);
    assert_eq!(digest(&data), before);
    let json = serde_json::to_string(&report).unwrap();
    for private_value in [
        "PRIVATE_SYNTHETIC_TITLE",
        "Synthetic Signer",
        "https://example.invalid",
        "PRIVATE_GENERATOR",
    ] {
        assert!(!json.contains(private_value));
    }
    assert_eq!(
        serde_json::from_str::<provenance::ProvenanceReport>(&json).unwrap(),
        report
    );
}

#[test]
fn local_root_trust_is_explicit_and_jpeg_is_supported() {
    let root = String::from_utf8(fixture("root.pem")).unwrap();
    let report = provenance::inspect_with_trust(
        &fixture("signed.jpg"),
        Format::Jpeg,
        &Limits::default(),
        Some(&root),
    )
    .unwrap()
    .unwrap();
    assert_eq!(report.signature, CheckStatus::Valid);
    assert_eq!(report.asset_binding, CheckStatus::Valid);
    assert_eq!(report.trust, TrustStatus::Trusted);
    assert_eq!(
        report.trust_anchor_sha256.as_deref(),
        Some(digest(root.as_bytes()).as_str())
    );
    assert_eq!(report.signature_algorithm.as_deref(), Some("es256"));
}

#[test]
fn unrelated_root_preserves_valid_signature_and_reports_untrusted() {
    let root = String::from_utf8(fixture("unrelated-root.pem")).unwrap();
    let report = provenance::inspect_with_trust(
        &fixture("signed.png"),
        Format::Png,
        &Limits::default(),
        Some(&root),
    )
    .unwrap()
    .unwrap();
    assert_eq!(report.signature, CheckStatus::Valid);
    assert_eq!(report.asset_binding, CheckStatus::Valid);
    assert_eq!(report.trust, TrustStatus::Untrusted);
}

#[test]
fn tampering_claim_breaks_signature_and_tampering_pixels_breaks_binding() {
    let data = fixture("signed.png");
    let manifest = c2pa::jumbf_io::load_jumbf_from_memory("image/png", &data).unwrap();
    let mut changed_claim = manifest.clone();
    let marker = b"PRIVATE_GENERATOR";
    let offset = changed_claim
        .windows(marker.len())
        .position(|bytes| bytes == marker)
        .unwrap();
    changed_claim[offset] ^= 1;
    let changed = c2pa::jumbf_io::save_jumbf_to_memory("image/png", &data, &changed_claim).unwrap();
    let report = provenance::inspect(&changed, Format::Png, &Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(report.signature, CheckStatus::Invalid);
    assert_eq!(report.manifest_validation, CheckStatus::Invalid);

    let changed = c2pa::jumbf_io::save_jumbf_to_memory("image/png", &png(251), &manifest).unwrap();
    let report = provenance::inspect(&changed, Format::Png, &Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(report.signature, CheckStatus::Valid);
    assert_eq!(report.asset_binding, CheckStatus::Invalid);
    assert_eq!(report.manifest_validation, CheckStatus::Invalid);
}

#[test]
fn remote_manifest_is_blocked_offline_and_url_stays_private() {
    let report = provenance::inspect(&fixture("remote.png"), Format::Png, &Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(report.presence, ManifestPresence::RemoteReference);
    assert_eq!(report.signature, CheckStatus::Unverifiable);
    assert!(report.offline);
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("example.invalid")
    );
}

#[test]
fn clean_unknown_and_malformed_inputs_do_not_claim_valid_credentials() {
    assert!(
        provenance::inspect(&png(16), Format::Png, &Limits::default())
            .unwrap()
            .is_none()
    );
    assert!(
        provenance::inspect(
            b"c2pa jumb PRIVATE_GENERATOR",
            Format::Text,
            &Limits::default()
        )
        .unwrap()
        .is_none()
    );
    let malformed =
        c2pa::jumbf_io::save_jumbf_to_memory("image/png", &png(16), b"malformed").unwrap();
    let report = provenance::inspect(&malformed, Format::Png, &Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(report.signature, CheckStatus::Unverifiable);
    assert_eq!(report.manifest_validation, CheckStatus::Unverifiable);
}

#[test]
fn file_manifest_and_trust_limits_are_enforced() {
    let data = fixture("signed.png");
    let limits = Limits {
        max_file_bytes: 1,
        ..Limits::default()
    };
    assert!(provenance::inspect(&data, Format::Png, &limits).is_err());
    let limits = Limits {
        max_metadata_bytes: 8,
        ..Limits::default()
    };
    assert!(provenance::inspect(&data, Format::Png, &limits).is_err());
    assert!(
        provenance::inspect_with_trust(
            &png(16),
            Format::Png,
            &limits,
            Some("invalid trust bundle larger than limit")
        )
        .is_err()
    );
    assert!(
        provenance::inspect_with_trust(&data, Format::Png, &Limits::default(), Some("invalid PEM"))
            .is_err()
    );
}

/// Reproducible local fixture creation. Only public signed images and root
/// certificates are retained. TempDir removes every generated private key.
#[test]
#[ignore = "manual public fixture regeneration requires a local OpenSSL executable"]
fn regenerate_public_fixtures() {
    generate_public_fixtures(FixtureSet::Images);
}

#[test]
#[ignore = "manual public document fixture regeneration requires local OpenSSL"]
fn regenerate_document_fixtures() {
    generate_public_fixtures(FixtureSet::Documents);
}

#[test]
#[ignore = "manual public audio fixture regeneration requires local OpenSSL"]
fn regenerate_audio_fixtures() {
    generate_public_fixtures(FixtureSet::Audio);
}

#[test]
#[ignore = "manual public media fixture regeneration requires local OpenSSL"]
fn regenerate_media_fixtures() {
    generate_public_fixtures(FixtureSet::Media);
}

enum FixtureSet {
    Images,
    Documents,
    Audio,
    Media,
}

fn generate_public_fixtures(fixture_set: FixtureSet) {
    use c2pa::{Builder, Context, SigningAlg, create_signer};
    use serde_json::json;
    use std::{path::Path, process::Command};

    fn openssl(dir: &Path, args: &[&str]) {
        let output = Command::new("openssl")
            .current_dir(dir)
            .args(args)
            .output()
            .expect("local OpenSSL for fixture generation");
        assert!(output.status.success(), "OpenSSL fixture command failed");
    }

    let temporary = tempfile::tempdir().unwrap();
    let dir = temporary.path();
    for (key, certificate, subject) in [
        ("root.key", "root.pem", "/CN=FileVeil Synthetic Root"),
        (
            "unrelated.key",
            "unrelated-root.pem",
            "/CN=FileVeil Unrelated Root",
        ),
    ] {
        openssl(
            dir,
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                key,
            ],
        );
        openssl(
            dir,
            &[
                "req",
                "-x509",
                "-new",
                "-key",
                key,
                "-sha256",
                "-days",
                "36500",
                "-subj",
                subject,
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-out",
                certificate,
            ],
        );
    }
    openssl(
        dir,
        &[
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            "signer.key",
        ],
    );
    openssl(
        dir,
        &[
            "req",
            "-new",
            "-key",
            "signer.key",
            "-subj",
            "/CN=FileVeil Synthetic Signer",
            "-out",
            "signer.csr",
        ],
    );
    fs::write(dir.join("signer.ext"), "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=emailProtection\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n").unwrap();
    openssl(
        dir,
        &[
            "x509",
            "-req",
            "-in",
            "signer.csr",
            "-CA",
            "root.pem",
            "-CAkey",
            "root.key",
            "-set_serial",
            "2",
            "-days",
            "36500",
            "-sha256",
            "-extfile",
            "signer.ext",
            "-out",
            "signer.pem",
        ],
    );
    let signer = create_signer::from_keys(
        &fs::read(dir.join("signer.pem")).unwrap(),
        &fs::read(dir.join("signer.key")).unwrap(),
        SigningAlg::Es256,
        None,
    )
    .unwrap();
    let context = Context::new().with_settings(json!({
        "verify": {"verify_after_sign": false, "remote_manifest_fetch": false, "ocsp_fetch": false},
        "core": {"allowed_network_hosts": [], "allow_redirects": false}
    })).unwrap().into_shared();
    let output_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/provenance");
    fs::create_dir_all(&output_dir).unwrap();
    if !matches!(fixture_set, FixtureSet::Images) {
        let samples = if matches!(fixture_set, FixtureSet::Audio) {
            vec![("wav", "audio/wav", document_wav())]
        } else if matches!(fixture_set, FixtureSet::Media) {
            let source_root =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
            vec![
                (
                    "heic",
                    "image/heic",
                    fs::read(source_root.join("heic_exif_gps.heic")).unwrap(),
                ),
                (
                    "avif",
                    "image/avif",
                    fs::read(source_root.join("avif_exif_gps.avif")).unwrap(),
                ),
                (
                    "mp4",
                    "video/mp4",
                    fs::read(source_root.join("mp4_container_times.mp4")).unwrap(),
                ),
                (
                    "mov",
                    "video/quicktime",
                    fs::read(source_root.join("mov_model_metadata.mov")).unwrap(),
                ),
            ]
        } else {
            vec![
                ("pdf", "application/pdf", document_pdf()),
                (
                    "txt",
                    "text/plain",
                    "Visible café text. Emoji ❤️ and العربية فارسی\u{200c}متن.\r\n"
                        .as_bytes()
                        .to_vec(),
                ),
                (
                    "md",
                    "text/markdown",
                    "# Visible document\r\n\r\nCafé ❤️ and normal text.\r\n"
                        .as_bytes()
                        .to_vec(),
                ),
            ]
        };
        for (extension, mime, source) in samples {
            let definition = json!({
                "claim_version": 2,
                "title": "PRIVATE_SYNTHETIC_DOCUMENT_TITLE",
                "format": mime,
                "claim_generator_info": [{"name": "PRIVATE_GENERATOR", "version": "0.3"}],
                "assertions": [{"label": "c2pa.actions", "data": {"actions": [{"action": "c2pa.created", "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/algorithmicMedia"}]}}]
            });
            let mut builder = Builder::from_shared_context(&context)
                .with_definition(definition.to_string())
                .unwrap();
            let mut output = Cursor::new(Vec::new());
            builder
                .sign(signer.as_ref(), mime, &mut Cursor::new(source), &mut output)
                .unwrap();
            fs::write(
                output_dir.join(format!("signed.{extension}")),
                output.into_inner(),
            )
            .unwrap();
        }
        let root_name = if matches!(fixture_set, FixtureSet::Audio) {
            "audio-root.pem"
        } else if matches!(fixture_set, FixtureSet::Media) {
            "media-root.pem"
        } else {
            "document-root.pem"
        };
        fs::copy(dir.join("root.pem"), output_dir.join(root_name)).unwrap();
        return;
    }
    for (extension, mime, image_format) in [
        ("png", "image/png", ImageFormat::Png),
        ("jpg", "image/jpeg", ImageFormat::Jpeg),
    ] {
        let image =
            DynamicImage::ImageRgb8(image::RgbImage::from_pixel(4, 4, image::Rgb([16, 64, 128])));
        let mut source = Cursor::new(Vec::new());
        image.write_to(&mut source, image_format).unwrap();
        let definition = json!({
            "claim_version": 2,
            "title": "PRIVATE_SYNTHETIC_TITLE",
            "format": mime,
            "claim_generator_info": [{"name": "PRIVATE_GENERATOR", "version": "0.3"}],
            "assertions": [{"label": "c2pa.actions", "data": {"actions": [{"action": "c2pa.created", "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/algorithmicMedia"}]}}]
        });
        let mut builder = Builder::from_shared_context(&context)
            .with_definition(definition.to_string())
            .unwrap();
        let mut output = Cursor::new(Vec::new());
        builder
            .sign(signer.as_ref(), mime, &mut source, &mut output)
            .unwrap();
        fs::write(
            output_dir.join(format!("signed.{extension}")),
            output.into_inner(),
        )
        .unwrap();
        if extension == "png" {
            let mut builder = Builder::from_shared_context(&context)
                .with_definition(definition.to_string())
                .unwrap();
            builder
                .set_remote_url("https://example.invalid/PRIVATE_SYNTHETIC_TITLE.c2pa")
                .set_no_embed(true);
            let mut output = Cursor::new(Vec::new());
            builder
                .sign(signer.as_ref(), mime, &mut source, &mut output)
                .unwrap();
            fs::write(output_dir.join("remote.png"), output.into_inner()).unwrap();
        }
    }
    for name in ["root.pem", "unrelated-root.pem"] {
        fs::copy(dir.join(name), output_dir.join(name)).unwrap();
    }
}

fn document_wav() -> Vec<u8> {
    let mut data = b"RIFF\0\0\0\0WAVEfmt \x10\0\0\0".to_vec();
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&8000u32.to_le_bytes());
    data.extend_from_slice(&16000u32.to_le_bytes());
    data.extend_from_slice(&2u16.to_le_bytes());
    data.extend_from_slice(&16u16.to_le_bytes());
    data.extend_from_slice(b"data\x08\0\0\0\0\0\x01\0\xff\xff\x02\0");
    let length = (data.len() - 8) as u32;
    data[4..8].copy_from_slice(&length.to_le_bytes());
    data
}

fn document_pdf() -> Vec<u8> {
    document_pdf_extra("", Vec::new())
}

fn document_pdf_extra(catalog_extra: &str, extra: Vec<Vec<u8>>) -> Vec<u8> {
    let visible = b"BT /F1 12 Tf 20 200 Td (Visible synthetic C2PA document) Tj ET";
    let mut objects = vec![
        format!("<< /Type /Catalog /Pages 2 0 R {catalog_extra} >>").into_bytes(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>".to_vec(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
        [format!("<< /Length {} >>\nstream\n", visible.len()).as_bytes(), visible, b"\nendstream"].concat(),
    ];
    objects.extend(extra);
    let mut bytes = b"%PDF-1.7\n".to_vec();
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
            "trailer\n<< /Root 1 0 R /Size {} >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    bytes
}

#[test]
fn repeated_markdown_candidates_with_long_prefixes_preserve_protected_text() {
    const CANDIDATE: &str =
        "-----BEGIN C2PA MANIFEST-----https://example.invalid/manifest-----END C2PA MANIFEST----- ";
    for prefix in [" ".repeat(100_000), format!("<!--{}", "\t".repeat(100_000))] {
        let text = prefix + &CANDIDATE.repeat(1_000);
        let scope =
            provenance::text_scope(text.as_bytes(), "text/markdown", &Limits::default()).unwrap();
        assert_eq!(scope.wrapper_count, 1_000);
        assert!(!scope.removal_supported);
        assert!(scope.ranges.is_empty());
        assert_eq!(
            scope.issue.as_deref(),
            Some("fileveil.c2pa.markdown_context_unsupported")
        );
        assert!(
            provenance::strip_text_wrappers(text.as_bytes(), "text/markdown", &Limits::default())
                .is_err()
        );
    }
    let valid = format!("   <!--\t{}-->\nVisible text", CANDIDATE.trim_end());
    let scope =
        provenance::text_scope(valid.as_bytes(), "text/markdown", &Limits::default()).unwrap();
    assert!(scope.removal_supported);
    assert_eq!(
        provenance::strip_text_wrappers(valid.as_bytes(), "text/markdown", &Limits::default())
            .unwrap(),
        b"Visible text"
    );
    let unsupported = format!(" {valid}");
    assert!(
        !provenance::text_scope(unsupported.as_bytes(), "text/markdown", &Limits::default())
            .unwrap()
            .removal_supported
    );
}
