// SPDX-License-Identifier: MPL-2.0
use des::{
    Des,
    cipher::{Block, BlockCipherEncrypt, KeyInit},
};
use fileveil_core::{Limits, digest};
use fileveil_engine::heritage::legacy::{self, LegacyKind, LegacyPlacement, LegacyStatus};
use std::{
    io::{Cursor, Read, Write},
    path::PathBuf,
};
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

fn image(png: bool) -> Vec<u8> {
    let image = image::RgbImage::from_fn(16, 16, |x, y| image::Rgb([x as u8 * 8, y as u8 * 9, 79]));
    let mut output = Cursor::new(Vec::new());
    image
        .write_to(
            &mut output,
            if png {
                image::ImageFormat::Png
            } else {
                image::ImageFormat::Jpeg
            },
        )
        .unwrap();
    output.into_inner()
}

fn packet(serials: &[&str]) -> Vec<u8> {
    let cipher = Des::new_from_slice(&[7, 6, 5, 4, 3, 2, 1, 0]).unwrap();
    let mut bytes = Vec::new();
    for serial in serials {
        let mut record = [0u8; 24];
        record[..serial.len()].copy_from_slice(serial.as_bytes());
        for chunk in record.as_chunks::<8>().0 {
            let mut block = Block::<Des>::default();
            block.copy_from_slice(chunk);
            cipher.encrypt_block(&mut block);
            bytes.extend_from_slice(&block);
        }
    }
    bytes.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    bytes.extend_from_slice(b"EOF");
    bytes
}

fn woolim(selfsign: bool) -> Vec<u8> {
    let total: usize = if selfsign { 792 } else { 272 };
    let mut bytes = (0..total - 16)
        .map(|i| (i % 251 + 1) as u8)
        .collect::<Vec<_>>();
    bytes.extend_from_slice(&(total as u32).to_le_bytes());
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(if selfsign { b"SELFSIGN" } else { b"NATISIGN" });
    bytes
}

fn docx() -> Vec<u8> {
    let entries = [
        (
            "[Content_Types].xml",
            r#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#,
        ),
        (
            "_rels/.rels",
            r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="main" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#,
        ),
        (
            "word/document.xml",
            r#"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Keep these visible words.</w:t></w:r></w:p></w:body></w:document>"#,
        ),
    ];
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, content) in entries {
        zip.start_file(name, SimpleFileOptions::default()).unwrap();
        zip.write_all(content.as_bytes()).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn padded_docx() -> (Vec<u8>, std::ops::Range<usize>) {
    let mut bytes = docx();
    let header_name_len = u16::from_le_bytes(bytes[26..28].try_into().unwrap()) as usize;
    let existing_extra = u16::from_le_bytes(bytes[28..30].try_into().unwrap());
    let insertion = 30 + header_name_len;
    let mut extra = Vec::new();
    extra.extend_from_slice(&0xa220u16.to_le_bytes());
    extra.extend_from_slice(&516u16.to_le_bytes());
    extra.extend_from_slice(&0xa028u16.to_le_bytes());
    extra.extend_from_slice(&512u16.to_le_bytes());
    extra.resize(520, 0);
    let mark = packet(&["FILEVEIL-TEST-0001"]);
    let range = insertion + 31..insertion + 31 + mark.len();
    extra[31..31 + mark.len()].copy_from_slice(&mark);
    let old_eocd = bytes.len() - 22;
    let old_central =
        u32::from_le_bytes(bytes[old_eocd + 16..old_eocd + 20].try_into().unwrap()) as usize;
    bytes.splice(insertion..insertion, extra);
    bytes[28..30].copy_from_slice(&(existing_extra + 520).to_le_bytes());
    let eocd = old_eocd + 520;
    bytes[eocd + 16..eocd + 20].copy_from_slice(&((old_central + 520) as u32).to_le_bytes());
    let mut central = old_central + 520;
    for _ in 0..3 {
        let local = u32::from_le_bytes(bytes[central + 42..central + 46].try_into().unwrap());
        if local != 0 {
            bytes[central + 42..central + 46].copy_from_slice(&(local + 520).to_le_bytes());
        }
        let n = u16::from_le_bytes(bytes[central + 28..central + 30].try_into().unwrap()) as usize;
        let x = u16::from_le_bytes(bytes[central + 30..central + 32].try_into().unwrap()) as usize;
        let c = u16::from_le_bytes(bytes[central + 32..central + 34].try_into().unwrap()) as usize;
        central += 46 + n + x + c;
    }
    (bytes, range)
}

fn members(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut zip = ZipArchive::new(Cursor::new(bytes)).unwrap();
    (0..zip.len())
        .map(|i| {
            let mut file = zip.by_index(i).unwrap();
            let name = file.name().unwrap().into_owned();
            let mut content = Vec::new();
            file.read_to_end(&mut content).unwrap();
            (name, content)
        })
        .collect()
}

#[test]
fn jpeg_multiple_records_are_decoded_redacted_and_removed_byte_exactly() {
    let original = image(false);
    let mut marked = original.clone();
    marked.extend_from_slice(&packet(&["FILEVEIL-TEST-0001", "SECOND-DEVICE-02"]));
    let limits = Limits::default();
    let report = legacy::detect(&marked, &limits).unwrap();
    assert_eq!(report.status, LegacyStatus::Detected);
    assert_eq!(report.locations[0].offset, original.len());
    assert_eq!(report.locations[0].record_count, 2);
    assert!(
        report
            .decoded_records
            .iter()
            .all(|record| record.identifier.is_none())
    );
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("FILEVEIL-TEST-0001")
    );
    let decoded = legacy::decode(&marked, &limits, true).unwrap();
    assert_eq!(
        decoded.decoded_records[0].identifier.as_deref(),
        Some("FILEVEIL-TEST-0001")
    );
    let cleaned = legacy::clean(&marked, &limits).unwrap();
    assert_eq!(cleaned, original);
    assert_eq!(
        legacy::verify(&marked, &cleaned, &limits).unwrap().result,
        "verified_within_scope"
    );
}

#[test]
fn original_binary_des_key_matches_an_independent_openssl_vector() {
    let original = image(false);
    let mut marked = original.clone();
    // OpenSSL DES-ECB, key 1352070d133a0810, padded FILEVEIL-REALKEY-01.
    marked.extend_from_slice(&[
        0x76, 0x31, 0x30, 0x72, 0x68, 0x86, 0xda, 0xfd, 0x52, 0x95, 0x3b, 0xa8, 0x74, 0x73, 0x08,
        0xe1, 0x93, 0x6b, 0x3a, 0x73, 0x2e, 0x0d, 0x30, 0x85,
    ]);
    marked.extend_from_slice(&24u32.to_le_bytes());
    marked.extend_from_slice(b"EOF");
    let report = legacy::decode(&marked, &Limits::default(), true).unwrap();
    assert_eq!(report.status, LegacyStatus::Detected);
    assert_eq!(report.decoded_records[0].key_profile, "original_binary");
    assert_eq!(
        report.decoded_records[0].identifier.as_deref(),
        Some("FILEVEIL-REALKEY-01")
    );
    assert_eq!(
        legacy::clean(&marked, &Limits::default()).unwrap(),
        original
    );
}

#[test]
fn png_trailer_removal_preserves_every_encoded_byte_and_decoded_pixel() {
    let original = image(true);
    let mut marked = original.clone();
    marked.extend_from_slice(&packet(&["PNG-REFERENCE-0001"]));
    let cleaned = legacy::clean(&marked, &Limits::default()).unwrap();
    assert_eq!(cleaned, original);
    assert_eq!(
        image::load_from_memory(&marked).unwrap().to_rgb8(),
        image::load_from_memory(&cleaned).unwrap().to_rgb8()
    );
}

#[test]
fn local_only_docx_padding_is_found_and_zeroed_without_repacking() {
    let (marked, range) = padded_docx();
    let report = legacy::detect(&marked, &Limits::default()).unwrap();
    assert_eq!(report.status, LegacyStatus::Detected);
    assert_eq!(
        report.locations[0].placement,
        LegacyPlacement::OoxmlLocalPadding
    );
    assert_eq!(report.locations[0].offset, range.start);
    let cleaned = legacy::clean(&marked, &Limits::default()).unwrap();
    assert_eq!(marked.len(), cleaned.len());
    assert_eq!(&marked[..range.start], &cleaned[..range.start]);
    assert_eq!(&marked[range.end..], &cleaned[range.end..]);
    assert!(cleaned[range].iter().all(|byte| *byte == 0));
    assert_eq!(members(&marked), members(&cleaned));
    assert_eq!(
        legacy::detect(&cleaned, &Limits::default()).unwrap().status,
        LegacyStatus::NotDetected
    );
}

#[test]
fn eof_bytes_inside_docx_ciphertext_do_not_replace_the_outer_packet_boundary() {
    let (mut marked, range) = padded_docx();
    marked[range.start..range.start + 3].copy_from_slice(b"EOF");
    let report = legacy::detect(&marked, &Limits::default()).unwrap();
    assert_eq!(report.locations[0].offset, range.start);
    assert_eq!(report.locations[0].bytes, range.len());
    assert_eq!(report.status, LegacyStatus::Detected);
    assert!(!report.decoded_records[0].plausible_serial);
    assert!(legacy::clean(&marked, &Limits::default()).is_ok());
}

#[test]
fn selfsign_structure_is_cleanable_and_crypto_remains_unassessed() {
    let original = image(false);
    let mut marked = original.clone();
    marked.extend_from_slice(&woolim(true));
    let report = legacy::decode(&marked, &Limits::default(), true).unwrap();
    assert_eq!(report.locations[0].kind, LegacyKind::WoolimSelfsign);
    assert_eq!(report.locations[0].crypto_status, "not_assessed");
    assert!(report.locations[0].identity_ciphertext_sha256.is_some());
    assert!(report.decoded_records.is_empty());
    assert_eq!(
        legacy::clean(&marked, &Limits::default()).unwrap(),
        original
    );
}

#[test]
fn natisign_candidates_are_reported_and_protected() {
    let mut marked = image(true);
    marked.extend_from_slice(&woolim(false));
    let report = legacy::detect(&marked, &Limits::default()).unwrap();
    assert_eq!(report.status, LegacyStatus::Indeterminate);
    assert_eq!(
        report.locations[0].evidence_status,
        "deprecated_candidate_unverified"
    );
    assert!(legacy::clean(&marked, &Limits::default()).is_err());
}

// Independently formulated inverse encoder using a chronological bit history.
// Production decoding uses a bounded shift register. No original library runs.
fn scramble_nati_metadata(plain: &[u8; 48]) -> Vec<u8> {
    let mut history = vec![0u8; 17];
    history.extend((0..8).map(|bit| (0xea >> bit) & 1));
    let mut encoded = Vec::new();
    for byte in plain {
        let mut output = 0u8;
        for bit in 0..8 {
            let run = history
                .iter()
                .rev()
                .take_while(|value| **value == 1)
                .count();
            let invert = u8::from(run != 0 && run % 64 == 0);
            let value = ((byte >> bit) & 1)
                ^ history[history.len() - 17]
                ^ history[history.len() - 14]
                ^ invert;
            history.push(value);
            output |= value << bit;
        }
        encoded.push(output);
    }
    encoded
}

fn nati_metadata(base: &[u8], png: bool) -> [u8; 48] {
    let mut plain = [0u8; 48];
    plain[4..8].copy_from_slice(&7u32.to_le_bytes());
    plain[24..28].copy_from_slice(&17u32.to_le_bytes());
    plain[28..32].copy_from_slice(&23u32.to_le_bytes());
    plain[32..36].copy_from_slice(if png { b".png" } else { b".jpg" });
    plain[40..48].copy_from_slice(&(base.len() as u64).to_le_bytes());
    plain
}

fn nati_packet(base: &[u8], plain: &[u8; 48], total: usize) -> Vec<u8> {
    let mut bytes = base.to_vec();
    bytes.extend_from_slice(&scramble_nati_metadata(plain));
    bytes.extend_from_slice(&17u32.to_le_bytes());
    bytes.resize(base.len() + total - 12, 0xa5);
    bytes.extend_from_slice(&(total as u32).to_le_bytes());
    bytes.extend_from_slice(b"NATISIGN");
    bytes
}

#[test]
fn pyongyang_320_structure_with_validated_metadata_cleans_with_partial_scope() {
    for png in [false, true] {
        let base = image(png);
        let plain = nati_metadata(&base, png);
        let marked = nati_packet(&base, &plain, 320);
        let report = legacy::decode(&marked, &Limits::default(), false).unwrap();
        assert_eq!(report.status, LegacyStatus::Detected);
        let location = &report.locations[0];
        assert_eq!(location.kind, LegacyKind::PyongyangNatisign);
        assert_eq!(location.layout_variant, "pyongyang2407_natisign_v1");
        assert_eq!(location.signature_offset, Some(base.len() + 52));
        assert_eq!(location.signature_bytes, Some(256));
        assert_eq!(location.length_field_offset, Some(marked.len() - 12));
        assert_eq!(location.crypto_status, "not_assessed");
        let metadata = location.metadata.as_ref().unwrap();
        assert_eq!(metadata.decoded_sha256, digest(&plain));
        assert!(
            metadata.schema_marker_zero
                && metadata.base_length_matches
                && metadata.encoded_content_boundary_matches
                && metadata.extension_matches_container
        );
        let clean = legacy::clean(&marked, &Limits::default()).unwrap();
        assert_eq!(clean, base);
        let verified = legacy::verify(&marked, &clean, &Limits::default()).unwrap();
        assert_eq!(verified.result, "partially_verified");
        assert!(verified.retained_bytes_unchanged);
        let directory = tempfile::tempdir().unwrap();
        let input = directory
            .path()
            .join(if png { "marked.png" } else { "marked.jpg" });
        let output = directory
            .path()
            .join(if png { "clean.png" } else { "clean.jpg" });
        std::fs::write(&input, &marked).unwrap();
        let result = fileveil_engine::heritage::run(
            &input,
            Some(&output),
            &fileveil_engine::heritage::HeritageRequest {
                action: fileveil_engine::heritage::HeritageAction::Clean,
                ..Default::default()
            },
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(
            result.advanced.unwrap()["heritage"]["legacy_verification"]["result"],
            "partially_verified"
        );
        assert_eq!(std::fs::read(output).unwrap(), base);
        assert_eq!(std::fs::read(input).unwrap(), marked);
    }
}

#[test]
fn pyongyang_variable_length_and_invalid_metadata_remain_read_only() {
    let base = image(false);
    let plain = nati_metadata(&base, false);
    let smaller = nati_packet(&base, &plain, 192);
    let report = legacy::detect(&smaller, &Limits::default()).unwrap();
    assert_eq!(report.status, LegacyStatus::Indeterminate);
    assert_eq!(report.locations[0].signature_bytes, Some(128));
    assert!(legacy::clean(&smaller, &Limits::default()).is_err());
    for offset in [0, 32, 40] {
        let mut changed = plain;
        changed[offset] ^= 1;
        let marked = nati_packet(&base, &changed, 320);
        assert_eq!(
            legacy::detect(&marked, &Limits::default()).unwrap().status,
            LegacyStatus::Indeterminate
        );
        assert!(legacy::clean(&marked, &Limits::default()).is_err());
    }
}

#[test]
fn pyongyang_metadata_matches_an_independent_python_bitstream_vector() {
    let base = image(false);
    let plain: [u8; 48] = std::array::from_fn(|index| index as u8);
    let mut marked = nati_packet(&base, &plain, 320);
    let vector = "80efe3273b83bea11ae2b9b7910fc95370a26eff1254376afb1712b17c5338ad1ed018b7d3a635038eafd51f729596a0";
    let encoded: Vec<_> = vector
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    marked[base.len()..base.len() + 48].copy_from_slice(&encoded);
    let report = legacy::decode(&marked, &Limits::default(), false).unwrap();
    assert_eq!(
        report.locations[0]
            .metadata
            .as_ref()
            .unwrap()
            .decoded_sha256,
        "4dbdc2b2b62cb00749785bc84202236dbc3777d74660611b8e58812f0cfde6c3"
    );
    assert_eq!(report.status, LegacyStatus::Indeterminate);
}

#[test]
fn pyongyang_cleaning_requires_the_exact_parsed_content_boundary() {
    let mut base = image(false);
    base.extend_from_slice(&packet(&["INNER-LEGACY-CONTROL"]));
    let marked = nati_packet(&base, &nati_metadata(&base, false), 320);
    let report = legacy::detect(&marked, &Limits::default()).unwrap();
    assert_eq!(report.status, LegacyStatus::Indeterminate);
    assert!(
        !report.locations[0]
            .metadata
            .as_ref()
            .unwrap()
            .encoded_content_boundary_matches
    );
    assert!(legacy::clean(&marked, &Limits::default()).is_err());
    let image = image(false);
    let mut invalid = nati_packet(&image, &nati_metadata(&image, false), 320);
    let length_offset = invalid.len() - 12;
    invalid[length_offset..length_offset + 4].copy_from_slice(&321u32.to_le_bytes());
    assert!(legacy::detect(&invalid, &Limits::default()).is_err());
}

#[test]
fn synthetic_nested_trailers_are_bounded_and_preserve_the_same_base() {
    let original = image(false);
    let mut marked = original.clone();
    marked.extend_from_slice(&woolim(true));
    marked.extend_from_slice(&packet(&["NESTED-CONTROL-1"]));
    assert_eq!(
        legacy::detect(&marked, &Limits::default())
            .unwrap()
            .locations
            .len(),
        2
    );
    assert_eq!(
        legacy::clean(&marked, &Limits::default()).unwrap(),
        original
    );
}

#[test]
fn invalid_lengths_padding_and_unknown_trailer_prefixes_fail_closed() {
    for length in [0u32, 1, 23, 25, u32::MAX] {
        let mut bytes = image(false);
        bytes.extend_from_slice(&[1; 24]);
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(b"EOF");
        assert!(legacy::clean(&bytes, &Limits::default()).is_err());
    }
    let mut bytes = image(true);
    let mut footer = woolim(true);
    footer[780] = 1;
    bytes.extend_from_slice(&footer);
    assert!(legacy::clean(&bytes, &Limits::default()).is_err());
    let mut bytes = image(false);
    bytes.extend_from_slice(b"PRESERVE-UNKNOWN-TRAILER");
    bytes.extend_from_slice(&packet(&["CONTROL-01"]));
    assert!(legacy::clean(&bytes, &Limits::default()).is_err());
}

#[test]
fn unknown_keys_retain_structural_detection_without_inventing_an_identity() {
    let original = image(false);
    let mut bytes = original.clone();
    bytes.extend_from_slice(&[0; 24]);
    bytes.extend_from_slice(&24u32.to_le_bytes());
    bytes.extend_from_slice(b"EOF");
    let report = legacy::detect(&bytes, &Limits::default()).unwrap();
    assert_eq!(report.status, LegacyStatus::Detected);
    assert!(!report.decoded_records[0].plausible_serial);
    assert!(report.decoded_records[0].identifier.is_none());
    assert!(report.decoded_records[0].plaintext_sha256.is_none());
    assert_eq!(report.decoded_records[0].key_profile, "unresolved");
    assert_eq!(legacy::clean(&bytes, &Limits::default()).unwrap(), original);
}

#[test]
fn content_tampering_and_unclean_outputs_fail_verification() {
    let original = image(false);
    let mut marked = original.clone();
    marked.extend_from_slice(&packet(&["VERIFICATION-001"]));
    assert_eq!(
        legacy::verify(&marked, &marked, &Limits::default())
            .unwrap()
            .result,
        "failed"
    );
    let other = image(true);
    assert_eq!(
        legacy::verify(&marked, &other, &Limits::default())
            .unwrap()
            .result,
        "failed"
    );
}

#[test]
fn record_and_metadata_budgets_are_enforced() {
    let mut marked = image(false);
    marked.extend_from_slice(&packet(&["BUDGET-1", "BUDGET-2"]));
    let limits = Limits {
        max_metadata_bytes: 24,
        ..Default::default()
    };
    assert!(legacy::detect(&marked, &limits).is_err());
    let limits = Limits {
        max_members: 1,
        ..Default::default()
    };
    assert!(legacy::detect(&marked, &limits).is_err());
    let (marked, _) = padded_docx();
    assert!(
        legacy::detect(
            &marked,
            &Limits {
                max_metadata_bytes: 100,
                ..Default::default()
            }
        )
        .is_err()
    );
}

#[test]
fn clean_controls_are_negative_and_cannot_be_reported_as_cleaned_marks() {
    for bytes in [image(false), image(true), docx()] {
        assert_eq!(
            legacy::detect(&bytes, &Limits::default()).unwrap().status,
            LegacyStatus::NotDetected
        );
        assert!(legacy::clean(&bytes, &Limits::default()).is_err());
    }
}

#[test]
#[ignore = "Requires pinned public research samples under work/v04-research"]
fn real_upstream_samples_match_independent_openssl_and_original_bytes() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../work/v04-research");
    let original = std::fs::read(root.join("preview_bottle_original.jpg")).unwrap();
    assert_eq!(
        digest(&original),
        "5fa55db03f0cee1209939ace1576a8b42da3855af567fed222e479d5ed50a451"
    );
    for (name, count, hash) in [
        (
            "preview_bottle_firstuser.jpg",
            1,
            "eae1a707d2dab40eb6e8c25c96bb919af63640567bc40fec3c4ce29aaa76a9da",
        ),
        (
            "preview_bottle_seconduser.jpg",
            2,
            "ab090c32f1a82228daf34a0827653bb4f9bd3191974f0c3053e1a05123b5acc1",
        ),
    ] {
        let marked = std::fs::read(root.join(name)).unwrap();
        assert_eq!(digest(&marked), hash);
        let report = legacy::decode(&marked, &Limits::default(), false).unwrap();
        assert_eq!(report.locations[0].record_count, count);
        let cleaned = legacy::clean(&marked, &Limits::default()).unwrap();
        assert_eq!(cleaned, original);
        assert_eq!(
            legacy::verify(&marked, &cleaned, &Limits::default())
                .unwrap()
                .result,
            "verified_within_scope"
        );
        std::fs::write(root.join(format!("cleaned-{name}")), cleaned).unwrap();
    }
    let marked = std::fs::read(root.join("love.docx")).unwrap();
    assert_eq!(
        digest(&marked),
        "ad90dd10a4520ad042878ea72f030795b8e51911ce913e4338b2115b1cd31976"
    );
    let report = legacy::decode(&marked, &Limits::default(), false).unwrap();
    assert_eq!(report.locations[0].offset, 80);
    let oracle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("legacy-openssl-oracle.json")).unwrap())
            .unwrap();
    let expected_hash = oracle["records"][2]["plaintext_sha256"].as_str().unwrap();
    assert_eq!(
        report.decoded_records[0].plaintext_sha256.as_deref(),
        Some(expected_hash)
    );
    let cleaned = legacy::clean(&marked, &Limits::default()).unwrap();
    assert_eq!(members(&marked), members(&cleaned));
    let differences: Vec<_> = marked
        .iter()
        .zip(&cleaned)
        .enumerate()
        .filter_map(|(offset, (a, b))| (a != b).then_some(offset))
        .collect();
    assert!(differences.iter().all(|offset| (80..111).contains(offset)));
    std::fs::write(root.join("cleaned-love.docx"), cleaned).unwrap();
}

// FVPROV1 23581 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIyNTIwZTFlODJhZDYzZjBiZDRjMDU3ZjEyNzE5ZDRjOTJkZGE1MjI3ZDc2ZmJiMTAxZGNiNWY4YTI2NDJmMGVkIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS40IiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuNCIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvdGVzdHMvaGVyaXRhZ2VfbGVnYWN5LnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiODdhMzcwMmUxNzMyOGNlNzVkZjZiMGU3Yjc4NDdhNTIwNTZkZTJlOThkMDgyOGJlY2NjMGJiNTBkZGY0YzhkNGFiYzg4NDJhMmQ4YzgwYTk4NWZlOTQwMWZlMGQ3NmU0NGVlM2VkNWRhZTk2NjA5MGI0OWNlN2YzODMxYmIyMGIifV19XQ== FVPROV1-END
