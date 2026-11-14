// SPDX-License-Identifier: MPL-2.0
use fileveil_core::{Format, Limits};
use fileveil_formats::{bmff, inspect};
use std::path::Path;

fn atom(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut result = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
    result.extend_from_slice(kind);
    result.extend_from_slice(payload);
    result
}
fn full_atom(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut full = vec![0; 4];
    full.extend_from_slice(payload);
    atom(kind, &full)
}
fn branded(brand: &[u8; 4], compatible: &[&[u8; 4]], boxes: &[u8]) -> Vec<u8> {
    let mut payload = brand.to_vec();
    payload.extend_from_slice(&0u32.to_be_bytes());
    for compatible in compatible {
        payload.extend_from_slice(*compatible);
    }
    let mut result = atom(b"ftyp", &payload);
    result.extend_from_slice(boxes);
    result
}
fn heif(brand: &[u8; 4], children: &[u8]) -> Vec<u8> {
    branded(brand, &[], &full_atom(b"meta", children))
}
fn movie(brand: &[u8; 4], children: &[u8]) -> Vec<u8> {
    branded(brand, &[], &atom(b"moov", children))
}
fn item(id: u16, kind: &[u8; 4], content_type: Option<&str>) -> Vec<u8> {
    let mut payload = vec![2, 0, 0, 0];
    payload.extend_from_slice(&id.to_be_bytes());
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(kind);
    payload.extend_from_slice(b"private item name\0");
    if let Some(content_type) = content_type {
        payload.extend_from_slice(content_type.as_bytes());
        payload.push(0);
    }
    atom(b"infe", &payload)
}
fn information(items: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = (items.len() as u16).to_be_bytes().to_vec();
    for item in items {
        payload.extend_from_slice(item);
    }
    full_atom(b"iinf", &payload)
}
fn location(id: u16, method: u16, offset: u32, length: u32, reference: u16) -> Vec<u8> {
    let mut payload = vec![1, 0, 0, 0, 0x44, 0];
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload.extend_from_slice(&id.to_be_bytes());
    payload.extend_from_slice(&method.to_be_bytes());
    payload.extend_from_slice(&reference.to_be_bytes());
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload.extend_from_slice(&offset.to_be_bytes());
    payload.extend_from_slice(&length.to_be_bytes());
    atom(b"iloc", &payload)
}
fn codes(data: &[u8], format: Format) -> Vec<String> {
    bmff::inspect(data, format, &Limits::default())
        .unwrap()
        .findings
        .into_iter()
        .map(|finding| finding.code)
        .collect()
}

#[test]
fn major_and_compatible_brands_identify_four_media_families() {
    for (major, compatible, expected) in [
        (b"heic", b"mif1", Format::Heic),
        (b"mif1", b"avif", Format::Avif),
        (b"isom", b"mp42", Format::Mp4),
        (b"qt  ", b"isom", Format::Mov),
    ] {
        let data = branded(major, &[compatible], &[]);
        assert_eq!(
            bmff::identify(&data, Path::new("misleading.txt")),
            Some(expected)
        );
        assert!(!expected.is_image());
        assert!(expected.is_media_container());
    }
    assert_eq!(
        bmff::identify(&branded(b"zzzz", &[], &[]), Path::new("fake.heic")),
        None
    );
    assert_eq!(
        bmff::identify(&atom(b"moov", &[]), Path::new("legacy.mov")),
        Some(Format::Mov)
    );
}

#[test]
fn clean_controls_have_no_privacy_metadata_or_watermark_detection_claim() {
    for (data, format) in [
        (heif(b"heic", &[]), Format::Heic),
        (heif(b"avif", &[]), Format::Avif),
        (movie(b"mp42", &[]), Format::Mp4),
        (movie(b"qt  ", &[]), Format::Mov),
    ] {
        let result = bmff::inspect(&data, format, &Limits::default()).unwrap();
        assert!(!result.rewrite_supported);
        assert!(result.limited_support);
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.code == "bmff.audit.scope")
        );
        assert!(fileveil_formats::sanitize(&data, format, &Limits::default()).is_err());
    }
}

#[test]
fn quicktime_keys_timestamps_and_values_are_reported_without_values() {
    let mut keys = 3u32.to_be_bytes().to_vec();
    for key in [
        "com.apple.quicktime.location.ISO6709",
        "com.apple.quicktime.model",
        "com.apple.quicktime.creationdate",
    ] {
        keys.extend_from_slice(&((key.len() + 8) as u32).to_be_bytes());
        keys.extend_from_slice(b"mdta");
        keys.extend_from_slice(key.as_bytes());
    }
    let values = atom(
        b"ilst",
        &atom(&1u32.to_be_bytes(), &atom(b"data", b"PRIVATE-COORDINATES")),
    );
    let mut metadata = full_atom(b"keys", &keys);
    metadata.extend_from_slice(&values);
    let mut children = full_atom(b"meta", &metadata);
    let mut timestamps = 123u32.to_be_bytes().to_vec();
    timestamps.extend_from_slice(&456u32.to_be_bytes());
    children.extend_from_slice(&full_atom(b"mvhd", &timestamps));
    let data = movie(b"qt  ", &children);
    let result = inspect(&data, Path::new("sample.mov"), &Limits::default()).unwrap();
    for code in [
        "bmff.metadata.location",
        "bmff.metadata.device",
        "bmff.metadata.creation_time",
        "bmff.metadata.timestamps",
        "bmff.metadata.value",
    ] {
        assert!(
            result.findings.iter().any(|finding| finding.code == code),
            "{code}"
        );
    }
    let rendered = format!("{:?}", result.findings);
    assert!(!rendered.contains("PRIVATE-COORDINATES"));
    assert!(!rendered.contains("com.apple.quicktime"));
}

#[test]
fn heif_exif_item_is_resolved_with_idat_and_reuses_bounded_tiff_parser() {
    let mut tiff = b"II\x2a\0\x08\0\0\0\x01\0".to_vec();
    tiff.extend_from_slice(&0x013bu16.to_le_bytes());
    tiff.extend_from_slice(&2u16.to_le_bytes());
    tiff.extend_from_slice(&4u32.to_le_bytes());
    tiff.extend_from_slice(b"ME!\0");
    tiff.extend_from_slice(&0u32.to_le_bytes());
    let mut exif = 0u32.to_be_bytes().to_vec();
    exif.extend_from_slice(&tiff);
    let mut exif_information = item(1, b"Exif", None);
    exif_information[11] = 1; // HEIF's standard hidden-item flag is valid for EXIF.
    let mut children = information(&[exif_information]);
    children.extend_from_slice(&location(1, 1, 0, exif.len() as u32, 0));
    children.extend_from_slice(&atom(b"idat", &exif));
    let data = heif(b"heic", &children);
    let codes = codes(&data, Format::Heic);
    assert!(codes.contains(&"bmff.metadata.exif_item".into()));
    assert!(codes.contains(&"bmff.exif.identity".into()));
    assert!(codes.contains(&"bmff.structure.hidden_item".into()));
}

#[test]
fn avif_xmp_items_are_resolved_without_xml_execution_or_value_disclosure() {
    let xmp = b"<x:xmpmeta>PRIVATE-AUTHOR</x:xmpmeta>";
    let mut children = information(&[item(2, b"mime", Some("application/rdf+xml"))]);
    children.extend_from_slice(&location(2, 1, 0, xmp.len() as u32, 0));
    children.extend_from_slice(&atom(b"idat", xmp));
    let data = heif(b"avif", &children);
    let result = inspect(&data, Path::new("image.avif"), &Limits::default()).unwrap();
    assert_eq!(result.format, Format::Avif);
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.code == "bmff.metadata.xmp_item")
    );
    assert!(!format!("{:?}", result.findings).contains("PRIVATE-AUTHOR"));
    assert!(!format!("{:?}", result.findings).contains("private item name"));
}

#[test]
fn unknown_boxes_and_uuid_have_offsets_without_vendor_or_watermark_inference() {
    let mut children = atom(b"zzzz", b"PRIVATE-VENDOR-PAYLOAD");
    let mut uuid = vec![7u8; 16];
    uuid.extend_from_slice(b"PRIVATE-UUID-PAYLOAD");
    children.extend_from_slice(&atom(b"uuid", &uuid));
    let data = movie(b"mp42", &children);
    let result = bmff::inspect(&data, Format::Mp4, &Limits::default()).unwrap();
    for code in ["bmff.structure.unknown_box", "bmff.structure.uuid"] {
        let finding = result
            .findings
            .iter()
            .find(|finding| finding.code == code)
            .unwrap();
        assert!(finding.location.contains("box@"));
        assert!(finding.location.contains("bytes="));
        assert_eq!(finding.action, fileveil_core::Action::Preserve);
    }
    assert!(!format!("{:?}", result.findings).contains("PRIVATE-"));
}

#[test]
fn external_item_references_are_reported_without_access_and_bad_extents_fail_closed() {
    let info = information(&[item(1, b"Exif", None)]);
    let mut external = info.clone();
    external.extend_from_slice(&location(1, 0, u32::MAX, u32::MAX, 1));
    assert!(
        codes(&heif(b"heic", &external), Format::Heic)
            .contains(&"bmff.structure.unresolved_item".into())
    );
    for method in [0, 1] {
        let mut children = info.clone();
        children.extend_from_slice(&location(1, method, u32::MAX, u32::MAX, 0));
        assert!(
            bmff::inspect(&heif(b"heic", &children), Format::Heic, &Limits::default()).is_err()
        );
    }
}

#[test]
fn malformed_headers_sizes_trailing_bytes_and_uuid_fail_closed() {
    for invalid in [
        vec![0, 0, 0, 4, b'f', b'r', b'e', b'e'],
        vec![0, 0, 0, 1, b'f', b'r', b'e', b'e', 0],
        vec![0, 0, 0, 8, b'u', b'u', b'i', b'd'],
        [
            1u32.to_be_bytes().as_slice(),
            b"free",
            &u64::MAX.to_be_bytes(),
        ]
        .concat(),
        b"trailing".to_vec(),
    ] {
        let data = movie(b"mp42", &invalid);
        assert!(bmff::inspect(&data, Format::Mp4, &Limits::default()).is_err());
    }
    let mut data = movie(b"mp42", &[]);
    data.extend_from_slice(b"private tail");
    assert!(bmff::inspect(&data, Format::Mp4, &Limits::default()).is_err());
}

#[test]
fn extended_size_and_zero_to_parent_end_are_bounded() {
    let extended = [1u32.to_be_bytes().as_slice(), b"free", &16u64.to_be_bytes()].concat();
    assert!(bmff::inspect(&movie(b"mp42", &extended), Format::Mp4, &Limits::default()).is_ok());
    let open = [0u32.to_be_bytes().as_slice(), b"free", b"unused"].concat();
    assert!(bmff::inspect(&movie(b"qt  ", &open), Format::Mov, &Limits::default()).is_ok());
}

#[test]
fn depth_member_and_metadata_limits_are_enforced() {
    let mut nested = Vec::new();
    for _ in 0..34 {
        nested = atom(b"trak", &nested);
    }
    assert!(bmff::inspect(&movie(b"mp42", &nested), Format::Mp4, &Limits::default()).is_err());
    let limits = Limits {
        max_members: 2,
        ..Default::default()
    };
    let many = movie(b"mp42", &atom(b"free", &[]));
    assert!(bmff::inspect(&many, Format::Mp4, &limits).is_err());
    let limits = Limits {
        max_metadata_bytes: 4,
        ..Default::default()
    };
    let uuid = atom(b"uuid", &[0; 24]);
    assert!(bmff::inspect(&movie(b"mp42", &uuid), Format::Mp4, &limits).is_err());
}

#[test]
fn item_counts_duplicates_and_invalid_field_widths_fail_closed() {
    let mut entries = 2u16.to_be_bytes().to_vec();
    entries.extend_from_slice(&item(1, b"Exif", None));
    assert!(
        bmff::inspect(
            &heif(b"heic", &full_atom(b"iinf", &entries)),
            Format::Heic,
            &Limits::default()
        )
        .is_err()
    );
    let duplicate = information(&[item(1, b"Exif", None), item(1, b"Exif", None)]);
    assert!(bmff::inspect(&heif(b"heic", &duplicate), Format::Heic, &Limits::default()).is_err());
    let malformed = atom(b"iloc", &[1, 0, 0, 0, 0x94, 0, 0, 0]);
    assert!(bmff::inspect(&heif(b"heic", &malformed), Format::Heic, &Limits::default()).is_err());
}

#[test]
fn native_codec_fixtures_expose_metadata_through_the_normal_format_entry_point() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    for (name, format, required) in [
        ("heic_exif_gps.heic", Format::Heic, "bmff.exif.gps"),
        ("avif_exif_gps.avif", Format::Avif, "bmff.metadata.xmp_item"),
        (
            "mp4_container_times.mp4",
            Format::Mp4,
            "bmff.metadata.timestamps",
        ),
        (
            "mov_model_metadata.mov",
            Format::Mov,
            "bmff.metadata.device",
        ),
    ] {
        let path = root.join(name);
        let original = std::fs::read(&path).unwrap();
        let report = inspect(&original, &path, &Limits::default()).unwrap();
        assert_eq!(report.format, format);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == required),
            "{name}"
        );
        assert!(report.rewrite_supported, "{name}: {:?}", report.blockers);
        assert_eq!(std::fs::read(path).unwrap(), original);
    }
}

#[test]
fn native_codec_samples_complete_metadata_rewrite_and_payload_verification() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    for (name, format) in [
        ("heic_exif_gps.heic", Format::Heic),
        ("avif_exif_gps.avif", Format::Avif),
        ("mp4_container_times.mp4", Format::Mp4),
        ("mov_model_metadata.mov", Format::Mov),
    ] {
        let original = std::fs::read(root.join(name)).unwrap();
        let before = bmff::inspect(&original, format, &Limits::default()).unwrap();
        assert!(before.rewrite_supported, "{name}: {:?}", before.blockers);
        let clean = bmff::sanitize(&original, format, &Limits::default()).unwrap();
        assert_eq!(clean.len(), original.len());
        assert_ne!(clean, original, "{name}");
        let after = bmff::inspect(&clean, format, &Limits::default()).unwrap();
        assert!(after.rewrite_supported, "{name}: {:?}", after.blockers);
        assert_eq!(before.content_digest, after.content_digest, "{name}");
        assert_eq!(
            bmff::sanitize(&clean, format, &Limits::default()).unwrap(),
            clean,
            "{name}"
        );
        assert!(
            after.findings.iter().all(|finding| !matches!(
                finding.action,
                fileveil_core::Action::Remove
                    | fileveil_core::Action::Normalize
                    | fileveil_core::Action::Rebuild
            )),
            "{name}: {:?}",
            after.findings
        );
        for private in [
            b"Synthetic Author".as_slice(),
            b"FileVeil Synthetic Device".as_slice(),
        ] {
            assert!(
                !clean.windows(private.len()).any(|window| window == private),
                "{name}"
            );
        }
        assert_eq!(
            bmff::retained_media_digest(&original, format, &Limits::default()).unwrap(),
            bmff::retained_media_digest(&clean, format, &Limits::default()).unwrap(),
            "{name}"
        );
        let verified = bmff::verify(&original, &clean, format, &Limits::default()).unwrap();
        assert_eq!(verified.integrity.content_equal, Some(true));
        assert_eq!(verified.result, fileveil_core::Outcome::PartiallyVerified);
    }
}

#[test]
fn credentials_and_shared_image_metadata_extents_protect_rewriting() {
    let signed =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../fileveil-engine/tests/fixtures/provenance");
    for (name, format) in [
        ("signed.heic", Format::Heic),
        ("signed.avif", Format::Avif),
        ("signed.mp4", Format::Mp4),
        ("signed.mov", Format::Mov),
    ] {
        let bytes = std::fs::read(signed.join(name)).unwrap();
        let audit = bmff::inspect(&bytes, format, &Limits::default()).unwrap();
        assert!(!audit.rewrite_supported);
        assert!(
            audit
                .findings
                .iter()
                .any(|finding| finding.code == "bmff.provenance")
        );
        assert!(bmff::sanitize(&bytes, format, &Limits::default()).is_err());
    }
    let exif = [
        0u32.to_be_bytes().as_slice(),
        b"II\x2a\0\x08\0\0\0\0\0\0\0\0\0",
    ]
    .concat();
    let mut children = information(&[item(1, b"hvc1", None), item(2, b"Exif", None)]);
    children.extend_from_slice(&location(1, 1, 0, exif.len() as u32, 0));
    children.extend_from_slice(&location(2, 1, 0, exif.len() as u32, 0));
    children.extend_from_slice(&atom(b"idat", &exif));
    let shared = heif(b"heic", &children);
    let audit = bmff::inspect(&shared, Format::Heic, &Limits::default()).unwrap();
    assert!(!audit.rewrite_supported);
    assert!(
        audit
            .blockers
            .iter()
            .any(|message| message.contains("shares encoded media"))
    );
    assert!(bmff::sanitize(&shared, Format::Heic, &Limits::default()).is_err());
}

#[test]
fn quicktime_privacy_keys_are_removed_while_playback_and_pairing_keys_survive() {
    let mut key_payload = 3u32.to_be_bytes().to_vec();
    for key in [
        "com.apple.quicktime.model",
        "com.apple.quicktime.full-frame-rate-playback-intent",
        "com.apple.quicktime.content.identifier",
    ] {
        key_payload.extend_from_slice(&((key.len() + 8) as u32).to_be_bytes());
        key_payload.extend_from_slice(b"mdta");
        key_payload.extend_from_slice(key.as_bytes());
    }
    let mut values = Vec::new();
    for (index, value) in [
        b"PRIVATE-DEVICE".as_slice(),
        b"KEEP-PLAYBACK",
        b"KEEP-CONTENT-ID",
    ]
    .iter()
    .enumerate()
    {
        values.extend_from_slice(&atom(
            &((index + 1) as u32).to_be_bytes(),
            &atom(b"data", value),
        ));
    }
    let mut metadata = full_atom(b"keys", &key_payload);
    metadata.extend_from_slice(&atom(b"ilst", &values));
    let mut data = movie(b"qt  ", &full_atom(b"meta", &metadata));
    data.extend_from_slice(&atom(b"mdat", b"RETAINED-CODED-MEDIA"));
    let clean = bmff::sanitize(&data, Format::Mov, &Limits::default()).unwrap();
    assert!(
        !clean
            .windows(b"PRIVATE-DEVICE".len())
            .any(|value| value == b"PRIVATE-DEVICE")
    );
    for retained in [b"KEEP-PLAYBACK".as_slice(), b"KEEP-CONTENT-ID"] {
        assert!(clean.windows(retained.len()).any(|value| value == retained));
    }
    let after = bmff::inspect(&clean, Format::Mov, &Limits::default()).unwrap();
    assert!(
        !after
            .findings
            .iter()
            .any(|finding| finding.code == "bmff.metadata.device")
    );
    assert!(
        after
            .findings
            .iter()
            .any(|finding| finding.code == "bmff.metadata.content_pairing"
                && finding.action == fileveil_core::Action::Preserve)
    );
    bmff::verify(&data, &clean, Format::Mov, &Limits::default()).unwrap();
}

#[test]
fn encoded_sample_and_presentation_tampering_fail_the_independent_media_digest() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let original = std::fs::read(root.join("mp4_container_times.mp4")).unwrap();
    let mut clean = bmff::sanitize(&original, Format::Mp4, &Limits::default()).unwrap();
    let kind = clean.windows(4).position(|bytes| bytes == b"mdat").unwrap();
    let extended = clean[kind - 4..kind] == 1u32.to_be_bytes();
    let payload = kind + 4 + if extended { 8 } else { 0 };
    clean[payload + 5] ^= 1;
    assert_ne!(
        bmff::retained_media_digest(&original, Format::Mp4, &Limits::default()).unwrap(),
        bmff::retained_media_digest(&clean, Format::Mp4, &Limits::default()).unwrap()
    );
    assert!(bmff::verify(&original, &clean, Format::Mp4, &Limits::default()).is_err());
    let original = std::fs::read(root.join("heic_exif_gps.heic")).unwrap();
    let mut clean = bmff::sanitize(&original, Format::Heic, &Limits::default()).unwrap();
    let rotation = clean
        .windows(8)
        .position(|bytes| bytes == b"\0\0\0\x09irot")
        .unwrap()
        + 8;
    clean[rotation] ^= 1;
    assert_ne!(
        bmff::retained_media_digest(&original, Format::Heic, &Limits::default()).unwrap(),
        bmff::retained_media_digest(&clean, Format::Heic, &Limits::default()).unwrap()
    );
    assert!(bmff::verify(&original, &clean, Format::Heic, &Limits::default()).is_err());
}

#[test]
fn unknown_vendor_extensions_are_retained_and_remain_unassessed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let mut original = std::fs::read(root.join("mov_model_metadata.mov")).unwrap();
    let mut extension = vec![0x45; 16];
    extension.extend_from_slice(b"PRIVATE-UNKNOWN-VENDOR-FIELD");
    original.extend_from_slice(&atom(b"uuid", &extension));
    let clean = bmff::sanitize(&original, Format::Mov, &Limits::default()).unwrap();
    assert!(
        clean
            .windows(extension.len())
            .any(|value| value == extension)
    );
    let verified = bmff::verify(&original, &clean, Format::Mov, &Limits::default()).unwrap();
    assert!(
        verified
            .findings
            .iter()
            .any(|finding| finding.code == "bmff.structure.uuid"
                && finding.action == fileveil_core::Action::Preserve
                && finding.state == fileveil_core::FindingState::Remains)
    );
    assert_eq!(verified.result, fileveil_core::Outcome::PartiallyVerified);
}

#[test]
fn encrypted_sample_entries_and_non_media_chunk_offsets_are_protected() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let original = std::fs::read(root.join("mp4_container_times.mp4")).unwrap();
    let mut encrypted = original.clone();
    let description = encrypted
        .windows(4)
        .position(|value| value == b"stsd")
        .unwrap();
    encrypted[description + 16..description + 20].copy_from_slice(b"encv");
    let audit = bmff::inspect(&encrypted, Format::Mp4, &Limits::default()).unwrap();
    assert!(!audit.rewrite_supported);
    assert!(
        audit
            .blockers
            .iter()
            .any(|message| message.contains("Encrypted media sample"))
    );
    assert!(bmff::sanitize(&encrypted, Format::Mp4, &Limits::default()).is_err());
    let mut invalid_offset = original;
    let offsets = invalid_offset
        .windows(4)
        .position(|value| value == b"stco")
        .unwrap();
    invalid_offset[offsets + 12..offsets + 16].copy_from_slice(&0u32.to_be_bytes());
    let audit = bmff::inspect(&invalid_offset, Format::Mp4, &Limits::default()).unwrap();
    assert!(!audit.rewrite_supported);
    assert!(
        audit
            .blockers
            .iter()
            .any(|message| message.contains("outside media-data"))
    );
    assert!(bmff::sanitize(&invalid_offset, Format::Mp4, &Limits::default()).is_err());
}

#[test]
fn nested_image_metadata_namespaces_are_protected() {
    let mut children = full_atom(b"meta", &[]);
    children.extend_from_slice(&atom(b"idat", &[0; 8]));
    let original = heif(b"heic", &children);
    let audit = bmff::inspect(&original, Format::Heic, &Limits::default()).unwrap();
    assert!(!audit.rewrite_supported);
    assert!(
        audit
            .blockers
            .iter()
            .any(|message| message.contains("Nested image metadata namespaces"))
    );
    assert!(bmff::sanitize(&original, Format::Heic, &Limits::default()).is_err());
}

#[test]
fn quicktime_key_reconstruction_also_cleans_nested_standard_metadata() {
    for (kind, payload, protected) in [
        (
            *b"XMP_",
            b"<x:xmpmeta>PRIVATE-XMP-AUTHOR</x:xmpmeta>".as_slice(),
            false,
        ),
        (
            *b"xml ",
            b"<x:xmpmeta>PRIVATE-XML-AUTHOR</x:xmpmeta>".as_slice(),
            false,
        ),
        (
            *b"XMP_",
            b"<x:xmpmeta c2pa:provenance='protected'/>".as_slice(),
            true,
        ),
        (
            *b"XMP_",
            b"<x:xmpmeta tiff:Orientation='6'/>".as_slice(),
            true,
        ),
    ] {
        let key = b"com.apple.quicktime.model";
        let mut keys = 1u32.to_be_bytes().to_vec();
        keys.extend_from_slice(&((key.len() + 8) as u32).to_be_bytes());
        keys.extend_from_slice(b"mdta");
        keys.extend_from_slice(key);
        let mut children = full_atom(b"keys", &keys);
        children.extend_from_slice(&atom(
            b"ilst",
            &atom(&1u32.to_be_bytes(), &atom(b"data", b"PRIVATE-DEVICE")),
        ));
        children.extend_from_slice(&atom(&kind, payload));
        let mut original = movie(b"qt  ", &full_atom(b"meta", &children));
        original.extend_from_slice(&atom(b"mdat", b"UNCHANGED-CODED-SAMPLES"));
        let result = bmff::sanitize(&original, Format::Mov, &Limits::default());
        if protected {
            assert!(
                result.is_err(),
                "Nested XMP presentation and credentials must stay protected"
            );
        } else {
            let cleaned = result.unwrap();
            assert!(
                !cleaned
                    .windows(b"PRIVATE-".len())
                    .any(|bytes| bytes == b"PRIVATE-")
            );
            assert!(
                cleaned
                    .windows(b"UNCHANGED-CODED-SAMPLES".len())
                    .any(|bytes| bytes == b"UNCHANGED-CODED-SAMPLES")
            );
            assert_eq!(cleaned.len(), original.len());
            bmff::verify(&original, &cleaned, Format::Mov, &Limits::default()).unwrap();
            assert_eq!(
                bmff::sanitize(&cleaned, Format::Mov, &Limits::default()).unwrap(),
                cleaned
            );
        }
    }
}

#[test]
fn wide_image_property_trees_keep_payload_and_remove_selected_xmp() {
    let xmp = b"<x:xmpmeta>PRIVATE-WIDE-TREE</x:xmpmeta>";
    let mut children = information(&[
        item(1, b"av01", None),
        item(2, b"mime", Some("application/rdf+xml")),
    ]);
    children.extend_from_slice(&location(1, 1, 0, 1, 0));
    children.extend_from_slice(&location(2, 1, 1, xmp.len() as u32, 0));
    let properties = atom(b"colr", b"nclx\0\x01\0\x01\0\x01\x80").repeat(4_000);
    children.extend_from_slice(&atom(b"iprp", &atom(b"ipco", &properties)));
    let mut payload = vec![0x42];
    payload.extend_from_slice(xmp);
    children.extend_from_slice(&atom(b"idat", &payload));
    let original = heif(b"avif", &children);
    let started = std::time::Instant::now();
    let cleaned = bmff::sanitize(&original, Format::Avif, &Limits::default()).unwrap();
    println!("4000-property HEIF rewrite elapsed {:?}", started.elapsed());
    assert_eq!(cleaned.len(), original.len());
    assert!(
        !cleaned
            .windows(b"PRIVATE-WIDE-TREE".len())
            .any(|bytes| bytes == b"PRIVATE-WIDE-TREE")
    );
    assert_eq!(
        bmff::retained_media_digest(&original, Format::Avif, &Limits::default()).unwrap(),
        bmff::retained_media_digest(&cleaned, Format::Avif, &Limits::default()).unwrap()
    );
    bmff::verify(&original, &cleaned, Format::Avif, &Limits::default()).unwrap();
}

// FVPROV1 26869 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI4ZTJhNzdkY2VmZTYxOGRiMDg2ZTU2MjYyODdjYjIzNWFmYmY4Y2Y0ZGY1ZWUyZWVhZGNlNWIyNWViMDUxNDY0IiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1mb3JtYXRzL3Rlc3RzL2JtZmYucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiJjODkyNmI2YTc5ZTA1ZTQyZTYxNzA5ZTgyMjc0YWQ0NzczZDM4OGRlOTg2ZGQ1MTU2NzY3MjNmODVkY2ZkNDMwZjdmMzRkOTllOWVlZWU2ZWIyNGEzYjRkNWQyZjQ4NjllOTZiYWEyMzU3ZmU5ZWRiNDk5MjNkZmM5NzdhZDEwZSJ9XX1d FVPROV1-END
