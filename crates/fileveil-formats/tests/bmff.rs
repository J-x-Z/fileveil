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
        assert!(!report.rewrite_supported);
        assert_eq!(std::fs::read(path).unwrap(), original);
    }
}
