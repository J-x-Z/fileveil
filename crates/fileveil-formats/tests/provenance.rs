// SPDX-License-Identifier: MPL-2.0
use fileveil_core::{Action, Error, Format, Limits, Policy, SanitizeOptions, digest};
use fileveil_formats::{inspect, inspect_with_options, sanitize, sanitize_with_options};
use std::path::Path;
const JPEG: &[u8] = include_bytes!("../../fileveil-engine/tests/fixtures/provenance/signed.jpg");
const PNG: &[u8] = include_bytes!("../../fileveil-engine/tests/fixtures/provenance/signed.png");
fn options() -> SanitizeOptions {
    SanitizeOptions {
        policy: Policy::Deep,
        remove_provenance: true,
        ..Default::default()
    }
}
fn jpeg_segment(marker: u8, payload: &[u8]) -> Vec<u8> {
    let mut segment = vec![255, marker];
    segment.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    segment.extend_from_slice(payload);
    segment
}
fn chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut data = (payload.len() as u32).to_be_bytes().to_vec();
    data.extend_from_slice(kind);
    data.extend_from_slice(payload);
    data.extend_from_slice(&crc32fast::hash(&data[4..]).to_be_bytes());
    data
}
#[test]
fn actual_sdk_credentials_require_explicit_deep_and_keep_pixels() {
    for (original, format, hint) in [
        (JPEG, Format::Jpeg, "signed.jpg"),
        (PNG, Format::Png, "signed.png"),
    ] {
        let original_hash = digest(original);
        let before = inspect(original, Path::new(hint), &Limits::default()).unwrap();
        assert!(!before.blockers.is_empty());
        assert!(sanitize(original, format, &Limits::default()).is_err());
        let selected =
            inspect_with_options(original, Path::new(hint), &Limits::default(), &options())
                .unwrap();
        assert!(selected.blockers.is_empty(), "{:?}", selected.blockers);
        assert!(selected.findings.iter().any(|finding| finding.layer
            == fileveil_core::RiskLayer::ProvenanceCredential
            && finding.action == Action::Remove));
        let output =
            sanitize_with_options(original, format, &Limits::default(), &options()).unwrap();
        let after = inspect(&output, Path::new(hint), &Limits::default()).unwrap();
        assert!(after.blockers.is_empty());
        assert_eq!(selected.content_digest, after.content_digest);
        assert_eq!(
            image::load_from_memory(original).unwrap().to_rgba8(),
            image::load_from_memory(&output).unwrap().to_rgba8()
        );
        assert_eq!(digest(original), original_hash);
        let mut invalid = options();
        invalid.policy = Policy::Safe;
        assert!(matches!(
            sanitize_with_options(original, format, &Limits::default(), &invalid),
            Err(Error::Blocked(_))
        ));
    }
}
#[test]
fn recognized_jpeg_jumbf_continuation_fragments_share_the_authorized_scope() {
    let mut offset = 2;
    while JPEG[offset + 1] != 0xeb {
        let size = u16::from_be_bytes([JPEG[offset + 2], JPEG[offset + 3]]) as usize;
        offset += 2 + size;
    }
    let length = u16::from_be_bytes([JPEG[offset + 2], JPEG[offset + 3]]) as usize;
    let payload = &JPEG[offset + 4..offset + 2 + length];
    assert!(payload.len() > 100);
    let mut first = payload[..80].to_vec();
    first[4..8].copy_from_slice(&1u32.to_be_bytes());
    let mut second = payload[..8].to_vec();
    second[4..8].copy_from_slice(&2u32.to_be_bytes());
    second.extend_from_slice(&payload[80..]);
    let mut fragmented = JPEG[..offset].to_vec();
    fragmented.extend(jpeg_segment(0xeb, &first));
    fragmented.extend(jpeg_segment(0xeb, &second));
    fragmented.extend_from_slice(&JPEG[offset + 2 + length..]);
    let output =
        sanitize_with_options(&fragmented, Format::Jpeg, &Limits::default(), &options()).unwrap();
    assert_eq!(
        image::load_from_memory(&fragmented).unwrap().to_rgba8(),
        image::load_from_memory(&output).unwrap().to_rgba8()
    );
    assert!(
        !inspect(&output, Path::new("output.jpg"), &Limits::default())
            .unwrap()
            .findings
            .iter()
            .any(|finding| finding.code == "jpeg.provenance")
    );
}
#[test]
fn explicit_provenance_selection_preserves_orientation_and_unknown_jumbf_protections() {
    let mut unknown = JPEG[..2].to_vec();
    unknown.extend(jpeg_segment(0xeb, b"JP unknown c2pa substring"));
    unknown.extend_from_slice(&JPEG[2..]);
    assert!(matches!(
        sanitize_with_options(&unknown, Format::Jpeg, &Limits::default(), &options()),
        Err(Error::Blocked(_))
    ));
    let mut orientation = JPEG[..2].to_vec();
    orientation.extend(jpeg_segment(
        0xe1,
        b"http://ns.adobe.com/xap/1.0/\0<c2pa orientation='6'/ >",
    ));
    orientation.extend_from_slice(&JPEG[2..]);
    assert!(matches!(
        sanitize_with_options(&orientation, Format::Jpeg, &Limits::default(), &options()),
        Err(Error::Blocked(_))
    ));
    let mut animated = PNG[..33].to_vec();
    animated.extend(chunk(b"acTL", &[0, 0, 0, 1, 0, 0, 0, 0]));
    animated.extend_from_slice(&PNG[33..]);
    assert!(matches!(
        sanitize_with_options(&animated, Format::Png, &Limits::default(), &options()),
        Err(Error::Blocked(_))
    ));
    let mut orientation = PNG[..33].to_vec();
    orientation.extend(chunk(b"tEXt", b"Source\0c2pa orientation=6"));
    orientation.extend_from_slice(&PNG[33..]);
    assert!(matches!(
        sanitize_with_options(&orientation, Format::Png, &Limits::default(), &options()),
        Err(Error::Blocked(_))
    ));
}

// FVPROV1 5483 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIwMWY3MDQ2ZjcxNGNkMDc2NWMxMWM5YjY0ODcyNDIzNmY1NmVhMDNhZDJjZjdlYmRkZDE2YzdmMjM3ZDJhOWViIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4zIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMyIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1mb3JtYXRzL3Rlc3RzL3Byb3ZlbmFuY2UucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI1YThhYWQxNGU2NGZlMDFhNGUzYjMwZjVjYWIzYTBjODkyMWQ5MzhmOGU2YzFkYWI0ODM3OTg0MzJhZDY2NmFiZTg3YjA1NGNiNWQ0MjQ4NjE2MmEzMzllZThjYjY0YTRiZjM2OWMxMzhjYTlmZDNiNWQ4M2JhMTA4OWY1YzQwNiJ9XX1d FVPROV1-END
