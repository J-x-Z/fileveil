// SPDX-License-Identifier: MPL-2.0
use std::{fs, path::Path};

use fileveil_core::{FilesystemOptions, Format, Limits, Outcome, Policy, SanitizeOptions};
use fileveil_engine::{sanitize, scan, verify};

fn fixtures() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn media_payload(data: &[u8]) -> Vec<&[u8]> {
    let mut cursor = 0;
    let mut payloads = Vec::new();
    while cursor < data.len() {
        let mut header = 8;
        let size = u32::from_be_bytes(data[cursor..cursor + 4].try_into().unwrap());
        let size = match size {
            0 => data.len() - cursor,
            1 => {
                header = 16;
                u64::from_be_bytes(data[cursor + 8..cursor + 16].try_into().unwrap()) as usize
            }
            size => size as usize,
        };
        assert!(size >= header && cursor + size <= data.len());
        if &data[cursor + 4..cursor + 8] == b"mdat" {
            payloads.push(&data[cursor + header..cursor + size]);
        }
        cursor += size;
    }
    payloads
}

#[test]
fn normal_mobile_media_scan_sanitize_verify_preserves_originals_and_video_streams() {
    let directory = tempfile::tempdir().unwrap();
    for (name, format) in [
        ("heic_exif_gps.heic", Format::Heic),
        ("avif_exif_gps.avif", Format::Avif),
        ("mp4_container_times.mp4", Format::Mp4),
        ("mp4_av_source.mp4", Format::Mp4),
        ("mov_model_metadata.mov", Format::Mov),
    ] {
        let input = fixtures().join(name);
        let bytes = fs::read(&input).unwrap();
        let original = scan(&input, &Limits::default()).unwrap();
        assert_eq!(original.input_format, format.mime());
        let output = directory.path().join(name);
        let cleaned = sanitize(&input, Some(&output), &Limits::default()).unwrap();
        assert!(matches!(
            cleaned.result,
            Outcome::VerifiedWithinScope | Outcome::PartiallyVerified
        ));
        assert_eq!(cleaned.integrity.original_unchanged, Some(true));
        assert_eq!(cleaned.integrity.content_equal, Some(true));
        assert_eq!(cleaned.integrity.pixel_equal, None);
        let checked = verify(&input, &output, &Limits::default()).unwrap();
        assert_eq!(checked.integrity.content_equal, Some(true));
        assert_eq!(checked.integrity.original_unchanged, Some(true));
        assert_eq!(fs::read(&input).unwrap(), bytes);
        if matches!(format, Format::Mp4 | Format::Mov) {
            let new_bytes = fs::read(&output).unwrap();
            assert_eq!(media_payload(&bytes), media_payload(&new_bytes));
        }
    }
}

#[test]
fn signed_mobile_media_remains_protected_through_normal_entry_points() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/provenance");
    let directory = tempfile::tempdir().unwrap();
    for name in ["signed.heic", "signed.avif", "signed.mp4", "signed.mov"] {
        let input = root.join(name);
        let output = directory.path().join(name);
        let bytes = fs::read(&input).unwrap();
        let report = scan(&input, &Limits::default()).unwrap();
        assert_eq!(report.provenance.as_ref().unwrap()["signature"], "valid");
        assert!(sanitize(&input, Some(&output), &Limits::default()).is_err());
        assert!(!output.exists());
        assert_eq!(fs::read(input).unwrap(), bytes);
    }
}

#[test]
fn deep_media_copies_verify_selected_filesystem_policy() {
    let input = fixtures().join("mp4_container_times.mp4");
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("media.mp4");
    let options = SanitizeOptions {
        policy: Policy::Deep,
        filesystem: FilesystemOptions {
            normalize_output_timestamps: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let result = fileveil_engine::advanced::sanitize_with_options(
        &input,
        Some(&output),
        &Limits::default(),
        &options,
    )
    .unwrap();
    assert_eq!(
        result.advanced.as_ref().unwrap()["selected_scope_verified"],
        true
    );
    assert_eq!(
        result.advanced.as_ref().unwrap()["media"]["retained_encoded_payload_and_structure_equal"],
        true
    );
    fileveil_engine::advanced::verify_with_options(&input, &output, &Limits::default(), &options)
        .unwrap();
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "uses independent platform ImageIO and AVAssetReader decoders"]
fn native_decoders_preserve_mobile_pixels_frames_and_timing() {
    let directory = tempfile::tempdir().unwrap();
    let helper = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/media_fidelity.swift");
    for name in [
        "heic_exif_gps.heic",
        "avif_exif_gps.avif",
        "mp4_container_times.mp4",
        "mov_model_metadata.mov",
        "mp4_av_source.mp4",
    ] {
        let input = fixtures().join(name);
        let output = directory.path().join(name);
        sanitize(&input, Some(&output), &Limits::default()).unwrap();
        let decoded = std::process::Command::new("/usr/bin/swift")
            .arg(&helper)
            .arg(&input)
            .arg(&output)
            .output()
            .unwrap();
        assert!(
            decoded.status.success(),
            "{}",
            String::from_utf8_lossy(&decoded.stderr)
        );
        let summaries: Vec<serde_json::Value> = String::from_utf8(decoded.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(summaries.len(), 2);
        assert_eq!(
            summaries[0], summaries[1],
            "Native decoder mismatch for {name}"
        );
    }
}

// FVPROV1 5761 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI3NjkyNTM4MmMzMWVlOTY4NGEyYjkzYjA5NGFiMWMzYjU5MTRkNDgxZWFjNGRjMjI0OGRmNDlmYTlmYTE5MzY1IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4yIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMiIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvdGVzdHMvbWVkaWEucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI2MDgwNDJkNjljY2QyZmZiYWE1Mzg4MWNjM2YxYTdlNWFiOWIxNzFhMWJhZjNhZjJhN2I0MWEzMzc1NjYyNmZjZjdjYjFhNDJhMDBiMWIxYmY2OTkwYmVjNDMxYjBhZDg2YWFiMjc5ZGYyMTA1YTk2NmIxMTEwYjFlNGE3NTcwMSJ9XX1d FVPROV1-END
