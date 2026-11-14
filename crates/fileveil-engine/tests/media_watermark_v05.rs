// SPDX-License-Identifier: MPL-2.0
use fileveil_core::{Format, Limits, Outcome, digest};
use fileveil_engine::{
    heritage::{self, HeritageAction, HeritageRequest, MarkSettings, container},
    media_pixels,
};
use fileveil_formats::bmff;
use std::{
    fs,
    path::{Path, PathBuf},
};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn nclx_properties(bytes: &[u8]) -> Option<&[u8]> {
    let offset = bytes.windows(8).position(|window| window == b"colrnclx")?;
    bytes.get(offset + 8..offset + 15)
}

fn boxed(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut bytes = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(kind);
    bytes.extend_from_slice(payload);
    bytes
}

fn image_structure(images: u16, extra_properties: &[u8]) -> Vec<u8> {
    let mut items = vec![0, 0, 0, 0];
    items.extend_from_slice(&images.to_be_bytes());
    for id in 1..=images {
        let mut info = vec![2, 0, 0, 0];
        info.extend_from_slice(&id.to_be_bytes());
        info.extend_from_slice(&[0, 0]);
        info.extend_from_slice(b"av01\0");
        items.extend(boxed(b"infe", &info));
    }
    let mut properties = boxed(b"ispe", &[0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 2, 0]);
    properties.extend(boxed(b"pixi", &[0, 0, 0, 0, 3, 8, 8, 8]));
    properties.extend_from_slice(extra_properties);
    let mut meta = vec![0, 0, 0, 0];
    meta.extend(boxed(b"pitm", &[0, 0, 0, 0, 0, 1]));
    meta.extend(boxed(b"iinf", &items));
    meta.extend(boxed(b"iprp", &boxed(b"ipco", &properties)));
    let mut bytes = boxed(b"ftyp", b"avif\0\0\0\0avif");
    bytes.extend(boxed(b"meta", &meta));
    bytes
}

#[test]
fn decoder_rejects_external_references_before_any_backend_runs() {
    let limits = Limits::default();
    for format in [Format::Heic, Format::Avif, Format::Mp4, Format::Mov] {
        let external = boxed(b"url ", b"\0\0\0\0file:///private/user-secret");
        let mut entries = vec![0, 0, 0, 0, 0, 0, 0, 1];
        entries.extend(external);
        let dref = boxed(
            b"moov",
            &boxed(
                b"trak",
                &boxed(
                    b"mdia",
                    &boxed(b"minf", &boxed(b"dinf", &boxed(b"dref", &entries))),
                ),
            ),
        );
        let error = bmff::validate_decoder_references(&dref, format, &limits).unwrap_err();
        assert!(error.to_string().contains("External"), "{error}");
        let mut local = vec![0, 0, 0, 0, 0, 0, 0, 1];
        local.extend(boxed(b"url ", &[0, 0, 0, 1]));
        assert!(
            bmff::validate_decoder_references(&boxed(b"dref", &local), format, &limits).is_ok()
        );
        local[7] = 2;
        assert!(
            bmff::validate_decoder_references(&boxed(b"dref", &local), format, &limits).is_err()
        );
    }
    // iloc version 0, zero-sized fields, one item, external data-reference 1.
    let iloc = boxed(b"iloc", &[0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0]);
    let mut meta = vec![0, 0, 0, 0];
    meta.extend(iloc);
    assert!(
        bmff::validate_decoder_references(&boxed(b"meta", &meta), Format::Avif, &limits).is_err()
    );
}

#[test]
fn pixel_rewrite_protects_auxiliary_hdr_depth_collections_and_canvases() {
    let limits = Limits::default();
    assert!(bmff::validate_pixel_rewrite(&image_structure(1, &[]), Format::Avif, &limits).is_ok());
    for property in [
        boxed(b"auxC", b"\0\0\0\0urn:aux:alpha\0"),
        boxed(b"colr", b"nclx\0\x09\0\x10\0\x09\x80"),
        boxed(b"pixi", &[0, 0, 0, 0, 3, 10, 10, 10]),
        boxed(b"av1C", &[0x81, 0, 0x40, 0]),
        boxed(b"av1C", &[0x81]),
    ] {
        assert!(
            bmff::validate_pixel_rewrite(&image_structure(1, &property), Format::Avif, &limits)
                .is_err()
        );
    }
    let mut hevc = vec![0; 23];
    hevc[0] = 1;
    hevc[17] = 2;
    assert!(
        bmff::validate_pixel_rewrite(
            &image_structure(1, &boxed(b"hvcC", &hevc)),
            Format::Heic,
            &limits
        )
        .is_err()
    );
    assert!(bmff::validate_pixel_rewrite(&image_structure(2, &[]), Format::Avif, &limits).is_err());
    let mut duplicate_meta = image_structure(1, &[]);
    duplicate_meta.extend_from_slice(&image_structure(1, &[])[20..]);
    assert!(bmff::validate_pixel_rewrite(&duplicate_meta, Format::Avif, &limits).is_err());
    let valid = image_structure(1, &[]);
    let mut cycle_meta = valid[28..].to_vec();
    let mut cycle_reference = vec![0, 0, 0, 0];
    cycle_reference.extend(boxed(b"dimg", &[0, 1, 0, 1, 0, 1]));
    cycle_meta.extend(boxed(b"iref", &cycle_reference));
    let mut cycle = valid[..20].to_vec();
    cycle.extend(boxed(b"meta", &cycle_meta));
    assert!(bmff::validate_pixel_rewrite(&cycle, Format::Avif, &limits).is_err());
    let mut sequence = image_structure(1, &[]);
    sequence.extend(boxed(b"moov", &[]));
    assert!(bmff::validate_pixel_rewrite(&sequence, Format::Avif, &limits).is_err());
    let mut over_budget = limits.clone();
    over_budget.max_pixels = 511 * 512;
    assert!(
        bmff::validate_pixel_dimensions(&image_structure(1, &[]), Format::Avif, &over_budget)
            .is_err()
    );
    over_budget.max_file_bytes = 8;
    assert!(
        bmff::validate_pixel_dimensions(&image_structure(1, &[]), Format::Avif, &over_budget)
            .is_err()
    );
    assert!(
        bmff::validate_pixel_dimensions(&image_structure(1, &[])[..20], Format::Avif, &limits)
            .is_err()
    );
    assert!(
        media_pixels::encode(
            &image::DynamicImage::new_rgb16(8, 8),
            Format::Avif,
            90,
            None,
            &limits
        )
        .is_err()
    );
    let mut profile_budget = limits;
    profile_budget.max_metadata_bytes = 4;
    assert!(
        media_pixels::encode(
            &image::DynamicImage::new_rgb8(8, 8),
            Format::Avif,
            90,
            Some(&[0; 5]),
            &profile_budget
        )
        .is_err()
    );
    let real_icc = fs::read(fixtures().join("heic_exif_gps.heic")).unwrap();
    let profile = bmff::embedded_icc_profile(&real_icc, Format::Heic, &Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(profile.len(), 500);
    assert_eq!(&profile[36..40], b"acsp");
}

#[test]
fn native_iso_carrier_roundtrip_is_byte_exact_and_preserves_originals() {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("signing.json");
    heritage::keygen(&key).unwrap();
    let limits = Limits::default();
    for (name, format) in [
        ("heic_exif_gps.heic", Format::Heic),
        ("avif_exif_gps.avif", Format::Avif),
        ("mp4_av_source.mp4", Format::Mp4),
        ("mov_model_metadata.mov", Format::Mov),
    ] {
        let input = fixtures().join(name);
        let original = fs::read(&input).unwrap();
        let marked = directory.path().join(format!("marked-{name}"));
        let request = HeritageRequest {
            action: HeritageAction::Mark,
            key_paths: vec![key.clone()],
            mark: MarkSettings {
                work_id: "media-work".into(),
                copy_id: "media-copy".into(),
                signature_v2: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let result = heritage::run(&input, Some(&marked), &request, &limits).unwrap();
        assert_eq!(result.integrity.original_unchanged, Some(true));
        let marked_bytes = fs::read(&marked).unwrap();
        let decoded = container::extract(&marked_bytes, format).unwrap();
        assert!(decoded.manifest.is_some());
        assert_eq!(decoded.base, original);
        let check = heritage::run(
            &marked,
            None,
            &HeritageRequest {
                action: HeritageAction::Verify,
                ..Default::default()
            },
            &limits,
        )
        .unwrap();
        assert_eq!(
            check.advanced.as_ref().unwrap()["heritage"]["verification"]["content_binding"],
            "valid"
        );
        let cleaned = directory.path().join(format!("cleaned-{name}"));
        let result = heritage::run(
            &marked,
            Some(&cleaned),
            &HeritageRequest {
                action: HeritageAction::Clean,
                ..Default::default()
            },
            &limits,
        )
        .unwrap();
        assert_ne!(result.result, Outcome::Failed);
        assert_eq!(fs::read(&cleaned).unwrap(), original);
        assert_eq!(fs::read(input).unwrap(), original);
        let mut open_ended = original.clone();
        open_ended.extend_from_slice(b"\0\0\0\0free");
        assert!(container::embed(&open_ended, format, b"{}").is_err());
        assert!(container::extract(&marked_bytes[..marked_bytes.len() - 1], format).is_err());
    }
}

#[test]
#[ignore = "Requires real local HEIC and AVIF encoding/decoding backends"]
fn real_heic_avif_v2_mark_verify_clean_preserves_profiles_and_originals() {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("signing.json");
    heritage::keygen(&key).unwrap();
    let limits = Limits::default();
    let source = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/watermark/astronaut.png"),
    )
    .unwrap();
    let rendered = media_pixels::decode_rendered(&source, Format::Png, &limits).unwrap();
    assert_eq!(
        (rendered.image.width(), rendered.image.height()),
        (512, 512)
    );
    assert!(rendered.icc_profile.is_some());
    let icc_heic = fs::read(fixtures().join("heic_exif_gps.heic")).unwrap();
    let heic_profile = bmff::embedded_icc_profile(&icc_heic, Format::Heic, &limits)
        .unwrap()
        .unwrap();
    eprintln!("codec capabilities {}", media_pixels::capabilities());
    for (format, extension) in [(Format::Heic, "heic"), (Format::Avif, "avif")] {
        let bytes = media_pixels::encode(
            &rendered.image,
            format,
            95,
            if format == Format::Avif {
                rendered.icc_profile.as_deref()
            } else {
                Some(&heic_profile)
            },
            &limits,
        )
        .unwrap();
        let input = directory.path().join(format!("original.{extension}"));
        fs::write(&input, &bytes).unwrap();
        let before = media_pixels::decode_rendered(&bytes, format, &limits).unwrap();
        if format == Format::Avif {
            assert_eq!(before.icc_profile, rendered.icc_profile);
            assert!(before.icc_profile.is_some());
        } else {
            assert_eq!(before.icc_profile.as_deref(), Some(heic_profile.as_slice()));
        }
        let source_hash = digest(&bytes);
        let marked = directory.path().join(format!("marked.{extension}"));
        let request = HeritageRequest {
            action: HeritageAction::Mark,
            key_paths: vec![key.clone()],
            watermark_key: Some(key.clone()),
            media_quality: Some(95),
            mark: MarkSettings {
                work_id: "native-media-work".into(),
                copy_id: "native-copy".into(),
                signature_v2: true,
                robust: true,
                watermark_version: 2,
                strength: 20,
                ..Default::default()
            },
            ..Default::default()
        };
        let report = heritage::run(&input, Some(&marked), &request, &limits).unwrap();
        assert_eq!(report.integrity.original_unchanged, Some(true));
        let check_request = HeritageRequest {
            action: HeritageAction::Verify,
            watermark_key: Some(key.clone()),
            ..Default::default()
        };
        let report = heritage::run(&marked, None, &check_request, &limits).unwrap();
        let details = &report.advanced.as_ref().unwrap()["heritage"];
        assert_eq!(details["robust"]["frame_valid"], true, "{details}");
        assert_eq!(details["robust"]["authenticated"], true);
        assert_eq!(details["verification"]["content_binding"], "valid");
        let marked_hash = digest(&fs::read(&marked).unwrap());
        let lab_report = heritage::run(
            &marked,
            None,
            &HeritageRequest {
                action: HeritageAction::Lab,
                watermark_key: Some(key.clone()),
                controls: vec![input.clone()],
                ..Default::default()
            },
            &limits,
        )
        .unwrap();
        let lab = &lab_report.advanced.as_ref().unwrap()["heritage"]["lab"];
        assert_eq!(
            lab["source_method"],
            heritage::robust_v2::METHOD_ID,
            "{lab}"
        );
        let rows = lab["rows"].as_array().unwrap();
        let original_row = rows
            .iter()
            .find(|row| row["operation"] == "original")
            .unwrap();
        assert_eq!(original_row["robust"]["status"], "detected", "{lab}");
        assert_eq!(original_row["robust"]["frame_valid"], true);
        let clean_row = rows
            .iter()
            .find(|row| row["operation"] == "targeted_fileveil_dct_clean")
            .unwrap();
        assert_eq!(clean_row["robust"]["status"], "not_detected", "{lab}");
        assert_eq!(clean_row["robust"]["frame_valid"], false);
        assert_eq!(lab["control_count"], 1);
        assert_eq!(lab["control_positive_count"], 0, "{lab}");
        assert_eq!(lab_report.integrity.original_unchanged, Some(true));
        assert_eq!(digest(&fs::read(&marked).unwrap()), marked_hash);
        assert_eq!(digest(&fs::read(&input).unwrap()), source_hash);
        let marked_pixels =
            media_pixels::decode_rendered(&fs::read(&marked).unwrap(), format, &limits).unwrap();
        assert_eq!(marked_pixels.icc_profile, before.icc_profile);
        if format == Format::Heic {
            assert_eq!(
                nclx_properties(&fs::read(&marked).unwrap()),
                nclx_properties(&bytes)
            );
        }
        assert_eq!(
            (marked_pixels.image.width(), marked_pixels.image.height()),
            (512, 512)
        );
        let cleaned = directory.path().join(format!("cleaned.{extension}"));
        let clean_request = HeritageRequest {
            action: HeritageAction::Clean,
            clean_signal: true,
            watermark_key: Some(key.clone()),
            media_quality: Some(95),
            ..Default::default()
        };
        let report = heritage::run(&marked, Some(&cleaned), &clean_request, &limits).unwrap();
        assert_eq!(report.integrity.original_unchanged, Some(true));
        let report = heritage::run(&cleaned, None, &check_request, &limits).unwrap();
        let details = &report.advanced.as_ref().unwrap()["heritage"];
        assert_eq!(details["robust"]["frame_valid"], false, "{details}");
        let after =
            media_pixels::decode_rendered(&fs::read(&cleaned).unwrap(), format, &limits).unwrap();
        assert_eq!(after.icc_profile, before.icc_profile);
        if format == Format::Heic {
            assert_eq!(
                nclx_properties(&fs::read(&cleaned).unwrap()),
                nclx_properties(&bytes)
            );
        }
        assert_eq!((after.image.width(), after.image.height()), (512, 512));
        assert_eq!(digest(&fs::read(&input).unwrap()), source_hash);
        eprintln!(
            "{extension} actual 512px codec Mark → MAC-Verify → Clean → Recheck complete, nonempty ICC or actual NCLX preserved, original SHA-256 unchanged"
        );
    }
    let actual = media_pixels::decode_rendered(&icc_heic, Format::Heic, &limits).unwrap();
    assert_eq!(actual.icc_profile.as_deref(), Some(heic_profile.as_slice()));
    let nclx = media_pixels::encode(&rendered.image, Format::Heic, 95, None, &limits).unwrap();
    assert!(nclx_properties(&nclx).is_some());
    let decoded = media_pixels::decode_rendered(&nclx, Format::Heic, &limits).unwrap();
    let roundtrip = media_pixels::encode(
        &decoded.image,
        Format::Heic,
        95,
        decoded.icc_profile.as_deref(),
        &limits,
    )
    .unwrap();
    assert_eq!(nclx_properties(&nclx), nclx_properties(&roundtrip));
    match media_pixels::encode(
        &rendered.image,
        Format::Heic,
        95,
        rendered.icc_profile.as_deref(),
        &limits,
    ) {
        Ok(encoded) => assert_eq!(
            bmff::embedded_icc_profile(&encoded, Format::Heic, &limits).unwrap(),
            rendered.icc_profile
        ),
        Err(error) => assert!(error.to_string().contains("ICC profile"), "{error}"),
    }
    eprintln!(
        "HEIC nonempty ICC500 preserved, NCLX roundtrip unchanged, profile-eliding codec output fails closed"
    );
}

// FVPROV1 16846 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJjOTZlNzIwZWE5NjdmNTY3Mjg2ZDk5NGE4M2Q4ZmY4ZmNkYWRkNWU1ZmQwMWUyZTVkNDFmYTY0NzlmNTE5MjMxIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4zIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMyIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvdGVzdHMvbWVkaWFfd2F0ZXJtYXJrX3YwNS5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjZiNDBhOWNkM2EzY2Y3MWM2MTg2NGI4ZDhiYzYyNjNkYjg5ZmZkMDMyYzJjYzJjZTM3OTY2MDkxODk1NGM2Yjg5ZjljZDhiZjVhYzY4ZGVlYjA4YzBlMjgxZGQyZDFmM2I5NDI1YTE0NTY4YTkxMjQwOWZhNmFjMjZjZjc0MjA3In1dfV0= FVPROV1-END
