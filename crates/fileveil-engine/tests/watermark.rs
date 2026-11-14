// SPDX-License-Identifier: MPL-2.0
use std::{fs, io::Cursor};

use fileveil_core::{Format, ImageProcessMode, ImageProcessOptions, Limits, digest};
use fileveil_engine::{
    process_image_in,
    watermark::{self, DetectionStatus, Detector, SyntheticLsbV1},
};
use image::{DynamicImage, ImageFormat, RgbImage};

fn png(image: RgbImage) -> Vec<u8> {
    let mut output = Cursor::new(Vec::new());
    DynamicImage::ImageRgb8(image)
        .write_to(&mut output, ImageFormat::Png)
        .unwrap();
    output.into_inner()
}

fn packet(payload: &[u8]) -> Vec<u8> {
    let mut bytes = watermark::SYNTHETIC_MAGIC.to_vec();
    bytes.push(watermark::SYNTHETIC_VERSION);
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    let hash = digest(payload);
    for pair in hash.as_bytes().as_chunks::<2>().0 {
        bytes.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
    }
    bytes.extend_from_slice(payload);
    bytes
}

fn marked(bytes: &[u8]) -> Vec<u8> {
    let mut image = RgbImage::from_fn(32, 32, |x, y| {
        image::Rgb([(x * 6) as u8, (y * 6) as u8, 96])
    });
    for (index, bit) in bytes
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |shift| (byte >> shift) & 1))
        .enumerate()
    {
        image.as_mut()[index] = (image.as_mut()[index] & !1) | bit;
    }
    png(image)
}

#[test]
fn static_descriptor_is_offline_and_reports_its_limits() {
    let descriptor = SyntheticLsbV1.descriptor();
    assert_eq!(descriptor.method_id, "synthetic_lsb_v1");
    assert_eq!(descriptor.formats, vec![Format::Png]);
    assert_eq!((descriptor.min_samples, descriptor.max_samples), (1, 1));
    assert!(!descriptor.requires_network);
    assert!(!descriptor.requires_key);
    assert!(descriptor.supports_postprocess_retest);
    assert!(!descriptor.false_positive_limits.is_empty());
    assert!(!descriptor.false_negative_limits.is_empty());
    assert_eq!(watermark::detectors().first(), Some(&descriptor));
    assert_eq!(watermark::detectors().len(), 3);
    assert!(SyntheticLsbV1.detect(&[], &Limits::default()).is_err());
}

const PHOTO: &[u8] = include_bytes!("fixtures/watermark/astronaut.png");
const PHOTO_SD1: &[u8] = include_bytes!("fixtures/watermark/astronaut-sd1.png");
const PHOTO_SDXL: &[u8] = include_bytes!("fixtures/watermark/astronaut-sdxl.png");
const PHOTO_OTHER: &[u8] = include_bytes!("fixtures/watermark/astronaut-other.png");
const PHOTO_SD1_JPEG: &[u8] = include_bytes!("fixtures/watermark/astronaut-sd1-444.jpg");
const PHOTO_SDXL_JPEG: &[u8] = include_bytes!("fixtures/watermark/astronaut-sdxl-444.jpg");

#[test]
fn deployed_sd_payloads_match_independent_upstream_natural_photo_fixtures() {
    for (photo, format, method, expected) in [
        (
            PHOTO_SD1,
            Format::Png,
            "stable_diffusion_dwt_dct_v1",
            "matched_bits=136",
        ),
        (
            PHOTO_SDXL,
            Format::Png,
            "stable_diffusion_xl_dwt_dct",
            "matched_bits=48",
        ),
        (
            PHOTO_SD1_JPEG,
            Format::Jpeg,
            "stable_diffusion_dwt_dct_v1",
            "matched_bits=136",
        ),
        (
            PHOTO_SDXL_JPEG,
            Format::Jpeg,
            "stable_diffusion_xl_dwt_dct",
            "matched_bits=48",
        ),
    ] {
        let reports = watermark::detect_all(photo, format, &Limits::default()).unwrap();
        let report = reports
            .iter()
            .find(|report| report.method_id == method)
            .unwrap();
        assert_eq!(report.status, DetectionStatus::Detected, "{report:?}");
        assert!(
            report.evidence_codes.iter().any(|code| code == expected),
            "{report:?}"
        );
        assert!(report.offline);
        assert!(report.scope.contains("without_origin_authentication"));
    }
    for photo in [PHOTO, PHOTO_OTHER] {
        let reports = watermark::detect_all(photo, Format::Png, &Limits::default()).unwrap();
        for report in reports {
            assert_ne!(report.status, DetectionStatus::Detected, "{report:?}");
        }
    }
}

#[test]
fn signal_recipe_has_named_retests_on_independently_encoded_sd_photos() {
    for (photo, extension, method) in [
        (PHOTO_SD1, "png", "stable_diffusion_dwt_dct_v1"),
        (PHOTO_SDXL, "png", "stable_diffusion_xl_dwt_dct"),
        (PHOTO_SD1_JPEG, "jpg", "stable_diffusion_dwt_dct_v1"),
        (PHOTO_SDXL_JPEG, "jpg", "stable_diffusion_xl_dwt_dct"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join(format!("source.{extension}"));
        let output = directory.path().join("processed.png");
        fs::write(&input, photo).unwrap();
        let original_hash = digest(photo);
        let report = process_image_in(
            &input,
            Some(&output),
            &ImageProcessOptions {
                mode: ImageProcessMode::Signal,
                low_bits: 1,
            },
            &Limits::default(),
            None,
        )
        .unwrap();
        let retests = report.advanced.as_ref().unwrap()["detector_retests"]
            .as_array()
            .unwrap();
        let retest = retests
            .iter()
            .find(|item| item["method_id"] == method)
            .unwrap();
        assert_eq!(retest["before"]["status"], "detected");
        assert_eq!(retest["after"]["status"], "not_detected", "{retest}");
        assert_eq!(retest["result"], "detector_no_longer_detects");
        assert_eq!(digest(&fs::read(&input).unwrap()), original_hash);
        assert!(report.integrity.original_unchanged == Some(true));
    }
}

#[test]
fn natural_photo_edits_and_lossy_encoding_controls_do_not_confirm_public_marks() {
    let source = image::load_from_memory(PHOTO).unwrap().to_rgb8();
    let controls = [
        source.clone(),
        image::imageops::flip_horizontal(&source),
        image::imageops::flip_vertical(&source),
        image::imageops::rotate90(&source),
        image::imageops::blur(&source, 0.75),
        image::imageops::resize(&source, 384, 384, image::imageops::FilterType::Triangle),
    ];
    for image in controls {
        let bytes = png(image);
        for report in watermark::detect_all(&bytes, Format::Png, &Limits::default()).unwrap() {
            assert_ne!(report.status, DetectionStatus::Detected, "{report:?}");
        }
    }
    for bytes in [
        include_bytes!("fixtures/watermark/astronaut-sd1.jpg").as_slice(),
        include_bytes!("fixtures/watermark/astronaut-sdxl.jpg").as_slice(),
    ] {
        for report in watermark::detect_all(bytes, Format::Jpeg, &Limits::default()).unwrap() {
            assert_ne!(report.status, DetectionStatus::Detected, "{report:?}");
        }
    }
    let small = png(RgbImage::from_pixel(16, 16, image::Rgb([128; 3])));
    let reports = watermark::detect_all(&small, Format::Png, &Limits::default()).unwrap();
    assert!(
        reports[1..]
            .iter()
            .all(|report| report.status == DetectionStatus::NotAssessed)
    );
    assert!(watermark::detect_all(PHOTO, Format::Jpeg, &Limits::default()).is_err());
}

#[test]
fn signal_processing_preserves_embedded_and_remote_credential_protection() {
    for source in [
        include_bytes!("fixtures/provenance/signed.png").as_slice(),
        include_bytes!("fixtures/provenance/remote.png").as_slice(),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("credential.png");
        let output = directory.path().join("processed.png");
        fs::write(&input, source).unwrap();
        let result = process_image_in(
            &input,
            Some(&output),
            &ImageProcessOptions {
                mode: ImageProcessMode::Signal,
                low_bits: 1,
            },
            &Limits::default(),
            None,
        );
        assert!(
            matches!(result, Err(fileveil_core::Error::Blocked(_))),
            "{result:?}"
        );
        assert!(!output.exists());
        assert_eq!(fs::read(&input).unwrap(), source);
    }
}

#[test]
fn valid_packet_exports_only_payload_digest_and_preserves_input() {
    let payload = b"PRIVATE_SYNTHETIC_PAYLOAD";
    let data = marked(&packet(payload));
    let before = digest(&data);
    let report = watermark::detect(&data, Format::Png, &Limits::default()).unwrap();
    assert_eq!(report.status, DetectionStatus::Detected);
    assert_eq!(
        report.payload_sha256.as_deref(),
        Some(digest(payload).as_str())
    );
    assert_eq!(report.payload_bytes, Some(payload.len() as u32));
    assert!(report.offline);
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("PRIVATE_SYNTHETIC_PAYLOAD")
    );
    assert_eq!(digest(&data), before);
    assert_eq!(
        watermark::detect(&marked(&packet(b"")), Format::Png, &Limits::default())
            .unwrap()
            .status,
        DetectionStatus::Detected
    );
}

#[test]
fn uniform_and_random_negative_controls_do_not_match() {
    let clean = png(RgbImage::from_pixel(32, 32, image::Rgb([128, 128, 128])));
    assert_eq!(
        watermark::detect(&clean, Format::Png, &Limits::default())
            .unwrap()
            .status,
        DetectionStatus::NotDetected
    );
    let mut state = 0x9e3779b9u32;
    for _ in 0..32 {
        let image = RgbImage::from_fn(32, 32, |_, _| {
            image::Rgb(std::array::from_fn(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            }))
        });
        assert_eq!(
            watermark::detect(&png(image), Format::Png, &Limits::default())
                .unwrap()
                .status,
            DetectionStatus::NotDetected
        );
    }
}

#[test]
fn tampered_payload_unknown_version_and_invalid_lengths_are_distinct() {
    let mut bytes = packet(b"control-payload");
    bytes[watermark::SYNTHETIC_HEADER_BYTES] ^= 1;
    let report = watermark::detect(&marked(&bytes), Format::Png, &Limits::default()).unwrap();
    assert_eq!(report.status, DetectionStatus::Indeterminate);
    assert!(
        report
            .evidence_codes
            .iter()
            .any(|code| code == "packet_payload_hash_mismatch")
    );
    assert!(report.payload_sha256.is_none());
    bytes = packet(b"control");
    bytes[8] = 2;
    let report = watermark::detect(&marked(&bytes), Format::Png, &Limits::default()).unwrap();
    assert_eq!(report.status, DetectionStatus::Indeterminate);
    assert!(
        report
            .evidence_codes
            .iter()
            .any(|code| code == "packet_version_unsupported")
    );
    bytes = packet(b"control");
    bytes[9..13].copy_from_slice(&u32::MAX.to_be_bytes());
    let report = watermark::detect(&marked(&bytes), Format::Png, &Limits::default()).unwrap();
    assert_eq!(report.status, DetectionStatus::Indeterminate);
    bytes[9..13].copy_from_slice(&1000u32.to_be_bytes());
    let report = watermark::detect(&marked(&bytes), Format::Png, &Limits::default()).unwrap();
    assert!(
        report
            .evidence_codes
            .iter()
            .any(|code| code == "packet_length_exceeds_capacity")
    );
}

#[test]
fn normal_low_bit_processing_has_an_independent_detector_retest() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("marked.png");
    let data = marked(&packet(b"retestable-payload"));
    fs::write(&input, &data).unwrap();
    assert_eq!(
        watermark::detect(&data, Format::Png, &Limits::default())
            .unwrap()
            .status,
        DetectionStatus::Detected
    );
    for bits in [1, 2] {
        let output = directory.path().join(format!("processed-{bits}.png"));
        let processing = process_image_in(
            &input,
            Some(&output),
            &ImageProcessOptions {
                mode: ImageProcessMode::LowBits,
                low_bits: bits,
            },
            &Limits::default(),
            None,
        )
        .unwrap();
        assert_eq!(
            processing
                .image_processing
                .as_ref()
                .unwrap()
                .detector_status,
            "not_assessed"
        );
        let retest = &processing.advanced.as_ref().unwrap()["watermark_retest"];
        assert_eq!(retest["before"]["status"], "detected");
        assert_eq!(retest["after"]["status"], "not_detected");
        assert_eq!(retest["result"], "detector_no_longer_detects");
        let result =
            watermark::detect(&fs::read(&output).unwrap(), Format::Png, &Limits::default())
                .unwrap();
        assert_eq!(result.status, DetectionStatus::NotDetected);
        assert_eq!(result.scope, "fileveil_synthetic_packet_only");
        assert_eq!(fs::read(&input).unwrap(), data);
    }
}

#[test]
fn unsupported_samples_limits_and_damage_fail_without_payload_disclosure() {
    assert_eq!(
        watermark::detect(b"", Format::Jpeg, &Limits::default())
            .unwrap()
            .status,
        DetectionStatus::NotAssessed
    );
    assert!(watermark::detect(b"broken PNG", Format::Png, &Limits::default()).is_err());
    let mut output = Cursor::new(Vec::new());
    DynamicImage::ImageLuma8(image::GrayImage::new(32, 32))
        .write_to(&mut output, ImageFormat::Png)
        .unwrap();
    assert_eq!(
        watermark::detect(output.get_ref(), Format::Png, &Limits::default())
            .unwrap()
            .status,
        DetectionStatus::NotAssessed
    );
    let data = marked(&packet(b"control"));
    assert!(
        watermark::detect(
            &data,
            Format::Png,
            &Limits {
                max_file_bytes: 1,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(
        watermark::detect(
            &data,
            Format::Png,
            &Limits {
                max_pixels: 1,
                ..Limits::default()
            }
        )
        .is_err()
    );
    let report = watermark::detect(
        &data,
        Format::Png,
        &Limits {
            max_metadata_bytes: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(report.status, DetectionStatus::Indeterminate);
}

// FVPROV1 14426 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIyYzQ3OGYzMTllZmQ0MzY0MDI3MTMwYTAyYTg3MDMwYTRhZWU3NWMxYzM3YWUwODk0N2YxODcyNmIxNWNiNjI0IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS40IiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuNCIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvdGVzdHMvd2F0ZXJtYXJrLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiY2E0YThmNDU4MDI0MzM5Nzc2ZTk3YzkxMDYzOWZkN2EwY2RjMWQ2Zjg5ZTRhZDYwMzNlZWEzYjlkYzEwMDYzOTk4NDQ4MjM4ZjI3N2NhYzNhODhkZmQ3NGQ2MWI1MDI0YmZjMTM5NDZhNTE1MmM3NmE5OTMxYjhhY2M5MDJhMGEifV19XQ== FVPROV1-END
