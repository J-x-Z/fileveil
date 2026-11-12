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
    assert_eq!(watermark::detectors(), vec![descriptor]);
    assert!(SyntheticLsbV1.detect(&[], &Limits::default()).is_err());
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
