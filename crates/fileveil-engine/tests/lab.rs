// SPDX-License-Identifier: MPL-2.0
use std::io::Cursor;

use fileveil_core::{Format, Limits, digest};
use fileveil_engine::lab::{self, LabSample};
use image::{DynamicImage, ImageFormat, RgbImage};

fn encode(image: RgbImage, format: ImageFormat) -> Vec<u8> {
    let mut output = Cursor::new(Vec::new());
    DynamicImage::ImageRgb8(image)
        .write_to(&mut output, format)
        .unwrap();
    output.into_inner()
}

fn solid(value: u8) -> Vec<u8> {
    encode(
        RgbImage::from_pixel(16, 16, image::Rgb([value; 3])),
        ImageFormat::Png,
    )
}

#[test]
fn repeated_controls_are_identical_with_zero_entropy_and_difference() {
    let data = solid(128);
    let hash = digest(&data);
    let inputs = [
        LabSample {
            data: &data,
            format: Format::Png,
        },
        LabSample {
            data: &data,
            format: Format::Png,
        },
    ];
    let report = lab::analyze(&inputs, &Limits::default()).unwrap();
    assert_eq!(report.samples.len(), 2);
    assert_eq!(report.comparisons.len(), 1);
    assert_eq!(report.attribution, "not_assessed");
    assert_eq!(report.watermark_detection, "not_assessed");
    assert_eq!(digest(&data), hash);
    for channel in &report.samples[0].channels {
        assert_eq!(channel.mean, 128.0);
        assert_eq!(channel.standard_deviation, 0.0);
        assert_eq!(channel.entropy_bits, 0.0);
        assert_eq!(channel.histogram[128], 256);
        assert_eq!(channel.lsb_one_counts, [0, 0]);
    }
    let pair = &report.comparisons[0];
    assert!(pair.identical_input);
    let difference = pair.pixels.as_ref().unwrap();
    assert_eq!(difference.mean_squared_error, 0.0);
    assert_eq!(difference.changed_pixel_fraction, 0.0);
    assert_eq!(pair.dft_band_distance, 0.0);
    assert_eq!(pair.dct_band_distance, 0.0);
    assert!(report.samples[0].frequency.dft_ac_energy < 1e-20);
    assert!(report.samples[0].frequency.dct_ac_energy < 1e-20);
    assert_eq!(
        serde_json::to_value(&report).unwrap(),
        serde_json::to_value(lab::analyze(&inputs, &Limits::default()).unwrap()).unwrap()
    );
}

#[test]
fn exact_pixel_and_low_bit_disagreement_match_the_known_control() {
    let a = solid(128);
    let b = solid(129);
    let report = lab::analyze(
        &[
            LabSample {
                data: &a,
                format: Format::Png,
            },
            LabSample {
                data: &b,
                format: Format::Png,
            },
        ],
        &Limits::default(),
    )
    .unwrap();
    let pair = report.comparisons[0].pixels.as_ref().unwrap();
    assert_eq!(pair.mean_absolute_error, 1.0);
    assert_eq!(pair.mean_squared_error, 1.0);
    assert_eq!(pair.maximum_sample_error, 1);
    assert_eq!(pair.changed_pixel_fraction, 1.0);
    assert_eq!(pair.lsb_disagreement_fraction, [1.0, 0.0]);
    assert_eq!(report.samples[1].channels[0].lsb_one_counts, [256, 0]);
    let previews = report.samples[0].previews.as_ref().unwrap();
    assert!(previews.low_bits.gray.iter().all(|value| *value == 0));
    assert!(previews.residual.gray.iter().all(|value| *value == 128));
    assert!(
        report.comparisons[0]
            .difference_preview
            .as_ref()
            .unwrap()
            .gray
            .iter()
            .all(|value| *value == 8)
    );
}

#[test]
fn frequency_and_entropy_detect_a_controlled_alternating_pattern() {
    let a = solid(128);
    let b = encode(
        RgbImage::from_fn(16, 16, |x, y| {
            image::Rgb([if (x + y) % 2 == 0 { 0 } else { 255 }; 3])
        }),
        ImageFormat::Png,
    );
    let report = lab::analyze(
        &[
            LabSample {
                data: &a,
                format: Format::Png,
            },
            LabSample {
                data: &b,
                format: Format::Png,
            },
        ],
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(report.samples[1].channels[0].entropy_bits, 1.0);
    assert!(report.samples[1].frequency.dft_ac_energy > 0.24);
    assert!(report.comparisons[0].dft_band_distance > 0.24);
    assert!(report.comparisons[0].entropy_delta_bits[0] > 0.99);
    // This 16-pixel checkerboard aliases in the independent 8-pixel DCT grid.
    // Both grids and their sampling limits are explicitly reported.
    assert_eq!(report.samples[1].frequency.dct_grid_side, 8);
    let native = report.samples[1].signal.as_ref().unwrap();
    assert!(native.block_dct_ac_power.iter().sum::<f64>() > 15.0);
    assert_eq!(native.block_dct_blocks, 4);
    assert!(native.haar_detail_power[2] > 0.99);
}

#[test]
fn unequal_geometry_skips_pixel_alignment_and_jpeg_is_a_valid_control() {
    let a = solid(128);
    let b = encode(
        RgbImage::from_pixel(8, 4, image::Rgb([128; 3])),
        ImageFormat::Jpeg,
    );
    let report = lab::analyze(
        &[
            LabSample {
                data: &a,
                format: Format::Png,
            },
            LabSample {
                data: &b,
                format: Format::Jpeg,
            },
        ],
        &Limits::default(),
    )
    .unwrap();
    assert!(!report.comparisons[0].same_dimensions);
    assert!(report.comparisons[0].pixels.is_none());
    assert_eq!(report.samples[1].width, 8);
    assert_eq!(report.samples[1].height, 4);
    assert!(report.comparisons[0].difference_preview.is_none());
    assert!(report.comparisons[0].residual_correlation.is_none());
    let jpeg = report.samples[1]
        .signal
        .as_ref()
        .unwrap()
        .jpeg
        .as_ref()
        .unwrap();
    assert!(!jpeg.progressive);
    assert_eq!(jpeg.frame_components.len(), 3);
    assert!(jpeg.quantization_tables >= 2);
}

fn fixed_pattern_frame(device: u32, capture: u32) -> Vec<u8> {
    encode(
        RgbImage::from_fn(64, 64, |x, y| {
            let mut state = (x + y * 64 + device * 9341)
                .wrapping_mul(1664525)
                .wrapping_add(1013904223);
            state ^= state >> 13;
            state = state.wrapping_mul(2246822519);
            let pattern = (state % 7) as i32 - 3;
            let scene = 96 + (capture * 7 + x / 8 + y / 8) as i32;
            image::Rgb([(scene + pattern) as u8; 3])
        }),
        ImageFormat::Png,
    )
}

#[test]
fn labeled_controls_use_leave_one_out_and_separate_unrelated_patterns() {
    let data = [
        fixed_pattern_frame(1, 1),
        fixed_pattern_frame(1, 2),
        fixed_pattern_frame(2, 1),
        fixed_pattern_frame(2, 2),
    ];
    let inputs = data
        .iter()
        .map(|data| LabSample {
            data,
            format: Format::Png,
        })
        .collect::<Vec<_>>();
    let report = lab::analyze_with_groups(
        &inputs,
        &[
            lab::SampleGroup {
                label: "reference A".into(),
                sample_indices: vec![0, 1],
            },
            lab::SampleGroup {
                label: "reference B".into(),
                sample_indices: vec![2, 3],
            },
        ],
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(report.attribution, "not_assessed");
    let group = &report.groups[0];
    assert!(group.tests[0].leave_one_out);
    assert_eq!(group.tests[0].reference_count, 1);
    assert!(group.tests[0].ncc.unwrap() > 0.95, "{:?}", group.tests);
    assert!(!group.tests[2].leave_one_out);
    assert_eq!(group.tests[2].reference_count, 2);
    assert!(
        group.tests[2].ncc.unwrap().abs() < 0.15,
        "{:?}",
        group.tests
    );
    assert!(group.scope.contains("without_device_attribution"));
    assert!(
        lab::analyze_with_groups(
            &inputs,
            &[lab::SampleGroup {
                label: "invalid".into(),
                sample_indices: vec![0, 0],
            }],
            &Limits::default()
        )
        .is_err()
    );
    assert!(
        lab::analyze_with_groups(
            &inputs,
            &[lab::SampleGroup {
                label: "invalid".into(),
                sample_indices: vec![0, 4],
            }],
            &Limits::default()
        )
        .is_err()
    );
}

#[test]
fn duplicate_reference_inputs_and_flat_samples_cannot_establish_a_noise_match() {
    let data = fixed_pattern_frame(1, 1);
    let inputs = [
        LabSample {
            data: &data,
            format: Format::Png,
        },
        LabSample {
            data: &data,
            format: Format::Png,
        },
    ];
    let report = lab::analyze_with_groups(
        &inputs,
        &[lab::SampleGroup {
            label: "duplicates".into(),
            sample_indices: vec![0, 1],
        }],
        &Limits::default(),
    )
    .unwrap();
    for test in &report.groups[0].tests {
        assert_eq!(test.reference_count, 0);
        assert_eq!(test.ncc, None);
    }
    let single = lab::analyze_signal(&solid(128), Format::Png, &Limits::default()).unwrap();
    assert_eq!(single.signal.lsb_pair_chi_square, [256.0; 3]);
    assert_eq!(single.signal.lsb_pair_degrees_of_freedom, [1; 3]);
    assert_eq!(single.signal.noise_residual_rms, 0.0);
    assert!(lab::analyze_signal(&data, Format::Jpeg, &Limits::default()).is_err());
}

#[test]
fn earlier_lab_reports_read_with_absent_signal_fields() {
    let data = solid(128);
    let inputs = [
        LabSample {
            data: &data,
            format: Format::Png,
        },
        LabSample {
            data: &data,
            format: Format::Png,
        },
    ];
    let report = lab::analyze(&inputs, &Limits::default()).unwrap();
    let mut json = serde_json::to_value(report).unwrap();
    json.as_object_mut().unwrap().remove("groups");
    for sample in json["samples"].as_array_mut().unwrap() {
        sample.as_object_mut().unwrap().remove("signal");
        sample.as_object_mut().unwrap().remove("previews");
    }
    for comparison in json["comparisons"].as_array_mut().unwrap() {
        comparison
            .as_object_mut()
            .unwrap()
            .remove("difference_preview");
        comparison
            .as_object_mut()
            .unwrap()
            .remove("residual_correlation");
    }
    let old: lab::LabReport = serde_json::from_value(json).unwrap();
    assert!(old.groups.is_empty());
    assert!(old.samples[0].signal.is_none());
}

#[test]
fn multigroup_comparisons_are_bounded_and_serializable() {
    let data = solid(128);
    let inputs = (0..8)
        .map(|_| LabSample {
            data: &data,
            format: Format::Png,
        })
        .collect::<Vec<_>>();
    let report = lab::analyze(&inputs, &Limits::default()).unwrap();
    assert_eq!(report.comparisons.len(), 28);
    assert!(report.offline);
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains("NaN"));
    assert!(!json.contains("Infinity"));
    assert!(!json.contains("/Users/"));
    let roundtrip: lab::LabReport = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtrip.comparisons.len(), 28);
}

#[test]
fn count_byte_pixel_and_format_limits_reject_invalid_inputs() {
    let data = solid(128);
    let one = [LabSample {
        data: &data,
        format: Format::Png,
    }];
    assert!(lab::analyze(&one, &Limits::default()).is_err());
    let nine = (0..9)
        .map(|_| LabSample {
            data: &data,
            format: Format::Png,
        })
        .collect::<Vec<_>>();
    assert!(lab::analyze(&nine, &Limits::default()).is_err());
    let two = [
        LabSample {
            data: &data,
            format: Format::Png,
        },
        LabSample {
            data: &data,
            format: Format::Png,
        },
    ];
    assert!(
        lab::analyze(
            &two,
            &Limits {
                max_file_bytes: 1,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(
        lab::analyze(
            &two,
            &Limits {
                max_uncompressed_bytes: data.len() as u64,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(
        lab::analyze(
            &two,
            &Limits {
                max_pixels: 300,
                ..Limits::default()
            }
        )
        .is_err()
    );
    let wrong_hint = [
        LabSample {
            data: &data,
            format: Format::Jpeg,
        },
        LabSample {
            data: &data,
            format: Format::Png,
        },
    ];
    assert!(lab::analyze(&wrong_hint, &Limits::default()).is_err());
    let broken = [
        LabSample {
            data: b"damaged",
            format: Format::Png,
        },
        LabSample {
            data: &data,
            format: Format::Png,
        },
    ];
    assert!(lab::analyze(&broken, &Limits::default()).is_err());
}

#[test]
fn invalid_groups_are_rejected_before_touching_image_decoders() {
    let invalid_image = LabSample {
        data: b"damaged",
        format: Format::Png,
    };
    let samples = [
        invalid_image,
        LabSample {
            data: b"damaged",
            format: Format::Png,
        },
    ];
    for group in [
        lab::SampleGroup {
            label: "reference".into(),
            sample_indices: vec![0; 100_000],
        },
        lab::SampleGroup {
            label: "reference".into(),
            sample_indices: vec![0, 99],
        },
        lab::SampleGroup {
            label: "\u{200d}".repeat(1_000_000),
            sample_indices: vec![0, 1],
        },
    ] {
        let result = lab::analyze_with_groups(&samples, &[group], &Limits::default());
        let error = result.unwrap_err().to_string();
        assert!(
            error.contains("Reference group") || error.contains("reference group"),
            "{error}"
        );
        assert!(!error.contains("container"), "{error}");
    }
}

#[test]
fn single_image_signal_reports_sample_conversion_and_reads_old_envelopes() {
    for image in [
        DynamicImage::ImageLuma16(image::ImageBuffer::from_pixel(
            16,
            16,
            image::Luma([32_768u16]),
        )),
        DynamicImage::ImageLuma8(image::ImageBuffer::from_pixel(16, 16, image::Luma([128u8]))),
        DynamicImage::ImageRgb8(RgbImage::from_pixel(16, 16, image::Rgb([128; 3]))),
    ] {
        let mut buffer = Cursor::new(Vec::new());
        image.write_to(&mut buffer, ImageFormat::Png).unwrap();
        let observation =
            lab::analyze_signal(&buffer.into_inner(), Format::Png, &Limits::default()).unwrap();
        assert_eq!(
            observation.converted_to_rgb8,
            !matches!(image, DynamicImage::ImageRgb8(_))
        );
        assert_eq!(
            observation.source_sample_model,
            format!("{:?}", image.color())
        );
        let mut old = serde_json::to_value(observation).unwrap();
        old.as_object_mut().unwrap().remove("converted_to_rgb8");
        old.as_object_mut().unwrap().remove("source_sample_model");
        let restored: lab::SignalObservation = serde_json::from_value(old).unwrap();
        assert!(!restored.converted_to_rgb8);
        assert!(restored.source_sample_model.is_empty());
    }
}

// FVPROV1 15225 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI1OGVjMThlMDkyYjI0OGQxYzdlMDMzOWEwZmYzNDEzNTE0ZjRkNzdmNTA1MDg3MGMxMWI5NDUyN2Y4ZGIwZWJmIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4yIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMiIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvdGVzdHMvbGFiLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiNjIyMWY3NjBlN2FmODk2ZDkyMjdlOTg5ZmQ5Y2E4MjUwYWJmYjM1M2Q1YjNkNjY0ODgwMWU3MjI4M2FiN2YzMTFmZjJlZTFjMjRmNzA5MDBiYzIzYTI2MDI5ZGUyYWYwNDA0YjBjYjUyMWEwZjhiMzVkNTIxNmI5YzQ5YWMzMGUifV19XQ== FVPROV1-END
