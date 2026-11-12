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
