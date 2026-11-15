// SPDX-License-Identifier: MPL-2.0
//! Bounded, reproducible image statistics for explicitly selected control samples.
use std::{borrow::Cow, f64::consts::PI, io::Cursor};

use fileveil_core::{Error, Format, Limits, Result, digest};
use image::{ImageFormat, ImageReader, RgbImage};
use serde::{Deserialize, Serialize};

mod signals;
pub use signals::{GrayPreview, JpegComponent, JpegStructure, SignalAnalysis, SignalPreviews};

const DFT_SIDE: usize = 16;
const DCT_SIDE: usize = 8;
const FREQUENCY_BANDS: usize = 8;

pub struct LabSample<'a> {
    pub data: &'a [u8],
    pub format: Format,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelStatistics {
    pub mean: f64,
    pub standard_deviation: f64,
    pub entropy_bits: f64,
    pub histogram: Vec<u64>,
    pub lsb_one_counts: [u64; 2],
    pub low_two_bit_counts: [u64; 4],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrequencyStatistics {
    pub dft_grid_side: usize,
    pub dft_radial_power: [f64; FREQUENCY_BANDS],
    pub dft_ac_energy: f64,
    pub dct_grid_side: usize,
    pub dct_frequency_power: [f64; FREQUENCY_BANDS],
    pub dct_ac_energy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleStatistics {
    pub sample_index: usize,
    pub input_sha256: String,
    pub width: u32,
    pub height: u32,
    pub decoded_sample_model: String,
    pub converted_to_rgb8: bool,
    pub channels: [ChannelStatistics; 3],
    pub frequency: FrequencyStatistics,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<SignalAnalysis>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previews: Option<SignalPreviews>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PixelDifference {
    pub mean_absolute_error: f64,
    pub mean_squared_error: f64,
    pub maximum_sample_error: u8,
    pub changed_pixel_fraction: f64,
    pub lsb_disagreement_fraction: [f64; 2],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairwiseComparison {
    pub first_sample: usize,
    pub second_sample: usize,
    pub identical_input: bool,
    pub same_dimensions: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pixels: Option<PixelDifference>,
    pub entropy_delta_bits: [f64; 3],
    pub dft_band_distance: f64,
    pub dct_band_distance: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub difference_preview: Option<GrayPreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub residual_correlation: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalObservation {
    #[serde(default)]
    pub source_sample_model: String,
    #[serde(default)]
    pub converted_to_rgb8: bool,
    pub signal: SignalAnalysis,
    pub previews: SignalPreviews,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleGroup {
    pub label: String,
    pub sample_indices: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMatch {
    pub sample_index: usize,
    pub reference_count: usize,
    pub ncc: Option<f64>,
    pub leave_one_out: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupComparison {
    pub group_index: usize,
    pub label: String,
    pub reference_samples: Vec<usize>,
    pub tests: Vec<GroupMatch>,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabReport {
    pub method_id: String,
    pub method_version: String,
    pub samples: Vec<SampleStatistics>,
    pub comparisons: Vec<PairwiseComparison>,
    pub offline: bool,
    pub attribution: String,
    pub watermark_detection: String,
    pub limitations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<GroupComparison>,
}

/// A single authorized image receives the same native-resolution observations
/// and bounded visualizations used by the multi-sample laboratory.
pub fn analyze_signal(data: &[u8], format: Format, limits: &Limits) -> Result<SignalObservation> {
    if data.len() as u64 > limits.max_file_bytes {
        return Err(Error::Blocked("Signal input exceeds the byte limit".into()));
    }
    let expected = match format {
        Format::Jpeg => ImageFormat::Jpeg,
        Format::Png => ImageFormat::Png,
        _ => {
            return Err(Error::Unsupported(
                "Signal analysis supports JPEG and PNG snapshots".into(),
            ));
        }
    };
    if image::guess_format(data).ok() != Some(expected) {
        return Err(Error::Input(
            "Signal container does not match the format hint".into(),
        ));
    }
    let image = super::decode_pixels(data, limits)?;
    Ok(analyze_signal_decoded(&image, data))
}

pub(crate) fn analyze_signal_decoded(
    image: &image::DynamicImage,
    data: &[u8],
) -> SignalObservation {
    let converted = !matches!(
        image,
        image::DynamicImage::ImageRgb8(_) | image::DynamicImage::ImageRgba8(_)
    );
    let rgb = match image {
        image::DynamicImage::ImageRgb8(rgb) => Cow::Borrowed(rgb),
        _ => Cow::Owned(image.to_rgb8()),
    };
    let (signal, previews, _) = signals::analyze(&rgb, data);
    SignalObservation {
        source_sample_model: format!("{:?}", image.color()),
        converted_to_rgb8: converted,
        signal,
        previews,
    }
}

/// Inputs are authorized byte snapshots. Sample indices preserve the caller's
/// order without exporting file paths, source labels or image metadata values.
pub fn analyze(inputs: &[LabSample<'_>], limits: &Limits) -> Result<LabReport> {
    analyze_with_groups(inputs, &[], limits)
}

pub fn analyze_with_groups(
    inputs: &[LabSample<'_>],
    groups: &[SampleGroup],
    limits: &Limits,
) -> Result<LabReport> {
    if !(2..=8).contains(&inputs.len()) {
        return Err(Error::Input(
            "Diff Lab requires two to eight samples".into(),
        ));
    }
    validate_groups(groups, inputs.len())?;
    let mut total_bytes = 0u64;
    let mut total_pixels = 0u64;
    let mut dimensions = Vec::with_capacity(inputs.len());
    for input in inputs {
        total_bytes = total_bytes.saturating_add(input.data.len() as u64);
        if input.data.len() as u64 > limits.max_file_bytes
            || total_bytes > limits.max_uncompressed_bytes
        {
            return Err(Error::Blocked(
                "Diff Lab inputs exceed the aggregate byte budget".into(),
            ));
        }
        let expected = match input.format {
            Format::Jpeg => ImageFormat::Jpeg,
            Format::Png => ImageFormat::Png,
            _ => {
                return Err(Error::Unsupported(
                    "Diff Lab supports JPEG and PNG snapshots".into(),
                ));
            }
        };
        if image::guess_format(input.data).ok() != Some(expected) {
            return Err(Error::Input(
                "Diff Lab container does not match the format hint".into(),
            ));
        }
        let reader = ImageReader::with_format(Cursor::new(input.data), expected);
        let (width, height) = reader
            .into_dimensions()
            .map_err(|_| Error::Input("Diff Lab image dimensions could not be decoded".into()))?;
        total_pixels = total_pixels.saturating_add(u64::from(width) * u64::from(height));
        if total_pixels > limits.max_pixels {
            return Err(Error::Blocked(
                "Diff Lab images exceed the aggregate pixel budget".into(),
            ));
        }
        dimensions.push((width, height));
    }
    let mut images = Vec::with_capacity(inputs.len());
    let mut samples = Vec::with_capacity(inputs.len());
    let mut noise_grids = Vec::with_capacity(inputs.len());
    for ((index, input), (width, height)) in inputs.iter().enumerate().zip(dimensions) {
        let image = super::decode_pixels(input.data, limits)?;
        let converted = !matches!(
            image,
            image::DynamicImage::ImageRgb8(_) | image::DynamicImage::ImageRgba8(_)
        );
        let rgb = image.into_rgb8();
        let (signal, previews, noise) = signals::analyze(&rgb, input.data);
        samples.push(SampleStatistics {
            sample_index: index,
            input_sha256: digest(input.data),
            width,
            height,
            decoded_sample_model: "rgb8".into(),
            converted_to_rgb8: converted,
            channels: channel_statistics(&rgb),
            frequency: frequency_statistics(&rgb),
            signal: Some(signal),
            previews: Some(previews),
        });
        noise_grids.push(noise);
        images.push(rgb);
    }
    let mut comparisons = Vec::new();
    for first in 0..images.len() {
        for second in first + 1..images.len() {
            let a = &samples[first];
            let b = &samples[second];
            let same_dimensions = images[first].dimensions() == images[second].dimensions();
            comparisons.push(PairwiseComparison {
                first_sample: first,
                second_sample: second,
                identical_input: a.input_sha256 == b.input_sha256,
                same_dimensions,
                pixels: same_dimensions.then(|| pixel_difference(&images[first], &images[second])),
                entropy_delta_bits: std::array::from_fn(|channel| {
                    b.channels[channel].entropy_bits - a.channels[channel].entropy_bits
                }),
                dft_band_distance: band_distance(
                    &a.frequency.dft_radial_power,
                    &b.frequency.dft_radial_power,
                ),
                dct_band_distance: band_distance(
                    &a.frequency.dct_frequency_power,
                    &b.frequency.dct_frequency_power,
                ),
                difference_preview: same_dimensions
                    .then(|| signals::difference_preview(&images[first], &images[second])),
                residual_correlation: same_dimensions
                    .then(|| {
                        signals::correlation(
                            &noise_grids[first].residual,
                            &noise_grids[second].residual,
                        )
                    })
                    .flatten(),
            });
        }
    }
    let hashes = samples
        .iter()
        .map(|sample| sample.input_sha256.as_str())
        .collect::<Vec<_>>();
    let group_comparisons = compare_groups(&noise_grids, groups, &hashes);
    Ok(LabReport {
        method_id: "image_diff_lab".into(),
        method_version: "1.1.0".into(),
        samples,
        comparisons,
        offline: true,
        attribution: "not_assessed".into(),
        watermark_detection: "not_assessed".into(),
        groups: group_comparisons,
        limitations: vec![
            "Statistics describe the selected decoded samples. Encoding, sensor noise and ordinary edits can produce the same differences.".into(),
            "Use known clean images, repeated captures and ordinary re-encoding as controls. Sample groups and device identity are supplied by the researcher.".into(),
            "No empirical false-positive or false-negative rate is established. Statistical differences alone do not identify an OEM, tracking system or watermark.".into(),
            "DFT uses a fixed 16x16 nearest-sampled luminance grid and DCT a fixed 8x8 grid. Alpha and color management are excluded. Converted RGB8 low bits differ from native higher-bit-depth samples.".into(),
            "Pixel differences require matching dimensions and assume aligned content. Different dimensions receive statistical comparisons only.".into(),
            "Native 8x8 DCT uses at most 256 original-resolution blocks. Haar detail uses at most 4096 original 2x2 blocks. Low-bit previews average the three RGB bit planes. Residual previews use 128 + 8 times a 3x3 Gaussian high-pass residual. Difference previews use eight times mean RGB absolute difference.".into(),
            "LSB pair chi-square and adjacent-bit correlation are steganalysis observations without a calibrated watermark probability. Ordinary noise, encoding and editing require negative controls.".into(),
            "Reference groups are user-supplied. Leave-one-out residual NCC suppresses dark/saturated pixels and strong edges but can retain scene or codec structure. Repeated unrelated scenes and separate encoder controls are required for device-fingerprint research. No OEM attribution is performed.".into(),
        ],
    })
}

pub(crate) fn validate_groups(groups: &[SampleGroup], sample_count: usize) -> Result<()> {
    if groups.len() > sample_count {
        return Err(Error::Input(
            "Reference groups exceed the sample count".into(),
        ));
    }
    for group in groups {
        if group.label.len() > 320
            || group.label.trim().is_empty()
            || group.label.chars().count() > 80
            || group.label.chars().any(char::is_control)
        {
            return Err(Error::Input(
                "Reference group labels require one to 80 printable characters".into(),
            ));
        }
        if !(2..=sample_count).contains(&group.sample_indices.len()) {
            return Err(Error::Input(
                "Reference group sample counts exceed the input budget".into(),
            ));
        }
        let mut indices = group.sample_indices.clone();
        indices.sort_unstable();
        indices.dedup();
        if indices.len() != group.sample_indices.len()
            || indices.len() < 2
            || indices.iter().any(|index| *index >= sample_count)
        {
            return Err(Error::Input(
                "Each reference group requires two or more distinct valid sample indices".into(),
            ));
        }
    }
    Ok(())
}

fn compare_groups(
    noise: &[signals::NoiseGrid],
    groups: &[SampleGroup],
    hashes: &[&str],
) -> Vec<GroupComparison> {
    let mut output = Vec::with_capacity(groups.len());
    for (group_index, group) in groups.iter().enumerate() {
        let mut indices = group.sample_indices.clone();
        indices.sort_unstable();
        let tests = noise
            .iter()
            .enumerate()
            .map(|(sample_index, query)| {
                let references = indices
                    .iter()
                    .filter(|index| {
                        **index != sample_index && hashes[**index] != hashes[sample_index]
                    })
                    .map(|index| &noise[*index])
                    .collect::<Vec<_>>();
                GroupMatch {
                    sample_index,
                    reference_count: references.len(),
                    ncc: signals::reference_correlation(query, &references),
                    leave_one_out: indices.contains(&sample_index),
                }
            })
            .collect();
        output.push(GroupComparison {
            group_index,
            label: group.label.clone(),
            reference_samples: indices,
            tests,
            scope: "user_labeled_fixed_pattern_residual_association_without_device_attribution"
                .into(),
        });
    }
    output
}

fn channel_statistics(image: &RgbImage) -> [ChannelStatistics; 3] {
    let mut histograms = [[0u64; 256]; 3];
    for pixel in image.pixels() {
        for channel in 0..3 {
            histograms[channel][usize::from(pixel[channel])] += 1;
        }
    }
    let count = f64::from(image.width()) * f64::from(image.height());
    histograms.map(|histogram| {
        let mean = histogram
            .iter()
            .enumerate()
            .map(|(value, n)| value as f64 * *n as f64)
            .sum::<f64>()
            / count;
        let variance = histogram
            .iter()
            .enumerate()
            .map(|(value, n)| (value as f64 - mean).powi(2) * *n as f64)
            .sum::<f64>()
            / count;
        let entropy_bits = histogram
            .iter()
            .filter(|n| **n > 0)
            .map(|n| {
                let probability = *n as f64 / count;
                -probability * probability.log2()
            })
            .sum();
        let lsb_one_counts = std::array::from_fn(|bit| {
            histogram
                .iter()
                .enumerate()
                .filter(|(value, _)| (value >> bit) & 1 == 1)
                .map(|(_, n)| *n)
                .sum()
        });
        let low_two_bit_counts = std::array::from_fn(|bits| {
            histogram
                .iter()
                .enumerate()
                .filter(|(value, _)| value & 3 == bits)
                .map(|(_, n)| *n)
                .sum()
        });
        ChannelStatistics {
            mean,
            standard_deviation: variance.sqrt(),
            entropy_bits,
            histogram: histogram.to_vec(),
            lsb_one_counts,
            low_two_bit_counts,
        }
    })
}

fn luminance_grid(image: &RgbImage, side: usize) -> Vec<f64> {
    (0..side * side)
        .map(|index| {
            let x = ((index % side) as u64 * u64::from(image.width()) / side as u64) as u32;
            let y = ((index / side) as u64 * u64::from(image.height()) / side as u64) as u32;
            let pixel = image.get_pixel(x, y);
            (0.2126 * f64::from(pixel[0])
                + 0.7152 * f64::from(pixel[1])
                + 0.0722 * f64::from(pixel[2]))
                / 255.0
        })
        .collect()
}

fn frequency_statistics(image: &RgbImage) -> FrequencyStatistics {
    let mut grid = luminance_grid(image, DFT_SIDE);
    let mean = grid.iter().sum::<f64>() / grid.len() as f64;
    for value in &mut grid {
        *value -= mean;
    }
    let mut dft = [0.0; FREQUENCY_BANDS];
    for v in 0..DFT_SIDE {
        for u in 0..DFT_SIDE {
            if u == 0 && v == 0 {
                continue;
            }
            let mut real = 0.0;
            let mut imaginary = 0.0;
            for (index, value) in grid.iter().enumerate() {
                let phase = 2.0 * PI * (u * (index % DFT_SIDE) + v * (index / DFT_SIDE)) as f64
                    / DFT_SIDE as f64;
                real += value * phase.cos();
                imaginary -= value * phase.sin();
            }
            let radius = u.min(DFT_SIDE - u) + v.min(DFT_SIDE - v);
            let band = (radius * FREQUENCY_BANDS / (DFT_SIDE + 1)).min(FREQUENCY_BANDS - 1);
            dft[band] += (real * real + imaginary * imaginary) / (DFT_SIDE as f64).powi(4);
        }
    }
    let grid = luminance_grid(image, DCT_SIDE);
    let mut dct = [0.0; FREQUENCY_BANDS];
    for v in 0..DCT_SIDE {
        for u in 0..DCT_SIDE {
            if u == 0 && v == 0 {
                continue;
            }
            let mut coefficient = 0.0;
            for (index, value) in grid.iter().enumerate() {
                let x = index % DCT_SIDE;
                let y = index / DCT_SIDE;
                coefficient += value
                    * (PI * (2 * x + 1) as f64 * u as f64 / (2 * DCT_SIDE) as f64).cos()
                    * (PI * (2 * y + 1) as f64 * v as f64 / (2 * DCT_SIDE) as f64).cos();
            }
            let alpha_u = if u == 0 {
                (1.0 / DCT_SIDE as f64).sqrt()
            } else {
                (2.0 / DCT_SIDE as f64).sqrt()
            };
            let alpha_v = if v == 0 {
                (1.0 / DCT_SIDE as f64).sqrt()
            } else {
                (2.0 / DCT_SIDE as f64).sqrt()
            };
            let band = ((u + v) * FREQUENCY_BANDS / (2 * DCT_SIDE - 1)).min(FREQUENCY_BANDS - 1);
            dct[band] += (coefficient * alpha_u * alpha_v).powi(2) / (DCT_SIDE * DCT_SIDE) as f64;
        }
    }
    FrequencyStatistics {
        dft_grid_side: DFT_SIDE,
        dft_radial_power: dft,
        dft_ac_energy: dft.iter().sum(),
        dct_grid_side: DCT_SIDE,
        dct_frequency_power: dct,
        dct_ac_energy: dct.iter().sum(),
    }
}

fn band_distance(first: &[f64; FREQUENCY_BANDS], second: &[f64; FREQUENCY_BANDS]) -> f64 {
    first.iter().zip(second).map(|(a, b)| (a - b).abs()).sum()
}

fn pixel_difference(first: &RgbImage, second: &RgbImage) -> PixelDifference {
    let mut absolute = 0u64;
    let mut squared = 0u64;
    let mut maximum = 0;
    let mut changed = 0u64;
    let mut lsb_disagreements = [0u64; 2];
    for (a, b) in first.pixels().zip(second.pixels()) {
        changed += u64::from(a != b);
        for channel in 0..3 {
            let difference = a[channel].abs_diff(b[channel]);
            absolute += u64::from(difference);
            squared += u64::from(difference).pow(2);
            maximum = maximum.max(difference);
            for (bit, disagreement) in lsb_disagreements.iter_mut().enumerate() {
                *disagreement += u64::from(((a[channel] ^ b[channel]) >> bit) & 1);
            }
        }
    }
    let pixels = f64::from(first.width()) * f64::from(first.height());
    PixelDifference {
        mean_absolute_error: absolute as f64 / (pixels * 3.0),
        mean_squared_error: squared as f64 / (pixels * 3.0),
        maximum_sample_error: maximum,
        changed_pixel_fraction: changed as f64 / pixels,
        lsb_disagreement_fraction: lsb_disagreements.map(|n| n as f64 / (pixels * 3.0)),
    }
}

// FVPROV1 21364 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJiM2EzZThjYzNhM2VmNjE3Yzg5Yjk2ZTEyMmU2NzE5NzVhNzRiOGJhMjU2ZTE3ODQzMzExMDRiYTkyMTQyMzdiIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL2xhYi5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjE2MDQyODhhMzEzOTNmODA1OGZhMmVjMWRjOTM5Yjg0MTU4YWYyZGY0ZWI0NWIxM2NmNGU5OWRlYTVkZTk4MTAxZDZkYWMzYmZjMWQxMjE0Yjc0ODlmMjM2ZTc3ZjVkYzA3ZDNkNTQzMGExNmQzZDUxNjBmZmEzNDZlNDMzZDBlIn1dfV0= FVPROV1-END
