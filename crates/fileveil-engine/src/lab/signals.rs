// SPDX-License-Identifier: MPL-2.0
//! Native-resolution, bounded signal observations. These statistics carry no
//! calibrated watermark probability or manufacturer attribution.
use std::f64::consts::PI;

use fileveil_core::digest;
use image::RgbImage;
use serde::{Deserialize, Serialize};

const PREVIEW_SIDE: u32 = 64;
const NOISE_SIDE: u32 = 96;
const MAX_BLOCKS: u64 = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrayPreview {
    pub width: u32,
    pub height: u32,
    pub gray: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalPreviews {
    pub low_bits: GrayPreview,
    pub residual: GrayPreview,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JpegComponent {
    pub id: u8,
    pub horizontal_sampling: u8,
    pub vertical_sampling: u8,
    pub quantization_table: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JpegStructure {
    pub quantization_sha256: String,
    pub quantization_tables: usize,
    pub frame_components: Vec<JpegComponent>,
    pub progressive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalAnalysis {
    pub lsb_pair_chi_square: [f64; 3],
    pub lsb_pair_degrees_of_freedom: [usize; 3],
    pub lsb_adjacent_correlation: [f64; 3],
    pub block_dct_ac_power: Vec<f64>,
    pub block_dct_blocks: usize,
    pub haar_detail_power: [f64; 3],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jpeg: Option<JpegStructure>,
    pub noise_residual_rms: f64,
}

pub(super) struct NoiseGrid {
    pub signal: Vec<f64>,
    pub residual: Vec<f64>,
    pub dimensions: (u32, u32),
}

pub(super) fn analyze(
    image: &RgbImage,
    data: &[u8],
) -> (SignalAnalysis, SignalPreviews, NoiseGrid) {
    let mut histograms = [[0u64; 256]; 3];
    let mut pair_counts = [[[0u64; 2]; 2]; 3];
    for (x, y, pixel) in image.enumerate_pixels() {
        for channel in 0..3 {
            histograms[channel][usize::from(pixel[channel])] += 1;
            if x > 0 {
                let previous = image.get_pixel(x - 1, y)[channel] & 1;
                pair_counts[channel][usize::from(previous)][usize::from(pixel[channel] & 1)] += 1;
            }
        }
    }
    // Pair-of-values chi-square is an observation of even/odd histogram
    // equalization. Natural textures, quantization and random noise can match it.
    let chi_square = histograms.map(|histogram| {
        histogram
            .as_chunks::<2>()
            .0
            .iter()
            .filter(|pair| pair[0] + pair[1] > 0)
            .map(|pair| (pair[0] as f64 - pair[1] as f64).powi(2) / (pair[0] + pair[1]) as f64)
            .sum()
    });
    let degrees = histograms.map(|histogram| {
        histogram
            .as_chunks::<2>()
            .0
            .iter()
            .filter(|pair| pair[0] + pair[1] > 0)
            .count()
    });
    let adjacent = pair_counts.map(|counts| {
        let [[a, b], [c, d]] = counts.map(|row| row.map(|n| n as f64));
        let denominator = ((a + b) * (c + d) * (a + c) * (b + d)).sqrt();
        if denominator == 0.0 {
            0.0
        } else {
            (a * d - b * c) / denominator
        }
    });
    let (dct, blocks) = block_dct(image);
    let noise = noise_grid(image);
    let residual_rms = (noise.residual.iter().map(|v| v * v).sum::<f64>()
        / noise.residual.len().max(1) as f64)
        .sqrt();
    let preview = previews(image);
    (
        SignalAnalysis {
            lsb_pair_chi_square: chi_square,
            lsb_pair_degrees_of_freedom: degrees,
            lsb_adjacent_correlation: adjacent,
            block_dct_ac_power: dct,
            block_dct_blocks: blocks,
            haar_detail_power: haar_power(image),
            jpeg: jpeg_structure(data),
            noise_residual_rms: residual_rms,
        },
        preview,
        noise,
    )
}

fn luma(image: &RgbImage, x: u32, y: u32) -> f64 {
    let pixel = image.get_pixel(x, y);
    0.2126 * f64::from(pixel[0]) + 0.7152 * f64::from(pixel[1]) + 0.0722 * f64::from(pixel[2])
}

fn residual(image: &RgbImage, x: u32, y: u32) -> f64 {
    let mut blurred = 0.0;
    for (dy, wy) in [1.0, 2.0, 1.0].into_iter().enumerate() {
        for (dx, wx) in [1.0, 2.0, 1.0].into_iter().enumerate() {
            let sx = (i64::from(x) + dx as i64 - 1).clamp(0, i64::from(image.width()) - 1) as u32;
            let sy = (i64::from(y) + dy as i64 - 1).clamp(0, i64::from(image.height()) - 1) as u32;
            blurred += wx * wy * luma(image, sx, sy) / 16.0;
        }
    }
    luma(image, x, y) - blurred
}

fn preview(image: &RgbImage, value: impl Fn(u32, u32) -> u8) -> GrayPreview {
    let width = image.width().min(PREVIEW_SIDE);
    let height = image.height().min(PREVIEW_SIDE);
    let mut gray = Vec::with_capacity((width * height) as usize);
    for y in 0..height {
        for x in 0..width {
            gray.push(value(
                x * image.width() / width,
                y * image.height() / height,
            ));
        }
    }
    GrayPreview {
        width,
        height,
        gray,
    }
}

fn previews(image: &RgbImage) -> SignalPreviews {
    SignalPreviews {
        low_bits: preview(image, |x, y| {
            let pixel = image.get_pixel(x, y);
            ((u16::from(pixel[0] & 1) + u16::from(pixel[1] & 1) + u16::from(pixel[2] & 1)) * 85)
                as u8
        }),
        residual: preview(image, |x, y| {
            (128.0 + residual(image, x, y) * 8.0).clamp(0.0, 255.0) as u8
        }),
    }
}

pub(super) fn difference_preview(first: &RgbImage, second: &RgbImage) -> GrayPreview {
    preview(first, |x, y| {
        let a = first.get_pixel(x, y);
        let b = second.get_pixel(x, y);
        let delta = (0..3)
            .map(|channel| u16::from(a[channel].abs_diff(b[channel])))
            .sum::<u16>();
        (delta * 8 / 3).min(255) as u8
    })
}

fn block_dct(image: &RgbImage) -> (Vec<f64>, usize) {
    let columns = image.width() / 8;
    let rows = image.height() / 8;
    let available = u64::from(columns) * u64::from(rows);
    let count = available.min(MAX_BLOCKS);
    let mut power = vec![0.0; 64];
    let cosine: [[f64; 8]; 8] = std::array::from_fn(|frequency| {
        std::array::from_fn(|position| {
            (PI * (2 * position + 1) as f64 * frequency as f64 / 16.0).cos()
        })
    });
    for sample in 0..count {
        let block = sample * available / count;
        let origin_x = (block % u64::from(columns)) as u32 * 8;
        let origin_y = (block / u64::from(columns)) as u32 * 8;
        let grid: [[f64; 8]; 8] = std::array::from_fn(|y| {
            std::array::from_fn(|x| luma(image, origin_x + x as u32, origin_y + y as u32) / 255.0)
        });
        for v in 0..8 {
            for u in 0..8 {
                if u == 0 && v == 0 {
                    continue;
                }
                let mut coefficient = 0.0;
                for (y, row) in grid.iter().enumerate() {
                    for (x, value) in row.iter().enumerate() {
                        coefficient += value * cosine[u][x] * cosine[v][y];
                    }
                }
                let normalization = 0.25
                    * if u == 0 { 0.5f64.sqrt() } else { 1.0 }
                    * if v == 0 { 0.5f64.sqrt() } else { 1.0 };
                power[v * 8 + u] += (coefficient * normalization).powi(2) / count as f64;
            }
        }
    }
    (power, count as usize)
}

fn haar_power(image: &RgbImage) -> [f64; 3] {
    let columns = image.width() / 2;
    let rows = image.height() / 2;
    let available = u64::from(columns) * u64::from(rows);
    let count = available.min(4096);
    let mut power = [0.0; 3];
    for index in 0..count {
        let position = index * available / count;
        let x = (position % u64::from(columns)) as u32 * 2;
        let y = (position / u64::from(columns)) as u32 * 2;
        let a = luma(image, x, y) / 255.0;
        let b = luma(image, x + 1, y) / 255.0;
        let c = luma(image, x, y + 1) / 255.0;
        let d = luma(image, x + 1, y + 1) / 255.0;
        for (band, coefficient) in [
            (a - b + c - d) * 0.5,
            (a + b - c - d) * 0.5,
            (a - b - c + d) * 0.5,
        ]
        .into_iter()
        .enumerate()
        {
            power[band] += coefficient * coefficient / count as f64;
        }
    }
    power
}

fn noise_grid(image: &RgbImage) -> NoiseGrid {
    let width = image.width().min(NOISE_SIDE);
    let height = image.height().min(NOISE_SIDE);
    let mut signal = Vec::with_capacity((width * height) as usize);
    let mut noise = Vec::with_capacity((width * height) as usize);
    for gy in 0..height {
        for gx in 0..width {
            let x = gx * image.width() / width;
            let y = gy * image.height() / height;
            let value = luma(image, x, y);
            let difference = residual(image, x, y);
            // Suppress saturation, darkness and edges before estimating a
            // multiplicative fixed-pattern reference. Scene leakage remains.
            let eligible = (16.0..240.0).contains(&value) && difference.abs() < 12.0;
            signal.push(if eligible { value } else { 0.0 });
            noise.push(if eligible { difference } else { 0.0 });
        }
    }
    NoiseGrid {
        signal,
        residual: noise,
        dimensions: image.dimensions(),
    }
}

pub(super) fn correlation(first: &[f64], second: &[f64]) -> Option<f64> {
    if first.len() != second.len() || first.len() < 16 {
        return None;
    }
    let mean_a = first.iter().sum::<f64>() / first.len() as f64;
    let mean_b = second.iter().sum::<f64>() / second.len() as f64;
    let mut covariance = 0.0;
    let mut variance_a = 0.0;
    let mut variance_b = 0.0;
    for (a, b) in first.iter().zip(second) {
        covariance += (a - mean_a) * (b - mean_b);
        variance_a += (a - mean_a).powi(2);
        variance_b += (b - mean_b).powi(2);
    }
    let denominator = (variance_a * variance_b).sqrt();
    (denominator > 1e-12).then(|| (covariance / denominator).clamp(-1.0, 1.0))
}

pub(super) fn reference_correlation(query: &NoiseGrid, references: &[&NoiseGrid]) -> Option<f64> {
    if references.is_empty() || references.iter().any(|r| r.dimensions != query.dimensions) {
        return None;
    }
    let mut observed = Vec::new();
    let mut predicted = Vec::new();
    for index in 0..query.signal.len() {
        let numerator = references
            .iter()
            .map(|r| r.residual[index] * r.signal[index])
            .sum::<f64>();
        let denominator = references
            .iter()
            .map(|r| r.signal[index].powi(2))
            .sum::<f64>();
        if denominator > 0.0 && query.signal[index] > 0.0 {
            observed.push(query.residual[index]);
            predicted.push(query.signal[index] * numerator / denominator);
        }
    }
    correlation(&observed, &predicted)
}

fn jpeg_structure(data: &[u8]) -> Option<JpegStructure> {
    if !data.starts_with(&[0xff, 0xd8]) {
        return None;
    }
    let mut position = 2;
    let mut quantization = Vec::new();
    let mut tables = 0;
    let mut components = Vec::new();
    let mut progressive = false;
    while position < data.len() {
        if data.get(position) != Some(&0xff) {
            return None;
        }
        while data.get(position) == Some(&0xff) {
            position += 1;
        }
        let marker = *data.get(position)?;
        position += 1;
        if marker == 0xda || marker == 0xd9 {
            break;
        }
        if marker == 0x01 || (0xd0..=0xd8).contains(&marker) {
            continue;
        }
        let length = usize::from(u16::from_be_bytes(
            data.get(position..position + 2)?.try_into().ok()?,
        ));
        if length < 2 {
            return None;
        }
        let payload = data.get(position + 2..position.checked_add(length)?)?;
        if marker == 0xdb {
            let mut table_position = 0;
            while table_position < payload.len() {
                let header = payload[table_position];
                if header >> 4 > 1 {
                    return None;
                }
                let size = 1 + 64 * (1 + usize::from(header >> 4));
                quantization.extend_from_slice(payload.get(table_position..table_position + size)?);
                table_position += size;
                tables += 1;
            }
        }
        if matches!(marker, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf) {
            progressive = matches!(marker, 0xc2 | 0xc6 | 0xca | 0xce);
            let count = usize::from(*payload.get(5)?);
            for index in 0..count {
                let fields = payload.get(6 + index * 3..9 + index * 3)?;
                components.push(JpegComponent {
                    id: fields[0],
                    horizontal_sampling: fields[1] >> 4,
                    vertical_sampling: fields[1] & 15,
                    quantization_table: fields[2],
                });
            }
        }
        position += length;
    }
    Some(JpegStructure {
        quantization_sha256: digest(&quantization),
        quantization_tables: tables,
        frame_components: components,
        progressive,
    })
}

// FVPROV1 13325 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI1YzgyMTMxZDUyZDQ1YjNhMjJmYjkyMzRjZDQ2MzljZDMxMzA1YmQxOGNmYzE4MWI0YTgxODE5ZGViODEwYjliIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4zIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMyIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL2xhYi9zaWduYWxzLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiMTM1ZTQ5MDg5ODQyNWE3YWY5MGQ0ODYxOTNlM2ZkYWMzOWM4ZTdjMjZmMjYyNmRlM2JkNWQ4ZDdmY2IyMmEyMTMzNTRkZDViYWFmYzhkZDZiZDZhYTVkODVlMTEzOGY0NjhlNDA3NjNiZGQ2YzlmNmY1MmIxZjU5MGU4MGYwMDUifV19XQ== FVPROV1-END
