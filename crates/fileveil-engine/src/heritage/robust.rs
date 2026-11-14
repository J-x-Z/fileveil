// SPDX-License-Identifier: MPL-2.0
//! Original, public, unkeyed work-reference watermark. No identity authentication.
//!
//! A 32-byte frame consists of `FVHDCT1\n`, the first 16 SHA-256 bytes of the
//! UTF-8 work reference, IEEE CRC32 of those first 24 bytes (big endian), and
//! version bytes [1, 0, 0, 0]. Bits are MSB-first in a repeated 16x16 block tile.
//! Each 8x8 luminance block orders orthonormal DCT coefficients (u,v)=(2,3)
//! and (3,2). Embedding uses a 512x512 reference grid and maps its residual back
//! to the original dimensions. Detection uses repetition votes and bounded grid
//! and phase searches. Anyone can copy or forge the public frame.
//!
//! This pixel-domain extension is independently implemented. The historical
//! Red Star/Woolim evidence concerns file records and signatures and supplies
//! no specification for this DCT protocol. See docs/HERITAGE_RESEARCH.md.

use crate::watermark::DetectionStatus;
use fileveil_core::{Error, Limits, Result, digest};
use image::{DynamicImage, GenericImageView, imageops::FilterType};
use serde::{Deserialize, Serialize};
use std::f32::consts::PI;

pub const METHOD_ID: &str = "fileveil_heritage_dct_v1";
pub const VERSION: &str = "1.0.0";
pub const DEFAULT_STRENGTH: u8 = 32;
const REFERENCE: u32 = 512;
const TILE: usize = 16;
const FRAME_BITS: usize = TILE * TILE;
const MAGIC: &[u8; 8] = b"FVHDCT1\n";
const FRAME_VERSION: [u8; 4] = [1, 0, 0, 0];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RobustReport {
    pub method_id: String,
    pub detector_version: String,
    pub status: DetectionStatus,
    pub work_id_digest: Option<String>,
    pub frame_valid: bool,
    pub authenticated: bool,
    pub strength: Option<u8>,
    pub matched_magic_bits: u32,
    pub minimum_repetitions: u32,
    pub bit_vote_agreement: f64,
    pub reference_dimensions: Option<[u32; 2]>,
    pub pixel_phase: Option<[u32; 2]>,
    pub tile_phase: Option<[u32; 2]>,
    pub tested_grids: u32,
    pub tested_phases: u32,
    pub scope: String,
    pub limitations: Vec<String>,
}

impl Default for RobustReport {
    fn default() -> Self {
        Self {
            method_id: METHOD_ID.into(),
            detector_version: VERSION.into(),
            status: DetectionStatus::NotDetected,
            work_id_digest: None,
            frame_valid: false,
            authenticated: false,
            strength: None,
            matched_magic_bits: 0,
            minimum_repetitions: 0,
            bit_vote_agreement: 0.0,
            reference_dimensions: None,
            pixel_phase: None,
            tile_phase: None,
            tested_grids: 0,
            tested_phases: 0,
            scope: "public_work_reference_signal_without_identity_authentication".into(),
            limitations: vec![
                "Public work digests can be copied, forged or enumerated. A match does not authenticate an author, device, content binding or ownership.".into(),
                "Repetition and CRC reject damaged frames within the tested search scope. False-positive rates on arbitrary images have not been calibrated.".into(),
                "Rotation, severe compression, arbitrary crops, aspect changes and large resampling can prevent detection. A negative result does not establish absence.".into(),
                "Search is bounded to the 512 reference, native dimensions at most 768 per axis, and 448/384/320/256 square grids. Only the native grid searches all eight pixel phases per axis.".into(),
            ],
        }
    }
}

/// Returns the public 128-bit work-reference digest embedded by this protocol.
pub fn work_id_digest(work_id: &str) -> Result<String> {
    if work_id.trim().is_empty() || work_id.len() > 4096 {
        return Err(Error::Input(
            "A work reference requires 1..4096 UTF-8 bytes".into(),
        ));
    }
    Ok(digest(work_id.as_bytes())[..32].to_owned())
}

/// Explicit pixel-changing operation. The caller owns encoding, signed-record
/// binding, file publication and original-file verification.
pub fn embed(
    image: &DynamicImage,
    work_id: &str,
    strength: u8,
    limits: &Limits,
) -> Result<(DynamicImage, RobustReport)> {
    validate(image, limits, 512)?;
    if !(16..=64).contains(&strength) {
        return Err(Error::Input("DCT watermark strength must be 16..64".into()));
    }
    let work_digest = work_id_digest(work_id)?;
    let frame = frame(&work_digest);
    let kernels = Kernels::new();
    let mut output = image.clone();
    // A second bounded pass compensates for RGB clipping and grid resampling.
    for _ in 0..2 {
        let gray = gray_reference(&output, REFERENCE, REFERENCE);
        let mut residual = vec![0.0_f32; (REFERENCE * REFERENCE) as usize];
        for by in 0..REFERENCE as usize / 8 {
            for bx in 0..REFERENCE as usize / 8 {
                let bit = bit(&frame, (by % TILE) * TILE + bx % TILE);
                let difference = kernels.difference(&gray, REFERENCE as usize, bx * 8, by * 8);
                let target = if bit {
                    strength as f32
                } else {
                    -(strength as f32)
                };
                let change = if bit {
                    (target - difference).max(0.0)
                } else {
                    (target - difference).min(0.0)
                } * 0.5;
                kernels.write_residual(&mut residual, REFERENCE as usize, bx * 8, by * 8, change);
            }
        }
        apply_residual(&mut output, &residual, REFERENCE, REFERENCE);
    }
    let mut report = detect(&output, limits)?;
    if report.status != DetectionStatus::Detected
        || report.work_id_digest.as_ref() != Some(&work_digest)
    {
        return Err(Error::Verification("Embedded DCT work reference could not be independently recovered from the output pixels".into()));
    }
    report.strength = Some(strength);
    Ok((output, report))
}

/// Neutralizes the detected public protocol's carrier coefficient pair, then
/// repeats blind detection. Success is scoped to this method's tested grids.
/// A negative input is rejected before modifying any samples.
pub fn clean(image: &DynamicImage, limits: &Limits) -> Result<(DynamicImage, RobustReport)> {
    let mut evidence = detect(image, limits)?;
    if evidence.status != DetectionStatus::Detected {
        return Err(Error::Unsupported(
            "Targeted DCT cleaning requires a detected FileVeil work-reference frame".into(),
        ));
    }
    let kernels = Kernels::new();
    let mut output = image.clone();
    // Bounded retries also cover an independently detectable secondary grid.
    for _ in 0..3 {
        let [width, height] = evidence.reference_dimensions.expect("detected grid");
        let [px, py] = evidence.pixel_phase.expect("detected pixel phase");
        for _ in 0..2 {
            let gray = gray_reference(&output, width, height);
            let mut residual = vec![0.0_f32; (width * height) as usize];
            for by in 0..(height - py) as usize / 8 {
                for bx in 0..(width - px) as usize / 8 {
                    let x = px as usize + bx * 8;
                    let y = py as usize + by * 8;
                    // Exact zero can retain every payload sign through RGB/JPEG
                    // rounding. A fixed, work-independent +/-4 checkerboard
                    // gives a small quantization guard around the neutral pair.
                    let target = if (bx + by) % 2 == 0 { 4.0 } else { -4.0 };
                    let change = 0.5 * (target - kernels.difference(&gray, width as usize, x, y));
                    kernels.write_residual(&mut residual, width as usize, x, y, change);
                }
            }
            apply_residual(&mut output, &residual, width, height);
        }
        evidence = detect(&output, limits)?;
        if evidence.status != DetectionStatus::Detected {
            evidence.scope = "targeted_public_dct_neutralization_with_postprocess_retest".into();
            evidence.limitations.push("Cleaning changes image samples and targets only the detected FileVeil DCT carrier. Other watermark schemes remain unassessed.".into());
            return Ok((output, evidence));
        }
    }
    Err(Error::Verification(
        "The targeted DCT frame remains detectable after bounded neutralization".into(),
    ))
}

/// Offline blind recovery with a fixed upper bound on reference pixels, grids
/// and phase candidates. Accepts caller-authorized, already decoded pixels.
pub fn detect(image: &DynamicImage, limits: &Limits) -> Result<RobustReport> {
    validate(image, limits, 256)?;
    let kernels = Kernels::new();
    let mut report = RobustReport::default();
    let reference = gray_reference(image, REFERENCE, REFERENCE);
    if search_grid(
        &reference,
        REFERENCE,
        REFERENCE,
        false,
        &kernels,
        &mut report,
    ) {
        return Ok(report);
    }
    let (width, height) = image.dimensions();
    if width <= 768 && height <= 768 {
        let native = gray_reference(image, width, height);
        if search_grid(&native, width, height, true, &kernels, &mut report) {
            return Ok(report);
        }
    }
    for edge in [448, 384, 320, 256] {
        let reference = gray_reference(image, edge, edge);
        if search_grid(&reference, edge, edge, false, &kernels, &mut report) {
            return Ok(report);
        }
    }
    if report.matched_magic_bits >= 56 {
        report.status = DetectionStatus::Indeterminate;
    }
    Ok(report)
}

fn validate(image: &DynamicImage, limits: &Limits, minimum_edge: u32) -> Result<()> {
    if !matches!(
        image,
        DynamicImage::ImageRgb8(_) | DynamicImage::ImageRgba8(_)
    ) {
        return Err(Error::Unsupported(
            "DCT work-reference marking supports RGB8 and RGBA8 samples".into(),
        ));
    }
    let (width, height) = image.dimensions();
    if width < minimum_edge || height < minimum_edge {
        return Err(Error::Unsupported(format!(
            "DCT work-reference operation requires both dimensions at least {minimum_edge} pixels"
        )));
    }
    if u64::from(width) * u64::from(height) > limits.max_pixels
        || u64::from(REFERENCE).pow(2) > limits.max_pixels
    {
        return Err(Error::Input(
            "DCT image or reference grid exceeds the configured pixel budget".into(),
        ));
    }
    Ok(())
}

fn frame(work_digest: &str) -> [u8; 32] {
    let mut frame = [0_u8; 32];
    frame[..8].copy_from_slice(MAGIC);
    for (index, byte) in frame[8..24].iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&work_digest[index * 2..index * 2 + 2], 16).expect("SHA-256 hex");
    }
    let crc = crc32(&frame[..24]);
    frame[24..28].copy_from_slice(&crc.to_be_bytes());
    frame[28..].copy_from_slice(&FRAME_VERSION);
    frame
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn bit(frame: &[u8; 32], index: usize) -> bool {
    frame[index / 8] & (1 << (7 - index % 8)) != 0
}

fn gray_reference(image: &DynamicImage, width: u32, height: u32) -> Vec<f32> {
    let reference = image
        .resize_exact(width, height, FilterType::Triangle)
        .to_rgb8();
    reference
        .pixels()
        .map(|pixel| 0.299 * pixel[0] as f32 + 0.587 * pixel[1] as f32 + 0.114 * pixel[2] as f32)
        .collect()
}

fn apply_residual(
    image: &mut DynamicImage,
    residual: &[f32],
    reference_width: u32,
    reference_height: u32,
) {
    let width = image.width();
    let height = image.height();
    for y in 0..height {
        let ry = ((y as f32 + 0.5) * reference_height as f32 / height as f32 - 0.5)
            .clamp(0.0, (reference_height - 1) as f32);
        let y0 = ry.floor() as usize;
        let y1 = (y0 + 1).min(reference_height as usize - 1);
        let fy = ry - y0 as f32;
        for x in 0..width {
            let rx = ((x as f32 + 0.5) * reference_width as f32 / width as f32 - 0.5)
                .clamp(0.0, (reference_width - 1) as f32);
            let x0 = rx.floor() as usize;
            let x1 = (x0 + 1).min(reference_width as usize - 1);
            let fx = rx - x0 as f32;
            let row0 = residual[y0 * reference_width as usize + x0] * (1.0 - fx)
                + residual[y0 * reference_width as usize + x1] * fx;
            let row1 = residual[y1 * reference_width as usize + x0] * (1.0 - fx)
                + residual[y1 * reference_width as usize + x1] * fx;
            let delta = row0 * (1.0 - fy) + row1 * fy;
            let channels = match image {
                DynamicImage::ImageRgb8(rgb) => &mut rgb.get_pixel_mut(x, y).0[..],
                DynamicImage::ImageRgba8(rgba) => &mut rgba.get_pixel_mut(x, y).0[..3],
                _ => unreachable!("validated sample model"),
            };
            for channel in channels {
                *channel = (*channel as f32 + delta).round().clamp(0.0, 255.0) as u8;
            }
        }
    }
}

struct Kernels {
    c2: [f32; 8],
    c3: [f32; 8],
}

impl Kernels {
    fn new() -> Self {
        Self {
            c2: std::array::from_fn(|x| ((2 * x + 1) as f32 * 2.0 * PI / 16.0).cos() * 0.5),
            c3: std::array::from_fn(|x| ((2 * x + 1) as f32 * 3.0 * PI / 16.0).cos() * 0.5),
        }
    }

    fn difference(&self, gray: &[f32], width: usize, x: usize, y: usize) -> f32 {
        let mut difference = 0.0;
        for row in 0..8 {
            for column in 0..8 {
                difference += gray[(y + row) * width + x + column]
                    * (self.c2[column] * self.c3[row] - self.c3[column] * self.c2[row]);
            }
        }
        difference
    }

    fn write_residual(&self, residual: &mut [f32], width: usize, x: usize, y: usize, change: f32) {
        for row in 0..8 {
            for column in 0..8 {
                let basis = self.c2[column] * self.c3[row] - self.c3[column] * self.c2[row];
                residual[(y + row) * width + x + column] = change * basis;
            }
        }
    }

    // Separable sliding convolution computes all pixel phases in O(16*W*H),
    // avoiding a full 8x8 transform at each of the 64 possible pixel phases.
    fn sliding_differences(&self, gray: &[f32], width: usize, height: usize) -> Vec<f32> {
        let stride = width - 7;
        let rows = height - 7;
        let mut h2 = vec![0.0_f32; stride * height];
        let mut h3 = vec![0.0_f32; stride * height];
        for y in 0..height {
            for x in 0..stride {
                for k in 0..8 {
                    let sample = gray[y * width + x + k];
                    h2[y * stride + x] += sample * self.c2[k];
                    h3[y * stride + x] += sample * self.c3[k];
                }
            }
        }
        let mut differences = vec![0.0_f32; stride * rows];
        for y in 0..rows {
            for x in 0..stride {
                for k in 0..8 {
                    differences[y * stride + x] += h2[(y + k) * stride + x] * self.c3[k]
                        - h3[(y + k) * stride + x] * self.c2[k];
                }
            }
        }
        differences
    }
}

fn search_grid(
    gray: &[f32],
    width: u32,
    height: u32,
    pixel_search: bool,
    kernels: &Kernels,
    report: &mut RobustReport,
) -> bool {
    report.tested_grids += 1;
    let differences =
        pixel_search.then(|| kernels.sliding_differences(gray, width as usize, height as usize));
    let phases = if pixel_search { 8 } else { 1 };
    for py in 0..phases {
        for px in 0..phases {
            let mut soft_votes = [0.0_f32; FRAME_BITS];
            let mut positive = [0_u32; FRAME_BITS];
            let mut negative = [0_u32; FRAME_BITS];
            for by in 0..(height as usize - py) / 8 {
                for bx in 0..(width as usize - px) / 8 {
                    let x = px + bx * 8;
                    let y = py + by * 8;
                    let difference = differences.as_ref().map_or_else(
                        || kernels.difference(gray, width as usize, x, y),
                        |values| values[y * (width as usize - 7) + x],
                    );
                    let index = (by % TILE) * TILE + bx % TILE;
                    soft_votes[index] += difference.clamp(-64.0, 64.0);
                    if difference >= 0.0 {
                        positive[index] += 1
                    } else {
                        negative[index] += 1
                    }
                }
            }
            let minimum = positive
                .iter()
                .zip(&negative)
                .map(|(p, n)| p + n)
                .min()
                .unwrap_or(0);
            if minimum < 3 {
                continue;
            }
            let agree = positive
                .iter()
                .zip(&negative)
                .map(|(p, n)| (*p).max(*n) as f64)
                .sum::<f64>()
                / positive
                    .iter()
                    .zip(&negative)
                    .map(|(p, n)| p + n)
                    .sum::<u32>() as f64;
            for ty in 0..TILE {
                for tx in 0..TILE {
                    report.tested_phases += 1;
                    let index =
                        |bit: usize| ((bit / TILE + ty) % TILE) * TILE + (bit % TILE + tx) % TILE;
                    let matches = (0..64)
                        .filter(|position| {
                            (soft_votes[index(*position)] >= 0.0) == bit_from_magic(*position)
                        })
                        .count() as u32;
                    report.matched_magic_bits = report.matched_magic_bits.max(matches);
                    if matches != 64 {
                        continue;
                    }
                    let mut recovered = [0_u8; 32];
                    for position in 0..FRAME_BITS {
                        if soft_votes[index(position)] >= 0.0 {
                            recovered[position / 8] |= 1 << (7 - position % 8);
                        }
                    }
                    if recovered[28..] != FRAME_VERSION
                        || recovered[24..28] != crc32(&recovered[..24]).to_be_bytes()
                    {
                        continue;
                    }
                    report.status = DetectionStatus::Detected;
                    report.work_id_digest = Some(
                        recovered[8..24]
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect(),
                    );
                    report.frame_valid = true;
                    report.minimum_repetitions = minimum;
                    report.bit_vote_agreement = agree;
                    report.reference_dimensions = Some([width, height]);
                    report.pixel_phase = Some([px as u32, py as u32]);
                    report.tile_phase = Some([tx as u32, ty as u32]);
                    return true;
                }
            }
        }
    }
    false
}

fn bit_from_magic(position: usize) -> bool {
    MAGIC[position / 8] & (1 << (7 - position % 8)) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_and_sliding_dct_match_independent_definitions() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        let kernels = Kernels::new();
        let gray: Vec<_> = (0..32 * 24)
            .map(|index| ((index * 17 + index / 32 * 7) % 256) as f32)
            .collect();
        let sliding = kernels.sliding_differences(&gray, 32, 24);
        for y in 0..17 {
            for x in 0..25 {
                let direct = kernels.difference(&gray, 32, x, y);
                assert!((sliding[y * 25 + x] - direct).abs() < 0.001);
            }
        }
    }

    #[test]
    fn damaged_payload_with_intact_magic_is_indeterminate_without_work_digest() {
        let limits = Limits::default();
        let kernels = Kernels::new();
        let mut damaged = frame(&work_id_digest("corrupt public frame").unwrap());
        damaged[10] ^= 1;
        let mut residual = vec![0.0_f32; (REFERENCE * REFERENCE) as usize];
        for by in 0..64 {
            for bx in 0..64 {
                let change = if bit(&damaged, by % TILE * TILE + bx % TILE) {
                    16.0
                } else {
                    -16.0
                };
                kernels.write_residual(&mut residual, REFERENCE as usize, bx * 8, by * 8, change);
            }
        }
        let mut image =
            DynamicImage::ImageRgb8(image::RgbImage::from_pixel(512, 512, image::Rgb([127; 3])));
        apply_residual(&mut image, &residual, REFERENCE, REFERENCE);
        let report = detect(&image, &limits).unwrap();
        assert_eq!(report.status, DetectionStatus::Indeterminate);
        assert_eq!(report.matched_magic_bits, 64);
        assert!(report.work_id_digest.is_none());
        assert!(!report.frame_valid);
    }
}

// FVPROV1 21197 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI1NmFiYmI2MzI2N2U2MGRmMWVkOTQ5NDI3YWFjOGJlNGEwYTM0NTdhNTliNDlmM2I1NmE2M2MwOThhZTM4YzJjIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4zIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMyIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL2hlcml0YWdlL3JvYnVzdC5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6ImY4NmE4MTI2MGViZmI4NWIyZTkzZDZjNzY4ODdjYjllMDlkMDQwNzNkZGY3NGNiY2E3MzY0YjliZGYwYzI4NjYzYmNiNjA2OGU3MjNmZGE5ZTUwNGQ1MjkyM2EzOWM3NWJhZDBhNjc1YmQxN2ExYmI0NDRiMmUzMzU4YjAxNjAzIn1dfV0= FVPROV1-END
