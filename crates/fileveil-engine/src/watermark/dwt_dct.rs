// SPDX-License-Identifier: MIT
// Copyright (c) 2021 ShieldMnt
// Copyright (c) 2026 FileVeil contributors
//
// Rust adaptation of EmbedMaxDct.decode/decode_frame/infer_dct_matrix from
// invisible-watermark, commit 68d0376d94a4701ed240af0841ec12e00676e325.
// The upstream MIT license is reproduced in
// assets/licenses/external-invisible-watermark/LICENSE-MIT.
// Its deployed "dwtDct" matrix route quantizes Haar approximation samples.
// Keep that behavior, including exclusion of the first sample in each block.

use image::RgbImage;

/// Extract the U-channel Haar-block decisions once, retaining the original
/// image geometry and row-major ordering used by the independent encoder.
pub(super) fn block_decisions(image: &RgbImage) -> [Vec<bool>; 3] {
    let block_columns = image.width() as usize / 8;
    let block_rows = image.height() as usize / 8;
    let mut decisions = std::array::from_fn(|_| Vec::with_capacity(block_columns * block_rows));
    for block_y in 0..block_rows {
        for block_x in 0..block_columns {
            let mut maximum = [-1.0f64; 3];
            for index in 1..16 {
                let x = (block_x * 8 + index % 4 * 2) as u32;
                let y = (block_y * 8 + index / 4 * 2) as u32;
                let values: [[f64; 2]; 2] = std::array::from_fn(|dy| {
                    std::array::from_fn(|dx| {
                        f64::from(opencv_u(image.get_pixel(x + dx as u32, y + dy as u32).0))
                    })
                });
                let [[a, b], [c, d]] = values;
                let q = std::f64::consts::FRAC_1_SQRT_2;
                // PyWavelets applies the vertical then horizontal Haar pass.
                // Its compiled convolution can use FMA or ordinary multiply/add.
                // Retain the original exact-half route and expose all three so
                // detector decisions can require numerical consensus.
                let exact = (a + b + c + d) * 0.5;
                let left = a * q + c * q;
                let right = b * q + d * q;
                let unfused = left * q + right * q;
                let left_fma = a.mul_add(q, c * q);
                let right_fma = b.mul_add(q, d * q);
                let fused = left_fma.mul_add(q, right_fma * q);
                for (maximum, value) in maximum.iter_mut().zip([exact, unfused, fused]) {
                    *maximum = maximum.max(value);
                }
            }
            for (route, maximum) in decisions.iter_mut().zip(maximum) {
                route.push(maximum % 36.0 > 18.0);
            }
        }
    }
    decisions
}

/// Integer OpenCV COLOR_RGB2YUV conversion. The decoder must use quantized
/// 8-bit Y and U, since using floating-point chroma changes boundary decisions.
fn opencv_u([red, green, blue]: [u8; 3]) -> u8 {
    let y = (4899 * i32::from(red) + 9617 * i32::from(green) + 1868 * i32::from(blue) + 8192) >> 14;
    (((i32::from(blue) - y) * 8061 + (128 << 14) + 8192) >> 14).clamp(0, 255) as u8
}

/// Overwrite the recognized public carrier with a constant zero-bit decision
/// independent of the original payload. Only one 2x2 cell per block is changed
/// when a bounded RGB adjustment can establish the neutral decision.
/// The subsequent detector retest decides whether the payload was disrupted.
pub(super) fn clean_public_carrier(image: &mut RgbImage) {
    let columns = image.width() / 8;
    let rows = image.height() / 8;
    for block_y in 0..rows {
        for block_x in 0..columns {
            overwrite_block(image, block_x * 8, block_y * 8, false);
        }
    }
}

fn overwrite_block(image: &mut RgbImage, x: u32, y: u32, desired: bool) {
    let samples: [f64; 16] = std::array::from_fn(|index| {
        let x = x + (index % 4 * 2) as u32;
        let y = y + (index / 4 * 2) as u32;
        (f64::from(opencv_u(image.get_pixel(x, y).0))
            + f64::from(opencv_u(image.get_pixel(x + 1, y).0))
            + f64::from(opencv_u(image.get_pixel(x, y + 1).0))
            + f64::from(opencv_u(image.get_pixel(x + 1, y + 1).0)))
            * 0.5
    });
    let maximum = samples[1..].iter().copied().fold(0.0, f64::max);
    if (maximum % 36.0 > 18.0) == desired {
        return;
    }
    let mut target = (maximum / 36.0).floor() * 36.0 + if desired { 27.0 } else { 9.0 };
    if target <= maximum {
        target += 36.0;
    }
    let mut best = None;
    for (index, sample) in samples.iter().enumerate().skip(1) {
        let nominal = (target - sample) * 0.5;
        // A large difference would turn this into a broad color transformation.
        if nominal > 24.0 {
            continue;
        }
        let left = x + (index % 4 * 2) as u32;
        let top = y + (index / 4 * 2) as u32;
        let pixels: [image::Rgb<u8>; 4] = std::array::from_fn(|pixel| {
            *image.get_pixel(left + (pixel % 2) as u32, top + (pixel / 2) as u32)
        });
        for correction in [-1.0, 0.0, 1.0] {
            let delta = nominal + correction;
            let adjusted = pixels.map(|pixel| {
                let [red, green, blue] = pixel.0;
                image::Rgb([
                    red,
                    (f64::from(green) - 0.39465 * delta)
                        .round()
                        .clamp(0.0, 255.0) as u8,
                    (f64::from(blue) + 2.03211 * delta)
                        .round()
                        .clamp(0.0, 255.0) as u8,
                ])
            });
            let coefficient = adjusted
                .iter()
                .map(|pixel| f64::from(opencv_u(pixel.0)))
                .sum::<f64>()
                * 0.5;
            let actual = samples
                .iter()
                .enumerate()
                .skip(1)
                .filter(|(other, _)| *other != index)
                .map(|(_, value)| *value)
                .fold(coefficient, f64::max);
            let remainder = actual % 36.0;
            let established = if desired {
                (22.0..=32.0).contains(&remainder)
            } else {
                (4.0..=14.0).contains(&remainder)
            };
            if !established {
                continue;
            }
            let error: i32 = pixels
                .iter()
                .zip(adjusted)
                .flat_map(|(before, after)| {
                    before
                        .0
                        .into_iter()
                        .zip(after.0)
                        .map(|(a, b)| (i32::from(a) - i32::from(b)).pow(2))
                })
                .sum();
            if best
                .as_ref()
                .is_none_or(|(_, _, _, lowest)| error < *lowest)
            {
                best = Some((left, top, adjusted, error));
            }
        }
    }
    if let Some((left, top, pixels, _)) = best {
        for (index, pixel) in pixels.into_iter().enumerate() {
            image.put_pixel(left + (index % 2) as u32, top + (index / 2) as u32, pixel);
        }
    }
}

pub(super) fn votes(decisions: &[bool], length: usize) -> Vec<(usize, usize)> {
    let mut votes = vec![(0usize, 0usize); length];
    for (index, bit) in decisions.iter().enumerate() {
        let vote = &mut votes[index % length];
        vote.0 += usize::from(*bit);
        vote.1 += 1;
    }
    votes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantization_boundary_retains_numeric_route_disagreement() {
        let color = [128, 128, 62];
        assert_eq!(opencv_u(color), 99);
        let image = RgbImage::from_pixel(8, 8, image::Rgb(color));
        let [exact, unfused, fused] = block_decisions(&image);
        assert_eq!(exact, [false]);
        assert_eq!(unfused, [true]);
        assert_eq!(fused, [true]);
    }
}
