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
pub(super) fn block_decisions(image: &RgbImage) -> Vec<bool> {
    let block_columns = image.width() as usize / 8;
    let block_rows = image.height() as usize / 8;
    let mut decisions = Vec::with_capacity(block_columns * block_rows);
    for block_y in 0..block_rows {
        for block_x in 0..block_columns {
            let mut maximum = -1.0f64;
            for index in 1..16 {
                let x = (block_x * 8 + index % 4 * 2) as u32;
                let y = (block_y * 8 + index / 4 * 2) as u32;
                let mut sum = 0u32;
                for dy in 0..2 {
                    for dx in 0..2 {
                        let pixel = image.get_pixel(x + dx, y + dy);
                        sum += u32::from(opencv_u(pixel.0));
                    }
                }
                maximum = maximum.max(f64::from(sum) * 0.5);
            }
            decisions.push(maximum % 36.0 > 18.0);
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

pub(super) fn votes(decisions: &[bool], length: usize) -> Vec<(usize, usize)> {
    let mut votes = vec![(0usize, 0usize); length];
    for (index, bit) in decisions.iter().enumerate() {
        let vote = &mut votes[index % length];
        vote.0 += usize::from(*bit);
        vote.1 += 1;
    }
    votes
}
