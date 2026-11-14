// SPDX-License-Identifier: MPL-2.0
//! Bounded, content-independent geometry proposals from periodic autocorrelation.
//! The MAC-valid payload detector makes the final decision. Correlation alone
//! supplies no evidence of watermark presence or authorship.
use std::f32::consts::PI;

const EDGE: usize = 512;
const FFT_EDGE: usize = 1024;

#[derive(Debug, Clone, Copy)]
pub(super) struct AngleCandidate {
    pub degrees: f32,
    pub periodic_score: f64,
}
#[derive(Clone, Copy, Default)]
struct Complex {
    re: f32,
    im: f32,
}
impl Complex {
    fn mul(self, other: Self) -> Self {
        Self {
            re: self.re * other.re - self.im * other.im,
            im: self.re * other.im + self.im * other.re,
        }
    }
}

/// Current-canvas aspect compensates anisotropic normalization to 512 square.
/// Three separated angles are proposed, with 0.25 degree angular resolution.
pub(super) fn proposals(gray: &[f32], canvas_aspect: f32) -> Vec<AngleCandidate> {
    if gray.len() != EDGE * EDGE || !(0.25..=4.0).contains(&canvas_aspect) {
        return Vec::new();
    }
    let mut spectrum = vec![Complex::default(); FFT_EDGE * FFT_EDGE];
    for y in 1..EDGE - 1 {
        for x in 1..EDGE - 1 {
            // Four-neighbor high-pass suppresses broad scene illumination.
            let i = y * EDGE + x;
            spectrum[y * FFT_EDGE + x].re =
                gray[i] - 0.25 * (gray[i - 1] + gray[i + 1] + gray[i - EDGE] + gray[i + EDGE]);
        }
    }
    fft2(&mut spectrum, FFT_EDGE, false);
    for value in &mut spectrum {
        value.re = value.re * value.re + value.im * value.im;
        value.im = 0.0;
    }
    fft2(&mut spectrum, FFT_EDGE, true);
    let mut angles = Vec::with_capacity(361);
    for step in -180..=180 {
        let angle = step as f32 * 0.25;
        let radians = angle * PI / 180.0;
        let (sin, cos) = radians.sin_cos();
        let score = |distance: f32| -> Option<f64> {
            let horizontal = sample(&spectrum, distance * cos, distance * canvas_aspect * sin)?;
            let vertical = sample(&spectrum, -distance / canvas_aspect * sin, distance * cos)?;
            Some(horizontal + vertical)
        };
        let Some(main) = score(128.0).zip(score(256.0)).map(|(a, b)| a + b) else {
            continue;
        };
        let background = [123.0, 133.0, 251.0, 261.0]
            .into_iter()
            .map(score)
            .collect::<Option<Vec<_>>>();
        let Some(background) = background else {
            continue;
        };
        angles.push(AngleCandidate {
            degrees: angle,
            periodic_score: main - background.into_iter().sum::<f64>() * 0.5,
        });
    }
    angles.sort_unstable_by(|a, b| b.periodic_score.total_cmp(&a.periodic_score));
    let mut result: Vec<AngleCandidate> = Vec::with_capacity(3);
    for candidate in angles {
        if candidate.degrees.abs() < 0.5 || candidate.periodic_score <= 0.0 {
            continue;
        }
        if result
            .iter()
            .any(|old| (old.degrees - candidate.degrees).abs() < 1.5)
        {
            continue;
        }
        result.push(candidate);
        if result.len() == 3 {
            break;
        }
    }
    result
}

fn sample(correlation: &[Complex], dx: f32, dy: f32) -> Option<f64> {
    if dx.abs() > 384.0 || dy.abs() > 384.0 {
        return None;
    }
    let x = dx.floor() as i32;
    let y = dy.floor() as i32;
    let fx = dx - x as f32;
    let fy = dy - y as f32;
    let get = |x: i32, y: i32| {
        correlation[y.rem_euclid(FFT_EDGE as i32) as usize * FFT_EDGE
            + x.rem_euclid(FFT_EDGE as i32) as usize]
            .re
    };
    let a = get(x, y) * (1.0 - fx) + get(x + 1, y) * fx;
    let b = get(x, y + 1) * (1.0 - fx) + get(x + 1, y + 1) * fx;
    let overlap = (EDGE as f64 - f64::from(dx.abs())) * (EDGE as f64 - f64::from(dy.abs()));
    Some(f64::from(a * (1.0 - fy) + b * fy) / overlap)
}

/// Rectify on the normalized grid using the physical-canvas aspect ratio.
/// Out-of-canvas samples receive the image mean, then have no keyed payload.
pub(super) fn rectify(
    gray: &[f32],
    width: u32,
    height: u32,
    degrees: f32,
    canvas_aspect: f32,
) -> Vec<f32> {
    let mut result = vec![0.0; gray.len()];
    let angle = degrees * PI / 180.0;
    let (sin, cos) = angle.sin_cos();
    let cx = (width - 1) as f32 * 0.5;
    let cy = (height - 1) as f32 * 0.5;
    let ratio = canvas_aspect * height as f32 / width as f32;
    let fill = gray.iter().sum::<f32>() / gray.len() as f32;
    for y in 0..height {
        for x in 0..width {
            let dx = x as f32 - cx;
            let dy = y as f32 - cy;
            let sx = cos * dx - sin / ratio * dy + cx;
            let sy = sin * ratio * dx + cos * dy + cy;
            result[(y * width + x) as usize] =
                interpolate(gray, width, height, sx, sy).unwrap_or(fill);
        }
    }
    result
}

pub(super) fn interpolate(data: &[f32], width: u32, height: u32, x: f32, y: f32) -> Option<f32> {
    if x < 0.0 || y < 0.0 || x > (width - 1) as f32 || y > (height - 1) as f32 {
        return None;
    }
    let x0 = x.floor() as usize;
    let y0 = y.floor() as usize;
    let x1 = (x0 + 1).min(width as usize - 1);
    let y1 = (y0 + 1).min(height as usize - 1);
    let fx = x - x0 as f32;
    let fy = y - y0 as f32;
    let a = data[y0 * width as usize + x0] * (1.0 - fx) + data[y0 * width as usize + x1] * fx;
    let b = data[y1 * width as usize + x0] * (1.0 - fx) + data[y1 * width as usize + x1] * fx;
    Some(a * (1.0 - fy) + b * fy)
}

fn fft2(values: &mut [Complex], edge: usize, inverse: bool) {
    for row in values.chunks_exact_mut(edge) {
        fft(row, inverse);
    }
    let mut column = vec![Complex::default(); edge];
    for x in 0..edge {
        for y in 0..edge {
            column[y] = values[y * edge + x];
        }
        fft(&mut column, inverse);
        for y in 0..edge {
            values[y * edge + x] = column[y];
        }
    }
}
fn fft(values: &mut [Complex], inverse: bool) {
    let n = values.len();
    let mut j = 0;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            values.swap(i, j);
        }
    }
    let mut length = 2;
    while length <= n {
        let theta = (if inverse { 2.0 } else { -2.0 }) * PI / length as f32;
        let step = Complex {
            re: theta.cos(),
            im: theta.sin(),
        };
        for start in (0..n).step_by(length) {
            let mut phase = Complex { re: 1.0, im: 0.0 };
            for i in 0..length / 2 {
                let a = values[start + i];
                let b = values[start + i + length / 2].mul(phase);
                values[start + i] = Complex {
                    re: a.re + b.re,
                    im: a.im + b.im,
                };
                values[start + i + length / 2] = Complex {
                    re: a.re - b.re,
                    im: a.im - b.im,
                };
                phase = phase.mul(step);
            }
        }
        length *= 2;
    }
    if inverse {
        for value in values {
            value.re /= n as f32;
            value.im /= n as f32;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fft_matches_direct_dft_and_roundtrip() {
        let original: Vec<_> = (0..16)
            .map(|i| Complex {
                re: (i * i % 13) as f32,
                im: 0.0,
            })
            .collect();
        let mut transformed = original.clone();
        fft(&mut transformed, false);
        for (k, value) in transformed.iter().enumerate() {
            let mut direct = Complex::default();
            for (i, sample) in original.iter().enumerate() {
                let angle = -2.0 * PI * (k * i) as f32 / 16.0;
                direct.re += sample.re * angle.cos();
                direct.im += sample.re * angle.sin();
            }
            assert!((value.re - direct.re).abs() < 0.001);
            assert!((value.im - direct.im).abs() < 0.001);
        }
        fft(&mut transformed, true);
        for (a, b) in original.iter().zip(&transformed) {
            assert!((a.re - b.re).abs() < 0.001);
            assert!(b.im.abs() < 0.001);
        }
    }
}

// FVPROV1 8381 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIxNmVjOTI2ZjM2YTRlYmU1OTBkNGM5NThiNTg4YWUyZmE5MjgxZDgwYWY3ZTE1NGIzMjM4N2VlMTljN2I3YjY1IiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL2hlcml0YWdlL3JvYnVzdF92Mi9nZW9tZXRyeS5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjhjMmVjNGNiNTE1MjM3ZjdmNzhjZTQxZTY4NGIxZTIzNTlmYTE0MTFkYjNhNGE2Mjk2YzhhMGZiNWYwNmJmYjhhOTg1ODNkYzIwMWJhYmRkMGU1MmViOWFlMTUzMWM4MDJiMzg5ZDNmN2Q5MjY5MzdiMzY4ZDIxZTUzNjNhZjBiIn1dfV0= FVPROV1-END
