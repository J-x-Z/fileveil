// SPDX-License-Identifier: MPL-2.0
//! Versioned, keyed blind work/copy-reference watermark with BCH correction.
//!
//! Frame layout is `FVW2 || SHA256(work)[0..12] || SHA256(copy)[0..8] ||
//! HMAC-SHA256(key, domain || preceding bytes)[0..12]`. Its 288 bits are padded
//! to seven 45-bit messages and encoded by a primitive narrow-sense BCH(63,45)
//! code, t=3, GF(64) polynomial x^6+x+1. The 441 coded bits and 71 keyed pilot
//! bits occupy two coefficient-pair channels in a repeated 16x16 block tile.
//! A keyed permutation and sign sequence select the carriers. Pilots rank
//! geometric candidates before BCH and MAC verification. HMAC establishes
//! possession of this watermark key, with authorship established separately by
//! the signed provenance record. Work and copy identifiers are truncated hashes.
//!
//! References are the BCH defining-root construction, Berlekamp-Massey and
//! Chien search, and RFC 2104 HMAC. Code is independently implemented.

use crate::watermark::DetectionStatus;
use fileveil_core::{Error, Limits, Result};
use image::{DynamicImage, GenericImageView, imageops::FilterType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::f32::consts::PI;
use zeroize::Zeroizing;

mod geometry;

pub const METHOD_ID: &str = "fileveil_keyed_dct_bch_v2";
pub const VERSION: &str = "2.0.0";
pub const DEFAULT_STRENGTH: u8 = 12;
const REFERENCE: u32 = 512;
const TILE: usize = 16;
const SLOTS: usize = 512;
const CODE_BITS: usize = 441;
const FRAME_BYTES: usize = 36;
const MAGIC: &[u8; 4] = b"FVW2";
const FRAME_DOMAIN: &[u8] = b"FileVeil watermark frame v2\0";
const CANDIDATES: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct V2Report {
    pub method_id: String,
    pub detector_version: String,
    pub status: DetectionStatus,
    pub frame_valid: bool,
    pub authenticated: bool,
    pub work_id_digest: Option<String>,
    pub copy_id_digest: Option<String>,
    pub key_id: String,
    pub strength: Option<u8>,
    pub corrected_codeword_bits: Option<u32>,
    pub decoded_codeword_disagreement_rate: Option<f64>,
    pub minimum_repetitions: u32,
    pub pilot_correlation: f64,
    pub reference_dimensions: Option<[u32; 2]>,
    pub rotation_degrees: Option<u16>,
    pub deskew_degrees: Option<f32>,
    pub periodic_geometry_score: Option<f64>,
    pub tested_deskew_candidates: u32,
    pub pixel_phase: Option<[u32; 2]>,
    pub tile_phase: Option<[u32; 2]>,
    pub tested_grids: u32,
    pub tested_phases: u32,
    pub ecc_candidates: u32,
    pub soft_decoding_trials: u32,
    pub scope: String,
    pub limitations: Vec<String>,
}
impl V2Report {
    fn new(key: &[u8; 32]) -> Self {
        Self {
            method_id: METHOD_ID.into(), detector_version: VERSION.into(),
            status: DetectionStatus::NotDetected, frame_valid: false, authenticated: false,
            work_id_digest: None, copy_id_digest: None, key_id: key_id(key), strength: None,
            corrected_codeword_bits: None, decoded_codeword_disagreement_rate: None,
            minimum_repetitions: 0, pilot_correlation: 0.0, reference_dimensions: None,
            rotation_degrees: None, deskew_degrees: None, periodic_geometry_score: None, tested_deskew_candidates: 0, pixel_phase: None, tile_phase: None,
            tested_grids: 0, tested_phases: 0, ecc_candidates: 0, soft_decoding_trials: 0,
            scope: "blind_keyed_work_and_copy_reference_with_bch_and_96_bit_mac".into(),
            limitations: vec![
                "A valid MAC authenticates this payload under the selected key. A copied valid watermark remains possible. Signed provenance separately binds current content and author/publisher assertions.".into(),
                "BCH correction observations compare a majority-voted codeword to its MAC-valid reconstruction. They are distinct from raw image-channel BER.".into(),
                "Search covers bounded scale grids, translations and quarter-turn rotations. Period-based proposals add bounded sub-quarter-turn deskew. Perspective, severe crops and heavy degradation can prevent detection.".into(),
                "A negative result covers this key and search scope. Wrong keys and absent marks share that result.".into(),
                "Autocorrelation proposes at most three deskew angles within -45..45 degrees at 0.25-degree spacing, with current-canvas aspect ratios 1:4 through 4:1. Correlation alone is never a positive detection.".into(),
            ],
        }
    }
}

pub fn key_id(key: &[u8; 32]) -> String {
    hex(&hash(&[b"FileVeil watermark key identifier v2\0", key]))
}
pub fn work_id_digest(work: &str) -> Result<String> {
    validate_identifier(work)?;
    Ok(hex(&hash(&[work.as_bytes()])[..12]))
}
pub fn copy_id_digest(copy: &str) -> Result<String> {
    validate_identifier(copy)?;
    Ok(hex(&hash(&[copy.as_bytes()])[..8]))
}

pub fn embed(
    image: &DynamicImage,
    work_id: &str,
    copy_id: &str,
    key: &[u8; 32],
    strength: u8,
    limits: &Limits,
) -> Result<(DynamicImage, V2Report)> {
    validate(image, limits, 512)?;
    if !(12..=64).contains(&strength) {
        return Err(Error::Input("V2 watermark strength must be 12..64".into()));
    }
    let frame = frame(work_id, copy_id, key)?;
    let bch = Bch::new();
    let layout = Layout::new(key);
    let bits = layout.tile_bits(&encode_frame(&frame, &bch));
    let kernels = Kernels::new();
    let mut output = image.clone();
    // Re-analysis compensates for clipping and for residual interpolation to
    // the native image. Low-variance blocks receive a weaker target.
    for _ in 0..2 {
        let gray = gray_reference(&output, REFERENCE, REFERENCE);
        let mut residual = vec![0.0_f32; (REFERENCE * REFERENCE) as usize];
        for by in 0..64 {
            for bx in 0..64 {
                let x = bx * 8;
                let y = by * 8;
                let level = adaptive_level(&gray, REFERENCE as usize, x, y, strength);
                for channel in 0..2 {
                    let position = channel * 256 + by % TILE * TILE + bx % TILE;
                    let difference = kernels.difference(&gray, 512, x, y, channel);
                    let target = if bits[position] { level } else { -level };
                    let delta = if bits[position] {
                        (target - difference).max(0.0)
                    } else {
                        (target - difference).min(0.0)
                    } * 0.5;
                    kernels.add_residual(&mut residual, 512, x, y, channel, delta);
                }
            }
        }
        apply_residual(&mut output, &residual, REFERENCE, REFERENCE);
    }
    let mut report = detect(&output, key, limits)?;
    if !report.frame_valid
        || report.work_id_digest != Some(work_id_digest(work_id)?)
        || report.copy_id_digest != Some(copy_id_digest(copy_id)?)
    {
        return Err(Error::Verification(
            "V2 watermark could not be recovered from its output pixels".into(),
        ));
    }
    report.strength = Some(strength);
    Ok((output, report))
}

pub fn detect(image: &DynamicImage, key: &[u8; 32], limits: &Limits) -> Result<V2Report> {
    detect_inner(image, key, limits, &mut None)
}

/// Benchmark-only known-payload observation. Candidate geometry is selected by
/// pilots or a valid MAC, independently of the supplied expected identifiers.
/// On synchronization failure this is the best-pilot candidate's coded BER.
pub fn analyze_known(
    image: &DynamicImage,
    work_id: &str,
    copy_id: &str,
    key: &[u8; 32],
    limits: &Limits,
) -> Result<(V2Report, Option<KnownPayloadMeasurement>)> {
    let expected = encode_frame(&frame(work_id, copy_id, key)?, &Bch::new());
    let mut observer = Some(KnownObserver {
        expected,
        best: None,
    });
    let report = detect_inner(image, key, limits, &mut observer)?;
    Ok((report, observer.and_then(|v| v.best)))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownPayloadMeasurement {
    pub selection: String,
    pub coded_bit_errors: u32,
    pub coded_bits: u32,
    pub coded_ber: f64,
    pub pilot_correlation: f64,
    pub reference_dimensions: [u32; 2],
    pub rotation_degrees: u16,
    pub deskew_degrees: f32,
    pub pixel_phase: [u32; 2],
    pub tile_phase: [u32; 2],
}
struct KnownObserver {
    expected: [bool; CODE_BITS],
    best: Option<KnownPayloadMeasurement>,
}
impl KnownObserver {
    fn consider(
        &mut self,
        coded: &[bool; CODE_BITS],
        geometry: KnownPayloadMeasurement,
        valid: bool,
    ) {
        if !valid
            && self
                .best
                .as_ref()
                .is_some_and(|best| best.pilot_correlation >= geometry.pilot_correlation)
        {
            return;
        }
        let errors = coded
            .iter()
            .zip(&self.expected)
            .filter(|(a, b)| a != b)
            .count() as u32;
        self.best = Some(KnownPayloadMeasurement {
            selection: if valid {
                "mac_valid_decoder_geometry"
            } else {
                "best_pilot_candidate_without_payload_feedback"
            }
            .into(),
            coded_bit_errors: errors,
            coded_bits: CODE_BITS as u32,
            coded_ber: errors as f64 / CODE_BITS as f64,
            ..geometry
        });
    }
}

fn detect_inner(
    image: &DynamicImage,
    key: &[u8; 32],
    limits: &Limits,
    observer: &mut Option<KnownObserver>,
) -> Result<V2Report> {
    validate(image, limits, 256)?;
    let layout = Layout::new(key);
    let bch = Bch::new();
    let kernels = Kernels::new();
    let mut report = V2Report::new(key);
    let (width, height) = image.dimensions();
    let mut grids = vec![
        (512, 512, false),
        (448, 448, false),
        (384, 384, false),
        (320, 320, false),
        (256, 256, false),
    ];
    if width <= 768 && height <= 768 && !grids.iter().any(|g| g.0 == width && g.1 == height) {
        grids.push((width, height, false));
    }
    // A cropped, non-square image must recover pixel alignment on the
    // pre-crop normalized grid. Searching only native pixels misses this case.
    for edge in [512, 384, 256, 448, 320] {
        grids.push((edge, edge, true));
    }
    if width <= 768 && height <= 768 && !grids.iter().any(|g| g.0 == width && g.1 == height && g.2)
    {
        grids.push((width, height, true));
    }
    let mut deskew_tested = false;
    for (width, height, pixel_search) in grids {
        if pixel_search && !deskew_tested {
            deskew_tested = true;
            if search_deskew(image, key, &layout, &bch, &kernels, &mut report, observer) {
                return Ok(report);
            }
        }
        if u64::from(width) * u64::from(height) > limits.max_pixels {
            continue;
        }
        let gray = gray_reference(image, width, height);
        for rotation in [0_u16, 90, 180, 270] {
            let oriented;
            let (samples, w, h) = if rotation == 0 {
                (gray.as_slice(), width, height)
            } else {
                oriented = rotate_gray(&gray, width, height, rotation);
                let (w, h) = if rotation == 180 {
                    (width, height)
                } else {
                    (height, width)
                };
                (oriented.as_slice(), w, h)
            };
            if search_grid(
                samples,
                w,
                h,
                pixel_search,
                rotation,
                0.0,
                &layout,
                &bch,
                &kernels,
                key,
                &mut report,
                observer,
            ) {
                return Ok(report);
            }
        }
    }
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn search_deskew(
    image: &DynamicImage,
    key: &[u8; 32],
    layout: &Layout,
    bch: &Bch,
    kernels: &Kernels,
    report: &mut V2Report,
    observer: &mut Option<KnownObserver>,
) -> bool {
    let reference = gray_reference(image, 512, 512);
    let native_aspect = image.width() as f32 / image.height() as f32;
    for candidate in geometry::proposals(&reference, native_aspect) {
        report.tested_deskew_candidates += 1;
        for rotation in [0_u16, 90, 180, 270] {
            let oriented;
            let samples = if rotation == 0 {
                reference.as_slice()
            } else {
                oriented = rotate_gray(&reference, 512, 512, rotation);
                oriented.as_slice()
            };
            let aspect = if rotation == 90 || rotation == 270 {
                1.0 / native_aspect
            } else {
                native_aspect
            };
            let rectified = geometry::rectify(samples, 512, 512, candidate.degrees, aspect);
            if search_grid(
                &rectified,
                512,
                512,
                false,
                rotation,
                candidate.degrees,
                layout,
                bch,
                kernels,
                key,
                report,
                observer,
            ) {
                report.periodic_geometry_score = Some(candidate.periodic_score);
                return true;
            }
        }
    }
    false
}

pub fn clean(
    image: &DynamicImage,
    key: &[u8; 32],
    limits: &Limits,
) -> Result<(DynamicImage, V2Report)> {
    let mut evidence = detect(image, key, limits)?;
    if !evidence.frame_valid {
        return Err(Error::Unsupported(
            "V2 cleaning requires a MAC-valid watermark under the selected key".into(),
        ));
    }
    let mut output = image.clone();
    let kernels = Kernels::new();
    // Neutralize both complete channels, including pilots. This is scoped to
    // the detected protocol and preserves the source alpha samples.
    for _ in 0..3 {
        let rotation = evidence.rotation_degrees.expect("valid geometry");
        let mut oriented = rotate(&output, rotation);
        let [width, height] = evidence.reference_dimensions.expect("valid geometry");
        let [px, py] = evidence.pixel_phase.expect("valid geometry");
        let deskew = evidence.deskew_degrees.unwrap_or(0.0);
        for _ in 0..2 {
            let gray = gray_reference(&oriented, width, height);
            let gray = if deskew == 0.0 {
                gray
            } else {
                geometry::rectify(
                    &gray,
                    width,
                    height,
                    deskew,
                    oriented.width() as f32 / oriented.height() as f32,
                )
            };
            let mut residual = vec![0.0_f32; (width * height) as usize];
            for by in 0..(height - py) as usize / 8 {
                for bx in 0..(width - px) as usize / 8 {
                    let x = px as usize + bx * 8;
                    let y = py as usize + by * 8;
                    for channel in 0..2 {
                        let target = if (bx + by + channel) % 2 == 0 {
                            3.0
                        } else {
                            -3.0
                        };
                        let delta = 0.5
                            * (target - kernels.difference(&gray, width as usize, x, y, channel));
                        kernels.add_residual(&mut residual, width as usize, x, y, channel, delta);
                    }
                }
            }
            apply_residual_with_deskew(&mut oriented, &residual, width, height, deskew);
        }
        output = rotate(&oriented, (360 - rotation) % 360);
        evidence = detect(&output, key, limits)?;
        if !evidence.frame_valid {
            evidence.scope =
                "targeted_keyed_v2_carrier_neutralization_and_full_bounded_recheck".into();
            return Ok((output, evidence));
        }
    }
    Err(Error::Verification(
        "V2 watermark remains detectable after bounded cleaning".into(),
    ))
}

fn rotate_gray(gray: &[f32], width: u32, height: u32, degrees: u16) -> Vec<f32> {
    let (w, h) = (width as usize, height as usize);
    let mut result = vec![0.0; gray.len()];
    for y in 0..h {
        for x in 0..w {
            let index = match degrees {
                90 => x * h + (h - 1 - y),
                180 => (h - 1 - y) * w + (w - 1 - x),
                270 => (w - 1 - x) * h + y,
                _ => y * w + x,
            };
            result[index] = gray[y * w + x];
        }
    }
    result
}

fn rotate(image: &DynamicImage, degrees: u16) -> DynamicImage {
    match degrees {
        90 => image.rotate90(),
        180 => image.rotate180(),
        270 => image.rotate270(),
        _ => image.clone(),
    }
}
fn validate(image: &DynamicImage, limits: &Limits, edge: u32) -> Result<()> {
    if !matches!(
        image,
        DynamicImage::ImageRgb8(_) | DynamicImage::ImageRgba8(_)
    ) {
        return Err(Error::Unsupported(
            "V2 watermark supports RGB8 and RGBA8 images".into(),
        ));
    }
    if image.width() < edge || image.height() < edge {
        return Err(Error::Unsupported(format!(
            "V2 watermark requires both dimensions at least {edge} pixels"
        )));
    }
    if u64::from(image.width()) * u64::from(image.height()) > limits.max_pixels
        || u64::from(REFERENCE).pow(2) > limits.max_pixels
    {
        return Err(Error::Blocked(
            "V2 image or reference exceeds the pixel budget".into(),
        ));
    }
    Ok(())
}
fn validate_identifier(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 4096 {
        return Err(Error::Input(
            "V2 work and copy identifiers require 1..4096 UTF-8 bytes".into(),
        ));
    }
    Ok(())
}
fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}
fn mac(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut inner = Zeroizing::new([0x36_u8; 64]);
    let mut outer = Zeroizing::new([0x5c_u8; 64]);
    for i in 0..32 {
        inner[i] ^= key[i];
        outer[i] ^= key[i];
    }
    let payload = hash(&[inner.as_ref(), FRAME_DOMAIN, message]);
    hash(&[outer.as_ref(), &payload])
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
fn frame(work: &str, copy: &str, key: &[u8; 32]) -> Result<[u8; FRAME_BYTES]> {
    validate_identifier(work)?;
    validate_identifier(copy)?;
    let mut value = [0_u8; FRAME_BYTES];
    value[..4].copy_from_slice(MAGIC);
    value[4..16].copy_from_slice(&hash(&[work.as_bytes()])[..12]);
    value[16..24].copy_from_slice(&hash(&[copy.as_bytes()])[..8]);
    let tag = mac(key, &value[..24]);
    value[24..].copy_from_slice(&tag[..12]);
    Ok(value)
}
fn encode_frame(frame: &[u8; FRAME_BYTES], bch: &Bch) -> [bool; CODE_BITS] {
    let mut bits = [false; CODE_BITS];
    for word in 0..7 {
        let mut message = 0_u64;
        for i in 0..45 {
            let position = word * 45 + i;
            message <<= 1;
            if position < FRAME_BYTES * 8 && frame[position / 8] & (1 << (7 - position % 8)) != 0 {
                message |= 1;
            }
        }
        let encoded = bch.encode(message);
        for i in 0..63 {
            bits[word * 63 + i] = encoded & (1_u64 << (62 - i)) != 0;
        }
    }
    bits
}

struct Layout {
    permutation: [usize; SLOTS],
    signs: [bool; SLOTS],
    pilots: [bool; SLOTS],
}
impl Layout {
    fn new(key: &[u8; 32]) -> Self {
        let mut rng = KeyStream::new(key);
        let mut permutation = std::array::from_fn(|i| i);
        for i in (1..SLOTS).rev() {
            permutation.swap(i, (rng.next() as usize) % (i + 1));
        }
        let signs = std::array::from_fn(|_| rng.next() & 1 != 0);
        let pilots = std::array::from_fn(|_| rng.next() & 1 != 0);
        Self {
            permutation,
            signs,
            pilots,
        }
    }
    fn tile_bits(&self, encoded: &[bool; CODE_BITS]) -> [bool; SLOTS] {
        let mut result = [false; SLOTS];
        for i in 0..SLOTS {
            let bit = if i < CODE_BITS {
                encoded[i]
            } else {
                self.pilots[i]
            };
            result[self.permutation[i]] = bit ^ self.signs[i];
        }
        result
    }
}
struct KeyStream {
    key: Zeroizing<[u8; 32]>,
    counter: u64,
    buffer: [u8; 32],
    position: usize,
}
impl KeyStream {
    fn new(key: &[u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(*key),
            counter: 0,
            buffer: [0; 32],
            position: 32,
        }
    }
    fn next(&mut self) -> u32 {
        if self.position == 32 {
            self.buffer = hash(&[
                b"FileVeil keyed carrier layout v2\0",
                self.key.as_ref(),
                &self.counter.to_be_bytes(),
            ]);
            self.counter += 1;
            self.position = 0;
        }
        let value = u32::from_be_bytes(
            self.buffer[self.position..self.position + 4]
                .try_into()
                .unwrap(),
        );
        self.position += 4;
        value
    }
}

struct Bch {
    exp: [u8; 126],
    log: [u8; 64],
    generator: u64,
}
impl Bch {
    fn new() -> Self {
        let mut exp = [0_u8; 126];
        let mut log = [0_u8; 64];
        let mut value = 1_u8;
        for (i, item) in exp.iter_mut().enumerate().take(63) {
            *item = value;
            log[value as usize] = i as u8;
            value <<= 1;
            if value & 64 != 0 {
                value ^= 0x43;
            }
        }
        for i in 63..126 {
            exp[i] = exp[i - 63];
        }
        let mut this = Self {
            exp,
            log,
            generator: 0,
        };
        let mut roots = [false; 63];
        for start in 1..=6 {
            let mut power = start;
            loop {
                roots[power] = true;
                power = power * 2 % 63;
                if power == start {
                    break;
                }
            }
        }
        let mut polynomial = vec![1_u8];
        for (power, included) in roots.iter().enumerate() {
            if !included {
                continue;
            }
            let mut next = vec![0; polynomial.len() + 1];
            for (i, coefficient) in polynomial.iter().enumerate() {
                next[i] ^= this.mul(*coefficient, this.exp[power]);
                next[i + 1] ^= coefficient;
            }
            polynomial = next;
        }
        assert_eq!(polynomial.len(), 19);
        for (i, coefficient) in polynomial.iter().enumerate() {
            assert!(*coefficient <= 1);
            this.generator |= u64::from(*coefficient) << i;
        }
        this
    }
    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp[self.log[a as usize] as usize + self.log[b as usize] as usize]
        }
    }
    fn div(&self, a: u8, b: u8) -> u8 {
        if a == 0 {
            0
        } else {
            self.exp[(self.log[a as usize] as usize + 63 - self.log[b as usize] as usize) % 63]
        }
    }
    fn encode(&self, message: u64) -> u64 {
        let shifted = (message & ((1_u64 << 45) - 1)) << 18;
        let mut remainder = shifted;
        for bit in (18..63).rev() {
            if remainder & (1_u64 << bit) != 0 {
                remainder ^= self.generator << (bit - 18);
            }
        }
        shifted | remainder
    }
    fn syndromes(&self, word: u64) -> [u8; 6] {
        std::array::from_fn(|i| {
            let mut syndrome = 0;
            for bit in 0..63 {
                if word & (1_u64 << bit) != 0 {
                    syndrome ^= self.exp[((i + 1) * bit) % 63];
                }
            }
            syndrome
        })
    }
    fn decode(&self, received: u64) -> Option<(u64, u32)> {
        let syndromes = self.syndromes(received);
        if syndromes == [0; 6] {
            return Some((received >> 18, 0));
        }
        let mut c = [0_u8; 7];
        c[0] = 1;
        let mut b = c;
        let mut degree = 0;
        let mut distance = 1;
        let mut previous = 1;
        for n in 0..6 {
            let mut discrepancy = syndromes[n];
            for i in 1..=degree {
                discrepancy ^= self.mul(c[i], syndromes[n - i]);
            }
            if discrepancy == 0 {
                distance += 1;
                continue;
            }
            let old = c;
            let factor = self.div(discrepancy, previous);
            for i in distance..7 {
                c[i] ^= self.mul(factor, b[i - distance]);
            }
            if 2 * degree <= n {
                degree = n + 1 - degree;
                b = old;
                previous = discrepancy;
                distance = 1;
            } else {
                distance += 1;
            }
        }
        if degree == 0 || degree > 3 {
            return None;
        }
        let mut corrected = received;
        let mut roots = 0;
        for bit in 0..63 {
            let x = self.exp[(63 - bit) % 63];
            let mut value = c[degree];
            for i in (0..degree).rev() {
                value = self.mul(value, x) ^ c[i];
            }
            if value == 0 {
                corrected ^= 1_u64 << bit;
                roots += 1;
            }
        }
        if roots != degree || self.syndromes(corrected) != [0; 6] {
            return None;
        }
        Some((corrected >> 18, roots as u32))
    }
}

struct Kernels {
    bases: [[f32; 64]; 2],
    cosine: [[f32; 8]; 4],
}
impl Kernels {
    fn new() -> Self {
        let cosine = std::array::from_fn(|frequency| {
            std::array::from_fn(|x| {
                let alpha = if frequency == 0 {
                    1.0 / 8.0_f32.sqrt()
                } else {
                    0.5
                };
                ((2 * x + 1) as f32 * frequency as f32 * PI / 16.0).cos() * alpha
            })
        });
        let pairs = [(1, 2), (1, 3)];
        let bases = std::array::from_fn(|channel| {
            std::array::from_fn(|i| {
                let (a, b) = pairs[channel];
                let x = i % 8;
                let y = i / 8;
                cosine[a][x] * cosine[b][y] - cosine[b][x] * cosine[a][y]
            })
        });
        Self { bases, cosine }
    }
    fn difference(&self, gray: &[f32], width: usize, x: usize, y: usize, channel: usize) -> f32 {
        let mut value = 0.0;
        for row in 0..8 {
            for column in 0..8 {
                value +=
                    gray[(y + row) * width + x + column] * self.bases[channel][row * 8 + column];
            }
        }
        value
    }
    fn add_residual(
        &self,
        residual: &mut [f32],
        width: usize,
        x: usize,
        y: usize,
        channel: usize,
        delta: f32,
    ) {
        for row in 0..8 {
            for column in 0..8 {
                residual[(y + row) * width + x + column] +=
                    delta * self.bases[channel][row * 8 + column];
            }
        }
    }
    fn sliding(&self, gray: &[f32], width: usize, height: usize, channel: usize) -> Vec<f32> {
        let (a, b) = [(1, 2), (1, 3)][channel];
        let stride = width - 7;
        let rows = height - 7;
        let mut ha = vec![0.0_f32; stride * height];
        let mut hb = vec![0.0_f32; stride * height];
        for y in 0..height {
            for x in 0..stride {
                for k in 0..8 {
                    let sample = gray[y * width + x + k];
                    ha[y * stride + x] += sample * self.cosine[a][k];
                    hb[y * stride + x] += sample * self.cosine[b][k];
                }
            }
        }
        let mut result = vec![0.0_f32; stride * rows];
        for y in 0..rows {
            for x in 0..stride {
                for k in 0..8 {
                    result[y * stride + x] += ha[(y + k) * stride + x] * self.cosine[b][k]
                        - hb[(y + k) * stride + x] * self.cosine[a][k];
                }
            }
        }
        result
    }
}

fn gray_reference(image: &DynamicImage, width: u32, height: u32) -> Vec<f32> {
    image
        .resize_exact(width, height, FilterType::Triangle)
        .to_rgb8()
        .pixels()
        .map(|p| 0.299 * p[0] as f32 + 0.587 * p[1] as f32 + 0.114 * p[2] as f32)
        .collect()
}
fn adaptive_level(gray: &[f32], width: usize, x: usize, y: usize, strength: u8) -> f32 {
    let mut sum = 0.0;
    let mut square = 0.0;
    for row in 0..8 {
        for column in 0..8 {
            let v = gray[(y + row) * width + x + column];
            sum += v;
            square += v * v;
        }
    }
    let sd = (square / 64.0 - (sum / 64.0).powi(2)).max(0.0).sqrt();
    f32::from(strength) * (0.65 + sd / 48.0).clamp(0.65, 1.35)
}
fn apply_residual(image: &mut DynamicImage, residual: &[f32], rw: u32, rh: u32) {
    apply_residual_with_deskew(image, residual, rw, rh, 0.0);
}
fn apply_residual_with_deskew(
    image: &mut DynamicImage,
    residual: &[f32],
    rw: u32,
    rh: u32,
    deskew: f32,
) {
    let width = image.width();
    let height = image.height();
    let ratio = (width as f32 / height as f32) * (rh as f32 / rw as f32);
    let (sin, cos) = (deskew * PI / 180.0).sin_cos();
    let cx = (rw - 1) as f32 * 0.5;
    let cy = (rh - 1) as f32 * 0.5;
    for y in 0..height {
        let ry = ((y as f32 + 0.5) * rh as f32 / height as f32 - 0.5).clamp(0.0, (rh - 1) as f32);
        for x in 0..width {
            let rx =
                ((x as f32 + 0.5) * rw as f32 / width as f32 - 0.5).clamp(0.0, (rw - 1) as f32);
            let tx = cos * (rx - cx) + sin / ratio * (ry - cy) + cx;
            let ty = -sin * ratio * (rx - cx) + cos * (ry - cy) + cy;
            let Some(delta) = geometry::interpolate(residual, rw, rh, tx, ty) else {
                continue;
            };
            let channels = match image {
                DynamicImage::ImageRgb8(rgb) => &mut rgb.get_pixel_mut(x, y).0[..],
                DynamicImage::ImageRgba8(rgba) => &mut rgba.get_pixel_mut(x, y).0[..3],
                _ => unreachable!(),
            };
            for value in channels {
                *value = (*value as f32 + delta).round().clamp(0.0, 255.0) as u8;
            }
        }
    }
}

struct GridCandidate {
    score: f32,
    coded: [bool; CODE_BITS],
    reliability: [f32; CODE_BITS],
    minimum_repetitions: u32,
    pixel_phase: [u32; 2],
    tile_phase: [u32; 2],
}

#[allow(clippy::too_many_arguments)]
fn search_grid(
    gray: &[f32],
    width: u32,
    height: u32,
    pixel_search: bool,
    rotation: u16,
    deskew: f32,
    layout: &Layout,
    bch: &Bch,
    kernels: &Kernels,
    key: &[u8; 32],
    report: &mut V2Report,
    observer: &mut Option<KnownObserver>,
) -> bool {
    report.tested_grids += 1;
    let sliding = pixel_search.then(|| {
        [
            kernels.sliding(gray, width as usize, height as usize, 0),
            kernels.sliding(gray, width as usize, height as usize, 1),
        ]
    });
    let phases = if pixel_search { 8 } else { 1 };
    let mut candidates: Vec<GridCandidate> = Vec::with_capacity(CANDIDATES);
    for py in 0..phases {
        for px in 0..phases {
            let mut votes = [0.0_f32; SLOTS];
            let mut count = [0_u16; 256];
            for by in 0..(height as usize - py) / 8 {
                for bx in 0..(width as usize - px) / 8 {
                    let index = by % TILE * TILE + bx % TILE;
                    count[index] += 1;
                    for channel in 0..2 {
                        let value = sliding.as_ref().map_or_else(
                            || {
                                kernels.difference(
                                    gray,
                                    width as usize,
                                    px + bx * 8,
                                    py + by * 8,
                                    channel,
                                )
                            },
                            |maps| {
                                maps[channel][(py + by * 8) * (width as usize - 7) + px + bx * 8]
                            },
                        );
                        votes[channel * 256 + index] += value.clamp(-64.0, 64.0);
                    }
                }
            }
            let minimum = *count.iter().min().unwrap() as u32;
            if minimum == 0 {
                continue;
            }
            for ty in 0..TILE {
                for tx in 0..TILE {
                    report.tested_phases += 1;
                    let mut score = 0.0;
                    let mut energy = 0.0;
                    for i in CODE_BITS..SLOTS {
                        let value = votes[shifted(layout.permutation[i], tx, ty)];
                        let expected = layout.pilots[i] ^ layout.signs[i];
                        score += if expected { value } else { -value };
                        energy += value.abs();
                    }
                    let score = if energy > 0.0 { score / energy } else { 0.0 };
                    report.pilot_correlation = report.pilot_correlation.max(score as f64);
                    if score < 0.25
                        || (candidates.len() == CANDIDATES
                            && score <= candidates.last().unwrap().score)
                    {
                        continue;
                    }
                    let candidate = GridCandidate {
                        score,
                        coded: std::array::from_fn(|i| {
                            (votes[shifted(layout.permutation[i], tx, ty)] >= 0.0) ^ layout.signs[i]
                        }),
                        reliability: std::array::from_fn(|i| {
                            votes[shifted(layout.permutation[i], tx, ty)].abs()
                        }),
                        minimum_repetitions: minimum,
                        pixel_phase: [px as u32, py as u32],
                        tile_phase: [tx as u32, ty as u32],
                    };
                    candidates.push(candidate);
                    candidates.sort_unstable_by(|a, b| b.score.total_cmp(&a.score));
                    candidates.truncate(CANDIDATES);
                }
            }
        }
    }
    for candidate in candidates {
        report.ecc_candidates += 1;
        let mut decoded = decode_frame(&candidate.coded, bch, key);
        if decoded.is_none() && candidate.score >= 0.82 && report.soft_decoding_trials < 1024 {
            decoded = soft_decode_frame(
                &candidate.coded,
                &candidate.reliability,
                bch,
                key,
                &mut report.soft_decoding_trials,
            );
        }
        if let Some(observer) = observer {
            observer.consider(
                &candidate.coded,
                KnownPayloadMeasurement {
                    selection: String::new(),
                    coded_bit_errors: 0,
                    coded_bits: CODE_BITS as u32,
                    coded_ber: 0.0,
                    pilot_correlation: candidate.score as f64,
                    reference_dimensions: [width, height],
                    rotation_degrees: rotation,
                    deskew_degrees: deskew,
                    pixel_phase: candidate.pixel_phase,
                    tile_phase: candidate.tile_phase,
                },
                decoded.is_some(),
            );
        }
        let Some((frame, corrected)) = decoded else {
            continue;
        };
        report.status = DetectionStatus::Detected;
        report.frame_valid = true;
        report.authenticated = true;
        report.work_id_digest = Some(hex(&frame[4..16]));
        report.copy_id_digest = Some(hex(&frame[16..24]));
        report.corrected_codeword_bits = Some(corrected);
        report.decoded_codeword_disagreement_rate = Some(corrected as f64 / CODE_BITS as f64);
        report.minimum_repetitions = candidate.minimum_repetitions;
        report.pilot_correlation = candidate.score as f64;
        report.reference_dimensions = Some([width, height]);
        report.rotation_degrees = Some(rotation);
        report.deskew_degrees = Some(deskew);
        report.pixel_phase = Some(candidate.pixel_phase);
        report.tile_phase = Some(candidate.tile_phase);
        return true;
    }
    false
}

fn shifted(slot: usize, tx: usize, ty: usize) -> usize {
    let channel = slot / 256;
    let location = slot % 256;
    channel * 256 + ((location / TILE + ty) % TILE) * TILE + (location % TILE + tx) % TILE
}
fn decode_frame(
    coded: &[bool; CODE_BITS],
    bch: &Bch,
    key: &[u8; 32],
) -> Option<([u8; FRAME_BYTES], u32)> {
    let mut bits = [false; 315];
    let mut corrections = 0;
    for word in 0..7 {
        let mut value = 0_u64;
        for i in 0..63 {
            value = (value << 1) | u64::from(coded[word * 63 + i]);
        }
        let (message, corrected) = bch.decode(value)?;
        corrections += corrected;
        for i in 0..45 {
            bits[word * 45 + i] = message & (1_u64 << (44 - i)) != 0;
        }
    }
    if bits[288..].iter().any(|v| *v) {
        return None;
    }
    let mut frame = [0_u8; FRAME_BYTES];
    for i in 0..288 {
        if bits[i] {
            frame[i / 8] |= 1 << (7 - i % 8);
        }
    }
    if &frame[..4] != MAGIC {
        return None;
    }
    let expected = mac(key, &frame[..24]);
    let mismatch = frame[24..]
        .iter()
        .zip(&expected[..12])
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b));
    (mismatch == 0).then_some((frame, corrections))
}

/// Chase-style bounded list decoding. The pilot threshold selects geometry
/// without expected payload feedback. Every final frame must pass its MAC.
fn soft_decode_frame(
    coded: &[bool; CODE_BITS],
    reliability: &[f32; CODE_BITS],
    bch: &Bch,
    key: &[u8; 32],
    trials: &mut u32,
) -> Option<([u8; FRAME_BYTES], u32)> {
    let mut lists: Vec<Vec<(u64, f32)>> = Vec::with_capacity(7);
    for word in 0..7 {
        let start = word * 63;
        let mut received = 0_u64;
        for i in 0..63 {
            received = (received << 1) | u64::from(coded[start + i]);
        }
        let mut weak: Vec<_> = (0..63).collect();
        weak.sort_unstable_by(|a, b| reliability[start + *a].total_cmp(&reliability[start + *b]));
        weak.truncate(6);
        let mut masks = vec![0_u64];
        for (i, a) in weak.iter().enumerate() {
            masks.push(1_u64 << (62 - a));
            for b in weak.iter().skip(i + 1) {
                masks.push((1_u64 << (62 - a)) | (1_u64 << (62 - b)));
            }
        }
        let mut candidates = Vec::new();
        for mask in masks {
            if *trials >= 1024 {
                break;
            }
            *trials += 1;
            let Some((message, _)) = bch.decode(received ^ mask) else {
                continue;
            };
            if word == 0 && message >> 13 != u64::from(u32::from_be_bytes(*MAGIC)) {
                continue;
            }
            if word == 6 && message & ((1_u64 << 27) - 1) != 0 {
                continue;
            }
            if candidates.iter().any(|(old, _)| *old == message) {
                continue;
            }
            let corrected = bch.encode(message);
            let metric = (0..63)
                .filter(|i| (received ^ corrected) & (1_u64 << (62 - i)) != 0)
                .map(|i| reliability[start + i])
                .sum::<f32>();
            candidates.push((message, metric));
        }
        if candidates.is_empty() {
            return None;
        }
        candidates.sort_unstable_by(|a, b| a.1.total_cmp(&b.1));
        candidates.truncate(2);
        lists.push(candidates);
    }
    // At most 2^7 candidates, with fixed header and padding constraints already
    // applied. The MAC validates the selected correction beyond t=3 radius.
    for selection in 0..128 {
        let mut frame = [0_u8; FRAME_BYTES];
        let mut valid = true;
        let mut corrections = 0;
        for word in 0..7 {
            let Some(&(message, _)) = lists[word].get((selection >> word) & 1) else {
                valid = false;
                break;
            };
            let codeword = bch.encode(message);
            for i in 0..63 {
                corrections +=
                    u32::from((codeword & (1_u64 << (62 - i)) != 0) != coded[word * 63 + i]);
            }
            for i in 0..45 {
                let position = word * 45 + i;
                if position < FRAME_BYTES * 8 && message & (1_u64 << (44 - i)) != 0 {
                    frame[position / 8] |= 1 << (7 - position % 8);
                }
            }
        }
        if !valid {
            continue;
        }
        let expected = mac(key, &frame[..24]);
        let mismatch = frame[24..]
            .iter()
            .zip(&expected[..12])
            .fold(0_u8, |v, (a, b)| v | (a ^ b));
        if mismatch == 0 {
            return Some((frame, corrections));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bch_corrects_three_errors_and_mac_rejects_changed_payload() {
        let bch = Bch::new();
        // Independently generated polynomial/word using Python GF arithmetic.
        assert_eq!(bch.generator, 0x0007_82cf);
        assert_eq!(bch.encode(0x0123_4567_89ab), 0x048d_159e_26ae_7d1a);
        for message in [0, 1, 0x0123_4567_89ab, (1_u64 << 45) - 1] {
            let encoded = bch.encode(message);
            assert_eq!(bch.syndromes(encoded), [0; 6]);
            for bits in [[0, 1, 62], [7, 29, 43], [8, 9, 10]] {
                let damaged = bits.iter().fold(encoded, |word, bit| word ^ (1_u64 << bit));
                assert_eq!(bch.decode(damaged), Some((message, 3)));
            }
        }
        let key = [0x39; 32];
        let value = frame("test-work", "copy-1", &key).unwrap();
        let coded = encode_frame(&value, &bch);
        assert_eq!(decode_frame(&coded, &bch, &key), Some((value, 0)));
        assert!(decode_frame(&coded, &bch, &[0x40; 32]).is_none());
    }
    #[test]
    fn hmac_matches_independent_rfc2104_construction_and_sliding_matches_direct() {
        // Python hmac.new(bytes([0x0b])*32, DOMAIN+b"Hi There", sha256).
        let key = [0x0b; 32];
        assert_eq!(
            hex(&mac(&key, b"Hi There")),
            "f4e935252365a5742aa7a056da9b213bee77527115d62d870225527474c1fa8f"
        );
        let kernels = Kernels::new();
        let gray: Vec<_> = (0..32 * 24)
            .map(|i| ((i * 17 + i / 32 * 7) % 256) as f32)
            .collect();
        for channel in 0..2 {
            let sliding = kernels.sliding(&gray, 32, 24, channel);
            for y in 0..17 {
                for x in 0..25 {
                    assert!(
                        (sliding[y * 25 + x] - kernels.difference(&gray, 32, x, y, channel)).abs()
                            < 0.003
                    );
                }
            }
        }
    }
    #[test]
    fn soft_decoding_recovers_four_unreliable_errors_without_weakening_mac() {
        let bch = Bch::new();
        let key = [0x39; 32];
        let value = frame("soft-work", "copy-A", &key).unwrap();
        let mut coded = encode_frame(&value, &bch);
        let mut reliability = [32.0; CODE_BITS];
        for offset in [3, 9, 19, 37] {
            coded[63 + offset] ^= true;
            reliability[63 + offset] = 0.01;
        }
        assert!(decode_frame(&coded, &bch, &key).is_none());
        assert_eq!(
            soft_decode_frame(&coded, &reliability, &bch, &key, &mut 0),
            Some((value, 4))
        );
        assert!(soft_decode_frame(&coded, &reliability, &bch, &[0x40; 32], &mut 0).is_none());
    }
}

// FVPROV1 44153 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJlN2MxZjY2NTk1YTMyMDFkYTJmYmNmMjEzYjRjYzRjNmZmMTc2ZTIyNTk1MjkyOWMxOTBiODUzNjg5NDAxNDE0IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4yIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMiIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL2hlcml0YWdlL3JvYnVzdF92Mi5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjU2YjViZjY5OTkyNTY3MzcwZjRhZWJlZjMyZWMyN2ZkMTU2MjhhMDY1MWQ3ZjZhMDYyNzY0NmJlZjg2YjdkMmY2OTRlNWU3ODgyMDFhZTc4NTFiMzY5ODk3OTFmMGQzMDNmNzE2MzhmYWJiNmY1OGE4YmE1YmE3MGJjZjU0NTBiIn1dfV0= FVPROV1-END
