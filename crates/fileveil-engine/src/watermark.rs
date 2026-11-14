// SPDX-License-Identifier: MPL-2.0
//! Read-only, offline detector contracts and a reproducible synthetic LSB protocol.
//!
//! V1 packs eight magic bytes, version 1, a big-endian u32 payload length,
//! 32 raw SHA-256 payload digest bytes, then the payload. Each byte is emitted
//! most-significant-bit first into consecutive RGB least-significant bits,
//! traversing rows top to bottom and pixels left to right. Alpha is excluded.
use fileveil_core::{Confidence, Error, Format, Limits, Result, digest};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

mod dwt_dct;

pub const SYNTHETIC_MAGIC: &[u8; 8] = b"FVLSB1\r\n";
pub const SYNTHETIC_VERSION: u8 = 1;
pub const SYNTHETIC_HEADER_BYTES: usize = 8 + 1 + 4 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionStatus {
    Detected,
    NotDetected,
    Indeterminate,
    NotAssessed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectorDescriptor {
    pub method_id: String,
    pub version: String,
    pub formats: Vec<Format>,
    pub min_samples: usize,
    pub max_samples: usize,
    pub requires_key: bool,
    pub requires_network: bool,
    pub evidence_types: Vec<String>,
    pub false_positive_limits: String,
    pub false_negative_limits: String,
    pub supports_postprocess_retest: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionReport {
    pub method_id: String,
    pub detector_version: String,
    pub status: DetectionStatus,
    pub confidence: Confidence,
    pub evidence_codes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_bytes: Option<u32>,
    pub offline: bool,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicCleanReport {
    pub before: Vec<DetectionReport>,
    pub after: Vec<DetectionReport>,
    pub processed_methods: Vec<String>,
    pub scope: String,
}

/// Target only successfully decoded public protocols and recheck their signals.
/// The caller applies its own quality budget and encoded-output verification.
pub fn clean_known_public(
    image: &image::DynamicImage,
    limits: &Limits,
) -> Result<(image::DynamicImage, PublicCleanReport)> {
    if u64::from(image.width()) * u64::from(image.height()) > limits.max_pixels {
        return Err(Error::Blocked(
            "Public watermark cleaning exceeds the pixel budget".into(),
        ));
    }
    let before = detect_decoded(Some(image), Format::Png, limits)?;
    let mut processed_methods = Vec::new();
    if !before
        .iter()
        .any(|report| report.status == DetectionStatus::Detected)
    {
        return Ok((
            image.clone(),
            PublicCleanReport {
                after: before.clone(),
                before,
                processed_methods,
                scope: "recognized_public_payloads_only".into(),
            },
        ));
    }
    let mut rgb = rgb8(image)
        .ok_or_else(|| {
            Error::Unsupported("Public watermark cleaning requires 8-bit RGB/RGBA samples".into())
        })?
        .into_owned();
    for report in before
        .iter()
        .filter(|report| report.status == DetectionStatus::Detected)
    {
        match report.method_id.as_str() {
            "synthetic_lsb_v1" => {
                let length =
                    SYNTHETIC_HEADER_BYTES + report.payload_bytes.unwrap_or_default() as usize;
                for sample in rgb.as_mut().iter_mut().take(length * 8) {
                    *sample &= !1;
                }
            }
            "stable_diffusion_dwt_dct_v1" | "stable_diffusion_xl_dwt_dct" => {
                dwt_dct::clean_public_carrier(&mut rgb)
            }
            _ => continue,
        }
        processed_methods.push(report.method_id.clone());
    }
    let output = match image {
        image::DynamicImage::ImageRgb8(_) => image::DynamicImage::ImageRgb8(rgb),
        image::DynamicImage::ImageRgba8(original) => {
            let mut output = original.clone();
            for (output, rgb) in output.pixels_mut().zip(rgb.pixels()) {
                output.0[..3].copy_from_slice(&rgb.0);
            }
            image::DynamicImage::ImageRgba8(output)
        }
        _ => {
            return Err(Error::Unsupported(
                "Public watermark cleaning requires 8-bit RGB/RGBA samples".into(),
            ));
        }
    };
    let after = detect_decoded(Some(&output), Format::Png, limits)?;
    if after
        .iter()
        .any(|report| report.status == DetectionStatus::Detected)
    {
        return Err(Error::Verification(
            "A recognized public watermark remains after targeted processing".into(),
        ));
    }
    Ok((
        output,
        PublicCleanReport {
            before,
            after,
            processed_methods,
            scope: "recognized_public_payloads_only_with_same_method_recheck".into(),
        },
    ))
}

pub struct DetectorSample<'a> {
    pub data: &'a [u8],
    pub format: Format,
}

/// Detectors receive caller-authorized snapshots and cannot open file paths.
/// Implementations are statically registered in this build. The contract grants
/// neither network access nor dynamic-library loading to future plugins.
pub trait Detector: Send + Sync {
    fn descriptor(&self) -> DetectorDescriptor;
    fn detect(&self, samples: &[DetectorSample<'_>], limits: &Limits) -> Result<DetectionReport>;
}

pub struct SyntheticLsbV1;

/// Public, deployed Stable Diffusion payload adapters. Matching a public mark
/// establishes a signal match and carries no cryptographic origin assertion.
pub struct StableDiffusionDwtDct {
    pub xl: bool,
}

impl Detector for StableDiffusionDwtDct {
    fn descriptor(&self) -> DetectorDescriptor {
        DetectorDescriptor {
            method_id: self.method_id().into(),
            version: "1.1.0".into(),
            formats: vec![Format::Jpeg, Format::Png],
            min_samples: 1,
            max_samples: 1,
            requires_key: false,
            requires_network: false,
            evidence_types: vec!["public_payload_bit_match".into(), "haar_chroma_block_votes".into()],
            false_positive_limits: "Public payloads can be copied by anyone. Detection requires agreement across exact-half, unfused Haar and FMA Haar numerical routes. Thresholds are method-specific signal evidence. Error rates for arbitrary images and OEM/device attribution have not been calibrated.".into(),
            false_negative_limits: "Only invisible-watermark's 8-bit U-channel dwtDct matrix route and the official SD1/SDXL payloads are tested. Cropping, resizing, re-encoding, floating-point variants, other payloads and other watermark families can evade detection.".into(),
            supports_postprocess_retest: true,
        }
    }

    fn detect(&self, samples: &[DetectorSample<'_>], limits: &Limits) -> Result<DetectionReport> {
        let [sample] = samples else {
            return Err(Error::Input(
                "Stable Diffusion detection requires one sample".into(),
            ));
        };
        let Some(image) = decode_image(sample.data, sample.format, limits)? else {
            return Ok(self.unassessed("unsupported_container_or_sample_model"));
        };
        let Some(rgb) = rgb8(&image) else {
            return Ok(self.unassessed("unsupported_container_or_sample_model"));
        };
        Ok(self.evaluate(&rgb, &dwt_dct::block_decisions(&rgb)))
    }
}

impl StableDiffusionDwtDct {
    fn method_id(&self) -> &'static str {
        if self.xl {
            "stable_diffusion_xl_dwt_dct"
        } else {
            "stable_diffusion_dwt_dct_v1"
        }
    }

    fn unassessed(&self, evidence: &str) -> DetectionReport {
        DetectionReport {
            method_id: self.method_id().into(),
            detector_version: "1.1.0".into(),
            status: DetectionStatus::NotAssessed,
            confidence: Confidence::Unknown,
            evidence_codes: vec![evidence.into()],
            payload_sha256: None,
            payload_bytes: None,
            offline: true,
            scope: "public_payload_signal_match_without_origin_authentication".into(),
        }
    }

    fn evaluate(&self, image: &image::RgbImage, decisions: &[Vec<bool>; 3]) -> DetectionReport {
        let mut report = self.unassessed("");
        report.evidence_codes.clear();
        if u64::from(image.width()) * u64::from(image.height()) < 256 * 256 {
            report
                .evidence_codes
                .push("image_area_below_upstream_minimum".into());
            return report;
        }
        let payload: &[u8] = if self.xl {
            &[0xb3, 0xec, 0x90, 0x7b, 0xb1, 0x9e]
        } else {
            b"StableDiffusionV1"
        };
        let length = payload.len() * 8;
        let votes = decisions
            .each_ref()
            .map(|route| dwt_dct::votes(route, length));
        if votes.iter().flatten().any(|(_, total)| *total < 4) {
            report
                .evidence_codes
                .push("insufficient_independent_block_votes".into());
            return report;
        }
        let matched = votes.each_ref().map(|votes| {
            votes
                .iter()
                .enumerate()
                .filter(|(index, (ones, total))| {
                    let expected = (payload[index / 8] >> (7 - index % 8)) & 1 != 0;
                    (*ones as f64 * 255.0 > *total as f64 * 127.0) == expected
                })
                .count()
        });
        let margins = votes.each_ref().map(|votes| {
            votes
                .iter()
                .map(|(ones, total)| (2.0 * *ones as f64 / *total as f64 - 1.0).abs())
                .sum::<f64>()
                / length as f64
        });
        let (positive, partial) = if self.xl { (36, 28) } else { (128, 102) };
        let statuses = matched.map(|score| {
            if score >= positive {
                DetectionStatus::Detected
            } else if score >= partial {
                DetectionStatus::Indeterminate
            } else {
                DetectionStatus::NotDetected
            }
        });
        let consensus = statuses.iter().all(|status| *status == statuses[0]);
        report.status = if consensus {
            statuses[0]
        } else {
            DetectionStatus::Indeterminate
        };
        report.confidence = if report.status == DetectionStatus::Detected {
            Confidence::StrongEvidence
        } else if report.status == DetectionStatus::Indeterminate {
            Confidence::Heuristic
        } else {
            Confidence::Unknown
        };
        report.evidence_codes = vec![
            format!("matched_bits={}", matched[0]),
            format!("total_bits={length}"),
            format!("positive_threshold={positive}"),
            format!("block_votes={}", decisions[0].len()),
            format!("mean_vote_margin={:.6}", margins[0]),
            format!("matched_bits_unfused={}", matched[1]),
            format!("matched_bits_fma={}", matched[2]),
            format!("matched_bits_min={}", matched.iter().min().unwrap_or(&0)),
            format!("matched_bits_max={}", matched.iter().max().unwrap_or(&0)),
            format!("numerical_consensus={consensus}"),
            "public_payload_is_not_authenticated_model_or_device_identity".into(),
        ];
        if report.status == DetectionStatus::Detected {
            report.payload_sha256 = Some(digest(payload));
            report.payload_bytes = Some(payload.len() as u32);
        }
        report
    }
}

fn decode_image(
    data: &[u8],
    format: Format,
    limits: &Limits,
) -> Result<Option<image::DynamicImage>> {
    if data.len() as u64 > limits.max_file_bytes {
        return Err(Error::Blocked(
            "Watermark input exceeds the file size limit".into(),
        ));
    }
    let expected = match format {
        Format::Png => image::ImageFormat::Png,
        Format::Jpeg => image::ImageFormat::Jpeg,
        _ => return Ok(None),
    };
    if image::guess_format(data).ok() != Some(expected) {
        return Err(Error::Input(
            "Watermark container does not match the format hint".into(),
        ));
    }
    super::decode_pixels(data, limits).map(Some)
}

fn rgb8(image: &image::DynamicImage) -> Option<Cow<'_, image::RgbImage>> {
    match image {
        image::DynamicImage::ImageRgb8(rgb) => Some(Cow::Borrowed(rgb)),
        image::DynamicImage::ImageRgba8(_) => Some(Cow::Owned(image.to_rgb8())),
        _ => None,
    }
}

impl Detector for SyntheticLsbV1 {
    fn descriptor(&self) -> DetectorDescriptor {
        DetectorDescriptor {
            method_id: "synthetic_lsb_v1".into(),
            version: "1.0.0".into(),
            formats: vec![Format::Png],
            min_samples: 1,
            max_samples: 1,
            requires_key: false,
            requires_network: false,
            evidence_types: vec!["packet_header".into(), "payload_sha256".into()],
            false_positive_limits: "A matching packet and SHA-256 establish this synthetic protocol. Deliberately copied packets carry no author or device authentication. Empirical error rates are uncalibrated.".into(),
            false_negative_limits: "Only row-major 8-bit RGB/RGBA PNG packets are recognized. Cropping, lossy encoding, resizing, different bit layouts and damaged headers can prevent detection. Other watermark schemes remain unassessed.".into(),
            supports_postprocess_retest: true,
        }
    }

    fn detect(&self, samples: &[DetectorSample<'_>], limits: &Limits) -> Result<DetectionReport> {
        let [sample] = samples else {
            return Err(Error::Input(
                "The synthetic LSB detector requires exactly one sample".into(),
            ));
        };
        if sample.data.len() as u64 > limits.max_file_bytes {
            return Err(Error::Blocked(
                "Watermark input exceeds the file size limit".into(),
            ));
        }
        if sample.format != Format::Png {
            return Ok(Self::unassessed("unsupported_container"));
        }
        if !sample.data.starts_with(b"\x89PNG\r\n\x1a\n") {
            return Err(Error::Input(
                "Watermark detector expected a PNG container".into(),
            ));
        }
        let image = super::decode_pixels(sample.data, limits)?;
        let Some(rgb) = rgb8(&image) else {
            return Ok(Self::unassessed("unsupported_sample_model"));
        };
        Self::from_rgb(&rgb, limits)
    }
}

impl SyntheticLsbV1 {
    fn unassessed(code: &str) -> DetectionReport {
        DetectionReport {
            method_id: "synthetic_lsb_v1".into(),
            detector_version: "1.0.0".into(),
            status: DetectionStatus::NotAssessed,
            confidence: Confidence::Unknown,
            evidence_codes: vec![code.into()],
            payload_sha256: None,
            payload_bytes: None,
            offline: true,
            scope: "fileveil_synthetic_packet_only".into(),
        }
    }

    fn from_rgb(rgb: &image::RgbImage, limits: &Limits) -> Result<DetectionReport> {
        let mut report = Self::unassessed("");
        report.evidence_codes.clear();
        let samples = rgb.as_raw();
        if samples.len() / 8 < SYNTHETIC_HEADER_BYTES {
            report.status = DetectionStatus::NotDetected;
            report
                .evidence_codes
                .push("packet_capacity_too_small".into());
            return Ok(report);
        }
        let header = lsb_bytes(&samples[..SYNTHETIC_HEADER_BYTES * 8]);
        if &header[..8] != SYNTHETIC_MAGIC {
            report.status = DetectionStatus::NotDetected;
            report.evidence_codes.push("packet_header_not_found".into());
            return Ok(report);
        }
        report.status = DetectionStatus::Indeterminate;
        report.evidence_codes.push("packet_magic_matched".into());
        if header[8] != SYNTHETIC_VERSION {
            report
                .evidence_codes
                .push("packet_version_unsupported".into());
            return Ok(report);
        }
        let payload_length = u32::from_be_bytes(header[9..13].try_into().map_err(|_| {
            Error::Verification("Synthetic packet length could not be decoded".into())
        })?);
        let length = payload_length as usize;
        if length.saturating_add(SYNTHETIC_HEADER_BYTES) > limits.max_metadata_bytes {
            report
                .evidence_codes
                .push("packet_payload_exceeds_limit".into());
            return Ok(report);
        }
        let available_bytes = samples.len() / 8 - SYNTHETIC_HEADER_BYTES;
        if length > available_bytes {
            report
                .evidence_codes
                .push("packet_length_exceeds_capacity".into());
            return Ok(report);
        }
        let start = SYNTHETIC_HEADER_BYTES * 8;
        let payload = lsb_bytes(&samples[start..start + length * 8]);
        let actual = digest(&payload);
        let expected = header[13..45]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if actual != expected {
            report
                .evidence_codes
                .push("packet_payload_hash_mismatch".into());
            return Ok(report);
        }
        report.status = DetectionStatus::Detected;
        report.confidence = Confidence::Verified;
        report.payload_sha256 = Some(actual);
        report.payload_bytes = Some(payload_length);
        report
            .evidence_codes
            .push("packet_payload_hash_verified".into());
        Ok(report)
    }
}

/// Registry entries are compiled-in detectors with explicit capabilities.
pub fn detectors() -> Vec<DetectorDescriptor> {
    vec![
        SyntheticLsbV1.descriptor(),
        StableDiffusionDwtDct { xl: false }.descriptor(),
        StableDiffusionDwtDct { xl: true }.descriptor(),
    ]
}

pub fn detect(data: &[u8], format: Format, limits: &Limits) -> Result<DetectionReport> {
    SyntheticLsbV1.detect(&[DetectorSample { data, format }], limits)
}

/// Additive multi-method entry point. `detect` retains its V1 packet contract.
pub fn detect_all(data: &[u8], format: Format, limits: &Limits) -> Result<Vec<DetectionReport>> {
    let image = decode_image(data, format, limits)?;
    detect_decoded(image.as_ref(), format, limits)
}

/// The audit operation shares one bounded decode between named detectors and
/// signal observations. The legacy detector-only API keeps its original output.
pub(crate) fn detect_with_signal(
    data: &[u8],
    format: Format,
    limits: &Limits,
) -> Result<(Vec<DetectionReport>, Option<crate::lab::SignalObservation>)> {
    let image = decode_image(data, format, limits)?;
    let reports = detect_decoded(image.as_ref(), format, limits)?;
    let observation = image
        .as_ref()
        .map(|image| crate::lab::analyze_signal_decoded(image, data));
    Ok((reports, observation))
}

/// Callers must provide pixels from the corresponding authorized snapshot.
/// Reusing verified decoded pixels avoids retaining another full image during
/// processing verification and preserves the source sample-model distinction.
pub(crate) fn detect_decoded(
    image: Option<&image::DynamicImage>,
    format: Format,
    limits: &Limits,
) -> Result<Vec<DetectionReport>> {
    let rgb = image.and_then(rgb8);
    let synthetic = if format != Format::Png {
        SyntheticLsbV1::unassessed("unsupported_container")
    } else if let Some(rgb) = &rgb {
        SyntheticLsbV1::from_rgb(rgb, limits)?
    } else {
        SyntheticLsbV1::unassessed("unsupported_sample_model")
    };
    let mut reports = vec![synthetic];
    let sd1 = StableDiffusionDwtDct { xl: false };
    let sdxl = StableDiffusionDwtDct { xl: true };
    if let Some(rgb) = rgb {
        let decisions = dwt_dct::block_decisions(&rgb);
        reports.push(sd1.evaluate(&rgb, &decisions));
        reports.push(sdxl.evaluate(&rgb, &decisions));
    } else {
        reports.push(sd1.unassessed("unsupported_container_or_sample_model"));
        reports.push(sdxl.unassessed("unsupported_container_or_sample_model"));
    }
    Ok(reports)
}

fn lsb_bytes(samples: &[u8]) -> Vec<u8> {
    samples
        .as_chunks::<8>()
        .0
        .iter()
        .map(|bits| {
            bits.iter()
                .fold(0, |value, sample| (value << 1) | (sample & 1))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_routes_require_consensus_and_preserve_disagreement_evidence() {
        let detector = StableDiffusionDwtDct { xl: true };
        let payload = [0xb3u8, 0xec, 0x90, 0x7b, 0xb1, 0x9e];
        let marked: Vec<_> = (0..1024)
            .map(|index| (payload[index % 48 / 8] >> (7 - index % 8)) & 1 != 0)
            .collect();
        let clean = vec![false; 1024];
        let image = image::RgbImage::new(256, 256);
        let positive = detector.evaluate(&image, &[marked.clone(), marked.clone(), marked.clone()]);
        assert_eq!(positive.status, DetectionStatus::Detected);
        assert_eq!(positive.detector_version, "1.1.0");
        let negative = detector.evaluate(&image, &[clean.clone(), clean.clone(), clean.clone()]);
        assert_eq!(negative.status, DetectionStatus::NotDetected);
        let disagreement = detector.evaluate(&image, &[marked.clone(), marked, clean]);
        assert_eq!(disagreement.status, DetectionStatus::Indeterminate);
        assert_eq!(disagreement.confidence, Confidence::Heuristic);
        assert!(disagreement.payload_sha256.is_none());
        assert!(
            disagreement
                .evidence_codes
                .iter()
                .any(|code| code == "matched_bits_min=21")
        );
        assert!(
            disagreement
                .evidence_codes
                .iter()
                .any(|code| code == "matched_bits_max=48")
        );
        assert!(
            disagreement
                .evidence_codes
                .iter()
                .any(|code| code == "numerical_consensus=false")
        );
    }
}

// FVPROV1 22407 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJlZTUwZTczMzcyYzU1NDE2ZWM4YWI1ZWZhZTg5Mjg4OWVlYTUyZTZlNWUyMjJhNjU0ZTRmMzZhYjU0ZjIzYzc1IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4zIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMyIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL3dhdGVybWFyay5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjY3OTY2OWY5MTUzMDhhOTBkZDRiNTk1NWM0NTRhNzNkNmVhZTc0NGRmZWEzZTkwN2ZlMTdhZTUzODE2Y2MzMGVkNmY2ZmY0ZDE3YjAwYjUxNmU3ZTVlNGI1OTcxY2EyOWM5ODFkYjgyNTI0ZjgzZGQwYjI1MDgxMzUzNGY1ZTA4In1dfV0= FVPROV1-END
