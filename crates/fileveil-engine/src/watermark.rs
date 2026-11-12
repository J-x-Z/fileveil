// SPDX-License-Identifier: MPL-2.0
//! Read-only, offline detector contracts and a reproducible synthetic LSB protocol.
//!
//! V1 packs eight magic bytes, version 1, a big-endian u32 payload length,
//! 32 raw SHA-256 payload digest bytes, then the payload. Each byte is emitted
//! most-significant-bit first into consecutive RGB least-significant bits,
//! traversing rows top to bottom and pixels left to right. Alpha is excluded.
use fileveil_core::{Confidence, Error, Format, Limits, Result, digest};
use serde::{Deserialize, Serialize};

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
            version: "1.0.0".into(),
            formats: vec![Format::Jpeg, Format::Png],
            min_samples: 1,
            max_samples: 1,
            requires_key: false,
            requires_network: false,
            evidence_types: vec!["public_payload_bit_match".into(), "haar_chroma_block_votes".into()],
            false_positive_limits: "Public payloads can be copied by anyone. Thresholds are method-specific signal evidence. Error rates for arbitrary images and OEM/device attribution have not been calibrated.".into(),
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
        let Some(image) = signal_image(sample.data, sample.format, limits)? else {
            return Ok(self.unassessed("unsupported_container_or_sample_model"));
        };
        Ok(self.evaluate(&image, &dwt_dct::block_decisions(&image)))
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
            detector_version: "1.0.0".into(),
            status: DetectionStatus::NotAssessed,
            confidence: Confidence::Unknown,
            evidence_codes: vec![evidence.into()],
            payload_sha256: None,
            payload_bytes: None,
            offline: true,
            scope: "public_payload_signal_match_without_origin_authentication".into(),
        }
    }

    fn evaluate(&self, image: &image::RgbImage, decisions: &[bool]) -> DetectionReport {
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
        let votes = dwt_dct::votes(decisions, length);
        if votes.iter().any(|(_, total)| *total < 4) {
            report
                .evidence_codes
                .push("insufficient_independent_block_votes".into());
            return report;
        }
        let matched = votes
            .iter()
            .enumerate()
            .filter(|(index, (ones, total))| {
                let expected = (payload[index / 8] >> (7 - index % 8)) & 1 != 0;
                (*ones as f64 * 255.0 > *total as f64 * 127.0) == expected
            })
            .count();
        let margin = votes
            .iter()
            .map(|(ones, total)| (2.0 * *ones as f64 / *total as f64 - 1.0).abs())
            .sum::<f64>()
            / length as f64;
        let (positive, partial) = if self.xl { (36, 28) } else { (128, 102) };
        report.status = if matched >= positive {
            DetectionStatus::Detected
        } else if matched >= partial {
            DetectionStatus::Indeterminate
        } else {
            DetectionStatus::NotDetected
        };
        report.confidence = if report.status == DetectionStatus::Detected {
            Confidence::StrongEvidence
        } else if report.status == DetectionStatus::Indeterminate {
            Confidence::Heuristic
        } else {
            Confidence::Unknown
        };
        report.evidence_codes = vec![
            format!("matched_bits={matched}"),
            format!("total_bits={length}"),
            format!("positive_threshold={positive}"),
            format!("block_votes={}", decisions.len()),
            format!("mean_vote_margin={margin:.6}"),
            "public_payload_is_not_authenticated_model_or_device_identity".into(),
        ];
        if report.status == DetectionStatus::Detected {
            report.payload_sha256 = Some(digest(payload));
            report.payload_bytes = Some(payload.len() as u32);
        }
        report
    }
}

fn signal_image(data: &[u8], format: Format, limits: &Limits) -> Result<Option<image::RgbImage>> {
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
    let image = super::decode_pixels(data, limits)?;
    if !matches!(
        image,
        image::DynamicImage::ImageRgb8(_) | image::DynamicImage::ImageRgba8(_)
    ) {
        return Ok(None);
    }
    Ok(Some(image.into_rgb8()))
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
        let (data, format) = (sample.data, sample.format);
        if data.len() as u64 > limits.max_file_bytes {
            return Err(Error::Blocked(
                "Watermark input exceeds the file size limit".into(),
            ));
        }
        let mut report = DetectionReport {
            method_id: "synthetic_lsb_v1".into(),
            detector_version: "1.0.0".into(),
            status: DetectionStatus::NotAssessed,
            confidence: Confidence::Unknown,
            evidence_codes: Vec::new(),
            payload_sha256: None,
            payload_bytes: None,
            offline: true,
            scope: "fileveil_synthetic_packet_only".into(),
        };
        if format != Format::Png {
            report.evidence_codes.push("unsupported_container".into());
            return Ok(report);
        }
        if !data.starts_with(b"\x89PNG\r\n\x1a\n") {
            return Err(Error::Input(
                "Watermark detector expected a PNG container".into(),
            ));
        }
        let image = super::decode_pixels(data, limits)?;
        if !matches!(
            image,
            image::DynamicImage::ImageRgb8(_) | image::DynamicImage::ImageRgba8(_)
        ) {
            report
                .evidence_codes
                .push("unsupported_sample_model".into());
            return Ok(report);
        }
        let rgb = image.into_rgb8();
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
    let mut reports = vec![detect(data, format, limits)?];
    let sd1 = StableDiffusionDwtDct { xl: false };
    let sdxl = StableDiffusionDwtDct { xl: true };
    if let Some(image) = signal_image(data, format, limits)? {
        let decisions = dwt_dct::block_decisions(&image);
        reports.push(sd1.evaluate(&image, &decisions));
        reports.push(sdxl.evaluate(&image, &decisions));
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
