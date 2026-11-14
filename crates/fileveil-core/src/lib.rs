// SPDX-License-Identifier: MPL-2.0
//! Shared, versioned contracts. Reports never contain metadata values or absolute paths.
mod options;
pub use options::{DeepOptions, FilesystemOptions, PdfOptions, SanitizeOptions, TextOptions};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCHEMA_VERSION: &str = "0.4";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Jpeg,
    Png,
    Docx,
    Xlsx,
    Pptx,
    Text,
    Html,
    Pdf,
    Heic,
    Avif,
    Mp4,
    Mov,
    Wav,
    Mp3,
    Flac,
    Unknown,
}
impl Format {
    pub fn mime(self) -> &'static str {
        match self {
            Self::Jpeg => "image/jpeg",
            Self::Png => "image/png",
            Self::Docx => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            Self::Xlsx => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            Self::Pptx => {
                "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            }
            Self::Text => "text/plain",
            Self::Html => "text/html",
            Self::Pdf => "application/pdf",
            Self::Heic => "image/heif",
            Self::Avif => "image/avif",
            Self::Mp4 => "video/mp4",
            Self::Mov => "video/quicktime",
            Self::Wav => "audio/wav",
            Self::Mp3 => "audio/mpeg",
            Self::Flac => "audio/flac",
            Self::Unknown => "application/octet-stream",
        }
    }
    pub fn is_image(self) -> bool {
        matches!(self, Self::Jpeg | Self::Png)
    }
    pub fn is_office(self) -> bool {
        matches!(self, Self::Docx | Self::Xlsx | Self::Pptx)
    }
    pub fn is_audio(self) -> bool {
        matches!(self, Self::Wav | Self::Mp3 | Self::Flac)
    }
    pub fn is_media_container(self) -> bool {
        matches!(self, Self::Heic | Self::Avif | Self::Mp4 | Self::Mov)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLayer {
    EmbeddedMetadata,
    ContainerStructure,
    Filesystem,
    ProvenanceCredential,
    ContentWatermark,
    StatisticalWatermark,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Verified,
    StrongEvidence,
    Heuristic,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingState {
    Present,
    RemovedVerified,
    AppliedVerified,
    Remains,
    NotAssessed,
    Blocked,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Preserve,
    Remove,
    Normalize,
    Rebuild,
    AskUser,
    Unsupported,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub code: String,
    pub layer: RiskLayer,
    pub location: String,
    pub summary: String,
    pub confidence: Confidence,
    pub action: Action,
    pub state: FindingState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<String>,
}
impl Finding {
    pub fn new(
        code: &str,
        layer: RiskLayer,
        location: &str,
        summary: &str,
        action: Action,
    ) -> Self {
        Self {
            code: code.into(),
            layer,
            location: location.into(),
            summary: summary.into(),
            confidence: Confidence::StrongEvidence,
            action,
            state: FindingState::Present,
            impact: None,
        }
    }
    pub fn unassessed(code: &str, layer: RiskLayer, location: &str, summary: &str) -> Self {
        Self {
            confidence: Confidence::Unknown,
            state: FindingState::NotAssessed,
            ..Self::new(code, layer, location, summary, Action::Unsupported)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Policy {
    #[default]
    Safe,
    Deep,
    Research,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    pub max_file_bytes: u64,
    pub max_uncompressed_bytes: u64,
    pub max_members: usize,
    pub max_metadata_bytes: usize,
    pub max_compression_ratio: u64,
    pub max_pixels: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: 64 * 1024 * 1024,
            max_uncompressed_bytes: 128 * 1024 * 1024,
            max_members: 10_000,
            max_metadata_bytes: 1024 * 1024,
            max_compression_ratio: 1000,
            max_pixels: 32_000_000,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Input(String),
    #[error("{0}")]
    Unsupported(String),
    #[error("{0}")]
    Verification(String),
    #[error("{0}")]
    Blocked(String),
    #[error("{0}")]
    Io(String),
    #[error("{0}")]
    Interrupted(String),
}
impl Error {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Input(_) | Self::Io(_) => 2,
            Self::Unsupported(_) => 3,
            Self::Verification(_) => 4,
            Self::Blocked(_) => 5,
            Self::Interrupted(_) => 6,
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct Inspection {
    pub format: Format,
    pub findings: Vec<Finding>,
    /// Reasons transformation is unsafe, independently of findings being removable.
    pub blockers: Vec<String>,
    /// Hash of all retained encoded structures / non-property OOXML parts.
    pub content_digest: String,
    pub rewrite_supported: bool,
    pub limited_support: bool,
}
impl Inspection {
    pub fn new(format: Format, content_digest: String) -> Self {
        Self {
            format,
            findings: Vec::new(),
            blockers: Vec::new(),
            content_digest,
            rewrite_supported: true,
            limited_support: false,
        }
    }
}

/// Adapters operate on a caller-bounded file snapshot. No adapter opens URLs or writes files.
pub trait FormatAdapter {
    fn inspect(&self, data: &[u8], limits: &Limits) -> Result<Inspection>;
    fn sanitize(&self, data: &[u8], limits: &Limits) -> Result<Vec<u8>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    VerifiedWithinScope,
    PartiallyVerified,
    Failed,
    Unsupported,
    Blocked,
    NotAssessed,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Integrity {
    pub parseable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decodeable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pixel_equal: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_equal: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_unchanged: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_markers_preserved: Option<bool>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageProcessMode {
    LowBits,
    Signal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageProcessOptions {
    pub mode: ImageProcessMode,
    /// RGB least-significant sample bits to clear in LowBits mode. Alpha is preserved.
    pub low_bits: u8,
}
impl Default for ImageProcessOptions {
    fn default() -> Self {
        Self {
            mode: ImageProcessMode::LowBits,
            low_bits: 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImageProcessingReport {
    pub mode: ImageProcessMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub low_bits: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resize_scale: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blur_sigma: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jpeg_quality: Option<u8>,
    pub input_dimensions: [u32; 2],
    pub output_dimensions: [u32; 2],
    pub changed_samples: u64,
    pub max_delta: u8,
    pub mse: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_low_bits: Option<bool>,
    pub detector_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: String,
    pub tool: String,
    pub version: String,
    pub operation: String,
    pub input_format: String,
    pub policy: Policy,
    pub result: Outcome,
    pub findings: Vec<Finding>,
    pub integrity: Integrity,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_sha256: Option<String>,
    /// Basename only. The CLI caller already knows the chosen output directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_processing: Option<ImageProcessingReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdf: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advanced: Option<serde_json::Value>,
}
impl Report {
    pub fn new(operation: &str, format: Format) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.into(),
            tool: "FileVeil".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            operation: operation.into(),
            input_format: format.mime().into(),
            policy: Policy::Safe,
            result: Outcome::PartiallyVerified,
            findings: Vec::new(),
            integrity: Integrity::default(),
            warnings: Vec::new(),
            input_sha256: None,
            output_sha256: None,
            output_name: None,
            image_processing: None,
            pdf: None,
            provenance: None,
            advanced: None,
        }
    }
}
pub fn digest(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

// FVPROV1 10514 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJlNzExZmMzMjMyOTgyMGQ2ZGQ5MDlkYzJiMDYzNDlmMTVlMTEwMjYwMGJhYTBmYTYyNzM2YTdmZGY4OWNkNmMxIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4yIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMiIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1jb3JlL3NyYy9saWIucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiJmMmY1YThhODAxMmYxM2RmMzc1MDY2YzI5OWM3NzEwOWRhNmIyMzMxMzA1MmY0YmI0ODRkNGViZDE0NzIyODU4NzQ3OWFhYTNjMDEzMDA3NjQ1NmE1MGNmNGVkMjc5ZmMyZThjY2ZmN2M3YzY1YzU1NDQxM2I1ZGQ1NDg5ZGQwNyJ9XX1d FVPROV1-END
