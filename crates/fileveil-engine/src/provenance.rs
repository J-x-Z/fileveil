// SPDX-License-Identifier: MPL-2.0
//! Offline C2PA validation over an already bounded file snapshot.
//!
//! Only fixed status codes, algorithm names and structural counts leave the SDK.
//! Manifest values, credential subjects, URLs and SDK error messages stay private.
use std::{
    borrow::Cow,
    collections::BTreeSet,
    fs,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
};

use c2pa::{Context, Reader, ValidationState, validation_results::StatusCodes};
use fileveil_core::{Error, Format, Limits, Policy, Result, SanitizeOptions, digest};
use serde::{Deserialize, Serialize};
use serde_json::json;
use unicode_normalization::is_nfc;

pub const SDK_VERSION: &str = "0.91.11";
const MIB: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceCapability {
    pub provider_id: String,
    pub evidence_kind: String,
    pub status: String,
    pub verified_formats: Vec<String>,
    pub additional_reader_formats: Vec<String>,
    pub network_enabled: bool,
    pub availability_reason: String,
}

/// Availability describes this build's configured backends. It makes no claim
/// that a named vendor has published a compatible detection service.
pub fn capabilities() -> Vec<ProvenanceCapability> {
    let mut capabilities = vec![ProvenanceCapability {
        provider_id: "c2pa".into(),
        evidence_kind: "signed_provenance_credential".into(),
        status: "available".into(),
        verified_formats: vec![
            "jpeg".into(),
            "png".into(),
            "pdf".into(),
            "txt".into(),
            "md".into(),
            "wav".into(),
            "heif".into(),
            "avif".into(),
            "mp4".into(),
            "mov".into(),
        ],
        additional_reader_formats: Vec::new(),
        network_enabled: false,
        availability_reason: "offline_cryptographic_reader".into(),
    }];
    for provider_id in ["stable_diffusion_v1", "stable_diffusion_xl"] {
        capabilities.push(ProvenanceCapability {
            provider_id: provider_id.into(),
            evidence_kind: "public_image_watermark_payload".into(),
            status: "available".into(),
            verified_formats: vec!["png".into(), "jpeg".into()],
            additional_reader_formats: Vec::new(),
            network_enabled: false,
            availability_reason: "offline_public_payload_detector_without_origin_authentication"
                .into(),
        });
    }
    for (provider_id, evidence_kind) in [
        (
            "openai_statistical_text",
            "keyed_statistical_text_watermark",
        ),
        (
            "anthropic_statistical_text",
            "keyed_statistical_text_watermark",
        ),
        ("proprietary_image_watermark", "content_watermark"),
        ("google_synthid_image", "proprietary_content_watermark"),
        ("google_synthid_text", "keyed_statistical_text_watermark"),
        ("oem_device_fingerprint", "device_attribution"),
    ] {
        capabilities.push(ProvenanceCapability {
            provider_id: provider_id.into(),
            evidence_kind: evidence_kind.into(),
            status: "unavailable".into(),
            verified_formats: Vec::new(),
            additional_reader_formats: Vec::new(),
            network_enabled: false,
            availability_reason: "authorized_detector_not_configured".into(),
        });
    }
    capabilities
}

/// Documented remote interfaces remain disabled in this offline build.
/// No credentials are loaded and no file content is transmitted by this API.
pub fn external_interfaces() -> serde_json::Value {
    json!({
        "checked_date":"2026-11-12", "network_enabled":false,
        "openai_media":{
            "status":"documented_api_not_configured", "evidence":["c2pa","synthid"],
            "endpoint":"https://api.openai.com/v1/content_provenance_checks",
            "reference":"https://developers.openai.com/api/docs/guides/content-provenance",
            "requires_api_access":true,"requires_explicit_upload_consent":true,
            "upload_scope":"whole_selected_file", "max_file_bytes":52_428_800,
            "max_audio_seconds":60,"executed":false
        },
        "openai_text":{
            "status":"organization_approval_required", "evidence":"keyed_text_watermark",
            "reference":"https://developers.openai.com/api/docs/guides/content-provenance",
            "requested_textgrain_name_verified":false,"executed":false
        },
        "anthropic_text":{
            "status":"restricted_private_preview_not_configured", "method_family":"synthid_text",
            "reference":"https://www.anthropic.com/news/claude-text-watermark",
            "requires_provider_access":true,"requires_explicit_upload_consent":true,
            "hidden_character_removal_is_a_separate_operation":true,"executed":false
        },
        "google_synthid":{
            "status":"official_portal_not_configured", "reference":"https://deepmind.google/models/synthid/",
            "portal":"https://synthid.com", "executed":false
        },
        "google_synthid_text_reference":{
            "status":"matching_generation_configuration_and_keys_required",
            "reference":"https://github.com/google-deepmind/synthid-text",
            "required_inputs":["matching_tokenizer","token_ids","sampling_keys","generation_configuration"],
            "commercial_model_compatibility":"not_assessed", "executed":false
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Valid,
    Invalid,
    Unverifiable,
    NotAssessed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustStatus {
    Trusted,
    Untrusted,
    Unverifiable,
    NotAssessed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestPresence {
    Embedded,
    RemoteReference,
    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceReport {
    pub standard: String,
    pub sdk_version: String,
    pub presence: ManifestPresence,
    pub manifest_count: usize,
    pub assertion_count: usize,
    pub ingredient_count: usize,
    pub claim_generator_count: usize,
    /// Overall SDK validation includes structure, assertions and ingredient validation.
    pub manifest_validation: CheckStatus,
    /// COSE claim signature validation, independently of asset binding and root trust.
    pub signature: CheckStatus,
    pub asset_binding: CheckStatus,
    pub asset_binding_scope: String,
    pub trust: TrustStatus,
    /// Only embedded/stapled revocation evidence can be checked in this module.
    pub revocation: CheckStatus,
    pub revocation_scope: String,
    pub timestamp: CheckStatus,
    pub timestamp_trust: TrustStatus,
    pub identity_assertions: CheckStatus,
    pub offline: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_anchor_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
    pub validation_codes: Vec<String>,
    pub unrecognized_code_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_scope: Option<TextCredentialScope>,
}

/// UTF-8 byte ranges of recognized standard text credential wrappers. The digest
/// covers every byte outside those ranges, including meaningful format characters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextCredentialScope {
    pub wrapper_count: usize,
    pub ranges: Vec<[usize; 2]>,
    pub visible_sha256: String,
    pub is_nfc: bool,
    pub removal_supported: bool,
    pub issue: Option<String>,
}

impl ProvenanceReport {
    fn unreadable(presence: ManifestPresence, code: &str) -> Self {
        Self {
            standard: "c2pa".into(),
            sdk_version: SDK_VERSION.into(),
            presence,
            manifest_count: 0,
            assertion_count: 0,
            ingredient_count: 0,
            claim_generator_count: 0,
            manifest_validation: CheckStatus::Unverifiable,
            signature: CheckStatus::Unverifiable,
            asset_binding: CheckStatus::Unverifiable,
            asset_binding_scope: "declared_hash_ranges".into(),
            trust: TrustStatus::Unverifiable,
            revocation: CheckStatus::NotAssessed,
            revocation_scope: "embedded_evidence_only".into(),
            timestamp: CheckStatus::NotAssessed,
            timestamp_trust: TrustStatus::NotAssessed,
            identity_assertions: CheckStatus::NotAssessed,
            offline: true,
            trust_anchor_sha256: None,
            signature_algorithm: None,
            validation_codes: vec![code.into()],
            unrecognized_code_count: 0,
            text_scope: None,
        }
    }
}

/// Validates supported image, PDF, WAV and plain-text assets without network access.
/// A successful absence result means this SDK found no embedded manifest or remote reference.
pub fn inspect(data: &[u8], format: Format, limits: &Limits) -> Result<Option<ProvenanceReport>> {
    inspect_with_trust(data, format, limits, None)
}

/// Explicitly removes removable PNG/JPEG credentials from a private snapshot.
/// The SDK receives only a new private file owned by this operation. The source
/// file path and every caller-provided destination stay outside its API.
pub fn remove(data: &[u8], format: Format, limits: &Limits) -> Result<Vec<u8>> {
    if data.len() as u64 > limits.max_file_bytes {
        return Err(Error::Blocked(
            "C2PA removal input exceeds the file size limit".into(),
        ));
    }
    let extension = match format {
        Format::Png => "png",
        Format::Jpeg => "jpg",
        _ => {
            return Err(Error::Unsupported(
                "Credential removal supports JPEG and PNG snapshots".into(),
            ));
        }
    };
    let options = SanitizeOptions {
        policy: Policy::Deep,
        remove_provenance: true,
        ..SanitizeOptions::default()
    };
    let hint = format!("snapshot.{extension}");
    let inspection =
        fileveil_formats::inspect_with_options(data, Path::new(&hint), limits, &options)?;
    if inspection.format != format || !inspection.blockers.is_empty() {
        return Err(Error::Blocked(
            "Protected image structures prevent credential removal".into(),
        ));
    }
    let stripped = remove_store(data, format.mime(), limits)?;
    let clean = fileveil_formats::sanitize_with_options(&stripped, format, limits, &options)?;
    if inspect(&clean, format, limits)?.is_some() {
        return Err(Error::Verification(
            "A credential store or provenance reference remains after removal".into(),
        ));
    }
    Ok(clean)
}

/// Removes the official embedded store from an operation-owned private copy.
/// Callers must subsequently verify the format-specific content and structure.
pub fn remove_store(data: &[u8], mime: &str, limits: &Limits) -> Result<Vec<u8>> {
    check_size(data, limits)?;
    let extension = match mime {
        "image/jpeg" => "jpg",
        "image/png" => "png",
        "application/pdf" => "pdf",
        "text/plain" => "txt",
        "text/markdown" => "md",
        _ => {
            return Err(Error::Unsupported(
                "Credential store removal is unavailable for this type".into(),
            ));
        }
    };
    let expected_text = if is_text_mime(mime) {
        Some(strip_text_wrappers(data, mime, limits)?)
    } else {
        None
    };
    let mut staging = tempfile::Builder::new();
    staging.prefix("fileveil-credential-");
    // Reuse the supervisor-owned helper root so forced worker termination also
    // removes private credential copies. Standalone callers own the TempDir.
    let directory = if let Some(root) = std::env::var_os("FILEVEIL_PDF_STAGING") {
        let root = PathBuf::from(root);
        if !root.is_absolute() {
            return Err(Error::Blocked(
                "Credential staging root must be an absolute trusted directory".into(),
            ));
        }
        staging.tempdir_in(root)
    } else {
        staging.tempdir()
    }
    .map_err(|_| Error::Io("Could not create private credential workspace".into()))?;
    let path = directory.path().join(format!("snapshot.{extension}"));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|_| Error::Io("Could not create private credential snapshot".into()))?;
    file.write_all(data)
        .map_err(|_| Error::Io("Could not write private credential snapshot".into()))?;
    drop(file);
    match c2pa::jumbf_io::remove_jumbf_from_file(&path) {
        Ok(()) | Err(c2pa::Error::JumbfNotFound | c2pa::Error::NotFound) => {}
        Err(_) => {
            return Err(Error::Blocked(
                "The official credential backend could not remove this store".into(),
            ));
        }
    }
    let file = fs::File::open(&path)
        .map_err(|_| Error::Io("Could not read the private credential result".into()))?;
    let mut stripped = Vec::new();
    file.take(limits.max_file_bytes.saturating_add(1))
        .read_to_end(&mut stripped)
        .map_err(|_| Error::Io("Could not read the private credential result".into()))?;
    if stripped.len() as u64 > limits.max_file_bytes {
        return Err(Error::Blocked(
            "Credential removal output exceeds the file size limit".into(),
        ));
    }
    if expected_text
        .as_ref()
        .is_some_and(|expected| expected != &stripped)
    {
        return Err(Error::Verification(
            "Credential removal changed bytes outside the recognized text wrapper".into(),
        ));
    }
    Ok(stripped)
}

/// Uses an explicitly supplied local PEM trust bundle. The bundle is never fetched.
/// The caller owns loading and authorizing the trust file before calling this API.
pub fn inspect_with_trust(
    data: &[u8],
    format: Format,
    limits: &Limits,
    trust_anchors_pem: Option<&str>,
) -> Result<Option<ProvenanceReport>> {
    let Some(mime) = supported_mime(data, format) else {
        return Ok(None);
    };
    inspect_mime(data, mime, limits, trust_anchors_pem)
}

/// Validates a known container MIME over an already authorized bounded snapshot.
/// Markdown is explicit because the shared text format also represents plain text.
pub fn inspect_mime(
    data: &[u8],
    mime: &str,
    limits: &Limits,
    trust_anchors_pem: Option<&str>,
) -> Result<Option<ProvenanceReport>> {
    check_size(data, limits)?;
    if !matches!(
        mime,
        "image/jpeg"
            | "image/png"
            | "image/heic"
            | "image/heif"
            | "image/avif"
            | "video/mp4"
            | "video/quicktime"
            | "application/pdf"
            | "text/plain"
            | "text/markdown"
            | "audio/wav"
    ) {
        return Err(Error::Unsupported(
            "C2PA reader is unavailable for this MIME type".into(),
        ));
    }
    let scope = if is_text_mime(mime) {
        let scope = text_scope(data, mime, limits)?;
        if scope.wrapper_count == 0 {
            return Ok(None);
        }
        let issue = scope.issue.as_deref();
        if scope.wrapper_count != 1 || issue.is_some() {
            let remote = issue == Some("fileveil.c2pa.remote_manifest_disabled");
            let mut report = ProvenanceReport::unreadable(
                if remote {
                    ManifestPresence::RemoteReference
                } else {
                    ManifestPresence::Unreadable
                },
                issue.unwrap_or("fileveil.c2pa.multiple_text_wrappers"),
            );
            report.text_scope = Some(scope);
            return Ok(Some(report));
        }
        Some(scope)
    } else {
        None
    };
    let wav_store_count = if mime == "audio/wav" {
        fileveil_formats::audio::inspect(data, Format::Wav, limits)?
            .findings
            .iter()
            .filter(|finding| finding.code == "wav.provenance")
            .count()
    } else {
        0
    };
    if wav_store_count > 1 {
        let mut report = ProvenanceReport::unreadable(
            ManifestPresence::Unreadable,
            "fileveil.c2pa.multiple_riff_stores",
        );
        report.manifest_count = wav_store_count;
        return Ok(Some(report));
    }
    let pdf_summary = if mime == "application/pdf" {
        Some(crate::pdf::credential_summary(data, limits)?)
    } else {
        None
    };
    if let Some(summary) = &pdf_summary
        && (summary.store_count > 1 || summary.unresolved_credential_entries > 0)
    {
        let mut report = ProvenanceReport::unreadable(
            ManifestPresence::Unreadable,
            if summary.store_count > 1 {
                "fileveil.c2pa.multiple_pdf_stores"
            } else {
                "fileveil.c2pa.pdf_store_structure_unresolved"
            },
        );
        report.manifest_count = summary.store_count;
        return Ok(Some(report));
    }
    let trust_anchors_pem = trust_anchors_pem.filter(|pem| !pem.is_empty());
    if trust_anchors_pem.is_some_and(|pem| pem.len() > limits.max_metadata_bytes) {
        return Err(Error::Blocked(
            "C2PA trust bundle exceeds the metadata limit".into(),
        ));
    }
    if let Some(pem) = trust_anchors_pem {
        validate_trust_bundle(pem, limits)?;
    }
    let unreadable = |presence, code: &str| {
        let mut report = ProvenanceReport::unreadable(presence, code);
        report.text_scope = scope.clone();
        report
    };

    // The official container handler loads only embedded C2PA bytes. Its result
    // limits the stored manifest before the Reader parses assertions and certificates.
    let embedded = match c2pa::jumbf_io::load_jumbf_from_memory(mime, data) {
        Ok(bytes) => {
            if bytes.len() > limits.max_metadata_bytes {
                return Err(Error::Blocked(
                    "C2PA manifest exceeds the metadata limit".into(),
                ));
            }
            true
        }
        Err(c2pa::Error::JumbfNotFound | c2pa::Error::NotFound) => false,
        Err(c2pa::Error::UnsupportedType) => return Ok(None),
        Err(_) => {
            return Ok(Some(unreadable(
                ManifestPresence::Unreadable,
                "fileveil.c2pa.container_unreadable",
            )));
        }
    };

    let context = offline_context(limits, trust_anchors_pem)?;
    let reader = match Reader::from_context(context).with_stream(mime, Cursor::new(data)) {
        Ok(reader) => reader,
        Err(c2pa::Error::JumbfNotFound | c2pa::Error::NotFound)
            if !embedded
                && scope.is_none()
                && wav_store_count == 0
                && !pdf_summary
                    .as_ref()
                    .is_some_and(|summary| summary.store_count > 0) =>
        {
            return Ok(None);
        }
        Err(c2pa::Error::RemoteManifestUrl(_) | c2pa::Error::RemoteManifestFetch(_)) => {
            return Ok(Some(unreadable(
                ManifestPresence::RemoteReference,
                "fileveil.c2pa.remote_manifest_disabled",
            )));
        }
        Err(_) => {
            return Ok(Some(unreadable(
                ManifestPresence::Unreadable,
                "fileveil.c2pa.manifest_unreadable",
            )));
        }
    };

    if reader.manifests().len() > limits.max_members {
        return Err(Error::Blocked(
            "C2PA manifest count exceeds the member limit".into(),
        ));
    }
    let mut report = ProvenanceReport::unreadable(ManifestPresence::Embedded, "");
    report.validation_codes.clear();
    report.manifest_count = reader.manifests().len();
    report.manifest_validation = match reader.validation_state() {
        ValidationState::Invalid => CheckStatus::Invalid,
        ValidationState::Valid | ValidationState::Trusted => CheckStatus::Valid,
    };
    report.trust_anchor_sha256 = trust_anchors_pem.map(|pem| digest(pem.as_bytes()));

    for manifest in reader.iter_manifests() {
        report.assertion_count += manifest.assertions().len();
        report.ingredient_count += manifest.ingredients().len();
        report.claim_generator_count += manifest.claim_generator_info.as_ref().map_or(0, Vec::len);
    }
    if report
        .assertion_count
        .saturating_add(report.ingredient_count)
        > limits.max_members
    {
        return Err(Error::Blocked(
            "C2PA assertion count exceeds the member limit".into(),
        ));
    }
    report.signature_algorithm = reader
        .active_manifest()
        .and_then(|manifest| manifest.signature_info())
        .and_then(|info| info.alg)
        .map(|alg| alg.to_string());

    let mut codes = BTreeSet::new();
    if let Some(results) = reader.validation_results() {
        if let Some(active) = results.active_manifest() {
            report.signature = check(
                active,
                &["claimSignature.validated"],
                &["claimSignature.mismatch", "claimSignature.missing"],
                CheckStatus::Unverifiable,
            );
            report.asset_binding = check(
                active,
                &[
                    "assertion.dataHash.match",
                    "assertion.bmffHash.match",
                    "assertion.boxesHash.match",
                    "assertion.collectionHash.match",
                ],
                &[
                    "assertion.dataHash.mismatch",
                    "assertion.bmffHash.mismatch",
                    "assertion.boxesHash.mismatch",
                    "claim.hardBindings.missing",
                    "assertion.multipleHardBindings",
                    "assertion.dataHash.malformed",
                    "assertion.bmffHash.malformed",
                    "assertion.boxesHash.malformed",
                ],
                CheckStatus::Unverifiable,
            );
            report.revocation = check(
                active,
                &["signingCredential.ocsp.notRevoked"],
                &["signingCredential.ocsp.revoked"],
                CheckStatus::NotAssessed,
            );
            report.timestamp = check(
                active,
                &["timeStamp.validated"],
                &[
                    "timeStamp.mismatch",
                    "timeStamp.malformed",
                    "timeStamp.outsideValidity",
                ],
                CheckStatus::NotAssessed,
            );
            report.timestamp_trust = if has_code(active, "timeStamp.untrusted") {
                TrustStatus::Untrusted
            } else if has_code(active, "timeStamp.trusted") {
                TrustStatus::Trusted
            } else {
                TrustStatus::NotAssessed
            };
            report.trust = match trust_anchors_pem {
                None => TrustStatus::NotAssessed,
                Some(_) if has_code(active, "signingCredential.untrusted") => {
                    TrustStatus::Untrusted
                }
                Some(_) if has_code(active, "signingCredential.trusted") => TrustStatus::Trusted,
                Some(_) => TrustStatus::Unverifiable,
            };
            collect_codes(active, &mut codes, &mut report.unrecognized_code_count);
        }
        if let Some(ingredients) = results.ingredient_deltas() {
            for ingredient in ingredients {
                collect_codes(
                    ingredient.validation_deltas(),
                    &mut codes,
                    &mut report.unrecognized_code_count,
                );
            }
        }
    }
    report.validation_codes = codes.into_iter().collect();
    if pdf_summary
        .as_ref()
        .is_some_and(|summary| summary.incremental_history_clues)
    {
        if report.manifest_validation == CheckStatus::Valid {
            report.manifest_validation = CheckStatus::Unverifiable;
        }
        report
            .validation_codes
            .push("fileveil.c2pa.pdf_incremental_history_not_fully_validated".into());
    }
    if mime == "text/plain" && scope.as_ref().is_some_and(|scope| !scope.is_nfc) {
        report.asset_binding = CheckStatus::Unverifiable;
        report.asset_binding_scope = "nfc_normalization_required_not_performed".into();
        if report.manifest_validation == CheckStatus::Valid
            || reader
                .validation_results()
                .and_then(|results| results.active_manifest())
                .is_some_and(|active| {
                    active.failure().iter().all(|status| {
                        matches!(
                            status.code(),
                            "assertion.dataHash.mismatch" | "signingCredential.untrusted"
                        )
                    })
                })
                && reader
                    .validation_results()
                    .and_then(|results| results.ingredient_deltas())
                    .is_none_or(|ingredients| {
                        ingredients
                            .iter()
                            .all(|ingredient| ingredient.validation_deltas().failure().is_empty())
                    })
        {
            report.manifest_validation = CheckStatus::Unverifiable;
        }
        report
            .validation_codes
            .push("fileveil.c2pa.plaintext_nfc_binding_unverifiable".into());
    }
    report.text_scope = scope;
    Ok(Some(report))
}

fn check_size(data: &[u8], limits: &Limits) -> Result<()> {
    if data.len() as u64 > limits.max_file_bytes {
        return Err(Error::Blocked(
            "C2PA input exceeds the file size limit".into(),
        ));
    }
    Ok(())
}

fn is_text_mime(mime: &str) -> bool {
    matches!(mime, "text/plain" | "text/markdown")
}

/// Finds A.8 frames or the conservative A.9 Markdown subset. A.9 removal is
/// restricted to a complete dedicated comment on the first physical line, where
/// it cannot be a fenced-code example, string literal or nested HTML content.
pub fn text_scope(data: &[u8], mime: &str, limits: &Limits) -> Result<TextCredentialScope> {
    check_size(data, limits)?;
    let text = std::str::from_utf8(data)
        .map_err(|_| Error::Unsupported("C2PA text requires valid UTF-8".into()))?;
    let mut scope = TextCredentialScope {
        wrapper_count: 0,
        ranges: Vec::new(),
        visible_sha256: String::new(),
        is_nfc: false,
        removal_supported: true,
        issue: None,
    };
    match mime {
        "text/plain" => plain_text_ranges(text, limits, &mut scope)?,
        "text/markdown" => markdown_ranges(text, limits, &mut scope)?,
        _ => {
            return Err(Error::Unsupported(
                "Standard text credential wrappers are unavailable for this MIME type".into(),
            ));
        }
    }
    let visible = if scope.ranges.is_empty() {
        Cow::Borrowed(data)
    } else {
        Cow::Owned(without_ranges(data, &scope.ranges))
    };
    scope.visible_sha256 = digest(&visible);
    scope.is_nfc =
        is_nfc(std::str::from_utf8(&visible).map_err(|_| {
            Error::Verification("Text wrapper ranges did not preserve UTF-8".into())
        })?);
    Ok(scope)
}

/// Preserves all bytes except independently recognized removable wrappers.
/// Cryptographic authenticity is reported by inspect_mime, separately from framing.
pub fn strip_text_wrappers(data: &[u8], mime: &str, limits: &Limits) -> Result<Vec<u8>> {
    let scope = text_scope(data, mime, limits)?;
    if !scope.removal_supported {
        return Err(Error::Blocked(
            "Text credential wrapper context is ambiguous or malformed".into(),
        ));
    }
    Ok(without_ranges(data, &scope.ranges))
}

fn without_ranges(data: &[u8], ranges: &[[usize; 2]]) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());
    let mut cursor = 0;
    for &[start, end] in ranges {
        output.extend_from_slice(&data[cursor..start]);
        cursor = end;
    }
    output.extend_from_slice(&data[cursor..]);
    output
}

fn selector_byte(character: char) -> Option<u8> {
    match character as u32 {
        point @ 0xfe00..=0xfe0f => Some((point - 0xfe00) as u8),
        point @ 0xe0100..=0xe01ef => Some((point - 0xe0100 + 16) as u8),
        _ => None,
    }
}

fn plain_text_ranges(text: &str, limits: &Limits, scope: &mut TextCredentialScope) -> Result<()> {
    let mut from = 0;
    while let Some(relative) = text[from..].find('\u{feff}') {
        let start = from + relative;
        let run_start = start + '\u{feff}'.len_utf8();
        let mut header = [0u8; 13];
        let mut count = 0usize;
        let mut end = run_start;
        for character in text[run_start..].chars() {
            let Some(byte) = selector_byte(character) else {
                break;
            };
            if count < header.len() {
                header[count] = byte;
            }
            count += 1;
            end += character.len_utf8();
        }
        from = end;
        if count < 8 || &header[..8] != b"C2PATXT\0" {
            continue;
        }
        scope.wrapper_count += 1;
        if scope.wrapper_count > limits.max_members {
            return Err(Error::Blocked(
                "C2PA text wrapper count exceeds the member limit".into(),
            ));
        }
        let declared = u32::from_be_bytes(
            header[9..13]
                .try_into()
                .map_err(|_| Error::Verification("Invalid text wrapper header".into()))?,
        ) as usize;
        if declared > limits.max_metadata_bytes
            || count
                > limits
                    .max_metadata_bytes
                    .saturating_mul(2)
                    .saturating_add(32)
        {
            return Err(Error::Blocked(
                "C2PA text wrapper exceeds the metadata limit".into(),
            ));
        }
        if count < header.len() || header[8] != 1 || count - header.len() < declared {
            scope.removal_supported = false;
            scope.issue = Some("fileveil.c2pa.plaintext_frame_malformed".into());
            continue;
        }
        scope.ranges.push([start, end]);
    }
    Ok(())
}

fn manifest_reference(reference: &str) -> bool {
    if reference.starts_with("data:application/c2pa;base64,") {
        return true;
    }
    if reference.is_empty() || reference.contains(char::is_whitespace) {
        return false;
    }
    reference.split_once(':').is_some_and(|(scheme, rest)| {
        !rest.is_empty()
            && scheme.starts_with(|character: char| character.is_ascii_alphabetic())
            && scheme.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
            })
    })
}

fn markdown_ranges(text: &str, limits: &Limits, scope: &mut TextCredentialScope) -> Result<()> {
    const BEGIN: &str = "-----BEGIN C2PA MANIFEST-----";
    const END: &str = "-----END C2PA MANIFEST-----";
    const DATA: &str = "data:application/c2pa;base64,";
    // Only a dedicated initial comment can be removed. Compute its candidate
    // start once so repeated invalid markers cannot rescan a long prefix.
    let indentation = text
        .bytes()
        .take(4)
        .take_while(|byte| *byte == b' ')
        .count();
    let allowed_begin = if indentation <= 3 {
        text[indentation..].strip_prefix("<!--").map(|comment| {
            indentation
                + 4
                + comment
                    .bytes()
                    .take_while(|byte| matches!(byte, b' ' | b'\t'))
                    .count()
        })
    } else {
        None
    };
    let mut from = 0;
    while let Some(relative) = text[from..].find(BEGIN) {
        let begin = from + relative;
        let reference_start = begin + BEGIN.len();
        let Some(relative_end) = text[reference_start..].find(END) else {
            if text[reference_start..].trim_start().starts_with(DATA) {
                scope.wrapper_count += 1;
                scope.removal_supported = false;
                scope.issue = Some("fileveil.c2pa.markdown_frame_malformed".into());
            }
            break;
        };
        let end = reference_start + relative_end;
        let past_end = end + END.len();
        from = past_end;
        let reference = text[reference_start..end].trim();
        if !manifest_reference(reference) {
            continue;
        }
        scope.wrapper_count += 1;
        if scope.wrapper_count > limits.max_members {
            return Err(Error::Blocked(
                "C2PA text wrapper count exceeds the member limit".into(),
            ));
        }
        if let Some(encoded) = reference.strip_prefix(DATA)
            && encoded.len()
                > limits
                    .max_metadata_bytes
                    .saturating_add(2)
                    .saturating_div(3)
                    .saturating_mul(4)
        {
            return Err(Error::Blocked(
                "C2PA text wrapper exceeds the metadata limit".into(),
            ));
        }
        if allowed_begin != Some(begin) || reference.contains(char::is_whitespace) {
            scope.removal_supported = false;
            scope.issue = Some("fileveil.c2pa.markdown_context_unsupported".into());
            continue;
        }
        let line_end = text[past_end..]
            .find('\n')
            .map_or(text.len(), |relative| past_end + relative + 1);
        if text[past_end..line_end].trim() != "-->" {
            scope.removal_supported = false;
            scope.issue = Some("fileveil.c2pa.markdown_context_unsupported".into());
            continue;
        }
        scope.ranges.push([0, line_end]);
        if !reference.starts_with(DATA) {
            scope.issue = Some("fileveil.c2pa.remote_manifest_disabled".into());
        }
    }
    Ok(())
}

fn offline_context(limits: &Limits, trust_anchors_pem: Option<&str>) -> Result<Context> {
    let anchors = trust_anchors_pem
        .map(|pem| {
            vec![json!({
                "trust_anchors": pem,
                "trust_kind": "manifest",
                "trust_uri": "urn:fileveil:local-trust-bundle"
            })]
        })
        .unwrap_or_default();
    let settings = json!({
        "verify": {
            "verify_after_reading": true,
            "verify_trust": true,
            "verify_timestamp_trust": true,
            "remote_manifest_fetch": false,
            "ocsp_fetch": false,
            "ocsp_fetch_should_override": false
        },
        "trust": {"anchors": anchors},
        "core": {
            "allowed_network_hosts": [],
            "allow_redirects": false,
            "decode_identity_assertions": false,
            "max_decompressed_manifest_size_in_mb": limits.max_metadata_bytes.div_ceil(MIB).clamp(1, 32)
        }
    });
    Context::new()
        .with_settings(settings)
        .map_err(|_| Error::Input("C2PA offline settings or local trust bundle are invalid".into()))
}

fn validate_trust_bundle(pem: &str, limits: &Limits) -> Result<()> {
    let mut count = 0;
    for certificate in x509_parser::pem::Pem::iter_from_buffer(pem.as_bytes()) {
        let certificate = certificate
            .map_err(|_| Error::Input("C2PA local trust bundle contains invalid PEM".into()))?;
        if certificate.label != "CERTIFICATE" || certificate.parse_x509().is_err() {
            return Err(Error::Input(
                "C2PA local trust bundle contains an invalid X.509 certificate".into(),
            ));
        }
        count += 1;
        if count > limits.max_members {
            return Err(Error::Blocked(
                "C2PA trust certificate count exceeds the member limit".into(),
            ));
        }
    }
    if count == 0 {
        return Err(Error::Input(
            "C2PA local trust bundle contains no certificates".into(),
        ));
    }
    Ok(())
}

fn check(
    status: &StatusCodes,
    success: &[&str],
    failure: &[&str],
    fallback: CheckStatus,
) -> CheckStatus {
    if status
        .failure
        .iter()
        .any(|entry| failure.contains(&entry.code()))
    {
        CheckStatus::Invalid
    } else if status
        .success
        .iter()
        .any(|entry| success.contains(&entry.code()))
    {
        CheckStatus::Valid
    } else {
        fallback
    }
}

fn has_code(status: &StatusCodes, code: &str) -> bool {
    status
        .success
        .iter()
        .chain(&status.informational)
        .chain(&status.failure)
        .any(|entry| entry.code() == code)
}

fn collect_codes(status: &StatusCodes, codes: &mut BTreeSet<String>, unknown: &mut usize) {
    for entry in status
        .success
        .iter()
        .chain(&status.informational)
        .chain(&status.failure)
    {
        // A strict allow-list prevents values supplied by a manifest or future
        // SDK extension from becoming identifiers in a privacy-safe report.
        if matches!(
            entry.code(),
            "claimSignature.validated"
                | "claimSignature.insideValidity"
                | "claimSignature.mismatch"
                | "claimSignature.missing"
                | "claimSignature.outsideValidity"
                | "signingCredential.trusted"
                | "signingCredential.untrusted"
                | "signingCredential.invalid"
                | "signingCredential.expired"
                | "signingCredential.ocsp.notRevoked"
                | "signingCredential.ocsp.revoked"
                | "signingCredential.ocsp.skipped"
                | "signingCredential.ocsp.inaccessible"
                | "signingCredential.ocsp.unknown"
                | "assertion.hashedURI.match"
                | "assertion.hashedURI.mismatch"
                | "assertion.dataHash.match"
                | "assertion.dataHash.additionalExclusionsPresent"
                | "assertion.dataHash.mismatch"
                | "assertion.bmffHash.match"
                | "assertion.bmffHash.additionalExclusionsPresent"
                | "assertion.bmffHash.mismatch"
                | "assertion.boxesHash.match"
                | "assertion.boxesHash.additionalExclusionsPresent"
                | "assertion.boxesHash.mismatch"
                | "assertion.collectionHash.match"
                | "assertion.dataHash.malformed"
                | "assertion.bmffHash.malformed"
                | "assertion.boxesHash.malformed"
                | "assertion.multipleHardBindings"
                | "assertion.missing"
                | "assertion.undeclared"
                | "assertion.inaccessible"
                | "assertion.required.missing"
                | "assertion.json.invalid"
                | "assertion.cbor.invalid"
                | "claim.malformed"
                | "claim.missing"
                | "claim.multiple"
                | "claim.hardBindings.missing"
                | "claim.required.missing"
                | "claim.cbor.invalid"
                | "manifest.inaccessible"
                | "manifest.unknownProvenance"
                | "manifest.unreferenced"
                | "manifest.update.invalid"
                | "manifest.compressed.invalid"
                | "ingredient.manifest.validated"
                | "ingredient.unknownProvenance"
                | "ingredient.claimSignature.validated"
                | "ingredient.hashedURI.mismatch"
                | "timeStamp.validated"
                | "timeStamp.trusted"
                | "timeStamp.mismatch"
                | "timeStamp.malformed"
                | "timeStamp.outsideValidity"
                | "timeStamp.untrusted"
                | "algorithm.deprecated"
                | "algorithm.unsupported"
                | "timeOfSigning.insideValidity"
                | "general.error"
        ) {
            codes.insert(entry.code().into());
        } else {
            *unknown += 1;
        }
    }
}

fn supported_mime(data: &[u8], format: Format) -> Option<&'static str> {
    match format {
        Format::Jpeg => Some("image/jpeg"),
        Format::Png => Some("image/png"),
        Format::Pdf => Some("application/pdf"),
        Format::Text => Some("text/plain"),
        Format::Wav => Some("audio/wav"),
        _ => bmff_mime(data),
    }
}

fn bmff_mime(data: &[u8]) -> Option<&'static str> {
    if data.len() < 16 || &data[4..8] != b"ftyp" {
        return None;
    }
    let size = u32::from_be_bytes(data[..4].try_into().ok()?) as usize;
    if size < 16 || size > data.len() || !size.is_multiple_of(4) {
        return None;
    }
    let brands = || {
        std::iter::once(&data[8..12]).chain(
            data[16..size]
                .as_chunks::<4>()
                .0
                .iter()
                .map(|brand| brand.as_slice()),
        )
    };
    if brands().any(|brand| matches!(brand, b"avif" | b"avis")) {
        Some("image/avif")
    } else if brands().any(|brand| {
        matches!(
            brand,
            b"heic" | b"heix" | b"hevc" | b"hevx" | b"mif1" | b"msf1"
        )
    }) {
        Some("image/heic")
    } else if &data[8..12] == b"qt  " {
        Some("video/quicktime")
    } else if brands().any(|brand| {
        matches!(
            brand,
            b"isom" | b"iso2" | b"iso4" | b"iso5" | b"iso6" | b"mp41" | b"mp42" | b"M4V "
        )
    }) {
        Some("video/mp4")
    } else {
        None
    }
}

// FVPROV1 41781 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI3MWMyMjUyYjA0NWY2NjJkOGQ4NTZhMThiMDQ1ZGRkYzFjODIzNjg5MjMzMzZjZDVmYTQxNzYzZjRlOWUwNTZkIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS40IiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuNCIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL3Byb3ZlbmFuY2UucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiIyMWNjMzc5ZTdlMjI1ZTVlN2RlMDgzZDc5YjJhYWYyMjJiNzZhYjYxYjQxNGU4M2IxYTNmMDhmNGRhYTk0MmEwZjJiNWE4NmNhMDE3Yzc1ODg0NTkzZjYyOGQ0NjY0NTY5MTdjMzhmZGMzMTZlYWM0MDZjMzA4MGFiYTM5NDMwYyJ9XX1d FVPROV1-END
