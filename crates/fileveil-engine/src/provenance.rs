// SPDX-License-Identifier: MPL-2.0
//! Offline C2PA validation over an already bounded file snapshot.
//!
//! Only fixed status codes, algorithm names and structural counts leave the SDK.
//! Manifest values, credential subjects, URLs and SDK error messages stay private.
use std::{collections::BTreeSet, io::Cursor};

use c2pa::{Context, Reader, ValidationState, validation_results::StatusCodes};
use fileveil_core::{Error, Format, Limits, Result, digest};
use serde::{Deserialize, Serialize};
use serde_json::json;

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
        verified_formats: vec!["jpeg".into(), "png".into()],
        additional_reader_formats: vec!["heif".into(), "avif".into(), "mp4".into(), "mov".into()],
        network_enabled: false,
        availability_reason: "offline_cryptographic_reader".into(),
    }];
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
        }
    }
}

/// Validates JPEG, PNG and recognized ISO BMFF assets without network access.
/// A successful absence result means this SDK found no embedded manifest or remote reference.
pub fn inspect(data: &[u8], format: Format, limits: &Limits) -> Result<Option<ProvenanceReport>> {
    inspect_with_trust(data, format, limits, None)
}

/// Uses an explicitly supplied local PEM trust bundle. The bundle is never fetched.
/// The caller owns loading and authorizing the trust file before calling this API.
pub fn inspect_with_trust(
    data: &[u8],
    format: Format,
    limits: &Limits,
    trust_anchors_pem: Option<&str>,
) -> Result<Option<ProvenanceReport>> {
    if data.len() as u64 > limits.max_file_bytes {
        return Err(Error::Blocked(
            "C2PA input exceeds the file size limit".into(),
        ));
    }
    let Some(mime) = supported_mime(data, format) else {
        return Ok(None);
    };
    let trust_anchors_pem = trust_anchors_pem.filter(|pem| !pem.is_empty());
    if trust_anchors_pem.is_some_and(|pem| pem.len() > limits.max_metadata_bytes) {
        return Err(Error::Blocked(
            "C2PA trust bundle exceeds the metadata limit".into(),
        ));
    }
    if let Some(pem) = trust_anchors_pem {
        validate_trust_bundle(pem, limits)?;
    }

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
            return Ok(Some(ProvenanceReport::unreadable(
                ManifestPresence::Unreadable,
                "fileveil.c2pa.container_unreadable",
            )));
        }
    };

    let context = offline_context(limits, trust_anchors_pem)?;
    let reader = match Reader::from_context(context).with_stream(mime, Cursor::new(data)) {
        Ok(reader) => reader,
        Err(c2pa::Error::JumbfNotFound | c2pa::Error::NotFound) if !embedded => return Ok(None),
        Err(c2pa::Error::RemoteManifestUrl(_) | c2pa::Error::RemoteManifestFetch(_)) => {
            return Ok(Some(ProvenanceReport::unreadable(
                ManifestPresence::RemoteReference,
                "fileveil.c2pa.remote_manifest_disabled",
            )));
        }
        Err(_) => {
            return Ok(Some(ProvenanceReport::unreadable(
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
    Ok(Some(report))
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
