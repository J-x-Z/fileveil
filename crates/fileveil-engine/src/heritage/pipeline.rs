// SPDX-License-Identifier: MPL-2.0
//! Shared read-only audits and verified new-copy Heritage operations.
use super::{container, legacy, robust, signing};
use crate::{Snapshot, ensure_new_artifact, inspect_snapshot, os, output_directory, publish};
use fileveil_core::{Error, Format, Limits, Outcome, Policy, Report, Result, digest};
use image::{DynamicImage, ImageEncoder, codecs::jpeg::JpegEncoder, imageops::FilterType};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use signing::{
    RecordBody, RecordKind, SignMode, SignedRecord, SigningKey, TrustStore, VerificationState,
};
use std::{
    borrow::Cow,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HeritageAction {
    #[default]
    Detect,
    Mark,
    Clean,
    Verify,
    Trace,
    Lab,
    C2paMark,
    Checkpoint,
    EvidenceExport,
    EvidenceVerify,
    TimestampQuery,
    TimestampVerify,
    TransferPrepare,
    TransferAccept,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MarkSettings {
    pub work_id: String,
    pub copy_id: String,
    pub signature_v2: bool,
    pub watermark_version: u8,
    pub rotation_to_key_id: Option<String>,
    pub transformation: Option<signing::Transformation>,
    pub author: String,
    pub edition: String,
    pub version: String,
    pub created_at: String,
    pub kind: RecordKind,
    pub mode: SignMode,
    pub transfer_to_key_id: Option<String>,
    pub issuer_threshold: u16,
    pub robust: bool,
    pub strength: u8,
}
impl Default for MarkSettings {
    fn default() -> Self {
        Self {
            work_id: String::new(),
            copy_id: String::new(),
            signature_v2: false,
            watermark_version: 1,
            rotation_to_key_id: None,
            transformation: None,
            author: String::new(),
            edition: String::new(),
            version: "1".into(),
            created_at: String::new(),
            kind: RecordKind::Create,
            mode: SignMode::SelfSign,
            transfer_to_key_id: None,
            issuer_threshold: 1,
            robust: false,
            strength: robust::DEFAULT_STRENGTH,
        }
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HeritageRequest {
    pub action: HeritageAction,
    pub mark: MarkSettings,
    pub key_paths: Vec<PathBuf>,
    pub key_refs: Vec<super::key_store::KeyStoreRef>,
    pub watermark_key: Option<PathBuf>,
    pub watermark_key_ref: Option<super::key_store::KeyStoreRef>,
    pub clean_metadata: bool,
    pub max_pixel_mse: Option<f64>,
    pub media_quality: Option<u8>,
    pub checkpoints: Vec<PathBuf>,
    pub checkpoint_anchors: Option<PathBuf>,
    pub timestamp_response: Option<PathBuf>,
    pub timestamp_query: Option<PathBuf>,
    pub timestamp_roots: Option<PathBuf>,
    pub trust_store: Option<PathBuf>,
    pub c2pa_trust_roots: Option<PathBuf>,
    pub previous: Option<PathBuf>,
    pub reference: Option<PathBuf>,
    pub controls: Vec<PathBuf>,
    pub disclose_identifiers: bool,
    pub disclose_claims: bool,
    pub clean_signal: bool,
    pub remove_c2pa: bool,
    pub certificate: Option<PathBuf>,
    pub private_key: Option<PathBuf>,
}
impl HeritageRequest {
    pub fn writes_file(&self) -> bool {
        matches!(
            self.action,
            HeritageAction::Mark
                | HeritageAction::Clean
                | HeritageAction::C2paMark
                | HeritageAction::Checkpoint
                | HeritageAction::EvidenceExport
                | HeritageAction::TimestampQuery
                | HeritageAction::TransferPrepare
                | HeritageAction::TransferAccept
        )
    }
    pub fn policy(&self) -> Policy {
        if (matches!(self.action, HeritageAction::Mark | HeritageAction::C2paMark)
            && self.mark.robust)
            || (self.action == HeritageAction::Clean && self.clean_signal)
        {
            Policy::Research
        } else {
            Policy::Safe
        }
    }
    pub fn signing_paths(&self) -> Vec<&Path> {
        self.key_paths
            .iter()
            .map(PathBuf::as_path)
            .chain(self.private_key.iter().map(PathBuf::as_path))
            .chain(self.watermark_key.iter().map(PathBuf::as_path))
            .collect()
    }
    pub fn auxiliary_paths_mut(&mut self) -> Vec<&mut PathBuf> {
        self.key_paths
            .iter_mut()
            .chain(self.watermark_key.iter_mut())
            .chain(self.checkpoints.iter_mut())
            .chain(self.checkpoint_anchors.iter_mut())
            .chain(self.timestamp_response.iter_mut())
            .chain(self.timestamp_query.iter_mut())
            .chain(self.timestamp_roots.iter_mut())
            .chain(self.trust_store.iter_mut())
            .chain(self.c2pa_trust_roots.iter_mut())
            .chain(self.previous.iter_mut())
            .chain(self.reference.iter_mut())
            .chain(self.controls.iter_mut())
            .chain(self.certificate.iter_mut())
            .chain(self.private_key.iter_mut())
            .collect()
    }
    pub fn digest(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(self).map_err(|_| {
            Error::Input("Invalid Heritage request".into())
        })?))
    }
    pub fn validate(&self) -> Result<()> {
        if self.key_paths.len().saturating_add(self.key_refs.len()) > signing::MAX_SIGNERS
            || self.controls.len() > 8
            || self.checkpoints.len() > 16
        {
            return Err(Error::Input(
                "Heritage accepts at most 32 signers and 8 controls".into(),
            ));
        }
        if !matches!(
            self.action,
            HeritageAction::Mark
                | HeritageAction::Checkpoint
                | HeritageAction::EvidenceExport
                | HeritageAction::TransferPrepare
                | HeritageAction::TransferAccept
        ) && (!self.key_paths.is_empty() || !self.key_refs.is_empty() || self.previous.is_some())
        {
            return Err(Error::Input(
                "Signing keys and prior history require the Mark action".into(),
            ));
        }
        if self.action != HeritageAction::C2paMark
            && (self.certificate.is_some() || self.private_key.is_some())
        {
            return Err(Error::Input(
                "Certificate credentials require the C2PA Mark action".into(),
            ));
        }
        if !matches!(self.mark.watermark_version, 1 | 2)
            || self.media_quality.is_some_and(|q| !(1..=100).contains(&q))
            || self
                .max_pixel_mse
                .is_some_and(|v| !v.is_finite() || !(0.0..=65025.0).contains(&v))
        {
            return Err(Error::Input(
                "Invalid watermark version, quality or pixel-error budget".into(),
            ));
        }
        if self.watermark_key.is_some() && self.watermark_key_ref.is_some() {
            return Err(Error::Input("Select one watermark-key source".into()));
        }
        Ok(())
    }
}

fn watermark_key(request: &HeritageRequest) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>> {
    if let Some(path) = &request.watermark_key {
        return Ok(Some(SigningKey::load(path)?.derive_watermark_key()));
    }
    request
        .watermark_key_ref
        .as_ref()
        .map(|reference| super::key_store::load(reference).map(|key| key.derive_watermark_key()))
        .transpose()
}

pub(crate) fn artifact_attributes(
    request: &HeritageRequest,
    attributes: &[os::Attribute],
) -> Vec<os::Attribute> {
    if matches!(
        request.action,
        HeritageAction::Checkpoint
            | HeritageAction::EvidenceExport
            | HeritageAction::TimestampQuery
            | HeritageAction::TransferPrepare
            | HeritageAction::TransferAccept
    ) {
        attributes
            .iter()
            .filter(|attribute| {
                let name = attribute.name.to_string_lossy();
                name == "com.apple.quarantine"
                    || name.eq_ignore_ascii_case(":Zone.Identifier:$DATA")
            })
            .cloned()
            .collect()
    } else {
        attributes.to_vec()
    }
}

pub fn keygen(output: &Path) -> Result<Report> {
    let key = SigningKey::generate()?;
    key.save_new(output)?;
    let mut report = Report::new("heritage_keygen", Format::Unknown);
    report.result = Outcome::VerifiedWithinScope;
    report.advanced = Some(
        json!({"heritage":{"public_key":key.public_key(),"private_key_saved":true,"scope":"local_owner_only_ed25519_key"}}),
    );
    report.output_name = output.file_name().map(|v| v.to_string_lossy().into_owned());
    Ok(report)
}

pub(crate) fn detect_format(data: &[u8], hint: &Path, limits: &Limits) -> Result<Format> {
    let mut format = if data.starts_with(b"PK") {
        fileveil_formats::inspect(data, hint, limits)?.format
    } else {
        fileveil_formats::identify(data, hint)
    };
    if matches!(format, Format::Unknown | Format::Text | Format::Html)
        && super::source::supported_path(hint)
    {
        super::source::validate_path(data, hint)?;
        format = Format::Text;
    }
    if !container::supported(format) {
        return Err(Error::Unsupported(
            "Watermark records support JPEG, PNG, PDF, Office, ISO media and supported UTF-8 source languages".into(),
        ));
    }
    Ok(format)
}
fn old_report(data: &[u8], format: Format, limits: &Limits, disclose: bool) -> Result<Value> {
    if matches!(format, Format::Jpeg | Format::Png | Format::Docx) {
        serde_json::to_value(legacy::decode(data, limits, disclose)?)
            .map_err(|_| Error::Io("Could not encode legacy evidence".into()))
    } else {
        Ok(json!({"status":"unsupported","locations":[],"scope":"legacy_reference_formats_only"}))
    }
}
fn old_clean(data: &[u8], format: Format, limits: &Limits) -> Result<Vec<u8>> {
    if matches!(format, Format::Jpeg | Format::Png | Format::Docx)
        && legacy::detect(data, limits)?.status != legacy::LegacyStatus::NotDetected
    {
        legacy::clean(data, limits)
    } else {
        Ok(data.to_vec())
    }
}
fn history(bytes: Option<&[u8]>) -> Result<Vec<SignedRecord>> {
    bytes
        .map(signing::parse_records)
        .transpose()
        .map(Option::unwrap_or_default)
}
fn trust(request: &HeritageRequest, limits: &Limits) -> Result<TrustStore> {
    let Some(path) = &request.trust_store else {
        return Ok(TrustStore::default());
    };
    let mut bounded = limits.clone();
    bounded.max_file_bytes = bounded.max_file_bytes.min(64 * 1024);
    let snapshot = Snapshot::open(path, &bounded)?;
    if snapshot.bytes.len() > 64 * 1024 {
        return Err(Error::Blocked("Heritage trust file exceeds 64 KiB".into()));
    }
    let store = serde_json::from_slice(&snapshot.bytes)
        .map_err(|_| Error::Input("Invalid Heritage trust store JSON".into()))?;
    if !snapshot.unchanged(path, limits)? {
        return Err(Error::Blocked("Heritage trust file changed".into()));
    }
    Ok(store)
}
fn reference_history(path: &Path, limits: &Limits) -> Result<Vec<SignedRecord>> {
    let snapshot = Snapshot::open(path, limits)?;
    let records = if !super::source::supported_path(path)
        && snapshot
            .bytes
            .iter()
            .copied()
            .find(|b| !b.is_ascii_whitespace())
            == Some(b'{')
    {
        let package = super::custody::parse_evidence(&snapshot.bytes)?;
        let verified =
            super::custody::verify_evidence(&package, &TrustStore::default(), &[], None)?;
        if verified.package_signature != VerificationState::Valid
            || verified.chain.signature != VerificationState::Valid
            || verified.chain.chain != VerificationState::Valid
        {
            return Err(Error::Verification(
                "Previous evidence package is invalid".into(),
            ));
        }
        package.body.records
    } else {
        let format = detect_format(&snapshot.bytes, path, limits)?;
        let extracted = container::extract(&snapshot.bytes, format)?;
        history(extracted.manifest.as_deref())?
    };
    if records.is_empty() {
        return Err(Error::Input(
            "Selected reference has no Heritage history".into(),
        ));
    }
    if !snapshot.unchanged(path, limits)? {
        return Err(Error::Blocked("Heritage reference changed".into()));
    }
    Ok(records)
}
fn claim_report(records: &[SignedRecord], disclose: bool) -> Value {
    Value::Array(
        records
            .iter()
            .map(|record| {
                let body = &record.body;
                let transformation = body.transformation.as_ref().map(|value| {
                    json!({
                        "source_sha256":value.source_sha256,
                        "source_format_sha256":digest(value.source_format.as_bytes()),
                        "target_format_sha256":digest(value.target_format.as_bytes()),
                        "operation_sha256":digest(value.operation.as_bytes())
                    })
                });
                let mut item = json!({
                    "sequence":body.sequence,
                    "kind":body.kind,
                    "mode":body.mode,
                    "work_id_sha256":digest(body.work_id.as_bytes()),
                    "author_declared":!body.author.is_empty(),
                    "author_sha256":digest(body.author.as_bytes()),
                    "edition_sha256":digest(body.edition.as_bytes()),
                    "version":body.version,
                    "parent_version":body.parent_version,
                    "copy_id_sha256":body.copy_id.as_ref().map(|value|digest(value.as_bytes())),
                    "rotation_to_key_id":body.rotation_to_key_id,
                    "transformation":transformation,
                    "actor_key_id":body.actor_key_id,
                    "transfer_to_key_id":body.transfer_to_key_id,
                    "previous_record_sha256":body.previous_record_sha256,
                    "content_sha256":body.content_sha256,
                    "record_sha256":signing::record_hash(record).ok()
                });
                if disclose {
                    item["work_id"] = json!(body.work_id);
                    item["author"] = json!(body.author);
                    item["edition"] = json!(body.edition);
                    item["created_at"] = json!(body.created_at);
                    item["copy_id"] = json!(body.copy_id);
                    item["transformation"] = json!(body.transformation);
                }
                item
            })
            .collect(),
    )
}

fn signal(
    data: &[u8],
    format: Format,
    request: &HeritageRequest,
    limits: &Limits,
) -> Result<Value> {
    let key = watermark_key(request)?;
    let evidence = crate::watermark_engine::inspect(data, format, key.as_deref(), limits)?;
    let mut primary = evidence["primary"].clone();
    primary["detections"] = evidence["detections"].clone();
    Ok(primary)
}

fn embed_pixels(
    base: &[u8],
    format: Format,
    request: &HeritageRequest,
    key: Option<&[u8; 32]>,
    limits: &Limits,
) -> Result<(Vec<u8>, Value)> {
    if matches!(format, Format::Heic | Format::Avif) {
        fileveil_formats::bmff::validate_pixel_rewrite(base, format, limits)?;
    }
    let rendered = crate::media_pixels::decode_rendered(base, format, limits)?;
    let image = &rendered.image;
    let (marked, _) = crate::watermark_engine::embed(
        image,
        &request.mark.work_id,
        &request.mark.copy_id,
        key,
        request.mark.watermark_version,
        request.mark.strength,
        limits,
    )?;
    let base = if matches!(format, Format::Heic | Format::Avif) {
        crate::media_pixels::encode(
            &marked,
            format,
            request.media_quality.unwrap_or(95),
            rendered.icc_profile.as_deref(),
            limits,
        )?
    } else {
        encode(
            &marked,
            format,
            request.media_quality.unwrap_or(95),
            base,
            limits,
        )?
    };
    drop(marked);
    drop(rendered);
    let decoded = crate::media_pixels::decode(&base, format, limits)?;
    let evidence = crate::watermark_engine::inspect_pixels(&decoded, key, limits)?;
    let detected = &evidence["primary"];
    let expected = if request.mark.watermark_version == 2 {
        super::robust_v2::work_id_digest(&request.mark.work_id)?
    } else {
        robust::work_id_digest(&request.mark.work_id)?
    };
    let copy_matches = request.mark.watermark_version != 2
        || detected["copy_id_digest"] == super::robust_v2::copy_id_digest(&request.mark.copy_id)?;
    if detected["frame_valid"] != true || detected["work_id_digest"] != expected || !copy_matches {
        return Err(Error::Verification(
            "Encoded watermark failed its blind detector".into(),
        ));
    }
    Ok((base, evidence))
}

fn encode(
    image: &DynamicImage,
    format: Format,
    quality: u8,
    source: &[u8],
    limits: &Limits,
) -> Result<Vec<u8>> {
    if matches!(format, Format::Heic | Format::Avif) {
        return crate::media_pixels::encode(image, format, quality, None, limits);
    }
    let profile = if source.starts_with(b"\x89PNG\r\n\x1a\n") || source.starts_with(&[0xff, 0xd8]) {
        crate::image_processing::decode_profile(source, limits)?
    } else {
        None
    };
    if format == Format::Png {
        return crate::image_processing::encode_png(image, source, profile);
    }
    let mut bytes = Vec::new();
    match format {
        Format::Jpeg => {
            let rgb = image
                .as_rgb8()
                .map_or_else(|| Cow::Owned(image.to_rgb8()), Cow::Borrowed);
            let mut encoder = JpegEncoder::new_with_quality(&mut bytes, quality);
            if let Some(profile) = profile {
                encoder.set_icc_profile(profile).map_err(|_| {
                    Error::Blocked("Heritage JPEG cannot preserve the ICC profile".into())
                })?;
            }
            encoder
                .encode_image(rgb.as_ref())
                .map_err(|_| Error::Io("Could not encode Heritage JPEG".into()))?;
        }
        _ => {
            return Err(Error::Unsupported(
                "Pixel Heritage operations require JPEG or PNG".into(),
            ));
        }
    }
    Ok(bytes)
}
fn check_write_safety(data: &[u8], format: Format, input: &Path, limits: &Limits) -> Result<()> {
    let inspected = inspect_snapshot(data, input, limits)?;
    if !inspected.blockers.is_empty() {
        return Err(Error::Blocked(inspected.blockers.join(". ")));
    }
    if format == Format::Pdf
        && crate::pdf::inspect(data, limits)?.details["safe_rewrite_allowed"] == false
    {
        return Err(Error::Blocked("Signed or protected PDF content cannot be marked without an explicit prior signature-removal operation".into()));
    }
    Ok(())
}

pub fn run(
    input: &Path,
    output: Option<&Path>,
    request: &HeritageRequest,
    limits: &Limits,
) -> Result<Report> {
    request.validate()?;
    if matches!(
        request.action,
        HeritageAction::Checkpoint
            | HeritageAction::EvidenceExport
            | HeritageAction::EvidenceVerify
            | HeritageAction::TimestampQuery
            | HeritageAction::TimestampVerify
            | HeritageAction::TransferPrepare
            | HeritageAction::TransferAccept
    ) {
        return super::provenance_ops::run(input, output, request, limits);
    }
    let snapshot = Snapshot::open(input, limits)?;
    let format = if request.action == HeritageAction::Clean
        && request.clean_metadata
        && !super::source::supported_path(input)
    {
        fileveil_formats::inspect(&snapshot.bytes, input, limits)?.format
    } else {
        detect_format(&snapshot.bytes, input, limits)?
    };
    let extracted = if container::supported(format) {
        container::extract(&snapshot.bytes, format)?
    } else {
        container::Extracted {
            base: snapshot.bytes.clone(),
            manifest: None,
            carrier: "standard_metadata_only",
        }
    };
    inspect_snapshot(&extracted.base, input, limits)?;
    let legacy_before = old_report(
        &extracted.base,
        format,
        limits,
        request.disclose_identifiers,
    )?;
    let store = trust(request, limits)?;
    let records = history(extracted.manifest.as_deref());
    let mut report = Report::new("heritage", format);
    report.policy = request.policy();
    report.input_sha256 = Some(digest(&snapshot.bytes));
    let mut details = json!({"action":request.action,"request_sha256":request.digest()?,"carrier":extracted.carrier,"legacy":legacy_before,"manifest_present":extracted.manifest.is_some(),"offline":true,"personal_identity_authenticated":false});
    if !request.writes_file() {
        let mut root_limits = limits.clone();
        root_limits.max_file_bytes = root_limits.max_file_bytes.min(256 * 1024);
        let roots = request
            .c2pa_trust_roots
            .as_ref()
            .map(|path| Snapshot::open(path, &root_limits))
            .transpose()?;
        let pem = roots
            .as_ref()
            .map(|snapshot| {
                std::str::from_utf8(&snapshot.bytes)
                    .map_err(|_| Error::Input("C2PA trust roots must be UTF-8 PEM".into()))
            })
            .transpose()?;
        let credentials =
            crate::provenance::inspect_with_trust(&snapshot.bytes, format, limits, pem)?;
        report.provenance = credentials
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| Error::Io("Could not serialize Heritage C2PA verification".into()))?;
        if report.provenance.as_ref().is_some_and(|value| {
            ["signature", "asset_binding", "manifest_validation"]
                .iter()
                .any(|field| value[field] == "invalid")
        }) {
            report.result = Outcome::Failed;
        }
        if let Some((roots, path)) = roots.as_ref().zip(request.c2pa_trust_roots.as_ref())
            && !roots.unchanged(path, &root_limits)?
        {
            return Err(Error::Blocked(
                "C2PA trust roots changed during verification".into(),
            ));
        }
    }
    if request.action == HeritageAction::Lab {
        details["lab"] = attack_lab(&snapshot.bytes, format, request, limits)?;
    } else if !request.writes_file() {
        let records = records?;
        let verification = signing::verify_chain(&records, &digest(&extracted.base), &store)?;
        details["verification"] = serde_json::to_value(&verification)
            .map_err(|_| Error::Io("Could not serialize signature evidence".into()))?;
        details["records"] = claim_report(&records, request.disclose_claims);
        if !request.checkpoints.is_empty() || request.timestamp_response.is_some() {
            let attachments = super::provenance_ops::assess_attachments(&records, request, limits)?;
            let invalid_checkpoint =
                attachments["external_checkpoints"]
                    .as_array()
                    .is_some_and(|rows| {
                        rows.iter().any(|row| {
                            row["signature"] == "invalid" || row["history_binding"] == "invalid"
                        })
                    });
            if invalid_checkpoint || attachments["timestamp"]["verification"] == "invalid" {
                report.result = Outcome::Failed;
            }
            details["external_provenance"] = attachments;
        }
        details["robust"] = signal(&extracted.base, format, request, limits)?;
        if report.provenance.is_some()
            && let Some(association) =
                super::c2pa_mark::extract_association(&snapshot.bytes, format, limits)?
        {
            let pixel = &details["robust"];
            let linked = if pixel["method_id"] == super::robust_v2::METHOD_ID
                && pixel["frame_valid"] == true
            {
                Some(
                    pixel["work_id_digest"] == association.work_id_digest
                        && association
                            .copy_id_digest
                            .as_deref()
                            .is_some_and(|copy| pixel["copy_id_digest"] == copy)
                        && association
                            .watermark
                            .as_ref()
                            .is_some_and(|mark| pixel["key_id"] == mark.key_id),
                )
            } else {
                None
            };
            if linked == Some(false) {
                report.result = Outcome::Failed;
            }
            details["c2pa_association"] = json!({"credential":association,"pixel_reference_match":linked,"scope":"signed_claim_and_keyed_pixel_payload_separately_verified"});
        }
        if let Some(reference) = &request.reference {
            let reference = reference_history(reference, limits)?;
            let reference_body = &reference.last().expect("nonempty reference").body;
            let source_record = if format == Format::Text
                && verification.signature == VerificationState::Valid
                && verification.chain == VerificationState::Valid
            {
                records.last()
            } else {
                None
            };
            let expected = if details["robust"]["method_id"] == super::robust_v2::METHOD_ID {
                super::robust_v2::work_id_digest(&reference_body.work_id)?
            } else {
                robust::work_id_digest(&reference_body.work_id)?
            };
            let verification = signing::verify_chain(&reference, &digest(&extracted.base), &store)?;
            let work_match = if let Some(record) = source_record {
                record.body.work_id == reference_body.work_id
            } else {
                details["robust"]["frame_valid"] == true
                    && details["robust"]["work_id_digest"] == expected
            };
            let copy_match = if let Some(record) = source_record {
                reference_body
                    .copy_id
                    .as_ref()
                    .map(|copy| record.body.copy_id.as_ref() == Some(copy))
            } else if details["robust"]["method_id"] == super::robust_v2::METHOD_ID {
                reference_body
                    .copy_id
                    .as_deref()
                    .map(super::robust_v2::copy_id_digest)
                    .transpose()?
                    .map(|expected| details["robust"]["copy_id_digest"] == expected)
            } else {
                None
            };
            details["work_digest_match"] = json!(work_match);
            details["copy_digest_match"] = json!(copy_match);
            details["reference_match_scope"] = json!(if source_record.is_some() {
                "signed_source_work_and_optional_copy"
            } else if copy_match.is_some() {
                "work_and_copy"
            } else {
                "work_only"
            });
            details["trace_reference_match"] = json!(
                work_match
                    && copy_match != Some(false)
                    && verification.signature == VerificationState::Valid
                    && verification.chain == VerificationState::Valid
            );
            details["reference_verification"] = json!(verification);
            details["reference_records"] = claim_report(&reference, request.disclose_claims);
        }
        if verification.signature == VerificationState::Invalid
            || verification.chain == VerificationState::Invalid
            || (request.action == HeritageAction::Verify
                && verification.content_binding == VerificationState::Invalid)
        {
            report.result = Outcome::Failed;
        }
    } else {
        if snapshot
            .attributes
            .iter()
            .any(|a| a.name == "com.apple.ResourceFork")
        {
            return Err(Error::Blocked(
                "Resource forks require a content-preserving Heritage backend".into(),
            ));
        }
        let mut base = extracted.base;
        if request.remove_c2pa {
            let present = crate::provenance::inspect(&base, format, limits)?.is_some();
            details["c2pa_present_before"] = json!(present);
            if present {
                base = match format {
                    Format::Pdf => crate::pdf::sanitize_with_provenance_removal(
                        &base,
                        limits,
                        &fileveil_core::PdfOptions::default(),
                    )?,
                    Format::Jpeg | Format::Png => crate::provenance::remove(&base, format, limits)?,
                    _ => {
                        return Err(Error::Unsupported(
                            "C2PA removal is unavailable for this Heritage carrier".into(),
                        ));
                    }
                };
                if crate::provenance::inspect(&base, format, limits)?.is_some() {
                    return Err(Error::Verification(
                        "C2PA structures remain after explicit removal".into(),
                    ));
                }
                details["c2pa_removed"] = json!(true);
            }
        }
        check_write_safety(&base, format, input, limits)?;
        let transformed = match request.action {
            HeritageAction::Mark => {
                let mut keys: Vec<_> = request
                    .key_paths
                    .iter()
                    .map(|path| SigningKey::load(path))
                    .collect::<Result<_>>()?;
                for reference in &request.key_refs {
                    keys.push(super::key_store::load(reference)?);
                }
                if keys.is_empty() {
                    return Err(Error::Input(
                        "Mark requires at least one explicit local Ed25519 signing key".into(),
                    ));
                }
                let mut records = match &request.previous {
                    Some(path) => reference_history(path, limits)?,
                    None => records?,
                };
                if request.mark.robust {
                    let explicit = watermark_key(request)?;
                    let derived = if request.mark.watermark_version == 2 && explicit.is_none() {
                        Some(keys[0].derive_watermark_key())
                    } else {
                        None
                    };
                    let key = explicit.as_deref().or(derived.as_deref());
                    let (encoded, evidence) = embed_pixels(&base, format, request, key, limits)?;
                    base = encoded;
                    let detected = &evidence["primary"];
                    details["robust"] = detected.clone();
                    details["watermarks"] = evidence;
                }
                let mut body = RecordBody::new(
                    digest(&base),
                    request.mark.work_id.clone(),
                    request.mark.author.clone(),
                    request.mark.version.clone(),
                    if request.mark.created_at.is_empty() {
                        format!(
                            "unix:{}",
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs()
                        )
                    } else {
                        request.mark.created_at.clone()
                    },
                    keys[0].public_key().key_id,
                );
                if request.mark.signature_v2 {
                    body.schema = signing::SCHEMA_V2.into();
                    body.copy_id = Some(request.mark.copy_id.clone());
                    body.rotation_to_key_id = request.mark.rotation_to_key_id.clone();
                    body.transformation = request.mark.transformation.clone();
                }
                body.kind = request.mark.kind;
                body.mode = request.mark.mode;
                body.edition = request.mark.edition.clone();
                body.transfer_to_key_id = request.mark.transfer_to_key_id.clone();
                if body.mode == SignMode::NatiSign {
                    body.issuer_policy = Some(signing::IssuerPolicy {
                        threshold: request.mark.issuer_threshold,
                        allowed_key_ids: keys.iter().map(|key| key.public_key().key_id).collect(),
                    });
                }
                let refs: Vec<_> = keys.iter().collect();
                let current = signing::append_record(&records, body, &refs)?;
                records.push(current);
                let verification = signing::verify_chain(&records, &digest(&base), &store)?;
                details["verification"] = json!(verification);
                details["records"] = claim_report(&records, request.disclose_claims);
                let encoded = signing::canonical_records(&records)?;
                let marked = if format == Format::Text {
                    super::source::embed(&base, input, &encoded)?
                } else {
                    container::embed(&base, format, &encoded)?
                };
                let parsed = container::extract(&marked, format)?;
                if parsed.base != base || history(parsed.manifest.as_deref())? != records {
                    return Err(Error::Verification(
                        "Heritage carrier round trip failed".into(),
                    ));
                }
                marked
            }
            HeritageAction::Clean => {
                let clean = old_clean(&base, format, limits)?;
                details["legacy_verification"] =
                    if matches!(format, Format::Jpeg | Format::Png | Format::Docx)
                        && legacy::detect(&base, limits)?.status
                            != legacy::LegacyStatus::NotDetected
                    {
                        json!(legacy::verify(&base, &clean, limits)?)
                    } else {
                        Value::Null
                    };
                base = clean;
                if request.clean_metadata
                    && format == Format::Text
                    && (super::source::supported_path(input) || extracted.manifest.is_some())
                {
                    details["standard_metadata_cleaned"] = json!(false);
                    details["source_content_preserved"] = json!(true);
                } else if request.clean_metadata {
                    let inspection = inspect_snapshot(&base, input, limits)?;
                    let sanitized = if format == Format::Pdf {
                        crate::pdf::sanitize(&base, limits)?
                    } else {
                        fileveil_formats::sanitize(&base, format, limits)?
                    };
                    let after = inspect_snapshot(&sanitized, input, limits)?;
                    if format != Format::Pdf && inspection.content_digest != after.content_digest {
                        return Err(Error::Verification(
                            "Standard cleaning changed retained content".into(),
                        ));
                    }
                    details["standard_metadata_cleaned"] = json!(true);
                    base = sanitized;
                }
                if request.clean_signal {
                    if matches!(format, Format::Heic | Format::Avif) {
                        fileveil_formats::bmff::validate_pixel_rewrite(&base, format, limits)?;
                    }
                    let key = watermark_key(request)?;
                    let rendered = crate::media_pixels::decode_rendered(&base, format, limits)?;
                    let original = &rendered.image;
                    let (cleaned, evidence) =
                        crate::watermark_engine::clean(original, key.as_deref(), limits)?;
                    base = if matches!(format, Format::Heic | Format::Avif) {
                        crate::media_pixels::encode(
                            &cleaned,
                            format,
                            request.media_quality.unwrap_or(95),
                            rendered.icc_profile.as_deref(),
                            limits,
                        )?
                    } else {
                        encode(
                            &cleaned,
                            format,
                            request.media_quality.unwrap_or(95),
                            &base,
                            limits,
                        )?
                    };
                    drop(cleaned);
                    drop(rendered);
                    let decoded = crate::media_pixels::decode(&base, format, limits)?;
                    let checked =
                        crate::watermark_engine::inspect_pixels(&decoded, key.as_deref(), limits)?;
                    if checked["detections"].as_array().is_some_and(|rows| {
                        rows.iter()
                            .any(|r| r["frame_valid"] == true || r["status"] == "detected")
                    }) {
                        return Err(Error::Verification(
                            "A selected watermark still detects after encoded-copy cleaning".into(),
                        ));
                    }
                    details["robust"] = evidence["before"]["primary"].clone();
                    details["robust"]["detections"] = evidence["before"]["detections"].clone();
                    details["signal_processing"] = evidence;
                    details["robust_recheck"] = checked["primary"].clone();
                    details["robust_recheck"]["detections"] = checked["detections"].clone();
                    details["watermarks"] = checked;
                }

                if container::supported(format)
                    && container::extract(&base, format)?.manifest.is_some()
                {
                    return Err(Error::Verification(
                        "A nested Heritage manifest remains".into(),
                    ));
                }
                details["modern_manifest_removed"] = json!(extracted.manifest.is_some());
                base
            }
            HeritageAction::C2paMark => {
                if extracted.manifest.is_some() {
                    return Err(Error::Blocked("C2PA creation would invalidate the existing Heritage binding. Clean that credential explicitly before creating a new credential.".into()));
                }
                let certificate = request.certificate.as_deref().ok_or_else(|| {
                    Error::Input("C2PA creation requires a local ES256 PEM certificate".into())
                })?;
                let key = request.private_key.as_deref().ok_or_else(|| {
                    Error::Input("C2PA creation requires a local PEM private key".into())
                })?;
                let mut bounded = limits.clone();
                bounded.max_file_bytes = bounded
                    .max_file_bytes
                    .min(256 * 1024)
                    .min(limits.max_metadata_bytes as u64);
                let cert = Snapshot::open(certificate, &bounded)?;
                let claims = super::c2pa_mark::C2paMarkClaims {
                    title: request.mark.work_id.clone(),
                    author: request.mark.author.clone(),
                    work_id: request.mark.work_id.clone(),
                    edition: request.mark.edition.clone(),
                    version: request.mark.version.clone(),
                    asserted_time: request.mark.created_at.clone(),
                };
                let watermark_key = watermark_key(request)?;
                let mut association = None;
                if request.mark.robust {
                    if request.mark.watermark_version != 2 {
                        return Err(Error::Input(
                            "Linked C2PA pixel marking requires watermark protocol 2".into(),
                        ));
                    }
                    let (encoded, evidence) =
                        embed_pixels(&base, format, request, watermark_key.as_deref(), limits)?;
                    base = encoded;
                    let detected = &evidence["primary"];
                    association = Some(super::c2pa_mark::C2paWatermarkAssociation {
                        method_id: super::robust_v2::METHOD_ID.into(),
                        work_id_digest: super::robust_v2::work_id_digest(&request.mark.work_id)?,
                        copy_id_digest: super::robust_v2::copy_id_digest(&request.mark.copy_id)?,
                        key_id: detected["key_id"].as_str().unwrap_or_default().into(),
                    });
                    details["robust"] = detected.clone();
                    details["watermarks"] = evidence;
                }
                let signed = if request.mark.copy_id.is_empty() {
                    super::c2pa_mark::sign_bytes_with_key_path(
                        &base,
                        format,
                        &cert.bytes,
                        key,
                        &claims,
                        limits,
                    )?
                } else {
                    let context = super::c2pa_mark::C2paMarkContext {
                        copy_id: request.mark.copy_id.clone(),
                        watermark: association,
                    };
                    super::c2pa_mark::sign_bytes_with_key_path_v2(
                        &base,
                        format,
                        &cert.bytes,
                        key,
                        &claims,
                        &context,
                        limits,
                    )?
                };
                if request.mark.robust {
                    let recheck = crate::watermark_engine::inspect(
                        &signed.bytes,
                        format,
                        watermark_key.as_deref(),
                        limits,
                    )?;
                    if recheck["primary"]["frame_valid"] != true
                        || recheck["primary"]["work_id_digest"]
                            != super::robust_v2::work_id_digest(&request.mark.work_id)?
                        || recheck["primary"]["copy_id_digest"]
                            != super::robust_v2::copy_id_digest(&request.mark.copy_id)?
                    {
                        return Err(Error::Verification(
                            "C2PA signed copy failed its keyed pixel-watermark recheck".into(),
                        ));
                    }
                    details["robust_recheck"] = recheck["primary"].clone();
                    details["robust_recheck"]["detections"] = recheck["detections"].clone();
                }
                details["c2pa_association"] = json!(super::c2pa_mark::extract_association(
                    &signed.bytes,
                    format,
                    limits
                )?);
                if !cert.unchanged(certificate, limits)? {
                    return Err(Error::Blocked("C2PA certificate changed".into()));
                }
                report.provenance = Some(json!(signed.provenance));
                details["c2pa_manifest_sha256"] = json!(signed.manifest_sha256);
                signed.bytes
            }
            _ => return Err(Error::Input("Unsupported Heritage write action".into())),
        };
        if transformed.len() as u64 > limits.max_file_bytes {
            return Err(Error::Blocked(
                "Heritage output exceeds the input byte budget".into(),
            ));
        }
        let output_format = if container::supported(format) {
            detect_format(&transformed, input, limits)?
        } else {
            fileveil_formats::inspect(&transformed, input, limits)?.format
        };
        if output_format != format {
            return Err(Error::Verification("Heritage output format changed".into()));
        }
        let parsed = if container::supported(format) {
            container::extract(&transformed, format)?
        } else {
            container::Extracted {
                base: transformed.clone(),
                manifest: None,
                carrier: "standard_metadata_only",
            }
        };
        let verified_base = old_clean(&parsed.base, format, limits)?;
        inspect_snapshot(&verified_base, input, limits)?;
        drop(verified_base);
        drop(parsed);
        if format == Format::Pdf {
            inspect_snapshot(&transformed, input, limits)?;
            let display =
                crate::pdf::verify_heritage_display(&snapshot.bytes, &transformed, limits)?;
            if [
                "independent_page_count_equal",
                "independent_text_equal",
                "independent_render_equal",
            ]
            .iter()
            .any(|field| display[field] == false)
            {
                return Err(Error::Verification(
                    "Heritage PDF visible content changed".into(),
                ));
            }
            details["pdf_display"] = display;
        }
        report.integrity.parseable = true;
        if matches!(format, Format::Jpeg | Format::Png)
            || (matches!(format, Format::Heic | Format::Avif)
                && request.policy() == Policy::Research)
        {
            if matches!(format, Format::Jpeg | Format::Png)
                && crate::image_processing::decode_profile(&snapshot.bytes, limits)?
                    != crate::image_processing::decode_profile(&transformed, limits)?
            {
                return Err(Error::Verification(
                    "Heritage output changed the retained ICC profile".into(),
                ));
            }
            if format == Format::Png
                && crate::image_processing::color_chunks(&snapshot.bytes)?
                    != crate::image_processing::color_chunks(&transformed)?
            {
                return Err(Error::Verification(
                    "Heritage output changed PNG color or display records".into(),
                ));
            }
            details["color_metadata_preserved"] =
                json!(matches!(format, Format::Jpeg | Format::Png));
            let before = crate::media_pixels::decode(&snapshot.bytes, format, limits)?.into_rgba8();
            let after = crate::media_pixels::decode(&transformed, format, limits)?.into_rgba8();
            report.integrity.decodeable = Some(true);
            report.integrity.pixel_equal = Some(before == after);
            if before.dimensions() == after.dimensions() {
                let mse = before
                    .as_raw()
                    .iter()
                    .zip(after.as_raw())
                    .map(|(&a, &b)| (a as f64 - b as f64).powi(2))
                    .sum::<f64>()
                    / before.as_raw().len().max(1) as f64;
                details["pixel_mse_rgba8"] = json!(mse);
                if request.max_pixel_mse.is_some_and(|budget| mse > budget) {
                    return Err(Error::Verification(
                        "Processed copy exceeds the selected pixel-error budget".into(),
                    ));
                }
            }
            if request.policy() == Policy::Safe && report.integrity.pixel_equal != Some(true) {
                return Err(Error::Verification(
                    "Structural Heritage operation changed decoded pixels".into(),
                ));
            }
        }
        if matches!(
            format,
            Format::Heic | Format::Avif | Format::Mp4 | Format::Mov
        ) && request.policy() == Policy::Safe
        {
            let original_base = container::extract(&snapshot.bytes, format)?.base;
            let output_base = container::extract(&transformed, format)?.base;
            let encoded_equal =
                fileveil_formats::bmff::retained_media_digest(&original_base, format, limits)?
                    == fileveil_formats::bmff::retained_media_digest(&output_base, format, limits)?;
            if !encoded_equal {
                return Err(Error::Verification(
                    "Native media encoded samples or presentation fields changed".into(),
                ));
            }
            if request.action == HeritageAction::Clean
                && request.clean_metadata
                && !request.remove_c2pa
            {
                let checked =
                    fileveil_formats::bmff::verify(&original_base, &output_base, format, limits)?;
                if checked.result == Outcome::Failed
                    || checked.integrity.content_equal != Some(true)
                {
                    return Err(Error::Verification(
                        "Native media metadata reconstruction failed".into(),
                    ));
                }
                details["media_verification"] = json!({"result":checked.result,"integrity":checked.integrity,"warnings":checked.warnings});
            } else {
                details["media_verification"] = json!({"encoded_samples_and_presentation_equal":true,
                    "base_byte_equal":original_base==output_base,"scope":"retained_encoded_media_and_known_presentation_fields"});
            }
        }
        report.integrity.content_equal = if format == Format::Pdf
            && (request.action == HeritageAction::C2paMark || request.remove_c2pa)
        {
            None
        } else {
            Some(request.policy() == Policy::Safe)
        };
        let directory = output_directory(input, output);
        let mut temporary = tempfile::Builder::new()
            .prefix(".fileveil-heritage-")
            .tempfile_in(directory)
            .map_err(|_| Error::Io("Could not create Heritage output staging".into()))?;
        temporary
            .write_all(&transformed)
            .map_err(|_| Error::Io("Could not write Heritage copy".into()))?;
        os::write(temporary.as_file(), temporary.path(), &snapshot.attributes)?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|_| Error::Io("Could not sync Heritage copy".into()))?;
        let staged = Snapshot::open(temporary.path(), limits)?;
        if staged.bytes != transformed || staged.attributes != snapshot.attributes {
            return Err(Error::Verification(
                "Heritage output attributes or bytes differ from verification".into(),
            ));
        }
        drop(staged);
        if !snapshot.unchanged(input, limits)? {
            return Err(Error::Blocked("Heritage original changed".into()));
        }
        report.output_sha256 = Some(digest(&transformed));
        drop(transformed);
        report.integrity.security_markers_preserved = Some(true);
        let target = publish(temporary.into_temp_path(), input, output)?;
        report.output_name = target.file_name().map(|v| v.to_string_lossy().into_owned());
    }
    if !request.writes_file() && !snapshot.unchanged(input, limits)? {
        return Err(Error::Blocked(
            "Heritage input changed during operation".into(),
        ));
    }
    report.integrity.original_unchanged = Some(true);
    report.integrity.parseable = true;
    report.advanced = Some(json!({"heritage":details}));
    if format == Format::Text {
        report.warnings.push("Source provenance covers the recognized FileVeil comment and exact unwrapped bytes. Other comments, strings and identifiers retain their own privacy scope.".into());
    }
    report.warnings.push("Watermark signals can be copied. Signatures, current content binding, issuer trust and trusted time are assessed separately. Offline dates are user assertions.".into());
    Ok(report)
}

pub fn publish_staged(
    input: &Path,
    staged: &Path,
    output: Option<&Path>,
    request: &HeritageRequest,
    report: &mut Report,
    limits: &Limits,
) -> Result<()> {
    if !request.writes_file()
        || report.operation != "heritage"
        || report.policy != request.policy()
        || report
            .advanced
            .as_ref()
            .is_none_or(|v| v["heritage"]["request_sha256"] != request.digest().unwrap_or_default())
        || report.integrity.original_unchanged != Some(true)
        || report.integrity.security_markers_preserved != Some(true)
        || !matches!(
            report.result,
            Outcome::VerifiedWithinScope | Outcome::PartiallyVerified
        )
    {
        return Err(Error::Blocked(
            "Heritage worker publication contract failed".into(),
        ));
    }
    let original = Snapshot::open(input, limits)?;
    let artifact = Snapshot::open(staged, limits)?;
    ensure_new_artifact(&original.file, &artifact.file)?;
    if report.input_sha256.as_deref() != Some(digest(&original.bytes).as_str())
        || report.output_sha256.as_deref() != Some(digest(&artifact.bytes).as_str())
        || artifact_attributes(request, &original.attributes) != artifact.attributes
    {
        return Err(Error::Blocked(
            "Heritage publication input or copy changed".into(),
        ));
    }
    let temporary = tempfile::TempPath::try_from_path(staged)
        .map_err(|_| Error::Io("Could not acquire Heritage staged file".into()))?;
    drop(artifact);
    let target = publish(temporary, input, output)?;
    report.output_name = target.file_name().map(|v| v.to_string_lossy().into_owned());
    Ok(())
}

fn attack_lab(
    data: &[u8],
    format: Format,
    request: &HeritageRequest,
    limits: &Limits,
) -> Result<Value> {
    if matches!(format, Format::Mp4 | Format::Mov) {
        let key = watermark_key(request)?;
        let frames = match crate::media_pixels::video_frames(data, format, limits, 3) {
            Ok(frames) => frames,
            Err(Error::Unsupported(reason)) => {
                return Ok(json!({
                    "pixel_protocol":"not_assessed", "scope":"selected_video_frames", "reason":reason,
                    "video_cleaning":"not_assessed", "frames":[]
                }));
            }
            Err(error) => return Err(error),
        };
        let mut rows = Vec::new();
        for (index, frame) in frames.iter().enumerate() {
            let signal = crate::watermark_engine::inspect_pixels(frame, key.as_deref(), limits)?;
            rows.push(json!({"second":index,"dimensions":[frame.width(),frame.height()],"watermarks":signal}));
        }
        return Ok(
            json!({"pixel_protocol":"selected_video_frames", "scope":"up_to_three_whole_second_frames",
            "frames":rows, "video_cleaning":"not_assessed",
            "limitations":["Unsampled frames and temporal watermark families are outside this assessment.","Frame signal matches carry no device or authorship attribution."]}),
        );
    }
    if !matches!(
        format,
        Format::Jpeg | Format::Png | Format::Heic | Format::Avif
    ) {
        return Ok(
            json!({"legacy":old_report(data,format,limits,request.disclose_identifiers)?,"pixel_protocol":"unsupported","scope":"legacy_structure_comparison"}),
        );
    }
    let key = watermark_key(request)?;
    let decoded = crate::media_pixels::decode(data, format, limits)?;
    let source_detection = detect_pixels(&decoded, key.as_deref(), limits, None)?;
    let clean_applicable = source_detection["status"] == "detected";
    let source_method = clean_applicable
        .then(|| source_detection["method_id"].as_str())
        .flatten()
        .map(str::to_owned);
    let source_has_work_reference = source_detection["work_id_digest"].as_str().is_some();
    let source_has_copy_reference = source_detection["copy_id_digest"].as_str().is_some();
    // One normalized source allocation also supplies the MSE reference.
    let image = DynamicImage::ImageRgba8(decoded.into_rgba8());
    let original = image.as_rgba8().expect("normalized source");
    let stripped = container::extract(data, format)?.base;
    let width = image.width();
    let height = image.height();
    let mut rows = vec![
        json!({"operation":"original","robust":source_detection,"pixel_mse_rgba8":0.0,"dimensions":[width,height],"file_sha256":digest(data)}),
    ];
    rows[0]
        .as_object_mut()
        .expect("Lab row")
        .extend(lab_structural_fields(data)?);
    let mut operations = vec![
        "structure_clean",
        "safe_metadata_clean",
        "jpeg_90",
        "jpeg_70",
        "resize_75_percent",
        "center_crop_75_percent",
    ];
    if clean_applicable {
        operations.push(if source_detection["frame_valid"] == true {
            "targeted_fileveil_dct_clean"
        } else {
            "targeted_public_watermark_clean"
        });
    }
    for name in operations {
        // Each variant is encoded, assessed and released before the next one.
        let bytes = match name {
            "structure_clean" => old_clean(&stripped, format, limits)?,
            "safe_metadata_clean" => {
                let cleaned = inspect_snapshot(data, Path::new("heritage-lab"), limits).and_then(
                    |inspection| {
                        if !inspection.blockers.is_empty() {
                            return Err(Error::Blocked(inspection.blockers.join(". ")));
                        }
                        fileveil_formats::sanitize(data, format, limits)
                    },
                );
                match cleaned {
                    Ok(bytes) => bytes,
                    Err(error @ (Error::Blocked(_) | Error::Unsupported(_))) => {
                        let status = if matches!(error, Error::Blocked(_)) {
                            "blocked"
                        } else {
                            "not_assessed"
                        };
                        rows.push(json!({"operation":name,"result":status,"reason":error.to_string(),"variant_generated":false,"structural_manifest_present":null,"signature":"not_assessed","content_binding":"not_assessed","robust":{"status":"not_assessed"}}));
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }
            "jpeg_90" => encode(
                &image,
                Format::Jpeg,
                90,
                if matches!(format, Format::Jpeg | Format::Png) {
                    data
                } else {
                    &[]
                },
                limits,
            )?,
            "jpeg_70" => encode(
                &image,
                Format::Jpeg,
                70,
                if matches!(format, Format::Jpeg | Format::Png) {
                    data
                } else {
                    &[]
                },
                limits,
            )?,
            "resize_75_percent" => encode(
                &image.resize_exact(
                    (width * 3 / 4).max(1),
                    (height * 3 / 4).max(1),
                    FilterType::Lanczos3,
                ),
                Format::Png,
                95,
                data,
                limits,
            )?,
            "targeted_fileveil_dct_clean" | "targeted_public_watermark_clean" => {
                let (cleaned, _) = crate::watermark_engine::clean(&image, key.as_deref(), limits)?;
                encode(&cleaned, Format::Png, 95, data, limits)?
            }
            _ => encode(
                &image.crop_imm(
                    width / 8,
                    height / 8,
                    (width * 3 / 4).max(1),
                    (height * 3 / 4).max(1),
                ),
                Format::Png,
                95,
                data,
                limits,
            )?,
        };
        if bytes.len() as u64 > limits.max_file_bytes {
            return Err(Error::Blocked(
                "Heritage Lab variant exceeds the configured file byte budget".into(),
            ));
        }
        let variant_format = fileveil_formats::identify(&bytes, Path::new("watermark-lab"));
        let current = crate::media_pixels::decode(&bytes, variant_format, limits)?;
        let detection = detect_pixels(&current, key.as_deref(), limits, source_method.as_deref())?;
        let decoded = current.into_rgba8();
        let mse = (decoded.dimensions() == original.dimensions()).then(|| {
            original
                .as_raw()
                .iter()
                .zip(decoded.as_raw())
                .map(|(&a, &b)| (a as f64 - b as f64).powi(2))
                .sum::<f64>()
                / original.as_raw().len().max(1) as f64
        });
        let mut row = json!({"operation":name,"robust":detection,"pixel_mse_rgba8":mse,"dimensions":[decoded.width(),decoded.height()],"file_sha256":digest(&bytes)});
        row.as_object_mut()
            .expect("Lab row")
            .extend(lab_structural_fields(&bytes)?);
        rows.push(row);
    }
    drop(image);
    drop(stripped);
    let mut controls = Vec::new();
    let mut total_bytes = data.len() as u64;
    for path in &request.controls {
        let mut remaining = limits.clone();
        remaining.max_file_bytes = limits
            .max_file_bytes
            .min(limits.max_uncompressed_bytes.saturating_sub(total_bytes));
        let snapshot = Snapshot::open(path, &remaining)?;
        total_bytes = total_bytes.saturating_add(snapshot.bytes.len() as u64);
        let control_format = fileveil_formats::identify(&snapshot.bytes, path);
        let checked = detect_pixels(
            &crate::media_pixels::decode(&snapshot.bytes, control_format, limits)?,
            key.as_deref(),
            limits,
            source_method.as_deref(),
        )?;
        if !snapshot.unchanged(path, limits)? {
            return Err(Error::Blocked("Heritage Lab control changed".into()));
        }
        controls.push(checked);
    }
    let assessed =
        |value: &Value| matches!(value["status"].as_str(), Some("detected" | "not_detected"));
    let positives = controls
        .iter()
        .filter(|value| value["status"] == "detected")
        .count();
    let assessed_controls = controls.iter().filter(|value| assessed(value)).count();
    let assessed_variants = rows.iter().filter(|row| assessed(&row["robust"])).count();
    let indeterminate_controls = controls
        .iter()
        .filter(|value| value["status"] == "indeterminate")
        .count();
    let indeterminate_variants = rows
        .iter()
        .filter(|row| row["robust"]["status"] == "indeterminate")
        .count();
    let survived = rows
        .iter()
        .filter(|row| row["robust"]["status"] == "detected")
        .count();
    let same_work = rows
        .iter()
        .filter(|row| {
            row["robust"]["frame_valid"] == true
                && row["robust"]["work_id_digest"] == rows[0]["robust"]["work_id_digest"]
        })
        .count();
    let same_copy = source_has_copy_reference.then(|| {
        rows.iter()
            .filter(|row| {
                row["robust"]["frame_valid"] == true
                    && row["robust"]["work_id_digest"] == rows[0]["robust"]["work_id_digest"]
                    && row["robust"]["copy_id_digest"] == rows[0]["robust"]["copy_id_digest"]
            })
            .count()
    });
    Ok(
        json!({"source_method":source_method,"work_reference_assessed":source_has_work_reference,"same_copy_variants":same_copy,"rows":rows,"detected_variants":survived,"same_work_variants":same_work,"tested_variants":rows.len(),"assessed_variants":assessed_variants,"indeterminate_variants":indeterminate_variants,"controls":controls,"control_positive_count":positives,"control_count":request.controls.len(),"assessed_controls":assessed_controls,"indeterminate_controls":indeterminate_controls,"scope":"Comparisons follow the original sample's detected method where available. Per-method outcomes are retained. Work and copy recovery have separate counts. Assessed denominators include detected and not_detected. Measurements cover these explicit variants and user-supplied controls."}),
    )
}

fn lab_structural_fields(data: &[u8]) -> Result<serde_json::Map<String, Value>> {
    let format = fileveil_formats::identify(data, Path::new("heritage-lab"));
    let extracted = container::extract(data, format)?;
    let mut fields = serde_json::Map::new();
    fields.insert(
        "structural_manifest_present".into(),
        json!(extracted.manifest.is_some()),
    );
    let checked = history(extracted.manifest.as_deref()).and_then(|records| {
        signing::verify_chain(&records, &digest(&extracted.base), &TrustStore::default())
    });
    match checked {
        Ok(verification) => {
            fields.insert("signature".into(), json!(verification.signature));
            fields.insert(
                "content_binding".into(),
                json!(verification.content_binding),
            );
            fields.insert("trust".into(), json!(verification.trust));
        }
        Err(_) => {
            fields.insert("signature".into(), json!("invalid"));
            fields.insert("content_binding".into(), json!("not_assessed"));
            fields.insert("trust".into(), json!("not_assessed"));
            fields.insert("structural_error".into(), json!("The structural record could not be parsed or verified within the supported contract"));
        }
    }
    Ok(fields)
}

fn detect_pixels(
    image: &DynamicImage,
    key: Option<&[u8; 32]>,
    limits: &Limits,
    reference_method: Option<&str>,
) -> Result<Value> {
    let evidence = crate::watermark_engine::inspect_pixels(image, key, limits)?;
    let selected = reference_method.and_then(|method| {
        evidence["detections"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["method_id"] == method))
    });
    let mut primary = selected.unwrap_or(&evidence["primary"]).clone();
    primary["detections"] = evidence["detections"].clone();
    Ok(primary)
}

// FVPROV1 66748 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJjYmYwY2VhYjhhZWExZGU0ZDBkMDg2MzQ0ZDMzMmM1MWJkZjgwNWE4MGJiMWE3MTQ5MWM1MGJiZDE3OWZiN2Q5IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS40IiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuNCIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL2hlcml0YWdlL3BpcGVsaW5lLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiMjBhZDE3Y2NiNzQyYmRmMjJhM2QwMjU3MmU2ZjY5N2MyYjMyMzMxMjRlZDhhOTlmMTU3MGJhM2E5NjAxZmU2NmQ3MzNmZWY0NjU3YTI1YWZkYTdmNmNlOTNmNjFlNTFkNDcwY2IyMTIyY2YxMWMwZTI4NDNhYmJiMjE1NmM3MDcifV19XQ== FVPROV1-END
