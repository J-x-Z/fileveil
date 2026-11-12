// SPDX-License-Identifier: MPL-2.0
//! Shared read-only audits and verified new-copy Heritage operations.
use super::{container, legacy, robust, signing};
use crate::{
    Snapshot, decode_pixels, ensure_new_artifact, inspect_snapshot, os, output_directory, publish,
};
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MarkSettings {
    pub work_id: String,
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
    pub trust_store: Option<PathBuf>,
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
            HeritageAction::Mark | HeritageAction::Clean | HeritageAction::C2paMark
        )
    }
    pub fn policy(&self) -> Policy {
        if (self.action == HeritageAction::Mark && self.mark.robust)
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
            .collect()
    }
    pub fn auxiliary_paths_mut(&mut self) -> Vec<&mut PathBuf> {
        self.key_paths
            .iter_mut()
            .chain(self.trust_store.iter_mut())
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
        if self.key_paths.len() > signing::MAX_SIGNERS || self.controls.len() > 8 {
            return Err(Error::Input(
                "Heritage accepts at most 32 signers and 8 controls".into(),
            ));
        }
        if self.action != HeritageAction::Mark
            && (!self.key_paths.is_empty() || self.previous.is_some())
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
        Ok(())
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

fn detect_format(data: &[u8], hint: &Path, limits: &Limits) -> Result<Format> {
    let format = if data.starts_with(b"PK") {
        fileveil_formats::inspect(data, hint, limits)?.format
    } else {
        fileveil_formats::identify(data, hint)
    };
    if !container::supported(format) {
        return Err(Error::Unsupported(
            "Heritage supports JPEG, PNG, PDF, DOCX, XLSX and PPTX".into(),
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
    let format = detect_format(&snapshot.bytes, path, limits)?;
    let extracted = container::extract(&snapshot.bytes, format)?;
    let records = history(extracted.manifest.as_deref())?;
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
    Value::Array(records.iter().map(|record| {
        let body = &record.body;
        let mut item = json!({"sequence":body.sequence,"kind":body.kind,"mode":body.mode,"work_id_sha256":digest(body.work_id.as_bytes()),"author_declared":!body.author.is_empty(),"author_sha256":digest(body.author.as_bytes()),"edition_sha256":digest(body.edition.as_bytes()),"version":body.version,"parent_version":body.parent_version,"actor_key_id":body.actor_key_id,"transfer_to_key_id":body.transfer_to_key_id,"previous_record_sha256":body.previous_record_sha256,"content_sha256":body.content_sha256,"record_sha256":signing::record_hash(record).ok()});
        if disclose { item["work_id"] = json!(body.work_id); item["author"] = json!(body.author); item["edition"] = json!(body.edition); item["created_at"] = json!(body.created_at); }
        item
    }).collect())
}
fn signal(data: &[u8], format: Format, limits: &Limits) -> Result<Value> {
    if matches!(format, Format::Jpeg | Format::Png) {
        match robust::detect(&decode_pixels(data, limits)?, limits) {
            Ok(value) => serde_json::to_value(value)
                .map_err(|_| Error::Io("Could not serialize signal evidence".into())),
            Err(Error::Unsupported(reason)) => Ok(json!({"status":"not_assessed","scope":reason})),
            Err(error) => Err(error),
        }
    } else {
        Ok(json!({"status":"not_assessed","scope":"heritage_dct_jpeg_png_only"}))
    }
}
fn encode(
    image: &DynamicImage,
    format: Format,
    quality: u8,
    source: &[u8],
    limits: &Limits,
) -> Result<Vec<u8>> {
    let profile = crate::image_processing::decode_profile(source, limits)?;
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
    let snapshot = Snapshot::open(input, limits)?;
    let format = detect_format(&snapshot.bytes, input, limits)?;
    let extracted = container::extract(&snapshot.bytes, format)?;
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
    if request.action == HeritageAction::Lab {
        details["lab"] = attack_lab(&snapshot.bytes, format, request, limits)?;
    } else if !request.writes_file() {
        let records = records?;
        let verification = signing::verify_chain(&records, &digest(&extracted.base), &store)?;
        details["verification"] = serde_json::to_value(&verification)
            .map_err(|_| Error::Io("Could not serialize signature evidence".into()))?;
        details["records"] = claim_report(&records, request.disclose_claims);
        details["robust"] = signal(&extracted.base, format, limits)?;
        if let Some(reference) = &request.reference {
            let reference = reference_history(reference, limits)?;
            let expected = robust::work_id_digest(
                &reference.last().expect("nonempty reference").body.work_id,
            )?;
            let verification = signing::verify_chain(&reference, &digest(&extracted.base), &store)?;
            let work_match = details["robust"]["frame_valid"] == true
                && details["robust"]["work_id_digest"] == expected;
            details["work_digest_match"] = json!(work_match);
            details["trace_reference_match"] = json!(
                work_match
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
            base = crate::provenance::remove(&base, format, limits)?;
        }
        check_write_safety(&base, format, input, limits)?;
        let transformed = match request.action {
            HeritageAction::Mark => {
                let keys: Vec<_> = request
                    .key_paths
                    .iter()
                    .map(|path| SigningKey::load(path))
                    .collect::<Result<_>>()?;
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
                    let image = decode_pixels(&base, limits)?;
                    let (marked, _) = robust::embed(
                        &image,
                        &request.mark.work_id,
                        request.mark.strength,
                        limits,
                    )?;
                    base = encode(&marked, format, 95, &base, limits)?;
                    drop(marked);
                    drop(image);
                    let detected = robust::detect(&decode_pixels(&base, limits)?, limits)?;
                    if !detected.frame_valid
                        || detected.work_id_digest
                            != Some(robust::work_id_digest(&request.mark.work_id)?)
                    {
                        return Err(Error::Verification(
                            "Encoded Heritage signal failed its detector".into(),
                        ));
                    }
                    details["robust"] = json!(detected);
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
                let marked = container::embed(&base, format, &encoded)?;
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
                if request.clean_signal {
                    let original = decode_pixels(&base, limits)?;
                    let (cleaned, _) = robust::clean(&original, limits)?;
                    base = encode(&cleaned, format, 95, &base, limits)?;
                    drop(cleaned);
                    drop(original);
                    let checked = robust::detect(&decode_pixels(&base, limits)?, limits)?;
                    if checked.frame_valid {
                        return Err(Error::Verification(
                            "Heritage DCT protocol still detects after cleaning".into(),
                        ));
                    }
                    details["robust_recheck"] = json!(checked);
                }
                if container::extract(&base, format)?.manifest.is_some() {
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
                let signed = super::c2pa_mark::sign_bytes_with_key_path(
                    &base,
                    format,
                    &cert.bytes,
                    key,
                    &claims,
                    limits,
                )?;
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
        let output_format = detect_format(&transformed, input, limits)?;
        if output_format != format {
            return Err(Error::Verification("Heritage output format changed".into()));
        }
        let parsed = container::extract(&transformed, format)?;
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
        if matches!(format, Format::Jpeg | Format::Png) {
            if crate::image_processing::decode_profile(&snapshot.bytes, limits)?
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
            details["color_metadata_preserved"] = json!(true);
            let before = decode_pixels(&snapshot.bytes, limits)?.into_rgba8();
            let after = decode_pixels(&transformed, limits)?.into_rgba8();
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
            }
            if request.policy() == Policy::Safe && report.integrity.pixel_equal != Some(true) {
                return Err(Error::Verification(
                    "Structural Heritage operation changed decoded pixels".into(),
                ));
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
    report.warnings.push("Historical DES records and public DCT work references do not authenticate a device or author. Modern signatures validate keys and content within their separately reported chain and trust scopes. Offline dates are user assertions.".into());
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
        || original.attributes != artifact.attributes
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
    if !matches!(format, Format::Jpeg | Format::Png) {
        return Ok(
            json!({"legacy":old_report(data,format,limits,request.disclose_identifiers)?,"pixel_protocol":"unsupported","scope":"legacy_structure_comparison"}),
        );
    }
    let decoded = decode_pixels(data, limits)?;
    let source_detection = detect_pixels(&decoded, limits)?;
    let clean_applicable = source_detection["frame_valid"] == true;
    // One normalized source allocation also supplies the MSE reference.
    let image = DynamicImage::ImageRgba8(decoded.into_rgba8());
    let original = image.as_rgba8().expect("normalized source");
    let stripped = container::extract(data, format)?.base;
    let width = image.width();
    let height = image.height();
    let mut rows = vec![
        json!({"operation":"original","robust":source_detection,"pixel_mse_rgba8":0.0,"dimensions":[width,height],"file_sha256":digest(data)}),
    ];
    let mut operations = vec![
        "structure_clean",
        "jpeg_90",
        "jpeg_70",
        "resize_75_percent",
        "center_crop_75_percent",
    ];
    if clean_applicable {
        operations.push("targeted_fileveil_dct_clean");
    }
    for name in operations {
        // Each variant is encoded, assessed and released before the next one.
        let bytes = match name {
            "structure_clean" => old_clean(&stripped, format, limits)?,
            "jpeg_90" => encode(&image, Format::Jpeg, 90, data, limits)?,
            "jpeg_70" => encode(&image, Format::Jpeg, 70, data, limits)?,
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
            "targeted_fileveil_dct_clean" => {
                let (cleaned, _) = robust::clean(&image, limits)?;
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
        let current = decode_pixels(&bytes, limits)?;
        let detection = detect_pixels(&current, limits)?;
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
        rows.push(json!({"operation":name,"robust":detection,"pixel_mse_rgba8":mse,"dimensions":[decoded.width(),decoded.height()],"file_sha256":digest(&bytes)}));
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
        let checked = detect_pixels(&decode_pixels(&snapshot.bytes, limits)?, limits)?;
        if !snapshot.unchanged(path, limits)? {
            return Err(Error::Blocked("Heritage Lab control changed".into()));
        }
        controls.push(checked);
    }
    let assessed =
        |value: &Value| matches!(value["status"].as_str(), Some("detected" | "not_detected"));
    let positives = controls.iter().filter(|v| v["frame_valid"] == true).count();
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
        .filter(|row| row["robust"]["frame_valid"] == true)
        .count();
    let same_work = rows
        .iter()
        .filter(|row| {
            row["robust"]["frame_valid"] == true
                && row["robust"]["work_id_digest"] == rows[0]["robust"]["work_id_digest"]
        })
        .count();
    Ok(
        json!({"rows":rows,"detected_variants":survived,"same_work_variants":same_work,"tested_variants":rows.len(),"assessed_variants":assessed_variants,"indeterminate_variants":indeterminate_variants,"controls":controls,"control_positive_count":positives,"control_count":request.controls.len(),"assessed_controls":assessed_controls,"indeterminate_controls":indeterminate_controls,"scope":"Observed outcomes on these explicit variants and user-supplied controls. Positive counts mean an executed named detector recovered a valid public frame. Assessed denominators include detected and not_detected only. These samples do not estimate population-wide false-positive rates."}),
    )
}

fn detect_pixels(image: &DynamicImage, limits: &Limits) -> Result<Value> {
    match robust::detect(image, limits) {
        Ok(value) => Ok(json!(value)),
        Err(Error::Unsupported(reason)) => Ok(json!({"status":"not_assessed","scope":reason})),
        Err(error) => Err(error),
    }
}
