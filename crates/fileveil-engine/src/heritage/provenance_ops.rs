// SPDX-License-Identifier: MPL-2.0
//! Normal-entry provenance sidecars, bound to read-only inputs and new outputs.
use super::{HeritageAction, HeritageRequest, container, custody, key_store, signing, timestamp};
use crate::{Snapshot, os, output_directory, publish};
use fileveil_core::{Error, Format, Limits, Outcome, Policy, Report, Result, digest};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use signing::{PublicKey, SignedRecord, SigningKey, TrustStore, VerificationState};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

struct AuxInput {
    path: PathBuf,
    snapshot: Snapshot,
}
struct AuxInputs {
    items: Vec<AuxInput>,
}
impl AuxInputs {
    fn new() -> Self {
        Self { items: Vec::new() }
    }
    fn read(&mut self, path: &Path, cap: u64, limits: &Limits) -> Result<Vec<u8>> {
        let mut bounded = limits.clone();
        bounded.max_file_bytes = bounded.max_file_bytes.min(cap);
        let snapshot = Snapshot::open(path, &bounded)?;
        let bytes = snapshot.bytes.clone();
        self.items.push(AuxInput {
            path: path.to_path_buf(),
            snapshot,
        });
        Ok(bytes)
    }
    fn json<T: DeserializeOwned>(&mut self, path: &Path, cap: u64, limits: &Limits) -> Result<T> {
        serde_json::from_slice(&self.read(path, cap, limits)?)
            .map_err(|_| Error::Input("Invalid strict provenance auxiliary JSON".into()))
    }
    fn unchanged(&self, limits: &Limits) -> Result<()> {
        for item in &self.items {
            if !item.snapshot.unchanged(&item.path, limits)? {
                return Err(Error::Blocked(
                    "Provenance auxiliary input changed during operation".into(),
                ));
            }
        }
        Ok(())
    }
}

fn format(data: &[u8], path: &Path, limits: &Limits) -> Result<Format> {
    super::pipeline::detect_format(data, path, limits)
}
fn asset_history(
    data: &[u8],
    path: &Path,
    limits: &Limits,
) -> Result<(Format, Vec<u8>, Vec<SignedRecord>)> {
    let format = format(data, path, limits)?;
    let carrier = container::extract(data, format)?;
    let encoded = carrier
        .manifest
        .ok_or_else(|| Error::Input("Selected asset has no signed provenance history".into()))?;
    let history = signing::parse_records(&encoded)?;
    if history.is_empty() {
        return Err(Error::Input("Selected provenance history is empty".into()));
    }
    Ok((format, carrier.base, history))
}
fn selected_key(request: &HeritageRequest) -> Result<SigningKey> {
    if request.key_paths.len() + request.key_refs.len() != 1 {
        return Err(Error::Input(
            "A provenance sidecar requires exactly one explicit signing key".into(),
        ));
    }
    match request.key_paths.first() {
        Some(path) => SigningKey::load(path),
        None => key_store::load(&request.key_refs[0]),
    }
}
fn trust(request: &HeritageRequest, aux: &mut AuxInputs, limits: &Limits) -> Result<TrustStore> {
    let store = if let Some(path) = &request.trust_store {
        aux.json(path, 64 * 1024, limits)?
    } else {
        TrustStore::default()
    };
    signing::verify_chain(&[], &digest(b""), &store)?;
    Ok(store)
}
fn checkpoint_anchors(
    request: &HeritageRequest,
    aux: &mut AuxInputs,
    limits: &Limits,
) -> Result<Vec<PublicKey>> {
    let Some(path) = &request.checkpoint_anchors else {
        return Ok(Vec::new());
    };
    let bytes = aux.read(path, 64 * 1024, limits)?;
    let keys = serde_json::from_slice::<Vec<PublicKey>>(&bytes)
        .or_else(|_| {
            serde_json::from_slice::<TrustStore>(&bytes).map(|store| store.trusted_issuers)
        })
        .map_err(|_| {
            Error::Input(
                "Checkpoint anchors require public keys or a trust-store JSON object".into(),
            )
        })?;
    let policy = TrustStore {
        trusted_issuers: keys.clone(),
        minimum_issuer_signatures: 1,
    };
    signing::verify_chain(&[], &digest(b""), &policy)?;
    Ok(keys)
}
fn checkpoints(
    request: &HeritageRequest,
    aux: &mut AuxInputs,
    limits: &Limits,
) -> Result<Vec<custody::SignedCheckpoint>> {
    request
        .checkpoints
        .iter()
        .map(|path| aux.json(path, 64 * 1024, limits))
        .collect()
}
struct TimestampInputs {
    response: Option<Vec<u8>>,
    query: Option<Vec<u8>>,
    roots: Option<Vec<u8>>,
}
fn timestamp_inputs(
    request: &HeritageRequest,
    aux: &mut AuxInputs,
    limits: &Limits,
) -> Result<TimestampInputs> {
    Ok(TimestampInputs {
        response: request
            .timestamp_response
            .as_ref()
            .map(|path| aux.read(path, timestamp::MAX_TIMESTAMP_BYTES as u64, limits))
            .transpose()?,
        query: request
            .timestamp_query
            .as_ref()
            .map(|path| aux.read(path, 16 * 1024, limits))
            .transpose()?,
        roots: request
            .timestamp_roots
            .as_ref()
            .map(|path| aux.read(path, 256 * 1024, limits))
            .transpose()?,
    })
}

pub(crate) fn assess_attachments(
    history: &[SignedRecord],
    request: &HeritageRequest,
    limits: &Limits,
) -> Result<Value> {
    let mut aux = AuxInputs::new();
    let anchors = checkpoint_anchors(request, &mut aux, limits)?;
    let mut results = Vec::new();
    for item in checkpoints(request, &mut aux, limits)? {
        results.push(custody::verify_checkpoint(&item, history, &anchors)?);
    }
    let TimestampInputs {
        response,
        query,
        roots,
    } = timestamp_inputs(request, &mut aux, limits)?;
    let timestamp = if let Some(response) = response {
        let last = history
            .last()
            .ok_or_else(|| Error::Input("A record timestamp requires a nonempty history".into()))?;
        Some(timestamp::verify_timestamp(
            &response,
            &signing::record_hash(last)?,
            roots.as_deref(),
            query.as_deref(),
        )?)
    } else {
        None
    };
    aux.unchanged(limits)?;
    Ok(json!({"external_checkpoints":results,"timestamp":timestamp,"offline":true}))
}

pub(crate) fn run(
    input: &Path,
    output: Option<&Path>,
    request: &HeritageRequest,
    limits: &Limits,
) -> Result<Report> {
    request.validate()?;
    let writes = request.writes_file();
    if writes && output.is_none() {
        return Err(Error::Input(
            "Provenance sidecar actions require an explicit new output path".into(),
        ));
    }
    if !writes && output.is_some() {
        return Err(Error::Input(
            "Read-only provenance verification has no output artifact".into(),
        ));
    }
    let mut input_limits = limits.clone();
    if matches!(
        request.action,
        HeritageAction::EvidenceVerify | HeritageAction::TransferAccept
    ) {
        input_limits.max_file_bytes = input_limits
            .max_file_bytes
            .min(custody::MAX_EVIDENCE_BYTES as u64);
    }
    let original = Snapshot::open(input, &input_limits)?;
    let mut aux = AuxInputs::new();
    let store = trust(request, &mut aux, limits)?;
    let anchors = checkpoint_anchors(request, &mut aux, limits)?;
    let TimestampInputs {
        response,
        query,
        roots,
    } = timestamp_inputs(request, &mut aux, limits)?;
    let mut report = Report::new("heritage", Format::Unknown);
    report.policy = Policy::Safe;
    report.input_sha256 = Some(digest(&original.bytes));
    report.result = Outcome::PartiallyVerified;
    let mut details = json!({"action":request.action,"request_sha256":request.digest()?,"offline":true,"scope":"signed provenance sidecar and explicitly supplied external evidence"});
    let artifact = if request.action == HeritageAction::TransferAccept {
        let proposal = custody::parse_transfer_proposal(&original.bytes)?;
        let mut reference_verified = None;
        if let Some(path) = &request.reference {
            let reference = aux.read(path, limits.max_file_bytes, limits)?;
            let format = format(&reference, path, limits)?;
            let base = container::extract(&reference, format)?.base;
            if digest(&base) != proposal.body.asset.sha256
                || base.len() as u64 != proposal.body.asset.size_bytes
            {
                return Err(Error::Verification(
                    "Transfer asset differs from the sender's signed proposal".into(),
                ));
            }
            reference_verified = Some(true);
        }
        let recipient = selected_key(request)?;
        let accepted = custody::accept_transfer(&proposal, &recipient)?;
        let mut checked = custody::verify_evidence(&accepted, &store, &anchors, roots.as_deref())?;
        checked.asset_bytes_assessed = reference_verified == Some(true);
        details["evidence_verification"] = json!(checked);
        details["reference_asset_verified"] = json!(reference_verified);
        details["export_contains_claim_values"] = json!(true);
        Some(custody::canonical_evidence(&accepted)?)
    } else if request.action == HeritageAction::EvidenceVerify {
        let package = custody::parse_evidence(&original.bytes)?;
        let mut verified = custody::verify_evidence(&package, &store, &anchors, roots.as_deref())?;
        let mut reference_verified = None;
        if let Some(path) = &request.reference {
            let reference = aux.read(path, limits.max_file_bytes, limits)?;
            let format = format(&reference, path, limits)?;
            let base = container::extract(&reference, format)?.base;
            let matched = package.body.assets.iter().any(|asset| {
                asset.sha256 == digest(&base) && asset.size_bytes == base.len() as u64
            });
            reference_verified = Some(matched);
            verified.asset_bytes_assessed = matched && package.body.assets.len() == 1;
        }
        let failed = verified.package_signature != VerificationState::Valid
            || verified.custody_signer != VerificationState::Valid
            || verified.chain.signature != VerificationState::Valid
            || verified.chain.chain != VerificationState::Valid
            || !verified.asset_declarations_bound
            || reference_verified == Some(false)
            || verified.checkpoints.iter().any(|item| {
                item.signature != VerificationState::Valid
                    || item.history_binding != VerificationState::Valid
            })
            || verified
                .timestamps
                .iter()
                .any(|item| item.verification == VerificationState::Invalid);
        if failed {
            report.result = Outcome::Failed;
        }
        details["evidence_verification"] = json!(verified);
        details["reference_asset_verified"] = json!(reference_verified);
        None
    } else {
        let (format, base, history) = asset_history(&original.bytes, input, limits)?;
        report.input_format = format.mime().into();
        let last = history.last().unwrap();
        let record_digest = signing::record_hash(last)?;
        let verified = signing::verify_chain(&history, &digest(&base), &store)?;
        if verified.signature != VerificationState::Valid
            || verified.chain != VerificationState::Valid
            || verified.content_binding != VerificationState::Valid
        {
            return Err(Error::Verification(
                "Current asset and signed provenance history do not verify".into(),
            ));
        }
        details["verification"] = json!(verified);
        details["record_sha256"] = json!(record_digest);
        match request.action {
            HeritageAction::TransferPrepare => {
                let sender = selected_key(request)?;
                let recipient = request.mark.transfer_to_key_id.as_deref().ok_or_else(|| {
                    Error::Input(
                        "Transfer preparation requires a recipient public-key identifier".into(),
                    )
                })?;
                let assertion = if request.mark.created_at.is_empty() {
                    format!(
                        "unix:{}",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                    )
                } else {
                    request.mark.created_at.clone()
                };
                let copy_id =
                    (!request.mark.copy_id.is_empty()).then_some(request.mark.copy_id.as_str());
                let proposal = custody::prepare_transfer(
                    &history,
                    custody::EvidenceAsset {
                        version: last.body.version.clone(),
                        sha256: digest(&base),
                        media_type: format.mime().into(),
                        size_bytes: base.len() as u64,
                    },
                    recipient,
                    &assertion,
                    copy_id,
                    &sender,
                )?;
                details["transfer_prepared"] = json!(true);
                details["recipient_acceptance"] = json!("pending");
                details["export_contains_claim_values"] = json!(true);
                Some(custody::canonical_transfer_proposal(&proposal)?)
            }
            HeritageAction::Checkpoint => {
                let key = selected_key(request)?;
                let assertion = if request.mark.created_at.is_empty() {
                    format!(
                        "unix:{}",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                    )
                } else {
                    request.mark.created_at.clone()
                };
                let checkpoint = custody::create_checkpoint(&history, &assertion, &key)?;
                let verified = custody::verify_checkpoint(&checkpoint, &history, &anchors)?;
                details["checkpoint_verification"] = json!(verified);
                Some(signing::canonical(&checkpoint)?)
            }
            HeritageAction::EvidenceExport => {
                let key = selected_key(request)?;
                let external = checkpoints(request, &mut aux, limits)?;
                let tokens = if let Some(response) = &response {
                    use base64::{Engine, engine::general_purpose::STANDARD};
                    let checked = timestamp::verify_timestamp(
                        response,
                        &record_digest,
                        roots.as_deref(),
                        query.as_deref(),
                    )?;
                    if checked.verification == VerificationState::Invalid {
                        return Err(Error::Verification(
                            "Evidence timestamp did not verify".into(),
                        ));
                    }
                    vec![custody::AttachedTimestamp {
                        subject: custody::TimestampSubject::Record,
                        subject_sha256: record_digest.clone(),
                        response_der_base64: STANDARD.encode(response),
                    }]
                } else {
                    Vec::new()
                };
                let package = custody::create_evidence(
                    &history,
                    vec![custody::EvidenceAsset {
                        version: last.body.version.clone(),
                        sha256: digest(&base),
                        media_type: format.mime().into(),
                        size_bytes: base.len() as u64,
                    }],
                    external,
                    tokens,
                    &key,
                )?;
                let checked =
                    custody::verify_evidence(&package, &store, &anchors, roots.as_deref())?;
                if checked.checkpoints.iter().any(|item| {
                    item.signature != VerificationState::Valid
                        || item.history_binding != VerificationState::Valid
                }) {
                    return Err(Error::Verification(
                        "An external evidence checkpoint does not match this history".into(),
                    ));
                }
                details["evidence_verification"] = json!(checked);
                details["export_contains_claim_values"] = json!(true);
                Some(custody::canonical_evidence(&package)?)
            }
            HeritageAction::TimestampQuery => {
                details["timestamp_query_imprint_sha256"] = json!(record_digest);
                details["request_contains_file_content"] = json!(false);
                Some(timestamp::create_query(&record_digest)?)
            }
            HeritageAction::TimestampVerify => {
                let response = response.as_ref().ok_or_else(|| {
                    Error::Input("Timestamp verification requires an explicit response file".into())
                })?;
                let checked = timestamp::verify_timestamp(
                    response,
                    &record_digest,
                    roots.as_deref(),
                    query.as_deref(),
                )?;
                if checked.verification == VerificationState::Invalid {
                    report.result = Outcome::Failed;
                }
                details["timestamp"] = json!(checked);
                None
            }
            _ => return Err(Error::Input("Unsupported provenance sidecar action".into())),
        }
    };
    if let Some(bytes) = artifact {
        if bytes.len() as u64 > limits.max_file_bytes {
            return Err(Error::Blocked(
                "Provenance output exceeds its byte budget".into(),
            ));
        }
        if original
            .attributes
            .iter()
            .any(|item| item.name == "com.apple.ResourceFork")
        {
            return Err(Error::Blocked(
                "Resource forks protect provenance sidecar creation".into(),
            ));
        }
        let mut temporary = tempfile::Builder::new()
            .prefix(".fileveil-provenance-")
            .tempfile_in(output_directory(input, output))
            .map_err(|_| Error::Io("Could not create private provenance output".into()))?;
        temporary
            .write_all(&bytes)
            .map_err(|_| Error::Io("Could not write provenance sidecar".into()))?;
        let expected_attributes =
            super::pipeline::artifact_attributes(request, &original.attributes);
        os::write(temporary.as_file(), temporary.path(), &expected_attributes)?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|_| Error::Io("Could not sync provenance sidecar".into()))?;
        let staged = Snapshot::open(temporary.path(), limits)?;
        if staged.bytes != bytes || staged.attributes != expected_attributes {
            return Err(Error::Verification(
                "Provenance staged bytes or attributes changed".into(),
            ));
        }
        drop(staged);
        aux.unchanged(limits)?;
        if !original.unchanged(input, &input_limits)? {
            return Err(Error::Blocked(
                "Provenance original changed before publication".into(),
            ));
        }
        report.output_sha256 = Some(digest(&bytes));
        report.integrity.security_markers_preserved = Some(true);
        let target = publish(temporary.into_temp_path(), input, output)?;
        report.output_name = target
            .file_name()
            .map(|value| value.to_string_lossy().into_owned());
    } else {
        aux.unchanged(limits)?;
        if !original.unchanged(input, &input_limits)? {
            return Err(Error::Blocked(
                "Provenance input changed during verification".into(),
            ));
        }
    }
    report.integrity.parseable = true;
    report.integrity.original_unchanged = Some(true);
    report.advanced = Some(json!({"heritage":details}));
    Ok(report)
}

// FVPROV1 20298 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIwOGFhMTM3OWM2NGU0Y2Y5OGI3M2ZjNDJlMTY0MzgwMzQ3YTQxYTEzOTc4ZjIyYzY3NmQ4NDQ1ZTFmZGI2MTM5IiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL2hlcml0YWdlL3Byb3ZlbmFuY2Vfb3BzLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiOWYyYTE0MzE3YjliZjBmYTAyMjM1ZTFhMDhiOTg3ZDVhMTVhMzM5NTVkMzJhNTI0M2NiNWYyOGI5MjEwYmRlNmYxN2RjMmQyNzMxNTNhOGFiOWNhOTJmMjMwMjk4Yjc4ZmZhMTcwOWUxYmY0ZGRiZWJlNzRkZWI5M2FjOWJiMGQifV19XQ== FVPROV1-END
