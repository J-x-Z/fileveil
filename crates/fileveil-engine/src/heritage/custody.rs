// SPDX-License-Identifier: MPL-2.0
//! Portable signed checkpoints and bounded, independently verifiable evidence.
use super::{signing, timestamp};
use base64::{Engine, engine::general_purpose::STANDARD};
use fileveil_core::{Error, Result, digest};
use serde::{Deserialize, Serialize};
use signing::{
    PublicKey, RecordSignature, SignedRecord, SigningKey, TrustStore, VerificationState,
};

const CHECKPOINT_DOMAIN: &[u8] = b"FileVeil external chain checkpoint v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"FileVeil copyright evidence package v1\0";
pub const MAX_EVIDENCE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointBody {
    pub schema: String,
    pub work_id: String,
    pub copy_id: Option<String>,
    pub sequence: u32,
    pub record_sha256: String,
    pub content_sha256: String,
    pub asserted_time: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCheckpoint {
    pub body: CheckpointBody,
    pub signature: RecordSignature,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointVerification {
    pub signature: VerificationState,
    pub trust: VerificationState,
    pub history_binding: VerificationState,
    pub checkpoint_sha256: String,
    pub evidence_codes: Vec<String>,
}

pub fn create_checkpoint(
    history: &[SignedRecord],
    asserted_time: &str,
    key: &SigningKey,
) -> Result<SignedCheckpoint> {
    let last = history
        .last()
        .ok_or_else(|| Error::Input("A checkpoint requires a signed history".into()))?;
    let verified =
        signing::verify_chain(history, &last.body.content_sha256, &TrustStore::default())?;
    if verified.signature != VerificationState::Valid || verified.chain != VerificationState::Valid
    {
        return Err(Error::Verification(
            "A checkpoint requires a valid supplied history".into(),
        ));
    }
    bounded_text(asserted_time)?;
    let body = CheckpointBody {
        schema: "fileveil.provenance.checkpoint.v1".into(),
        work_id: last.body.work_id.clone(),
        copy_id: last.body.copy_id.clone(),
        sequence: last.body.sequence,
        record_sha256: signing::record_hash(last)?,
        content_sha256: last.body.content_sha256.clone(),
        asserted_time: asserted_time.into(),
    };
    Ok(SignedCheckpoint {
        signature: signing::sign_detached(CHECKPOINT_DOMAIN, &body, key)?,
        body,
    })
}

pub fn checkpoint_digest(checkpoint: &SignedCheckpoint) -> Result<String> {
    Ok(digest(&signing::canonical(checkpoint)?))
}

pub fn verify_checkpoint(
    checkpoint: &SignedCheckpoint,
    history: &[SignedRecord],
    anchors: &[PublicKey],
) -> Result<CheckpointVerification> {
    validate_checkpoint(checkpoint)?;
    signing::canonical_records(history)?;
    let signature =
        if signing::verify_detached(CHECKPOINT_DOMAIN, &checkpoint.body, &checkpoint.signature)
            .is_ok()
        {
            VerificationState::Valid
        } else {
            VerificationState::Invalid
        };
    let trust = if signature == VerificationState::Valid
        && anchors.iter().any(|key| {
            key.key_id == checkpoint.signature.key_id
                && key.ed25519_hex == checkpoint.signature.public_key_hex
        }) {
        VerificationState::Valid
    } else {
        VerificationState::Untrusted
    };
    let matches = history
        .get(checkpoint.body.sequence as usize)
        .is_some_and(|record| {
            record.body.work_id == checkpoint.body.work_id
                && record.body.copy_id == checkpoint.body.copy_id
                && record.body.content_sha256 == checkpoint.body.content_sha256
                && signing::record_hash(record)
                    .is_ok_and(|hash| hash == checkpoint.body.record_sha256)
        });
    Ok(CheckpointVerification {
        signature,
        trust,
        history_binding: if matches {
            VerificationState::Valid
        } else {
            VerificationState::Invalid
        },
        checkpoint_sha256: checkpoint_digest(checkpoint)?,
        evidence_codes: vec![
            "external_checkpoint_must_be_obtained_independently".into(),
            "asserted_time_requires_separate_rfc3161_token".into(),
        ],
    })
}

fn validate_checkpoint(value: &SignedCheckpoint) -> Result<()> {
    if value.body.schema != "fileveil.provenance.checkpoint.v1"
        || value.body.sequence as usize >= signing::MAX_RECORDS
    {
        return Err(Error::Input("Unsupported or oversized checkpoint".into()));
    }
    bounded_text(&value.body.work_id)?;
    bounded_text(&value.body.asserted_time)?;
    if let Some(copy) = &value.body.copy_id {
        bounded_text(copy)?;
    }
    validate_digest(&value.body.record_sha256)?;
    validate_digest(&value.body.content_sha256)?;
    if signing::canonical(value)?.len() > 64 * 1024 {
        return Err(Error::Blocked("Checkpoint exceeds its byte budget".into()));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAsset {
    pub version: String,
    pub sha256: String,
    pub media_type: String,
    pub size_bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampSubject {
    Record,
    Checkpoint,
    Asset,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachedTimestamp {
    pub subject: TimestampSubject,
    pub subject_sha256: String,
    pub response_der_base64: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBody {
    pub schema: String,
    pub work_id: String,
    pub copy_id: Option<String>,
    pub records: Vec<SignedRecord>,
    pub assets: Vec<EvidenceAsset>,
    pub checkpoints: Vec<SignedCheckpoint>,
    pub timestamps: Vec<AttachedTimestamp>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePackage {
    pub body: EvidenceBody,
    pub signature: RecordSignature,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceVerification {
    pub package_signature: VerificationState,
    pub custody_signer: VerificationState,
    pub chain: signing::ChainVerification,
    pub asset_declarations_bound: bool,
    pub asset_bytes_assessed: bool,
    pub checkpoints: Vec<CheckpointVerification>,
    pub timestamps: Vec<timestamp::TimestampVerification>,
    pub evidence_codes: Vec<String>,
}

pub fn create_evidence(
    history: &[SignedRecord],
    assets: Vec<EvidenceAsset>,
    checkpoints: Vec<SignedCheckpoint>,
    timestamps: Vec<AttachedTimestamp>,
    key: &SigningKey,
) -> Result<EvidencePackage> {
    let last = history
        .last()
        .ok_or_else(|| Error::Input("Evidence requires a signed history".into()))?;
    let body = EvidenceBody {
        schema: "fileveil.provenance.evidence.v1".into(),
        work_id: last.body.work_id.clone(),
        copy_id: last.body.copy_id.clone(),
        records: history.to_vec(),
        assets,
        checkpoints,
        timestamps,
    };
    let package = EvidencePackage {
        signature: signing::sign_detached(EVIDENCE_DOMAIN, &body, key)?,
        body,
    };
    let checked = verify_evidence(&package, &TrustStore::default(), &[], None)?;
    if checked.package_signature != VerificationState::Valid
        || checked.custody_signer != VerificationState::Valid
        || checked.chain.signature != VerificationState::Valid
        || checked.chain.chain != VerificationState::Valid
        || !checked.asset_declarations_bound
    {
        return Err(Error::Verification("Evidence creation requires a valid chain, active custodian and bound asset declarations".into()));
    }
    Ok(package)
}

pub fn parse_evidence(bytes: &[u8]) -> Result<EvidencePackage> {
    if bytes.len() > MAX_EVIDENCE_BYTES {
        return Err(Error::Blocked(
            "Evidence package exceeds its byte budget".into(),
        ));
    }
    let package = serde_json::from_slice(bytes)
        .map_err(|_| Error::Input("Invalid strict evidence JSON".into()))?;
    validate_evidence(&package)?;
    Ok(package)
}
pub fn canonical_evidence(package: &EvidencePackage) -> Result<Vec<u8>> {
    validate_evidence(package)?;
    signing::canonical(package)
}

pub fn verify_evidence(
    package: &EvidencePackage,
    trust: &TrustStore,
    checkpoint_anchors: &[PublicKey],
    timestamp_roots_pem: Option<&[u8]>,
) -> Result<EvidenceVerification> {
    validate_evidence(package)?;
    let body = &package.body;
    let last = body
        .records
        .last()
        .ok_or_else(|| Error::Input("Evidence history is empty".into()))?;
    let chain = signing::verify_chain(&body.records, &last.body.content_sha256, trust)?;
    let package_signature =
        if signing::verify_detached(EVIDENCE_DOMAIN, body, &package.signature).is_ok() {
            VerificationState::Valid
        } else {
            VerificationState::Invalid
        };
    let active = last
        .body
        .transfer_to_key_id
        .as_ref()
        .or(last.body.rotation_to_key_id.as_ref())
        .unwrap_or(&last.body.actor_key_id);
    let custody_signer =
        if package.signature.key_id == *active && package_signature == VerificationState::Valid {
            VerificationState::Valid
        } else {
            VerificationState::Invalid
        };
    let declarations = body.assets.iter().all(|asset| {
        body.records
            .iter()
            .any(|r| r.body.version == asset.version && r.body.content_sha256 == asset.sha256)
    }) && body
        .assets
        .iter()
        .any(|a| a.version == last.body.version && a.sha256 == last.body.content_sha256)
        && body.work_id == last.body.work_id
        && body.copy_id == last.body.copy_id;
    let checkpoints = body
        .checkpoints
        .iter()
        .map(|c| verify_checkpoint(c, &body.records, checkpoint_anchors))
        .collect::<Result<_>>()?;
    let mut timestamps = Vec::new();
    for attachment in &body.timestamps {
        let exists = match attachment.subject {
            TimestampSubject::Record => body
                .records
                .iter()
                .any(|r| signing::record_hash(r).is_ok_and(|s| s == attachment.subject_sha256)),
            TimestampSubject::Checkpoint => body
                .checkpoints
                .iter()
                .any(|c| checkpoint_digest(c).is_ok_and(|s| s == attachment.subject_sha256)),
            TimestampSubject::Asset => body
                .assets
                .iter()
                .any(|a| a.sha256 == attachment.subject_sha256),
        };
        if !exists {
            return Err(Error::Verification(
                "Timestamp subject is absent from the evidence package".into(),
            ));
        }
        let token = STANDARD
            .decode(&attachment.response_der_base64)
            .map_err(|_| Error::Input("Invalid timestamp response base64".into()))?;
        timestamps.push(timestamp::verify_timestamp(
            &token,
            &attachment.subject_sha256,
            timestamp_roots_pem,
            None,
        )?);
    }
    Ok(EvidenceVerification {
        package_signature,
        custody_signer,
        chain,
        asset_declarations_bound: declarations,
        asset_bytes_assessed: false,
        checkpoints,
        timestamps,
        evidence_codes: vec![
            "asset_hashes_require_external_originals_for_recomputation".into(),
            "self_signature_does_not_authenticate_copyright_identity".into(),
            "external_checkpoints_bound_only_at_their_signed_sequence".into(),
        ],
    })
}

fn validate_evidence(package: &EvidencePackage) -> Result<()> {
    let body = &package.body;
    if body.schema != "fileveil.provenance.evidence.v1"
        || body.assets.len() > 256
        || body.checkpoints.len() > 32
        || body.timestamps.len() > 8
        || body.records.is_empty()
        || body.records.len() > signing::MAX_RECORDS
        || signing::canonical(package)?.len() > MAX_EVIDENCE_BYTES
    {
        return Err(Error::Blocked(
            "Evidence schema or collection budget is invalid".into(),
        ));
    }
    signing::canonical_records(&body.records)?;
    bounded_text(&body.work_id)?;
    if let Some(copy) = &body.copy_id {
        bounded_text(copy)?;
    }
    for asset in &body.assets {
        bounded_text(&asset.version)?;
        bounded_text(&asset.media_type)?;
        validate_digest(&asset.sha256)?;
    }
    for checkpoint in &body.checkpoints {
        validate_checkpoint(checkpoint)?;
    }
    for token in &body.timestamps {
        validate_digest(&token.subject_sha256)?;
        if token.response_der_base64.len() > 2 * 1024 * 1024 {
            return Err(Error::Blocked("Timestamp exceeds its byte budget".into()));
        }
    }
    Ok(())
}
fn bounded_text(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(Error::Input(
            "Evidence text must be bounded non-control text".into(),
        ));
    }
    Ok(())
}
fn validate_digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Input("Expected lower-case SHA-256 digest".into()));
    }
    Ok(())
}

const TRANSFER_DOMAIN: &[u8] = b"FileVeil transfer proposal v1\0";
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferProposalBody {
    pub schema: String,
    pub history: Vec<SignedRecord>,
    pub pending: SignedRecord,
    pub asset: EvidenceAsset,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferProposal {
    pub body: TransferProposalBody,
    pub signature: RecordSignature,
}

pub fn prepare_transfer(
    history: &[SignedRecord],
    asset: EvidenceAsset,
    recipient_key_id: &str,
    asserted_time: &str,
    copy_id: Option<&str>,
    sender: &SigningKey,
) -> Result<TransferProposal> {
    validate_digest(recipient_key_id)?;
    bounded_text(asserted_time)?;
    let previous = history
        .last()
        .ok_or_else(|| Error::Input("Transfer preparation requires a signed history".into()))?;
    let verified = signing::verify_chain(history, &asset.sha256, &TrustStore::default())?;
    if verified.signature != VerificationState::Valid
        || verified.chain != VerificationState::Valid
        || verified.content_binding != VerificationState::Valid
        || previous.body.version != asset.version
    {
        return Err(Error::Verification(
            "Transfer preparation requires the exact current signed asset".into(),
        ));
    }
    let active = previous
        .body
        .transfer_to_key_id
        .as_ref()
        .or(previous.body.rotation_to_key_id.as_ref())
        .unwrap_or(&previous.body.actor_key_id);
    if sender.public_key().key_id != *active || recipient_key_id == active {
        return Err(Error::Verification(
            "Only the active custodian can propose a transfer to a distinct recipient".into(),
        ));
    }
    let selected_copy = copy_id
        .map(str::to_owned)
        .or_else(|| previous.body.copy_id.clone())
        .ok_or_else(|| {
            Error::Input(
                "Upgrading a version-one transfer requires an explicit copy identifier".into(),
            )
        })?;
    let mut body = previous.body.clone();
    body.schema = signing::SCHEMA_V2.into();
    body.kind = signing::RecordKind::Transfer;
    body.mode = signing::SignMode::SelfSign;
    body.sequence = history.len() as u32;
    body.previous_record_sha256 = Some(signing::record_hash(previous)?);
    body.created_at = asserted_time.into();
    body.actor_key_id = active.clone();
    body.transfer_to_key_id = Some(recipient_key_id.into());
    body.rotation_to_key_id = None;
    body.transformation = None;
    body.issuer_policy = None;
    body.copy_id = Some(selected_copy);
    let pending = signing::sign_record(body, &[sender])?;
    let proposal_body = TransferProposalBody {
        schema: "fileveil.provenance.transfer_proposal.v1".into(),
        history: history.to_vec(),
        pending,
        asset,
    };
    let proposal = TransferProposal {
        signature: signing::sign_detached(TRANSFER_DOMAIN, &proposal_body, sender)?,
        body: proposal_body,
    };
    validate_transfer_proposal(&proposal)?;
    Ok(proposal)
}
pub fn parse_transfer_proposal(bytes: &[u8]) -> Result<TransferProposal> {
    if bytes.len() > MAX_EVIDENCE_BYTES {
        return Err(Error::Blocked(
            "Transfer proposal exceeds its byte budget".into(),
        ));
    }
    let proposal = serde_json::from_slice(bytes)
        .map_err(|_| Error::Input("Invalid strict transfer proposal JSON".into()))?;
    validate_transfer_proposal(&proposal)?;
    Ok(proposal)
}
pub fn canonical_transfer_proposal(proposal: &TransferProposal) -> Result<Vec<u8>> {
    validate_transfer_proposal(proposal)?;
    signing::canonical(proposal)
}

fn validate_transfer_proposal(proposal: &TransferProposal) -> Result<()> {
    let body = &proposal.body;
    if body.schema != "fileveil.provenance.transfer_proposal.v1"
        || body.history.is_empty()
        || body.history.len() >= signing::MAX_RECORDS
        || body.pending.body.schema != signing::SCHEMA_V2
        || body.pending.body.kind != signing::RecordKind::Transfer
        || body.pending.body.mode != signing::SignMode::SelfSign
        || body.pending.signatures.len() != 1
        || body.pending.signatures[0].key_id != body.pending.body.actor_key_id
        || proposal.signature.key_id != body.pending.body.actor_key_id
    {
        return Err(Error::Input(
            "Invalid single-sender transfer proposal".into(),
        ));
    }
    if signing::canonical(proposal)?.len() > MAX_EVIDENCE_BYTES {
        return Err(Error::Blocked(
            "Transfer proposal exceeds its byte budget".into(),
        ));
    }
    signing::verify_detached(TRANSFER_DOMAIN, body, &proposal.signature)?;
    let prior = signing::verify_chain(&body.history, &body.asset.sha256, &TrustStore::default())?;
    if prior.signature != VerificationState::Valid
        || prior.chain != VerificationState::Valid
        || prior.content_binding != VerificationState::Valid
        || body.asset.sha256 != body.pending.body.content_sha256
        || body.asset.version != body.pending.body.version
    {
        return Err(Error::Verification(
            "Transfer proposal history or asset declaration does not verify".into(),
        ));
    }
    let mut provisional = body.history.clone();
    provisional.push(body.pending.clone());
    let checked = signing::verify_chain(&provisional, &body.asset.sha256, &TrustStore::default())?;
    let codes = &checked.records.last().unwrap().evidence_codes;
    let allowed = [
        "self_signature_identity_not_authenticated",
        "recipient_acceptance_signature_required_v2",
        "transfer_recipient_acceptance_not_assessed",
    ];
    if checked.signature != VerificationState::Valid
        || checked.content_binding != VerificationState::Valid
        || !codes
            .iter()
            .any(|code| code == "recipient_acceptance_signature_required_v2")
        || codes.iter().any(|code| !allowed.contains(&code.as_str()))
    {
        return Err(Error::Verification(
            "Transfer proposal has invalid predecessor, sender or custody fields".into(),
        ));
    }
    bounded_text(&body.asset.version)?;
    bounded_text(&body.asset.media_type)?;
    Ok(())
}

pub fn accept_transfer(
    proposal: &TransferProposal,
    recipient: &SigningKey,
) -> Result<EvidencePackage> {
    validate_transfer_proposal(proposal)?;
    if proposal.body.pending.body.transfer_to_key_id.as_deref()
        != Some(recipient.public_key().key_id.as_str())
    {
        return Err(Error::Blocked(
            "The selected key is not the proposal's designated recipient".into(),
        ));
    }
    let mut accepted = proposal.body.pending.clone();
    signing::append_signature(&mut accepted, recipient)?;
    let mut history = proposal.body.history.clone();
    history.push(accepted);
    create_evidence(
        &history,
        vec![proposal.body.asset.clone()],
        Vec::new(),
        Vec::new(),
        recipient,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use signing::{RecordBody, RecordKind, SCHEMA_V2};
    fn record(key: &SigningKey, content: &[u8]) -> SignedRecord {
        let mut body = RecordBody::new(
            digest(content),
            "work-α".into(),
            "Synthetic author".into(),
            "1".into(),
            "2026-11-12T00:00:00Z".into(),
            key.public_key().key_id,
        );
        body.schema = SCHEMA_V2.into();
        body.copy_id = Some("copy-1".into());
        signing::append_record(&[], body, &[key]).unwrap()
    }
    #[test]
    fn external_checkpoint_detects_truncation_forks_and_mutations() {
        let owner = SigningKey::generate().unwrap();
        let witness = SigningKey::generate().unwrap();
        let mut history = vec![record(&owner, b"v1")];
        let mut change = history[0].body.clone();
        change.kind = RecordKind::Modify;
        change.version = "2".into();
        change.content_sha256 = digest(b"v2");
        history.push(signing::append_record(&history, change, &[&owner]).unwrap());
        let checkpoint = create_checkpoint(&history, "2026-11-12T12:00:00Z", &witness).unwrap();
        let checked = verify_checkpoint(&checkpoint, &history, &[witness.public_key()]).unwrap();
        assert_eq!(checked.signature, VerificationState::Valid);
        assert_eq!(checked.trust, VerificationState::Valid);
        assert_eq!(checked.history_binding, VerificationState::Valid);
        assert_eq!(
            verify_checkpoint(&checkpoint, &history, &[]).unwrap().trust,
            VerificationState::Untrusted
        );
        assert_eq!(
            verify_checkpoint(&checkpoint, &history[..1], &[witness.public_key()])
                .unwrap()
                .history_binding,
            VerificationState::Invalid
        );
        let other = vec![record(&owner, b"another asset")];
        assert_eq!(
            verify_checkpoint(&checkpoint, &other, &[witness.public_key()])
                .unwrap()
                .history_binding,
            VerificationState::Invalid
        );
        let mut changed = checkpoint;
        changed.body.asserted_time.push('!');
        assert_eq!(
            verify_checkpoint(&changed, &history, &[witness.public_key()])
                .unwrap()
                .signature,
            VerificationState::Invalid
        );
    }
    #[test]
    fn evidence_binds_declarations_and_requires_active_custodian_signature() {
        let owner = SigningKey::generate().unwrap();
        let other = SigningKey::generate().unwrap();
        let history = vec![record(&owner, b"asset")];
        let assets = vec![EvidenceAsset {
            version: "1".into(),
            sha256: digest(b"asset"),
            media_type: "image/png".into(),
            size_bytes: 5,
        }];
        assert!(create_evidence(&history, assets.clone(), vec![], vec![], &other).is_err());
        let package = create_evidence(&history, assets, vec![], vec![], &owner).unwrap();
        let bytes = canonical_evidence(&package).unwrap();
        let parsed = parse_evidence(&bytes).unwrap();
        let checked = verify_evidence(&parsed, &TrustStore::default(), &[], None).unwrap();
        assert_eq!(checked.package_signature, VerificationState::Valid);
        assert_eq!(checked.custody_signer, VerificationState::Valid);
        assert!(checked.asset_declarations_bound);
        assert!(!checked.asset_bytes_assessed);
        let mut changed = parsed;
        changed.body.assets[0].sha256 = digest(b"altered");
        let checked = verify_evidence(&changed, &TrustStore::default(), &[], None).unwrap();
        assert_eq!(checked.package_signature, VerificationState::Invalid);
        assert!(!checked.asset_declarations_bound);
        assert!(parse_evidence(b"{\"body\":{},\"unexpected\":1}").is_err());
    }
    #[test]
    #[ignore = "Independent Python/OpenSSL evidence verifier interoperability"]
    fn standalone_python_openssl_verifies_public_evidence_and_rejects_tampering() {
        let owner = SigningKey::generate().unwrap();
        let witness = SigningKey::generate().unwrap();
        let history = vec![record(&owner, b"asset")];
        let checkpoint = create_checkpoint(&history, "2026-11-12T12:00:00Z", &witness).unwrap();
        let package = create_evidence(
            &history,
            vec![EvidenceAsset {
                version: "1".into(),
                sha256: digest(b"asset"),
                media_type: "image/png".into(),
                size_bytes: 5,
            }],
            vec![checkpoint],
            vec![],
            &owner,
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let evidence = directory.path().join("evidence.json");
        std::fs::write(&evidence, canonical_evidence(&package).unwrap()).unwrap();
        let asset = directory.path().join("asset.png");
        std::fs::write(&asset, b"asset").unwrap();
        let script =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/verify-evidence.py");
        let run = |path: &std::path::Path| {
            std::process::Command::new(if cfg!(windows) { "python" } else { "python3" })
                .arg(&script)
                .arg(path)
                .arg("--asset")
                .arg(&asset)
                .arg("--checkpoint-key")
                .arg(witness.public_key().ed25519_hex)
                .output()
                .unwrap()
        };
        let output = run(&evidence);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let decoded: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(decoded["package_signature"], "valid");
        assert_eq!(decoded["provided_assets_verified"], 1);
        let mut altered = package;
        altered.body.records[0].body.author = "Tampered".into();
        std::fs::write(&evidence, canonical_evidence(&altered).unwrap()).unwrap();
        assert!(!run(&evidence).status.success());
    }
}
