// SPDX-License-Identifier: MPL-2.0
//! FileVeil's independent, offline Heritage signatures.
//!
//! Woolim's published SELFSIGN and NATISIGN describe device-created files and
//! authority-approved distribution respectively. This module preserves that role
//! distinction using Ed25519. Its versioned JSON format is independent of the
//! original RSA/Rijndael trailers and carries no device identifiers.
//!
//! Signed bytes are `SIGNING_DOMAIN || canonical(record body)`. Canonical JSON is
//! the RFC 8785 subset used by these typed structures: fixed ASCII property names,
//! UTF-8 strings preserved without normalization, integer values within the I-JSON
//! exact range, ordered arrays, sorted properties, and no whitespace or floats.
//! Deserialization rejects unknown and duplicate fields. A predecessor digest
//! binds the complete finalized predecessor, including its sorted signatures.
//! Finish co-signing a record before appending another record.

use ed25519_dalek::{Signature, Signer, SigningKey as DalekSigningKey, VerifyingKey};
use fileveil_core::{Error, Result, digest};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashSet},
    fmt,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub const SCHEMA: &str = "fileveil.heritage.signature.v1";
pub const SCHEMA_V2: &str = "fileveil.provenance.signature.v2";
pub const ALGORITHM: &str = "Ed25519";
pub const MAX_RECORDS: usize = 256;
pub const MAX_SIGNERS: usize = 32;
pub const MAX_HISTORY_BYTES: usize = 4 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_KEY_BYTES: u64 = 16 * 1024;
const KEY_MAGIC: &[u8] = b"FILEVEIL-ED25519-KEY-V1\n";
const SIGNING_DOMAIN: &[u8] = b"FileVeil Heritage signature v1\0";
const RECORD_DOMAIN: &[u8] = b"FileVeil Heritage finalized record v1\0";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignMode {
    SelfSign,
    NatiSign,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    Create,
    Modify,
    Issue,
    Transfer,
    RotateKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicKey {
    /// Lower-case SHA-256 of the 32 raw public-key bytes.
    pub key_id: String,
    pub ed25519_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuerPolicy {
    pub threshold: u16,
    pub allowed_key_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Transformation {
    pub source_sha256: String,
    pub source_format: String,
    pub target_format: String,
    pub operation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecordBody {
    pub schema: String,
    pub algorithm: String,
    pub kind: RecordKind,
    pub mode: SignMode,
    pub sequence: u32,
    pub previous_record_sha256: Option<String>,
    pub content_sha256: String,
    pub work_id: String,
    /// A signed author assertion, without independent identity authentication.
    pub author: String,
    pub edition: String,
    pub version: String,
    pub parent_version: Option<String>,
    /// User-asserted time. An offline signature supplies no trusted timestamp.
    pub created_at: String,
    pub actor_key_id: String,
    pub transfer_to_key_id: Option<String>,
    pub issuer_policy: Option<IssuerPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_to_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transformation: Option<Transformation>,
}

impl RecordBody {
    pub fn new(
        content_sha256: String,
        work_id: String,
        author: String,
        version: String,
        created_at: String,
        actor_key_id: String,
    ) -> Self {
        Self {
            schema: SCHEMA.into(),
            algorithm: ALGORITHM.into(),
            kind: RecordKind::Create,
            mode: SignMode::SelfSign,
            sequence: 0,
            previous_record_sha256: None,
            content_sha256,
            work_id,
            author,
            edition: String::new(),
            version,
            parent_version: None,
            created_at,
            actor_key_id,
            transfer_to_key_id: None,
            issuer_policy: None,
            copy_id: None,
            rotation_to_key_id: None,
            transformation: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecordSignature {
    pub key_id: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedRecord {
    pub body: RecordBody,
    pub signatures: Vec<RecordSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustStore {
    /// Explicit local trust anchors. Payload-supplied keys never populate this.
    pub trusted_issuers: Vec<PublicKey>,
    pub minimum_issuer_signatures: u16,
}

impl Default for TrustStore {
    fn default() -> Self {
        Self {
            trusted_issuers: Vec::new(),
            minimum_issuer_signatures: 1,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    Valid,
    Invalid,
    Untrusted,
    NotAssessed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordVerification {
    pub sequence: u32,
    pub mode: SignMode,
    pub signature: VerificationState,
    pub trust: VerificationState,
    pub valid_signer_key_ids: Vec<String>,
    pub trusted_issuer_signatures: usize,
    pub author_declared: bool,
    pub author_claim_sha256: String,
    pub evidence_codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainVerification {
    pub signature: VerificationState,
    pub content_binding: VerificationState,
    pub chain: VerificationState,
    pub trust: VerificationState,
    pub record_count: usize,
    pub records: Vec<RecordVerification>,
    pub evidence_codes: Vec<String>,
}

/// Secret material has no Serialize or Clone implementation and redacted Debug.
pub struct SigningKey {
    inner: DalekSigningKey,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SigningKey([REDACTED])")
    }
}

impl SigningKey {
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(seed.as_mut())
            .map_err(|_| Error::Io("Could not obtain secure signing-key randomness".into()))?;
        Ok(Self {
            inner: DalekSigningKey::from_bytes(&seed),
        })
    }

    pub fn public_key(&self) -> PublicKey {
        let raw = self.inner.verifying_key().to_bytes();
        PublicKey {
            key_id: digest(&raw),
            ed25519_hex: hex(&raw),
        }
    }

    /// RFC 5869 extract/expand with a fixed domain-separated salt and info.
    /// A distinct key is used for pixel frames, keeping signing seeds private.
    pub fn derive_watermark_key(&self) -> Zeroizing<[u8; 32]> {
        use hmac::{Hmac, KeyInit, Mac};
        type HmacSha256 = Hmac<sha2_v11::Sha256>;
        let seed = Zeroizing::new(self.inner.to_bytes());
        let mut extract = HmacSha256::new_from_slice(b"FileVeil Watermark Engine 2.0 HKDF salt")
            .expect("HMAC accepts this fixed salt");
        extract.update(seed.as_ref());
        let prk = Zeroizing::new(<[u8; 32]>::from(extract.finalize().into_bytes()));
        let mut expand = HmacSha256::new_from_slice(prk.as_ref())
            .expect("HMAC accepts the SHA-256 extract output");
        expand.update(b"FileVeil watermark keyed embedding v2\0\x01");
        Zeroizing::new(<[u8; 32]>::from(expand.finalize().into_bytes()))
    }

    pub(crate) fn secret_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.inner.to_bytes())
    }

    pub(crate) fn from_secret_seed(seed: &[u8; 32]) -> Self {
        Self {
            inner: DalekSigningKey::from_bytes(seed),
        }
    }

    /// Creates a new private file, with no replacement of an existing path.
    pub fn save_new(&self, path: &Path) -> Result<()> {
        let mut file = private_file(path, true)?;
        let seed = Zeroizing::new(self.inner.to_bytes());
        file.write_all(KEY_MAGIC)
            .and_then(|_| file.write_all(seed.as_ref()))
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::Io("Could not persist local signing key".into()))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let encoded = read_private_key_bytes(path)?;
        if encoded.len() != KEY_MAGIC.len() + 32 || !encoded.starts_with(KEY_MAGIC) {
            return Err(Error::Input("Invalid local Ed25519 key format".into()));
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&encoded[KEY_MAGIC.len()..]);
        Ok(Self {
            inner: DalekSigningKey::from_bytes(&seed),
        })
    }
}

/// Shared private-key loader for local Ed25519 files and explicitly selected PEM
/// keys. The buffer zeroizes on drop and is never included in a public report.
pub(crate) fn read_private_key_bytes(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = if let Some(file) = crate::access_guard::open_bound(path)? {
        validate_private_file(&file)?;
        file
    } else {
        private_file(path, false)?
    };
    let mut encoded = Zeroizing::new(Vec::new());
    Read::by_ref(&mut file)
        .take(MAX_KEY_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|_| Error::Io("Could not read local private key".into()))?;
    if encoded.len() as u64 > MAX_KEY_BYTES {
        return Err(Error::Blocked(
            "Local private key exceeds its byte limit".into(),
        ));
    }
    Ok(encoded)
}

pub fn parse_records(bytes: &[u8]) -> Result<Vec<SignedRecord>> {
    if bytes.len() > MAX_HISTORY_BYTES {
        return Err(Error::Blocked(
            "Heritage history exceeds its byte limit".into(),
        ));
    }
    let records: Vec<SignedRecord> = serde_json::from_slice(bytes)
        .map_err(|_| Error::Input("Invalid or non-strict Heritage history JSON".into()))?;
    validate_history(&records)?;
    Ok(records)
}

pub fn canonical_records(records: &[SignedRecord]) -> Result<Vec<u8>> {
    validate_history(records)?;
    canonical(records)
}

pub fn sign_record(body: RecordBody, keys: &[&SigningKey]) -> Result<SignedRecord> {
    validate_body(&body)?;
    if keys.is_empty() || keys.len() > MAX_SIGNERS {
        return Err(Error::Input(
            "Provide between one and 32 signing keys".into(),
        ));
    }
    let mut record = SignedRecord {
        body,
        signatures: Vec::new(),
    };
    for key in keys {
        append_signature(&mut record, key)?;
    }
    if !record
        .signatures
        .iter()
        .any(|s| s.key_id == record.body.actor_key_id)
    {
        return Err(Error::Input(
            "The custody actor must sign the record".into(),
        ));
    }
    Ok(record)
}

pub fn append_signature(record: &mut SignedRecord, key: &SigningKey) -> Result<()> {
    validate_body(&record.body)?;
    if record.signatures.len() >= MAX_SIGNERS {
        return Err(Error::Blocked(
            "Heritage signature count exceeds its limit".into(),
        ));
    }
    let public = key.public_key();
    if record.signatures.iter().any(|s| s.key_id == public.key_id) {
        return Err(Error::Input(
            "A key may sign each Heritage record once".into(),
        ));
    }
    let bytes = signing_bytes(&record.body)?;
    record.signatures.push(RecordSignature {
        key_id: public.key_id,
        public_key_hex: public.ed25519_hex,
        signature_hex: hex(&key.inner.sign(&bytes).to_bytes()),
    });
    record.signatures.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    Ok(())
}

/// Binds all predecessor signatures. Co-signing a predecessor changes this hash.
pub fn record_hash(record: &SignedRecord) -> Result<String> {
    validate_history(std::slice::from_ref(record))?;
    let mut normalized = record.clone();
    normalized
        .signatures
        .sort_by(|a, b| a.key_id.cmp(&b.key_id));
    let mut bytes = if record.body.schema == SCHEMA_V2 {
        b"FileVeil provenance finalized record v2\0".to_vec()
    } else {
        RECORD_DOMAIN.to_vec()
    };
    bytes.extend(canonical(&normalized)?);
    Ok(digest(&bytes))
}

/// Assigns sequence and predecessor binding, and checks the complete resulting
/// custody chain. Existing records can be inherited from an explicit prior asset.
pub fn append_record(
    history: &[SignedRecord],
    mut body: RecordBody,
    keys: &[&SigningKey],
) -> Result<SignedRecord> {
    if history.len() >= MAX_RECORDS {
        return Err(Error::Blocked(
            "Heritage history exceeds its record limit".into(),
        ));
    }
    body.sequence = history.len() as u32;
    body.previous_record_sha256 = history.last().map(record_hash).transpose()?;
    if let Some(previous) = history.last() {
        body.parent_version = if body.kind == RecordKind::Modify {
            Some(previous.body.version.clone())
        } else {
            previous.body.parent_version.clone()
        };
    }
    let current = sign_record(body, keys)?;
    let mut candidate = history.to_vec();
    candidate.push(current.clone());
    let verified = verify_chain(
        &candidate,
        &current.body.content_sha256,
        &TrustStore::default(),
    )?;
    if verified.signature != VerificationState::Valid || verified.chain != VerificationState::Valid
    {
        return Err(Error::Verification(
            "The resulting Heritage custody chain is invalid".into(),
        ));
    }
    Ok(current)
}

pub fn verify_chain(
    history: &[SignedRecord],
    expected_content_sha256: &str,
    trust_store: &TrustStore,
) -> Result<ChainVerification> {
    validate_digest(expected_content_sha256)?;
    validate_history(history)?;
    let anchors = trusted_anchors(trust_store)?;
    if history.is_empty() {
        return Ok(ChainVerification {
            signature: VerificationState::NotAssessed,
            content_binding: VerificationState::NotAssessed,
            chain: VerificationState::NotAssessed,
            trust: VerificationState::NotAssessed,
            record_count: 0,
            records: Vec::new(),
            evidence_codes: vec!["heritage_signature_absent".into()],
        });
    }
    let mut records = Vec::with_capacity(history.len());
    let mut chain_valid = true;
    let mut custodian: Option<&str> = None;
    let mut previous: Option<&SignedRecord> = None;
    for (index, record) in history.iter().enumerate() {
        let mut result = verify_record(record, trust_store, &anchors)?;
        let body = &record.body;
        if body.sequence as usize != index {
            chain_valid = false;
            result
                .evidence_codes
                .push("record_sequence_mismatch".into());
        }
        if let Some(prior) = previous {
            if body.kind == RecordKind::Create
                || body.previous_record_sha256.as_deref() != Some(record_hash(prior)?.as_str())
                || body.work_id != prior.body.work_id
                || (body.schema == SCHEMA_V2
                    && prior.body.schema == SCHEMA_V2
                    && body.copy_id != prior.body.copy_id
                    && body.kind != RecordKind::Issue)
                || (body.schema == SCHEMA && prior.body.schema == SCHEMA_V2)
                || Some(body.actor_key_id.as_str()) != custodian
            {
                chain_valid = false;
                result
                    .evidence_codes
                    .push("predecessor_or_custody_mismatch".into());
            }
            let version_valid = if body.kind == RecordKind::Modify {
                body.version != prior.body.version
                    && body.parent_version.as_deref() == Some(prior.body.version.as_str())
            } else {
                body.content_sha256 == prior.body.content_sha256
                    && body.version == prior.body.version
                    && body.parent_version == prior.body.parent_version
                    && body.author == prior.body.author
                    && (body.kind == RecordKind::Issue || body.edition == prior.body.edition)
            };
            if !version_valid {
                chain_valid = false;
                result
                    .evidence_codes
                    .push("content_or_version_transition_invalid".into());
            }
        } else if body.kind != RecordKind::Create
            || body.previous_record_sha256.is_some()
            || body.parent_version.is_some()
        {
            chain_valid = false;
            result
                .evidence_codes
                .push("creation_record_required".into());
        }
        if !result.valid_signer_key_ids.contains(&body.actor_key_id) {
            chain_valid = false;
            result
                .evidence_codes
                .push("custody_actor_signature_missing".into());
        }
        if body.schema == SCHEMA_V2 {
            let recipient = body
                .transfer_to_key_id
                .as_ref()
                .or(body.rotation_to_key_id.as_ref());
            if recipient.is_some_and(|id| !result.valid_signer_key_ids.contains(id)) {
                chain_valid = false;
                result
                    .evidence_codes
                    .push("recipient_acceptance_signature_required_v2".into());
            }
            if let Some(change) = &body.transformation
                && previous.is_none_or(|prior| change.source_sha256 != prior.body.content_sha256)
            {
                chain_valid = false;
                result
                    .evidence_codes
                    .push("transformation_source_binding_invalid".into());
            }
        }
        custodian = Some(
            body.transfer_to_key_id
                .as_deref()
                .or(body.rotation_to_key_id.as_deref())
                .unwrap_or(&body.actor_key_id),
        );
        if let Some(recipient) = &body.transfer_to_key_id {
            result
                .evidence_codes
                .push(if result.valid_signer_key_ids.contains(recipient) {
                    "transfer_recipient_cosigned".into()
                } else {
                    "transfer_recipient_acceptance_not_assessed".into()
                });
        }
        previous = Some(record);
        records.push(result);
    }
    let signature_valid = records
        .iter()
        .all(|r| r.signature == VerificationState::Valid);
    let issuances: Vec<_> = records
        .iter()
        .filter(|r| r.mode == SignMode::NatiSign)
        .collect();
    let trust = if issuances.is_empty() {
        VerificationState::NotAssessed
    } else if issuances
        .iter()
        .all(|r| r.trust == VerificationState::Valid)
    {
        VerificationState::Valid
    } else {
        VerificationState::Untrusted
    };
    Ok(ChainVerification {
        signature: state(signature_valid),
        content_binding: state(
            history
                .last()
                .is_some_and(|r| r.body.content_sha256 == expected_content_sha256),
        ),
        chain: state(chain_valid),
        trust,
        record_count: history.len(),
        records,
        evidence_codes: vec![
            "offline_ed25519_strict_verification".into(),
            "author_and_time_are_signed_assertions".into(),
            "historical_content_digests_require_prior_assets_for_recomputation".into(),
            "trust_anchors_are_local_configuration_only".into(),
            "key_revocation_and_trusted_timestamp_not_assessed".into(),
        ],
    })
}

fn verify_record(
    record: &SignedRecord,
    store: &TrustStore,
    anchors: &HashSet<String>,
) -> Result<RecordVerification> {
    let bytes = signing_bytes(&record.body)?;
    let mut valid = BTreeSet::new();
    let mut seen = HashSet::new();
    let mut all_valid = !record.signatures.is_empty();
    let mut evidence_codes = Vec::new();
    for entry in &record.signatures {
        let verified = (|| {
            let public = parse_public(&PublicKey {
                key_id: entry.key_id.clone(),
                ed25519_hex: entry.public_key_hex.clone(),
            })?;
            let signature = Signature::from_bytes(&unhex::<64>(&entry.signature_hex)?);
            public
                .verify_strict(&bytes, &signature)
                .map_err(|_| Error::Verification("Invalid Ed25519 signature".into()))
        })();
        if !seen.insert(entry.key_id.as_str()) || verified.is_err() {
            all_valid = false;
            evidence_codes.push("invalid_or_duplicate_signature".into());
        } else {
            valid.insert(entry.key_id.clone());
        }
    }
    let mut trusted_count = 0;
    let trust = if let Some(policy) = &record.body.issuer_policy {
        trusted_count = valid
            .iter()
            .filter(|id| anchors.contains(*id) && policy.allowed_key_ids.contains(*id))
            .count();
        let threshold = policy.threshold.max(store.minimum_issuer_signatures) as usize;
        if all_valid && trusted_count >= threshold {
            VerificationState::Valid
        } else {
            evidence_codes.push("trusted_distinct_issuer_threshold_not_met".into());
            VerificationState::Untrusted
        }
    } else {
        evidence_codes.push("self_signature_identity_not_authenticated".into());
        VerificationState::NotAssessed
    };
    Ok(RecordVerification {
        sequence: record.body.sequence,
        mode: record.body.mode,
        signature: state(all_valid),
        trust,
        valid_signer_key_ids: valid.into_iter().collect(),
        trusted_issuer_signatures: trusted_count,
        author_declared: !record.body.author.is_empty(),
        author_claim_sha256: digest(record.body.author.as_bytes()),
        evidence_codes,
    })
}

pub(crate) fn sign_detached<T: Serialize>(
    domain: &[u8],
    body: &T,
    key: &SigningKey,
) -> Result<RecordSignature> {
    let mut bytes = domain.to_vec();
    bytes.extend(canonical(body)?);
    let public = key.public_key();
    Ok(RecordSignature {
        key_id: public.key_id,
        public_key_hex: public.ed25519_hex,
        signature_hex: hex(&key.inner.sign(&bytes).to_bytes()),
    })
}

pub(crate) fn verify_detached<T: Serialize>(
    domain: &[u8],
    body: &T,
    signature: &RecordSignature,
) -> Result<()> {
    let public = parse_public(&PublicKey {
        key_id: signature.key_id.clone(),
        ed25519_hex: signature.public_key_hex.clone(),
    })?;
    let mut bytes = domain.to_vec();
    bytes.extend(canonical(body)?);
    public
        .verify_strict(
            &bytes,
            &Signature::from_bytes(&unhex::<64>(&signature.signature_hex)?),
        )
        .map_err(|_| Error::Verification("Invalid detached Ed25519 signature".into()))
}

fn state(valid: bool) -> VerificationState {
    if valid {
        VerificationState::Valid
    } else {
        VerificationState::Invalid
    }
}

fn validate_history(records: &[SignedRecord]) -> Result<()> {
    if records.len() > MAX_RECORDS {
        return Err(Error::Blocked(
            "Heritage history exceeds its record limit".into(),
        ));
    }
    let mut total = 0usize;
    for record in records {
        validate_body(&record.body)?;
        if record.signatures.len() > MAX_SIGNERS {
            return Err(Error::Blocked(
                "Heritage signature count exceeds its limit".into(),
            ));
        }
        if record.signatures.iter().any(|s| {
            s.key_id.len() > 64 || s.public_key_hex.len() > 64 || s.signature_hex.len() > 128
        }) {
            return Err(Error::Blocked(
                "Heritage signature encoding exceeds its length limit".into(),
            ));
        }
        let size = canonical(record)?.len();
        total = total.saturating_add(size);
        if size > MAX_RECORD_BYTES || total > MAX_HISTORY_BYTES {
            return Err(Error::Blocked(
                "Heritage history exceeds its byte limit".into(),
            ));
        }
    }
    Ok(())
}

fn validate_body(body: &RecordBody) -> Result<()> {
    if !matches!(body.schema.as_str(), SCHEMA | SCHEMA_V2) || body.algorithm != ALGORITHM {
        return Err(Error::Unsupported(
            "Unsupported Heritage schema or signature algorithm".into(),
        ));
    }
    if body.schema == SCHEMA {
        if body.copy_id.is_some()
            || body.rotation_to_key_id.is_some()
            || body.transformation.is_some()
            || body.kind == RecordKind::RotateKey
        {
            return Err(Error::Input(
                "Version-one signatures cannot contain version-two fields".into(),
            ));
        }
    } else {
        if body
            .copy_id
            .as_ref()
            .is_none_or(|id| id.is_empty() || id.len() > 4096)
        {
            return Err(Error::Input(
                "Version-two signatures require a bounded copy identifier".into(),
            ));
        }
        if (body.kind == RecordKind::RotateKey) != body.rotation_to_key_id.is_some()
            || body.rotation_to_key_id.as_deref() == Some(body.actor_key_id.as_str())
        {
            return Err(Error::Input(
                "Key rotation requires a distinct successor key".into(),
            ));
        }
        if let Some(id) = &body.rotation_to_key_id {
            validate_digest(id)?;
        }
        if let Some(change) = &body.transformation {
            validate_digest(&change.source_sha256)?;
            if body.kind != RecordKind::Modify
                || [
                    &change.source_format,
                    &change.target_format,
                    &change.operation,
                ]
                .iter()
                .any(|text| {
                    text.is_empty() || text.len() > 256 || text.chars().any(char::is_control)
                })
            {
                return Err(Error::Input(
                    "A transformation requires a modification and bounded format/operation labels"
                        .into(),
                ));
            }
        }
    }
    validate_digest(&body.content_sha256)?;
    validate_digest(&body.actor_key_id)?;
    for digest in [&body.previous_record_sha256, &body.transfer_to_key_id]
        .into_iter()
        .flatten()
    {
        validate_digest(digest)?;
    }
    for text in [
        &body.work_id,
        &body.author,
        &body.edition,
        &body.version,
        &body.created_at,
    ] {
        if text.len() > 4096 {
            return Err(Error::Blocked(
                "Heritage statement text exceeds its length limit".into(),
            ));
        }
    }
    if body.work_id.is_empty()
        || body.version.is_empty()
        || body.created_at.is_empty()
        || body
            .parent_version
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 4096)
    {
        return Err(Error::Input(
            "Heritage work, version and asserted time must be present".into(),
        ));
    }
    if (body.kind == RecordKind::Transfer) != body.transfer_to_key_id.is_some()
        || body.transfer_to_key_id.as_deref() == Some(body.actor_key_id.as_str())
    {
        return Err(Error::Input(
            "A custody transfer requires a distinct recipient key ID".into(),
        ));
    }
    match (&body.mode, &body.issuer_policy) {
        (SignMode::SelfSign, None) => {}
        (SignMode::NatiSign, Some(policy)) => {
            let distinct: HashSet<_> = policy.allowed_key_ids.iter().collect();
            if policy.threshold == 0
                || policy.threshold as usize > distinct.len()
                || distinct.len() != policy.allowed_key_ids.len()
                || distinct.len() > MAX_SIGNERS
            {
                return Err(Error::Input(
                    "Invalid distinct-issuer signature policy".into(),
                ));
            }
            for id in &policy.allowed_key_ids {
                validate_digest(id)?;
            }
        }
        _ => {
            return Err(Error::Input(
                "Heritage signing mode and issuer policy disagree".into(),
            ));
        }
    }
    Ok(())
}

fn trusted_anchors(store: &TrustStore) -> Result<HashSet<String>> {
    if store.trusted_issuers.len() > MAX_SIGNERS
        || store.minimum_issuer_signatures == 0
        || store.minimum_issuer_signatures as usize > MAX_SIGNERS
    {
        return Err(Error::Input("Invalid local issuer trust policy".into()));
    }
    let mut anchors = HashSet::new();
    for key in &store.trusted_issuers {
        parse_public(key)?;
        if !anchors.insert(key.key_id.clone()) {
            return Err(Error::Input("Duplicate local issuer trust anchor".into()));
        }
    }
    Ok(anchors)
}

fn parse_public(public: &PublicKey) -> Result<VerifyingKey> {
    let raw = unhex::<32>(&public.ed25519_hex)?;
    if public.key_id != digest(&raw) {
        return Err(Error::Input(
            "Heritage public-key ID does not match its key".into(),
        ));
    }
    let key = VerifyingKey::from_bytes(&raw)
        .map_err(|_| Error::Input("Invalid Ed25519 public key".into()))?;
    if key.is_weak()
        || !key.to_edwards().is_torsion_free()
        || key.to_edwards().compress().to_bytes() != raw
    {
        return Err(Error::Input(
            "Non-canonical or weak Ed25519 public key rejected".into(),
        ));
    }
    Ok(key)
}

fn validate_digest(value: &str) -> Result<()> {
    unhex::<32>(value).map(|_| ())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 15) as usize] as char);
    }
    encoded
}

fn unhex<const N: usize>(text: &str) -> Result<[u8; N]> {
    if text.len() != N * 2 {
        return Err(Error::Input(
            "Invalid lower-case hexadecimal field length".into(),
        ));
    }
    let mut decoded = [0; N];
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    for (output, pair) in decoded.iter_mut().zip(pairs) {
        let nibble = |byte| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(Error::Input("Invalid lower-case hexadecimal field".into())),
        };
        *output = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(decoded)
}

fn signing_bytes(body: &RecordBody) -> Result<Vec<u8>> {
    let mut bytes = if body.schema == SCHEMA_V2 {
        b"FileVeil provenance signature v2\0".to_vec()
    } else {
        SIGNING_DOMAIN.to_vec()
    };
    bytes.extend(canonical(body)?);
    Ok(bytes)
}

pub(crate) fn canonical<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)
        .map_err(|_| Error::Input("Could not encode Heritage canonical JSON".into()))?;
    let mut bytes = Vec::new();
    write_canonical(&value, &mut bytes)?;
    Ok(bytes)
}

fn write_canonical(value: &serde_json::Value, output: &mut Vec<u8>) -> Result<()> {
    use serde_json::Value;
    match value {
        Value::Object(object) => {
            let mut keys: Vec<_> = object.keys().collect();
            if keys.iter().any(|key| !key.is_ascii()) {
                return Err(Error::Input(
                    "Unsupported canonical JSON property name".into(),
                ));
            }
            keys.sort();
            output.push(b'{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)
                    .map_err(|_| Error::Input("Could not encode canonical JSON key".into()))?;
                output.push(b':');
                write_canonical(&object[*key], output)?;
            }
            output.push(b'}');
        }
        Value::Array(array) => {
            output.push(b'[');
            for (index, entry) in array.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical(entry, output)?;
            }
            output.push(b']');
        }
        Value::Number(number) if number.as_u64().is_none_or(|n| n > 9_007_199_254_740_991) => {
            return Err(Error::Input(
                "Heritage canonical JSON permits exact non-negative integers only".into(),
            ));
        }
        _ => serde_json::to_writer(output, value)
            .map_err(|_| Error::Input("Could not encode canonical JSON value".into()))?,
    }
    Ok(())
}

fn key_path(path: &Path) -> Result<(PathBuf, std::ffi::OsString)> {
    let name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| Error::Input("A local signing-key filename is required".into()))?;
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(Error::Input(
            "Parent traversal is not allowed in signing-key paths".into(),
        ));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = std::fs::canonicalize(parent)
        .map_err(|_| Error::Io("Could not resolve local signing-key directory".into()))?;
    Ok((parent, name.into()))
}

#[cfg(unix)]
fn private_file(path: &Path, create: bool) -> Result<File> {
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::ffi::OsStrExt,
        },
    };
    let (parent, name) = key_path(path)?;
    let mut directory = File::open("/")
        .map_err(|_| Error::Io("Could not open signing-key filesystem root".into()))?;
    for component in parent.components() {
        let std::path::Component::Normal(name) = component else {
            continue;
        };
        let name = CString::new(name.as_bytes())
            .map_err(|_| Error::Input("Invalid signing-key directory component".into()))?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(Error::Io(
                "Could not bind signing-key directory without links".into(),
            ));
        }
        directory = unsafe { File::from_raw_fd(fd) };
    }
    let name = CString::new(name.as_bytes())
        .map_err(|_| Error::Input("Invalid signing-key filename".into()))?;
    let access = if create {
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL
    } else {
        libc::O_RDONLY
    };
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            access | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(Error::Io(
            "Could not open private signing-key file without replacement or links".into(),
        ));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    validate_private_file(&file)?;
    Ok(file)
}

#[cfg(unix)]
fn validate_private_file(file: &File) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file
        .metadata()
        .map_err(|_| Error::Io("Could not inspect private signing key".into()))?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.len() > MAX_KEY_BYTES
    {
        return Err(Error::Blocked(
            "Signing keys require a private owner-only regular file with one link".into(),
        ));
    }
    #[cfg(target_os = "macos")]
    validate_macos_acl(file)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_macos_acl(file: &File) -> Result<()> {
    use std::{ffi::c_void, os::fd::AsRawFd, ptr};
    // Darwin ACLs can grant access beyond the POSIX mode bits. The dedicated
    // key store accepts the owner-only mode without additional ACL entries.
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut c_void;
        fn acl_get_entry(
            acl: *mut c_void,
            index: libc::c_int,
            entry: *mut *mut c_void,
        ) -> libc::c_int;
        fn acl_free(acl: *mut c_void) -> libc::c_int;
    }
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
    if acl.is_null() {
        // Darwin represents an existing file without an extended ACL as
        // ENOENT. The already-open descriptor and fstat above establish that
        // this is the missing ACL, rather than a missing pathname.
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(Error::Blocked(
            "Could not verify private-key macOS ACL permissions".into(),
        ));
    }
    let mut entry = ptr::null_mut();
    let has_entry = unsafe { acl_get_entry(acl, 0, &mut entry) } == 0;
    unsafe {
        acl_free(acl);
    }
    if has_entry {
        return Err(Error::Blocked(
            "Private signing keys require owner-only permissions without extended ACL entries"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn private_file(path: &Path, create: bool) -> Result<File> {
    windows_private::open(path, create)
}

#[cfg(windows)]
fn validate_private_file(file: &File) -> Result<()> {
    windows_private::validate(file)
}

#[cfg(not(any(unix, windows)))]
fn private_file(_path: &Path, _create: bool) -> Result<File> {
    Err(Error::Unsupported(
        "Private signing-key storage is unavailable on this platform".into(),
    ))
}

#[cfg(not(any(unix, windows)))]
fn validate_private_file(_file: &File) -> Result<()> {
    Err(Error::Unsupported(
        "Private signing-key storage is unavailable on this platform".into(),
    ))
}

#[cfg(windows)]
mod windows_private {
    use super::*;
    use std::{
        ffi::c_void,
        fs::OpenOptions,
        mem::size_of,
        os::windows::{
            ffi::{OsStrExt, OsStringExt},
            fs::OpenOptionsExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{INVALID_HANDLE_VALUE, LocalFree},
        Security::{
            ACCESS_ALLOWED_ACE, ACL,
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
            },
            DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetSecurityDescriptorControl,
            GetTokenInformation, OWNER_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED,
            SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateFileW, FILE_ALL_ACCESS,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_GENERIC_WRITE, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_READ_DATA,
            FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
            GetFinalPathNameByHandleW, READ_CONTROL, VOLUME_NAME_GUID,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    struct LocalAllocation(*mut c_void);
    impl Drop for LocalAllocation {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }

    struct Identity {
        _token: OwnedHandle,
        information: Vec<usize>,
    }
    impl Identity {
        fn current() -> Result<Self> {
            let mut raw = ptr::null_mut();
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
                return Err(Error::Blocked(
                    "Could not determine private-key owner identity".into(),
                ));
            }
            let token = unsafe { OwnedHandle::from_raw_handle(raw) };
            let mut length = 0u32;
            unsafe {
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenUser,
                    ptr::null_mut(),
                    0,
                    &mut length,
                );
            }
            if length == 0 || length > 64 * 1024 {
                return Err(Error::Blocked(
                    "Invalid private-key owner identity size".into(),
                ));
            }
            let mut information = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
            if unsafe {
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenUser,
                    information.as_mut_ptr().cast(),
                    length,
                    &mut length,
                )
            } == 0
            {
                return Err(Error::Blocked(
                    "Could not inspect private-key owner identity".into(),
                ));
            }
            Ok(Self {
                _token: token,
                information,
            })
        }
        fn sid(&self) -> PSID {
            unsafe { (*(self.information.as_ptr().cast::<TOKEN_USER>())).User.Sid }
        }
        fn descriptor(&self) -> Result<LocalAllocation> {
            let mut sid_text = ptr::null_mut();
            if unsafe { ConvertSidToStringSidW(self.sid(), &mut sid_text) } == 0 {
                return Err(Error::Blocked(
                    "Could not encode private-key owner identity".into(),
                ));
            }
            let sid_allocation = LocalAllocation(sid_text.cast());
            let mut length = 0usize;
            while length < 256 && unsafe { *sid_text.add(length) } != 0 {
                length += 1;
            }
            if length == 256 {
                return Err(Error::Blocked("Invalid private-key owner SID".into()));
            }
            let sid =
                String::from_utf16(unsafe { std::slice::from_raw_parts(sid_text, length) })
                    .map_err(|_| Error::Blocked("Invalid private-key owner SID encoding".into()))?;
            let sddl: Vec<u16> = format!("O:{sid}D:P(A;;FA;;;{sid})")
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let mut descriptor = ptr::null_mut();
            let success = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            };
            drop(sid_allocation);
            if success == 0 {
                return Err(Error::Blocked(
                    "Could not create owner-only private-key permissions".into(),
                ));
            }
            Ok(LocalAllocation(descriptor))
        }
    }

    pub(super) fn open(path: &Path, create: bool) -> Result<File> {
        let (parent, name) = key_path(path)?;
        if name.encode_wide().any(|unit| unit == b':' as u16) {
            return Err(Error::Input(
                "Alternate data streams cannot store signing keys".into(),
            ));
        }
        // Excluding FILE_SHARE_DELETE keeps the bound parent in place while the
        // child is opened and its final parent path is checked before any read.
        let directory = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(parent)
            .map_err(|_| Error::Io("Could not bind private-key directory".into()))?;
        let parent = final_path(&directory)?;
        let target = parent.join(name);
        let file = if create {
            let owner = Identity::current()?;
            let descriptor = owner.descriptor()?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: 0,
            };
            let wide: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
            let raw = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES | READ_CONTROL,
                    FILE_SHARE_READ,
                    &attributes,
                    CREATE_NEW,
                    FILE_FLAG_OPEN_REPARSE_POINT,
                    ptr::null_mut(),
                )
            };
            if raw == INVALID_HANDLE_VALUE {
                return Err(Error::Io(
                    "Could not create private signing key without replacement".into(),
                ));
            }
            unsafe { File::from_raw_handle(raw) }
        } else {
            OpenOptions::new()
                .access_mode(FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&target)
                .map_err(|_| Error::Io("Could not open private signing key without links".into()))?
        };
        if final_path(&file)?.parent() != Some(parent.as_path()) {
            return Err(Error::Blocked(
                "Private-key parent changed during opening".into(),
            ));
        }
        validate(&file)?;
        Ok(file)
    }

    fn final_path(file: &File) -> Result<PathBuf> {
        let mut path = vec![0u16; 32768];
        let length = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                path.as_mut_ptr(),
                path.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_GUID,
            )
        };
        if length == 0 || length as usize >= path.len() {
            return Err(Error::Blocked(
                "Private keys require a verifiable local-volume path".into(),
            ));
        }
        Ok(PathBuf::from(std::ffi::OsString::from_wide(
            &path[..length as usize],
        )))
    }

    pub(super) fn validate(file: &File) -> Result<()> {
        let metadata = file
            .metadata()
            .map_err(|_| Error::Io("Could not inspect private signing key".into()))?;
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        if !metadata.is_file()
            || metadata.len() > MAX_KEY_BYTES
            || unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
            || info.nNumberOfLinks != 1
            || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(Error::Blocked(
                "Signing keys require a private regular file with one link".into(),
            ));
        }
        let identity = Identity::current()?;
        let mut owner = ptr::null_mut();
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut descriptor = ptr::null_mut();
        let error = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if error != 0 {
            return Err(Error::Blocked(
                "Could not inspect private-key permissions".into(),
            ));
        }
        let _descriptor = LocalAllocation(descriptor);
        let mut control = 0u16;
        let mut revision = 0u32;
        if owner.is_null()
            || dacl.is_null()
            || unsafe { EqualSid(owner, identity.sid()) } == 0
            || unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
            || control & SE_DACL_PROTECTED == 0
            || unsafe { (*dacl).AceCount } != 1
        {
            return Err(Error::Blocked(
                "Signing keys require a protected owner-only DACL".into(),
            ));
        }
        let mut raw_ace = ptr::null_mut();
        if unsafe { GetAce(dacl, 0, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(Error::Blocked(
                "Could not inspect private-key owner ACL entry".into(),
            ));
        }
        let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = (&ace.SidStart as *const u32).cast_mut().cast();
        if ace.Header.AceType != 0
            || ace.Header.AceFlags != 0
            || ace.Mask != FILE_ALL_ACCESS
            || unsafe { EqualSid(sid, identity.sid()) } == 0
        {
            return Err(Error::Blocked(
                "Signing keys permit access only to their current owner".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "signing_tests.rs"]
mod tests;

// FVPROV1 50399 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJlMTlkY2Q1MDY5ZDVlOWU1ZjM4MjU2MWE0ZDViMjExMWEzMTg2NTgzOGY0OGMwNTAwODlmYzA1NjI5ZWM2YWE5IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4zIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMyIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL2hlcml0YWdlL3NpZ25pbmcucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI1MGJhY2U3NjQxNjMyZGY4N2JlZWY5NWQzOGI4Mjg4Yzg3NDIyMWEwY2VmMWJhNmYwYzUxOWYwZTU5MzdmYjA3ODI4NjY1NGYyNzJiZDQzOWVhN2I0ZjZkZDE5ZGE3YzY5YTZjYjdiN2Q5NmI1ZTczOWNiNmY1OWU2YmVjNzIwZCJ9XX1d FVPROV1-END
