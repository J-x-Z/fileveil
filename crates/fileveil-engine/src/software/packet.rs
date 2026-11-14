// SPDX-License-Identifier: MPL-2.0
//! Domain-separated extraction keys and authenticated software declarations.
use super::SoftwareRequest;
use crate::heritage::signing::{PublicKey, RecordSignature, SigningKey};
use crate::heritage::{key_store, signing};
use crate::project::ProjectKey;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use fileveil_core::{Error, Result, digest};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"FileVeil software packet signature v1\0";
const AAD: &[u8] = b"FileVeil software encrypted claims v1\0";
pub(super) const MAX_PACKET_BYTES: usize = 32768;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    work_id: String,
    copy_id: String,
    author: String,
    version: String,
    created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    schema: String,
    encryption: String,
    nonce_hex: String,
    ciphertext_hex: String,
    witness_hex: String,
    input_sha256: String,
    canonical_ir_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    body: Body,
    signature: RecordSignature,
}

pub(super) struct PreparedPacket {
    pub bytes: Vec<u8>,
    pub witness: u64,
    pub challenge: u64,
}

impl PreparedPacket {
    pub fn pass_json(&self) -> Value {
        json!({
            "schema": "fileveil.software.pass_packet.v1",
            "packet_hex": hex(&self.bytes),
            "witness_hex": format!("{:016x}", self.witness),
            "challenge_hex": format!("{:016x}", self.challenge),
        })
    }
}

pub(super) fn load_key(request: &SoftwareRequest) -> Result<Option<SigningKey>> {
    request
        .key
        .as_ref()
        .map(|key| match key {
            ProjectKey::File { path } => SigningKey::load(path),
            ProjectKey::System { key_id } => key_store::load(&key_store::KeyStoreRef {
                key_id: key_id.clone(),
            }),
        })
        .transpose()
}

fn derive(key: &SigningKey, label: &[u8]) -> Zeroizing<[u8; 32]> {
    type HmacSha256 = Hmac<sha2_v11::Sha256>;
    let seed = key.secret_seed();
    let mut extract =
        <HmacSha256 as hmac::KeyInit>::new_from_slice(b"FileVeil software HKDF salt v1")
            .expect("fixed HMAC salt");
    extract.update(seed.as_ref());
    let intermediate = Zeroizing::new(<[u8; 32]>::from(extract.finalize().into_bytes()));
    let mut expand = <HmacSha256 as hmac::KeyInit>::new_from_slice(intermediate.as_ref())
        .expect("SHA-256 HMAC key");
    expand.update(label);
    expand.update(&[1]);
    Zeroizing::new(<[u8; 32]>::from(expand.finalize().into_bytes()))
}

fn token(key: &SigningKey, label: &[u8], message: &[u8]) -> u64 {
    type HmacSha256 = Hmac<sha2_v11::Sha256>;
    let material = derive(key, label);
    let mut mac =
        <HmacSha256 as hmac::KeyInit>::new_from_slice(material.as_ref()).expect("SHA-256 HMAC key");
    mac.update(message);
    let bytes = mac.finalize().into_bytes();
    u64::from_le_bytes(bytes[..8].try_into().expect("fixed digest prefix"))
}

pub(super) fn prepare(
    request: &SoftwareRequest,
    key: &SigningKey,
    input_sha256: &str,
    canonical_ir_sha256: Option<&str>,
) -> Result<PreparedPacket> {
    if request.work_id.is_empty() || request.copy_id.is_empty() {
        return Err(Error::Blocked(
            "Software marking requires work and copy identifiers".into(),
        ));
    }
    if [
        &request.work_id,
        &request.copy_id,
        &request.author,
        &request.version,
        &request.created_at,
    ]
    .iter()
    .any(|value| value.len() > 4096)
    {
        return Err(Error::Blocked(
            "Software declaration exceeds its string budget".into(),
        ));
    }
    let claims = Claims {
        work_id: request.work_id.clone(),
        copy_id: request.copy_id.clone(),
        author: request.author.clone(),
        version: request.version.clone(),
        created_at: request.created_at.clone(),
    };
    let plaintext = Zeroizing::new(signing::canonical(&claims)?);
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|_| Error::Io("Software packet randomness is unavailable".into()))?;
    let witness = token(key, b"software witness v1\0", plaintext.as_ref());
    let challenge = token(key, b"software challenge v1\0", &nonce_bytes);
    let material = derive(key, b"software ChaCha20Poly1305 v1\0");
    let cipher = ChaCha20Poly1305::new_from_slice(material.as_ref())
        .map_err(|_| Error::Verification("Software extraction-key construction failed".into()))?;
    let nonce = Nonce::from(nonce_bytes);
    let encrypted = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_ref(),
                aad: AAD,
            },
        )
        .map_err(|_| Error::Verification("Software declaration encryption failed".into()))?;
    let body = Body {
        schema: "fileveil.software.packet.v1".into(),
        encryption: "ChaCha20Poly1305-RFC8439".into(),
        nonce_hex: hex(&nonce_bytes),
        ciphertext_hex: hex(&encrypted),
        witness_hex: format!("{witness:016x}"),
        input_sha256: input_sha256.into(),
        canonical_ir_sha256: canonical_ir_sha256.map(str::to_owned),
    };
    let signature = signing::sign_detached(DOMAIN, &body, key)?;
    let bytes = signing::canonical(&Envelope { body, signature })?;
    if bytes.len() > MAX_PACKET_BYTES {
        return Err(Error::Blocked(
            "Software packet exceeds its byte budget".into(),
        ));
    }
    Ok(PreparedPacket {
        bytes,
        witness,
        challenge,
    })
}

pub(super) fn inspect(
    bytes: &[u8],
    key: Option<&SigningKey>,
    trusted: &[PublicKey],
    disclose: bool,
) -> Result<Value> {
    if bytes.len() > MAX_PACKET_BYTES || trusted.len() > 128 {
        return Err(Error::Blocked(
            "Software packet verification budget exceeded".into(),
        ));
    }
    let envelope: Envelope = serde_json::from_slice(bytes)
        .map_err(|_| Error::Verification("Malformed software packet".into()))?;
    let body = &envelope.body;
    if body.schema != "fileveil.software.packet.v1"
        || body.encryption != "ChaCha20Poly1305-RFC8439"
        || body.input_sha256.len() != 64
        || body.witness_hex.len() != 16
    {
        return Err(Error::Verification(
            "Unsupported software packet identity".into(),
        ));
    }
    if unhex(&body.nonce_hex)?.len() != 12
        || unhex(&body.ciphertext_hex)?.len() < 16
        || unhex(&body.input_sha256)?.len() != 32
        || unhex(&body.witness_hex)?.len() != 8
        || body
            .canonical_ir_sha256
            .as_ref()
            .is_some_and(|value| value.len() != 64 || unhex(value).is_err())
    {
        return Err(Error::Verification(
            "Malformed software packet fields".into(),
        ));
    }
    signing::verify_detached(DOMAIN, body, &envelope.signature)?;
    let trusted_key = trusted.iter().any(|public| {
        public.key_id == envelope.signature.key_id
            && public.ed25519_hex == envelope.signature.public_key_hex
    });
    let mut report = json!({
        "schema": body.schema, "signature": "valid", "decoded": false,
        "key_id": envelope.signature.key_id, "packet_sha256": digest(bytes),
        "trust": if trusted_key { "trusted" } else if trusted.is_empty() { "not_assessed" } else { "untrusted" },
        "trust_scope": "explicit_public_key_anchors",
        "witness_hex": body.witness_hex, "input_sha256": body.input_sha256,
        "ir_sha256": body.canonical_ir_sha256,
        "decryption": "not_assessed", "watermark_copy_resistance": "not_assessed",
    });
    let Some(key) = key else {
        return Ok(report);
    };
    if key.public_key().key_id != envelope.signature.key_id {
        report["decryption"] = "key_mismatch".into();
        return Ok(report);
    }
    let nonce_bytes: [u8; 12] = unhex(&body.nonce_hex)?
        .try_into()
        .map_err(|_| Error::Verification("Invalid software packet nonce".into()))?;
    let encrypted = unhex(&body.ciphertext_hex)?;
    let material = derive(key, b"software ChaCha20Poly1305 v1\0");
    let cipher = ChaCha20Poly1305::new_from_slice(material.as_ref())
        .map_err(|_| Error::Verification("Invalid software extraction key".into()))?;
    let nonce = Nonce::from(nonce_bytes);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &encrypted,
                    aad: AAD,
                },
            )
            .map_err(|_| Error::Verification("Software packet authentication failed".into()))?,
    );
    let claims: Claims = serde_json::from_slice(plaintext.as_ref())
        .map_err(|_| Error::Verification("Malformed decrypted software declaration".into()))?;
    let canonical = Zeroizing::new(signing::canonical(&claims)?);
    let witness = token(key, b"software witness v1\0", canonical.as_ref());
    if format!("{witness:016x}") != body.witness_hex {
        return Err(Error::Verification(
            "Software witness and authenticated declaration disagree".into(),
        ));
    }
    report["decoded"] = true.into();
    report["decryption"] = "valid".into();
    report["work_id_digest"] = digest(claims.work_id.as_bytes()).into();
    report["copy_id_digest"] = digest(claims.copy_id.as_bytes()).into();
    report["challenge_hex"] = format!(
        "{:016x}",
        token(key, b"software challenge v1\0", &nonce_bytes)
    )
    .into();
    if disclose {
        report["claims"] = serde_json::to_value(claims)
            .map_err(|_| Error::Verification("Could not serialize software declaration".into()))?;
    }
    Ok(report)
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

pub(super) fn unhex(value: &str) -> Result<Vec<u8>> {
    if value.len() > MAX_PACKET_BYTES * 4 || !value.len().is_multiple_of(2) || !value.is_ascii() {
        return Err(Error::Verification(
            "Invalid software hexadecimal field".into(),
        ));
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair)
                .map_err(|_| Error::Verification("Invalid software hex".into()))?;
            u8::from_str_radix(text, 16)
                .map_err(|_| Error::Verification("Invalid software hex".into()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_claims_require_the_correct_private_key() {
        let owner = SigningKey::generate().unwrap();
        let other = SigningKey::generate().unwrap();
        let request = SoftwareRequest {
            work_id: "work".into(),
            copy_id: "copy".into(),
            author: "Author".into(),
            ..Default::default()
        };
        let packet = prepare(&request, &owner, &digest(b"source"), None).unwrap();
        let verified = inspect(&packet.bytes, Some(&owner), &[owner.public_key()], true).unwrap();
        assert_eq!(verified["claims"]["work_id"], "work");
        assert_eq!(verified["trust"], "trusted");
        assert_eq!(
            verified["challenge_hex"],
            format!("{:016x}", packet.challenge)
        );
        let wrong = inspect(&packet.bytes, Some(&other), &[], false).unwrap();
        assert_eq!(wrong["decryption"], "key_mismatch");
        assert_eq!(wrong["decoded"], false);
        assert!(wrong.get("claims").is_none());
        let public = inspect(&packet.bytes, None, &[], false).unwrap();
        assert_eq!(public["signature"], "valid");
        assert!(public.get("claims").is_none());
    }

    #[test]
    fn tampering_and_signed_malformed_envelopes_fail_closed() {
        let key = SigningKey::generate().unwrap();
        let request = SoftwareRequest {
            work_id: "work".into(),
            copy_id: "copy".into(),
            ..Default::default()
        };
        let packet = prepare(&request, &key, &digest(b"source"), None).unwrap();
        let mut envelope: Envelope = serde_json::from_slice(&packet.bytes).unwrap();
        envelope.body.ciphertext_hex.replace_range(..2, "ff");
        assert!(
            inspect(
                &signing::canonical(&envelope).unwrap(),
                Some(&key),
                &[],
                false
            )
            .is_err()
        );
        envelope.body.nonce_hex = "zz".repeat(12);
        envelope.signature = signing::sign_detached(DOMAIN, &envelope.body, &key).unwrap();
        assert!(inspect(&signing::canonical(&envelope).unwrap(), None, &[], false).is_err());
    }
}
