// SPDX-License-Identifier: MPL-2.0
use super::*;

fn key(byte: u8) -> SigningKey {
    SigningKey {
        inner: DalekSigningKey::from_bytes(&[byte; 32]),
    }
}

fn body(key: &SigningKey, content: &[u8]) -> RecordBody {
    RecordBody::new(
        digest(content),
        "work-example".into(),
        "作者 Alice".into(),
        "1".into(),
        "2026-11-12T12:00:00Z".into(),
        key.public_key().key_id,
    )
}

fn trust(keys: &[&SigningKey], minimum: u16) -> TrustStore {
    TrustStore {
        trusted_issuers: keys.iter().map(|k| k.public_key()).collect(),
        minimum_issuer_signatures: minimum,
    }
}

#[test]
fn rfc8032_known_answer_and_domain_separation() {
    let seed =
        unhex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
    let signing = SigningKey {
        inner: DalekSigningKey::from_bytes(&seed),
    };
    assert_eq!(
        signing.public_key().ed25519_hex,
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    assert_eq!(
        hex(&signing.inner.sign(b"").to_bytes()),
        concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
    );
    let record = sign_record(body(&signing, b"asset"), &[&signing]).unwrap();
    let signature =
        Signature::from_bytes(&unhex::<64>(&record.signatures[0].signature_hex).unwrap());
    assert!(
        signing
            .inner
            .verifying_key()
            .verify_strict(&canonical(&record.body).unwrap(), &signature)
            .is_err()
    );
    assert!(
        signing
            .inner
            .verifying_key()
            .verify_strict(&signing_bytes(&record.body).unwrap(), &signature)
            .is_ok()
    );
}

#[test]
fn self_sign_is_content_bound_without_identity_trust() {
    let signing = key(1);
    let records = vec![append_record(&[], body(&signing, b"asset"), &[&signing]).unwrap()];
    let verified = verify_chain(&records, &digest(b"asset"), &TrustStore::default()).unwrap();
    assert_eq!(verified.signature, VerificationState::Valid);
    assert_eq!(verified.chain, VerificationState::Valid);
    assert_eq!(verified.content_binding, VerificationState::Valid);
    assert_eq!(verified.trust, VerificationState::NotAssessed);
    let report = serde_json::to_string(&verified).unwrap();
    assert!(!report.contains("Alice"));
    assert!(!report.contains("作者"));
    assert!(verified.records[0].author_declared);
    assert_eq!(
        verified.records[0].author_claim_sha256,
        digest("作者 Alice".as_bytes())
    );
    assert_eq!(
        verify_chain(&records, &digest(b"altered"), &TrustStore::default())
            .unwrap()
            .content_binding,
        VerificationState::Invalid
    );
}

#[test]
fn nat_sign_counts_distinct_local_trust_anchors() {
    let author = key(1);
    let issuer_a = key(2);
    let issuer_b = key(3);
    let first = append_record(&[], body(&author, b"asset"), &[&author]).unwrap();
    let mut issue = body(&author, b"asset");
    issue.kind = RecordKind::Issue;
    issue.mode = SignMode::NatiSign;
    issue.edition = "edition-42".into();
    issue.issuer_policy = Some(IssuerPolicy {
        threshold: 2,
        allowed_key_ids: vec![issuer_a.public_key().key_id, issuer_b.public_key().key_id],
    });
    let second = append_record(
        std::slice::from_ref(&first),
        issue,
        &[&author, &issuer_a, &issuer_b],
    )
    .unwrap();
    let mut records = vec![first, second];
    let good = verify_chain(
        &records,
        &digest(b"asset"),
        &trust(&[&issuer_a, &issuer_b], 2),
    )
    .unwrap();
    assert_eq!(good.trust, VerificationState::Valid);
    assert_eq!(good.records[1].trusted_issuer_signatures, 2);
    assert_eq!(
        verify_chain(&records, &digest(b"asset"), &TrustStore::default())
            .unwrap()
            .trust,
        VerificationState::Untrusted
    );
    assert_eq!(
        verify_chain(&records, &digest(b"asset"), &trust(&[&issuer_a], 1))
            .unwrap()
            .trust,
        VerificationState::Untrusted
    );
    let duplicate = records[1]
        .signatures
        .iter()
        .find(|s| s.key_id == issuer_a.public_key().key_id)
        .unwrap()
        .clone();
    records[1]
        .signatures
        .retain(|s| s.key_id != issuer_b.public_key().key_id);
    records[1].signatures.push(duplicate);
    let bad = verify_chain(
        &records,
        &digest(b"asset"),
        &trust(&[&issuer_a, &issuer_b], 2),
    )
    .unwrap();
    assert_eq!(bad.signature, VerificationState::Invalid);
    assert_eq!(bad.trust, VerificationState::Untrusted);
    assert_eq!(bad.records[1].trusted_issuer_signatures, 1);
}

#[test]
fn local_threshold_cannot_be_lowered_by_signed_payload() {
    let a = key(4);
    let b = key(5);
    let mut declaration = body(&a, b"asset");
    declaration.mode = SignMode::NatiSign;
    declaration.issuer_policy = Some(IssuerPolicy {
        threshold: 1,
        allowed_key_ids: vec![a.public_key().key_id, b.public_key().key_id],
    });
    let record = sign_record(declaration, &[&a]).unwrap();
    assert_eq!(
        verify_chain(&[record], &digest(b"asset"), &trust(&[&a, &b], 2))
            .unwrap()
            .trust,
        VerificationState::Untrusted
    );
}

#[test]
fn custody_transfer_and_modified_version_are_authorized() {
    let creator = key(6);
    let recipient = key(7);
    let first = append_record(&[], body(&creator, b"v1"), &[&creator]).unwrap();
    let mut transfer = body(&creator, b"v1");
    transfer.kind = RecordKind::Transfer;
    transfer.transfer_to_key_id = Some(recipient.public_key().key_id);
    let transfer = append_record(
        std::slice::from_ref(&first),
        transfer,
        &[&creator, &recipient],
    )
    .unwrap();
    let mut records = vec![first, transfer];
    let mut modified = body(&recipient, b"v2");
    modified.kind = RecordKind::Modify;
    modified.version = "2".into();
    let modified = append_record(&records, modified, &[&recipient]).unwrap();
    assert_eq!(modified.body.parent_version.as_deref(), Some("1"));
    records.push(modified);
    let result = verify_chain(&records, &digest(b"v2"), &TrustStore::default()).unwrap();
    assert_eq!(result.chain, VerificationState::Valid);
    assert!(
        result.records[1]
            .evidence_codes
            .iter()
            .any(|e| e == "transfer_recipient_cosigned")
    );
    let mut wrong_actor = records[2].body.clone();
    wrong_actor.actor_key_id = creator.public_key().key_id;
    records[2] = sign_record(wrong_actor, &[&creator]).unwrap();
    assert_eq!(
        verify_chain(&records, &digest(b"v2"), &TrustStore::default())
            .unwrap()
            .chain,
        VerificationState::Invalid
    );
}

#[test]
fn signed_predecessor_and_sequence_tampering_are_detected() {
    let a = key(8);
    let b = key(9);
    let first = append_record(&[], body(&a, b"asset"), &[&a]).unwrap();
    let mut issued = body(&a, b"asset");
    issued.kind = RecordKind::Issue;
    let second = append_record(std::slice::from_ref(&first), issued, &[&a]).unwrap();
    let mut records = vec![first, second];
    append_signature(&mut records[0], &b).unwrap();
    let result = verify_chain(&records, &digest(b"asset"), &TrustStore::default()).unwrap();
    assert_eq!(result.signature, VerificationState::Valid);
    assert_eq!(result.chain, VerificationState::Invalid);
    records[1].body.sequence = 4;
    let result = verify_chain(&records, &digest(b"asset"), &TrustStore::default()).unwrap();
    assert_eq!(result.signature, VerificationState::Invalid);
    assert_eq!(result.chain, VerificationState::Invalid);
}

#[test]
fn modifying_content_requires_a_new_linked_version() {
    let a = key(10);
    let first = append_record(&[], body(&a, b"v1"), &[&a]).unwrap();
    let mut bad = body(&a, b"v2");
    bad.kind = RecordKind::Issue;
    assert!(append_record(std::slice::from_ref(&first), bad, &[&a]).is_err());
    let mut bad = body(&a, b"v2");
    bad.kind = RecordKind::Modify;
    assert!(append_record(&[first], bad, &[&a]).is_err());
}

#[test]
fn canonical_json_is_order_invariant_and_preserves_unicode() {
    let a = key(11);
    let mut declaration = body(&a, b"asset");
    declaration.author = "e\u{301} / €\n\"\\".into();
    let encoded = canonical(&declaration).unwrap();
    let text = String::from_utf8(encoded.clone()).unwrap();
    assert!(text.starts_with("{\"actor_key_id\":"));
    assert!(text.contains("e\u{301} / €\\n\\\"\\\\"));
    assert!(!text.contains("é"));
    let mut object = serde_json::to_value(&declaration).unwrap();
    let mut reordered = serde_json::Map::new();
    let object = object.as_object_mut().unwrap();
    for key in object.keys().rev() {
        reordered.insert(key.clone(), object[key].clone());
    }
    assert_eq!(
        canonical(&serde_json::Value::Object(reordered)).unwrap(),
        encoded
    );
    assert!(canonical(&serde_json::json!(1.0)).is_err());
    assert!(canonical(&serde_json::json!(9_007_199_254_740_992u64)).is_err());
}

#[test]
fn strict_json_rejects_unknown_duplicate_float_and_oversized_fields() {
    let a = key(12);
    let record = sign_record(body(&a, b"asset"), &[&a]).unwrap();
    let encoded = serde_json::to_string(&vec![record.clone()]).unwrap();
    assert!(
        parse_records(
            encoded
                .replacen("\"sequence\":0", "\"sequence\":0,\"sequence\":0", 1)
                .as_bytes()
        )
        .is_err()
    );
    assert!(
        parse_records(
            encoded
                .replacen("\"sequence\":0", "\"sequence\":0,\"extra\":null", 1)
                .as_bytes()
        )
        .is_err()
    );
    assert!(
        parse_records(
            encoded
                .replacen("\"sequence\":0", "\"sequence\":0.0", 1)
                .as_bytes()
        )
        .is_err()
    );
    assert!(
        parse_records(
            encoded
                .replacen("\"algorithm\":\"Ed25519\"", "\"algorithm\":\"RSA\"", 1)
                .as_bytes()
        )
        .is_err()
    );
    assert!(parse_records(&vec![b' '; MAX_HISTORY_BYTES + 1]).is_err());
    let mut bad = record;
    bad.body.author = "x".repeat(4097);
    assert!(verify_chain(&[bad], &digest(b"asset"), &TrustStore::default()).is_err());
}

#[test]
fn weak_key_and_public_key_substitution_are_rejected() {
    let a = key(13);
    let b = key(14);
    let record = sign_record(body(&a, b"asset"), &[&a]).unwrap();
    let mut bad = record.clone();
    bad.signatures[0].public_key_hex = b.public_key().ed25519_hex;
    assert_eq!(
        verify_chain(&[bad], &digest(b"asset"), &TrustStore::default())
            .unwrap()
            .signature,
        VerificationState::Invalid
    );
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert!(
        parse_public(&PublicKey {
            key_id: digest(&identity),
            ed25519_hex: hex(&identity)
        })
        .is_err()
    );
    let mut changed = record;
    changed.body.author = "replacement".into();
    assert_eq!(
        verify_chain(&[changed], &digest(b"asset"), &TrustStore::default())
            .unwrap()
            .signature,
        VerificationState::Invalid
    );
}

#[test]
fn key_file_round_trip_is_private_and_never_overwrites() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("author.key");
    let key = SigningKey::generate().unwrap();
    key.save_new(&path).unwrap();
    assert_eq!(
        SigningKey::load(&path).unwrap().public_key(),
        key.public_key()
    );
    assert!(key.save_new(&path).is_err());
    assert_eq!(format!("{key:?}"), "SigningKey([REDACTED])");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    }
}

#[test]
fn key_loading_uses_authorized_descriptor_bindings() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bound.key");
    let key = key(15);
    key.save_new(&path).unwrap();
    let alias = PathBuf::from("/fileveil-bound-key-not-a-filesystem-path");
    let public = crate::access_guard::with_bound_files(
        vec![(alias.clone(), File::open(&path).unwrap())],
        || Ok(SigningKey::load(&alias)?.public_key()),
    )
    .unwrap();
    assert_eq!(public, key.public_key());
}

#[cfg(unix)]
#[test]
fn private_keys_reject_links_permissions_fifo_and_oversize() {
    use std::{
        ffi::CString,
        os::unix::{
            ffi::OsStrExt,
            fs::{PermissionsExt, symlink},
        },
    };
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secret.key");
    let key = key(16);
    key.save_new(&path).unwrap();
    let symbolic = directory.path().join("symbolic.key");
    symlink(&path, &symbolic).unwrap();
    assert!(SigningKey::load(&symbolic).is_err());
    assert!(key.save_new(&symbolic).is_err());
    let hard = directory.path().join("hard.key");
    std::fs::hard_link(&path, &hard).unwrap();
    assert!(SigningKey::load(&path).is_err());
    std::fs::remove_file(hard).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(SigningKey::load(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&path, vec![0; MAX_KEY_BYTES as usize + 1]).unwrap();
    assert!(SigningKey::load(&path).is_err());
    let fifo = directory.path().join("fifo.key");
    let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
    assert!(SigningKey::load(&fifo).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn private_keys_reject_acl_access_even_with_mode_0600() {
    use std::{os::unix::fs::MetadataExt, process::Command};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("acl.key");
    let signing = key(18);
    signing.save_new(&path).unwrap();
    let status = Command::new("/bin/chmod")
        .args(["+a", "everyone allow read"])
        .arg(&path)
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    assert!(SigningKey::load(&path).is_err());
}

#[test]
fn duplicate_issuer_and_empty_history_states_are_explicit() {
    let a = key(17);
    let result = verify_chain(&[], &digest(b"asset"), &TrustStore::default()).unwrap();
    assert_eq!(result.signature, VerificationState::NotAssessed);
    assert_eq!(result.chain, VerificationState::NotAssessed);
    assert!(verify_chain(&[], &digest(b"asset"), &trust(&[&a, &a], 1)).is_err());
    let mut record = sign_record(body(&a, b"asset"), &[&a]).unwrap();
    assert!(append_signature(&mut record, &a).is_err());
    record.body.issuer_policy = Some(IssuerPolicy {
        threshold: 1,
        allowed_key_ids: vec![a.public_key().key_id],
    });
    assert!(sign_record(record.body, &[&a]).is_err());
}

fn v2_body(key: &SigningKey, content: &[u8]) -> RecordBody {
    let mut value = body(key, content);
    value.schema = SCHEMA_V2.into();
    value.copy_id = Some("edition-copy-001".into());
    value
}

#[test]
fn v1_canonical_bytes_omit_all_v2_fields_and_v2_domain_is_distinct() {
    let signer = key(41);
    let original = body(&signer, b"asset");
    let encoded = canonical(&original).unwrap();
    let text = std::str::from_utf8(&encoded).unwrap();
    for name in ["copy_id", "rotation_to_key_id", "transformation"] {
        assert!(!text.contains(name));
    }
    let record = sign_record(original.clone(), &[&signer]).unwrap();
    let mut upgraded = record.clone();
    upgraded.body.schema = SCHEMA_V2.into();
    upgraded.body.copy_id = Some("copy-1".into());
    assert_eq!(
        verify_chain(&[upgraded], &digest(b"asset"), &TrustStore::default())
            .unwrap()
            .signature,
        VerificationState::Invalid
    );
    let mut invalid = original;
    invalid.copy_id = Some("must-use-v2".into());
    assert!(sign_record(invalid, &[&signer]).is_err());
}

#[test]
fn v2_transfer_and_rotation_require_both_current_and_successor_signatures() {
    let creator = key(42);
    let recipient = key(43);
    let replacement = key(44);
    let first = append_record(&[], v2_body(&creator, b"v1"), &[&creator]).unwrap();
    let mut transfer = v2_body(&creator, b"v1");
    transfer.kind = RecordKind::Transfer;
    transfer.transfer_to_key_id = Some(recipient.public_key().key_id);
    assert!(append_record(std::slice::from_ref(&first), transfer.clone(), &[&creator]).is_err());
    let transfer = append_record(
        std::slice::from_ref(&first),
        transfer,
        &[&creator, &recipient],
    )
    .unwrap();
    let mut history = vec![first, transfer];
    let mut rotation = v2_body(&recipient, b"v1");
    rotation.kind = RecordKind::RotateKey;
    rotation.rotation_to_key_id = Some(replacement.public_key().key_id);
    assert!(append_record(&history, rotation.clone(), &[&recipient]).is_err());
    history.push(append_record(&history, rotation, &[&recipient, &replacement]).unwrap());
    let mut invalid = v2_body(&recipient, b"v2");
    invalid.kind = RecordKind::Modify;
    invalid.version = "2".into();
    assert!(append_record(&history, invalid, &[&recipient]).is_err());
    let mut next = v2_body(&replacement, b"v2");
    next.kind = RecordKind::Modify;
    next.version = "2".into();
    next.transformation = Some(Transformation {
        source_sha256: digest(b"v1"),
        source_format: "image/png".into(),
        target_format: "image/jpeg".into(),
        operation: "jpeg_reencode".into(),
    });
    history.push(append_record(&history, next, &[&replacement]).unwrap());
    let result = verify_chain(&history, &digest(b"v2"), &TrustStore::default()).unwrap();
    assert_eq!(result.signature, VerificationState::Valid);
    assert_eq!(result.chain, VerificationState::Valid);
    assert_eq!(history[3].body.parent_version.as_deref(), Some("1"));
    let mut downgrade = body(&replacement, b"v3");
    downgrade.kind = RecordKind::Modify;
    downgrade.version = "3".into();
    assert!(append_record(&history, downgrade, &[&replacement]).is_err());
}

#[test]
fn v2_issuance_can_create_a_distinct_copy_and_conversion_must_bind_its_source() {
    let signer = key(45);
    let first = append_record(&[], v2_body(&signer, b"v1"), &[&signer]).unwrap();
    let mut issue = v2_body(&signer, b"v1");
    issue.kind = RecordKind::Issue;
    issue.copy_id = Some("copy-002".into());
    let issue = append_record(std::slice::from_ref(&first), issue, &[&signer]).unwrap();
    let history = vec![first, issue];
    let mut modify = v2_body(&signer, b"v2");
    modify.copy_id = Some("copy-002".into());
    modify.kind = RecordKind::Modify;
    modify.version = "2".into();
    modify.transformation = Some(Transformation {
        source_sha256: digest(b"wrong source"),
        source_format: "image/png".into(),
        target_format: "image/jpeg".into(),
        operation: "convert".into(),
    });
    assert!(append_record(&history, modify.clone(), &[&signer]).is_err());
    modify.transformation.as_mut().unwrap().source_sha256 = digest(b"v1");
    assert!(append_record(&history, modify, &[&signer]).is_ok());
}

#[test]
fn watermark_derivation_matches_independent_hmac_sha256_vector() {
    let signer = key(1);
    assert_eq!(
        hex(signer.derive_watermark_key().as_ref()),
        "f4df56cc755e5c4b93054af9a591b881c73fd7e791316f09d93efc3e7d3fb135"
    );
    assert_ne!(
        signer.derive_watermark_key().as_ref(),
        signer.secret_seed().as_ref()
    );
}

// FVPROV1 19893 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJlYTVlMjI3ZTQyNzJjMzc2ODkxNmNiOWRmYjY3YzU2Y2M3ZDJmMmZmNTM0ZjcwYjM0MjYzMWUxODI2MjUyMWVjIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL2hlcml0YWdlL3NpZ25pbmdfdGVzdHMucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI4MjIzM2M5YzcwNWUyODZmODdkODE3ZTM4MmVhNjBlNzBiZWJiY2FlYTNiYmY5ZDZmYzNkNjExNzEyZTVkYjg2YjVmNjYyMmM0YjhkNWNmYzI0NjBhNzFmMjhmMjQ3OGZlNjI2Y2FlMzM4MmQwOGMzN2RlMmFmMGUyM2U2ODgwNyJ9XX1d FVPROV1-END
