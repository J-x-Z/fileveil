// SPDX-License-Identifier: MPL-2.0
//! Provenance v2 through the shared normal-entry dispatcher and sidecar publisher.
use fileveil_core::{Limits, Outcome, digest};
use fileveil_engine::heritage::{
    self, HeritageAction, HeritageRequest, MarkSettings, container, custody,
    signing::{self, RecordKind, SigningKey, VerificationState},
};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn fixture() -> Vec<u8> {
    fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/png_clean.png"))
        .unwrap()
}
fn key(path: &Path) -> SigningKey {
    let key = SigningKey::generate().unwrap();
    key.save_new(path).unwrap();
    key
}
fn mark(
    path: &Path,
    output: &Path,
    keys: Vec<PathBuf>,
    kind: RecordKind,
    recipient: Option<String>,
    rotation: Option<String>,
) -> fileveil_core::Result<fileveil_core::Report> {
    heritage::run(
        path,
        Some(output),
        &HeritageRequest {
            action: HeritageAction::Mark,
            key_paths: keys,
            mark: MarkSettings {
                work_id: "provenance-work".into(),
                copy_id: "copy-001".into(),
                signature_v2: true,
                created_at: "2026-11-13T00:00:00Z".into(),
                author: "Explicit private author claim".into(),
                kind,
                transfer_to_key_id: recipient,
                rotation_to_key_id: rotation,
                ..Default::default()
            },
            ..Default::default()
        },
        &Limits::default(),
    )
}
#[test]
fn normal_entry_cosigned_transfer_rotation_checkpoint_and_evidence_are_bound_to_originals() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let source = root.join("input.png");
    let original = fixture();
    fs::write(&source, &original).unwrap();
    let key_a_path = root.join("owner.key");
    let a = key(&key_a_path);
    let key_b_path = root.join("recipient.key");
    let b = key(&key_b_path);
    let key_c_path = root.join("replacement.key");
    let c = key(&key_c_path);
    let marked = root.join("marked.png");
    mark(
        &source,
        &marked,
        vec![key_a_path.clone()],
        RecordKind::Create,
        None,
        None,
    )
    .unwrap();
    let transferred = root.join("transferred.png");
    assert!(
        mark(
            &marked,
            &transferred,
            vec![key_a_path.clone()],
            RecordKind::Transfer,
            Some(b.public_key().key_id.clone()),
            None
        )
        .is_err()
    );
    assert!(!transferred.exists());
    mark(
        &marked,
        &transferred,
        vec![key_a_path, key_b_path.clone()],
        RecordKind::Transfer,
        Some(b.public_key().key_id.clone()),
        None,
    )
    .unwrap();
    let rotated = root.join("rotated.png");
    mark(
        &transferred,
        &rotated,
        vec![key_b_path, key_c_path.clone()],
        RecordKind::RotateKey,
        None,
        Some(c.public_key().key_id.clone()),
    )
    .unwrap();
    let checkpoint = root.join("checkpoint.json");
    let checkpoint_request = HeritageRequest {
        action: HeritageAction::Checkpoint,
        key_paths: vec![key_c_path.clone()],
        ..Default::default()
    };
    let report = heritage::run(
        &rotated,
        Some(&checkpoint),
        &checkpoint_request,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(report.integrity.original_unchanged, Some(true));
    assert!(
        heritage::run(
            &rotated,
            Some(&checkpoint),
            &checkpoint_request,
            &Limits::default()
        )
        .is_err()
    );
    let anchors = root.join("anchors.json");
    fs::write(&anchors, serde_json::to_vec(&vec![c.public_key()]).unwrap()).unwrap();
    let evidence = root.join("evidence.json");
    let export = HeritageRequest {
        action: HeritageAction::EvidenceExport,
        key_paths: vec![key_c_path],
        checkpoints: vec![checkpoint.clone()],
        checkpoint_anchors: Some(anchors.clone()),
        ..Default::default()
    };
    let report = heritage::run(&rotated, Some(&evidence), &export, &Limits::default()).unwrap();
    assert_eq!(report.integrity.security_markers_preserved, Some(true));
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("Explicit private author claim")
    );
    let package = custody::parse_evidence(&fs::read(&evidence).unwrap()).unwrap();
    assert_eq!(package.body.records.len(), 3);
    assert!(
        fs::read_to_string(&evidence)
            .unwrap()
            .contains("Explicit private author claim")
    );
    let verification = HeritageRequest {
        action: HeritageAction::EvidenceVerify,
        reference: Some(rotated.clone()),
        checkpoint_anchors: Some(anchors),
        ..Default::default()
    };
    let checked = heritage::run(&evidence, None, &verification, &Limits::default()).unwrap();
    assert_ne!(checked.result, Outcome::Failed);
    let details = &checked.advanced.as_ref().unwrap()["heritage"];
    assert_eq!(details["reference_asset_verified"], true);
    assert_eq!(details["evidence_verification"]["chain"]["chain"], "valid");
    assert_eq!(
        details["evidence_verification"]["checkpoints"][0]["trust"],
        "valid"
    );
    let mut altered = package;
    altered.body.assets[0].sha256 = digest(b"tampered");
    fs::write(&evidence, custody::canonical_evidence(&altered).unwrap()).unwrap();
    assert_eq!(
        heritage::run(&evidence, None, &verification, &Limits::default())
            .unwrap()
            .result,
        Outcome::Failed
    );
    assert_eq!(fs::read(&source).unwrap(), original);
    let extracted =
        container::extract(&fs::read(&rotated).unwrap(), fileveil_core::Format::Png).unwrap();
    assert_eq!(extracted.base, original);
    assert_eq!(
        signing::verify_chain(
            &signing::parse_records(extracted.manifest.as_ref().unwrap()).unwrap(),
            &digest(&original),
            &signing::TrustStore::default()
        )
        .unwrap()
        .signature,
        VerificationState::Valid
    );
    assert_eq!(a.public_key().key_id.len(), 64);
}

#[cfg(unix)]
#[test]
fn sidecar_drops_source_tracking_xattrs_and_preserves_security_markers() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let source = root.join("input.png");
    fs::write(&source, fixture()).unwrap();
    let key_path = root.join("key.key");
    let _key = key(&key_path);
    let marked = root.join("marked.png");
    mark(
        &source,
        &marked,
        vec![key_path.clone()],
        RecordKind::Create,
        None,
        None,
    )
    .unwrap();
    #[cfg(target_os = "macos")]
    let (tracking, security) = (
        "com.apple.metadata:kMDItemWhereFroms",
        "com.apple.quarantine",
    );
    #[cfg(not(target_os = "macos"))]
    let (tracking, security) = ("user.source_url", "user.fileveil-security-test");
    xattr::set(&marked, tracking, b"https://example.invalid/private-source").unwrap();
    #[cfg(target_os = "macos")]
    xattr::set(&marked, security, b"0083;00000000;FileVeilTest;").unwrap();
    let checkpoint = root.join("checkpoint.json");
    heritage::run(
        &marked,
        Some(&checkpoint),
        &HeritageRequest {
            action: HeritageAction::Checkpoint,
            key_paths: vec![key_path],
            ..Default::default()
        },
        &Limits::default(),
    )
    .unwrap();
    assert!(xattr::get(&checkpoint, tracking).unwrap().is_none());
    #[cfg(target_os = "macos")]
    assert_eq!(
        xattr::get(&checkpoint, security).unwrap(),
        xattr::get(&marked, security).unwrap()
    );
    #[cfg(not(target_os = "macos"))]
    let _ = security;
    assert!(xattr::get(&marked, tracking).unwrap().is_some());
}

#[test]
fn timestamp_normal_entry_requires_explicit_output_and_binds_record_imprint() {
    if heritage::timestamp::capabilities()["rfc3161_query"] != true {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let source = root.join("input.png");
    fs::write(&source, fixture()).unwrap();
    let key_path = root.join("key.key");
    let _key = key(&key_path);
    let marked = root.join("marked.png");
    mark(
        &source,
        &marked,
        vec![key_path],
        RecordKind::Create,
        None,
        None,
    )
    .unwrap();
    let request = HeritageRequest {
        action: HeritageAction::TimestampQuery,
        ..Default::default()
    };
    assert!(heritage::run(&marked, None, &request, &Limits::default()).is_err());
    let output = root.join("request.tsq");
    let report = heritage::run(&marked, Some(&output), &request, &Limits::default()).unwrap();
    assert!(output.exists());
    assert_eq!(
        report.advanced.as_ref().unwrap()["heritage"]["request_contains_file_content"],
        false
    );
    assert_eq!(report.integrity.original_unchanged, Some(true));
    assert!(heritage::run(&marked, Some(&output), &request, &Limits::default()).is_err());
}

#[test]
fn two_device_transfer_uses_separate_private_keys_and_portable_signed_proposal() {
    let directory = tempfile::tempdir().unwrap();
    let a_dir = directory.path().join("sender-device");
    let b_dir = directory.path().join("receiver-device");
    fs::create_dir_all(&a_dir).unwrap();
    fs::create_dir_all(&b_dir).unwrap();
    let source = a_dir.join("original.png");
    let original = fixture();
    fs::write(&source, &original).unwrap();
    let a_path = a_dir.join("sender.key");
    let sender = key(&a_path);
    let b_path = b_dir.join("receiver.key");
    let receiver = key(&b_path);
    let marked = a_dir.join("signed.png");
    mark(
        &source,
        &marked,
        vec![a_path.clone()],
        RecordKind::Create,
        None,
        None,
    )
    .unwrap();
    let proposal = a_dir.join("proposal.json");
    let prepare = HeritageRequest {
        action: HeritageAction::TransferPrepare,
        key_paths: vec![a_path.clone()],
        mark: MarkSettings {
            transfer_to_key_id: Some(receiver.public_key().key_id.clone()),
            ..Default::default()
        },
        ..Default::default()
    };
    let report = heritage::run(&marked, Some(&proposal), &prepare, &Limits::default()).unwrap();
    assert_eq!(
        report.advanced.as_ref().unwrap()["heritage"]["recipient_acceptance"],
        "pending"
    );
    let transferred_proposal = b_dir.join("proposal.json");
    fs::copy(&proposal, &transferred_proposal).unwrap();
    let received_asset = b_dir.join("received.png");
    fs::copy(&marked, &received_asset).unwrap();
    let accepted = b_dir.join("accepted.evidence.json");
    let accept = HeritageRequest {
        action: HeritageAction::TransferAccept,
        key_paths: vec![b_path.clone()],
        reference: Some(received_asset.clone()),
        ..Default::default()
    };
    let report = heritage::run(
        &transferred_proposal,
        Some(&accepted),
        &accept,
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(
        report.advanced.as_ref().unwrap()["heritage"]["reference_asset_verified"],
        true
    );
    let package = custody::parse_evidence(&fs::read(&accepted).unwrap()).unwrap();
    assert_eq!(package.body.records.len(), 2);
    assert_eq!(package.body.records[1].signatures.len(), 2);
    assert_eq!(package.signature.key_id, receiver.public_key().key_id);
    let mut replaced_history = package.body.records.clone();
    replaced_history[0].body.author = "Receiver cannot replace prior author".into();
    assert!(
        custody::create_evidence(
            &replaced_history,
            package.body.assets.clone(),
            vec![],
            vec![],
            &receiver
        )
        .is_err()
    );
    let mut changed_proposal =
        custody::parse_transfer_proposal(&fs::read(&transferred_proposal).unwrap()).unwrap();
    changed_proposal.body.pending.body.author = "Replaced sender statement".into();
    assert!(custody::accept_transfer(&changed_proposal, &receiver).is_err());

    let mut wrong_key = accept.clone();
    wrong_key.key_paths = vec![a_path];
    assert!(
        heritage::run(
            &transferred_proposal,
            Some(&b_dir.join("wrong-key.evidence.json")),
            &wrong_key,
            &Limits::default()
        )
        .is_err()
    );
    let mut wrong_asset = accept.clone();
    wrong_asset.reference = Some(b_dir.join("other.png"));
    fs::write(
        wrong_asset.reference.as_ref().unwrap(),
        fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/png_itxt_exif_icc.png"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        heritage::run(
            &transferred_proposal,
            Some(&b_dir.join("wrong-asset.evidence.json")),
            &wrong_asset,
            &Limits::default()
        )
        .is_err()
    );
    let mut modified = image::load_from_memory(&original).unwrap().to_rgba8();
    let pixel = modified.get_pixel_mut(0, 0);
    pixel[0] ^= 0xff;
    let edited = b_dir.join("edited.png");
    modified.save(&edited).unwrap();
    let version2 = b_dir.join("version2.png");
    let modify = HeritageRequest {
        action: HeritageAction::Mark,
        key_paths: vec![b_path],
        previous: Some(accepted.clone()),
        mark: MarkSettings {
            signature_v2: true,
            work_id: "provenance-work".into(),
            copy_id: "copy-001".into(),
            author: "Explicit private author claim".into(),
            version: "2".into(),
            created_at: "2026-11-13T00:01:00Z".into(),
            kind: RecordKind::Modify,
            ..Default::default()
        },
        ..Default::default()
    };
    heritage::run(&edited, Some(&version2), &modify, &Limits::default()).unwrap();
    let extracted =
        container::extract(&fs::read(&version2).unwrap(), fileveil_core::Format::Png).unwrap();
    let history = signing::parse_records(extracted.manifest.as_ref().unwrap()).unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[2].body.parent_version.as_deref(), Some("1"));
    assert_eq!(
        signing::verify_chain(
            &history,
            &digest(&extracted.base),
            &signing::TrustStore::default()
        )
        .unwrap()
        .chain,
        VerificationState::Valid
    );
    assert_eq!(fs::read(&source).unwrap(), original);
    assert_ne!(sender.public_key(), receiver.public_key());
}
