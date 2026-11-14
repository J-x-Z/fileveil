// SPDX-License-Identifier: MPL-2.0
use fileveil_core::{Limits, Outcome, digest};
use fileveil_engine::{heritage::signing::SigningKey, project::*};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

struct Fixture {
    _directory: tempfile::TempDir,
    source: PathBuf,
    output: PathBuf,
    state: PathBuf,
    key: PathBuf,
    config: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        let private = directory.path().join("private");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&private).unwrap();
        let key = private.join("owner.key");
        SigningKey::generate().unwrap().save_new(&key).unwrap();
        let fixture = Self {
            source: source.clone(),
            output: directory.path().join("releases"),
            state: private.join("state"),
            key,
            config: source.join("fileveil.project.json"),
            _directory: directory,
        };
        fs::write(fixture.source.join("main.rs"), b"fn main() {}\n").unwrap();
        fixture
    }
    fn request(&self, action: ProjectAction) -> ProjectRequest {
        ProjectRequest {
            action,
            config_path: self.config.clone(),
            state_directory: Some(self.state.clone()),
            ..Default::default()
        }
    }
    fn init(&self, configure: impl FnOnce(&mut ProjectConfig)) -> Value {
        let mut config = ProjectConfig {
            work_id: "project-example".into(),
            author: "Example Author".into(),
            copy_id: "development".into(),
            source_root: ".".into(),
            output_directory: self.output.clone(),
            ..Default::default()
        };
        configure(&mut config);
        let mut request = self.request(ProjectAction::Init);
        request.init = Some(config);
        request.key = Some(ProjectKey::File {
            path: self.key.clone(),
        });
        let report = run(&request, &Limits::default(), &AtomicBool::new(false)).unwrap();
        assert_eq!(report.result, Outcome::PartiallyVerified);
        report.advanced.unwrap()["project"].clone()
    }
    fn execute(&self, action: ProjectAction) -> fileveil_core::Report {
        run(
            &self.request(action),
            &Limits::default(),
            &AtomicBool::new(false),
        )
        .unwrap()
    }
    fn generation(&self, details: &Value) -> PathBuf {
        self.output
            .join(details["project_id"].as_str().unwrap())
            .join(details["generation"].as_str().unwrap())
    }
}
fn details(report: &fileveil_core::Report) -> &Value {
    &report.advanced.as_ref().unwrap()["project"]
}

#[test]
fn external_project_is_incremental_idempotent_and_preserves_originals() {
    let fixture = Fixture::new();
    fixture.init(|_| {});
    let original = fs::read(fixture.source.join("main.rs")).unwrap();
    let first = fixture.execute(ProjectAction::Sync);
    assert_eq!(first.result, Outcome::VerifiedWithinScope);
    assert_eq!(details(&first)["published"], true);
    assert_eq!(details(&first)["revision"], 1);
    assert!(!fixture.generation(details(&first)).join("files").exists());
    assert_eq!(fs::read(fixture.source.join("main.rs")).unwrap(), original);
    let second = fixture.execute(ProjectAction::Sync);
    assert_eq!(details(&second)["published"], false);
    assert_eq!(details(&second)["revision"], 1);
    assert_eq!(details(&second)["unchanged"], 1);
    assert_eq!(first.output_sha256, second.output_sha256);
    assert_eq!(
        fixture.execute(ProjectAction::Verify).result,
        Outcome::VerifiedWithinScope
    );
    let config = fs::read_to_string(&fixture.config).unwrap();
    assert!(!config.contains("owner.key"));
    assert!(!config.contains("state.json"));
}

#[test]
fn edits_additions_deletions_and_unique_renames_preserve_version_links() {
    let fixture = Fixture::new();
    fixture.init(|_| {});
    let first = fixture.execute(ProjectAction::Sync);
    fs::rename(
        fixture.source.join("main.rs"),
        fixture.source.join("renamed.rs"),
    )
    .unwrap();
    let renamed = fixture.execute(ProjectAction::Sync);
    assert_eq!(details(&renamed)["renamed"], 1);
    assert_eq!(details(&renamed)["added"], 0);
    fs::write(
        fixture.source.join("renamed.rs"),
        b"fn main() { println!(\"new\"); }\n",
    )
    .unwrap();
    fs::write(fixture.source.join("new.asset"), b"new asset").unwrap();
    let changed = fixture.execute(ProjectAction::Sync);
    assert_eq!(details(&changed)["modified"], 1);
    assert_eq!(details(&changed)["added"], 1);
    fs::remove_file(fixture.source.join("new.asset")).unwrap();
    let deleted = fixture.execute(ProjectAction::Sync);
    assert_eq!(details(&deleted)["deleted"], 1);
    assert_eq!(details(&deleted)["revision"], 4);
    assert!(fixture.generation(details(&first)).is_dir());
    assert_eq!(
        fixture.execute(ProjectAction::Verify).result,
        Outcome::VerifiedWithinScope
    );
}

#[test]
fn changed_source_is_pending_status_and_failed_verification_until_sync() {
    let fixture = Fixture::new();
    fixture.init(|_| {});
    fixture.execute(ProjectAction::Sync);
    fs::write(
        fixture.source.join("main.rs"),
        b"fn main() { } // changed\n",
    )
    .unwrap();
    let status = fixture.execute(ProjectAction::Status);
    assert_eq!(status.result, Outcome::PartiallyVerified);
    assert_eq!(details(&status)["dirty"], true);
    assert_eq!(
        fixture.execute(ProjectAction::Verify).result,
        Outcome::Failed
    );
    fixture.execute(ProjectAction::Sync);
    assert_eq!(
        fixture.execute(ProjectAction::Verify).result,
        Outcome::VerifiedWithinScope
    );
}

#[test]
fn watch_probe_is_stable_and_does_not_hash_or_sign_payloads() {
    let fixture = Fixture::new();
    fixture.init(|_| {});
    let request = fixture.request(ProjectAction::WatchProbe);
    let first = watch_fingerprint(&request, &Limits::default()).unwrap();
    assert_eq!(
        first,
        watch_fingerprint(&request, &Limits::default()).unwrap()
    );
    let report = run(&request, &Limits::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(report.result, Outcome::NotAssessed);
    assert_eq!(details(&report)["source_sha256_assessed"], false);
    assert!(!fixture.output.exists());
    fs::write(fixture.source.join("main.rs"), b"changed length\n").unwrap();
    assert_ne!(
        first,
        watch_fingerprint(&request, &Limits::default()).unwrap()
    );
}

#[test]
fn automatic_configuration_changes_wait_for_explicit_user_sync() {
    let fixture = Fixture::new();
    fixture.init(|_| {});
    fixture.execute(ProjectAction::Sync);
    let mut config: ProjectConfig =
        serde_json::from_slice(&fs::read(&fixture.config).unwrap()).unwrap();
    config.author = "Updated author assertion".into();
    fs::write(&fixture.config, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let mut automatic = fixture.request(ProjectAction::WatchProbe);
    automatic.options.automatic = true;
    assert!(run(&automatic, &Limits::default(), &AtomicBool::new(false)).is_err());
    fixture.execute(ProjectAction::Sync);
    assert!(run(&automatic, &Limits::default(), &AtomicBool::new(false)).is_ok());
}

#[test]
fn rotation_and_copy_registration_keep_a_verifiable_custody_chain() {
    let fixture = Fixture::new();
    fixture.init(|_| {});
    fixture.execute(ProjectAction::Sync);
    let key = fixture.key.with_file_name("rotated.key");
    SigningKey::generate().unwrap().save_new(&key).unwrap();
    let mut request = fixture.request(ProjectAction::Sync);
    request.options.rotate_to = Some(ProjectKey::File { path: key });
    let rotated = run(&request, &Limits::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(rotated.result, Outcome::VerifiedWithinScope);
    assert_eq!(details(&rotated)["revision"], 2);
    assert_eq!(
        details(&fixture.execute(ProjectAction::Sync))["revision"],
        2
    );
    request.options.rotate_to = None;
    request.options.copy_id = Some("distribution-2".into());
    let issued = run(&request, &Limits::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(details(&issued)["revision"], 3);
    assert!(
        details(&issued)["copies"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("distribution-2"))
    );
    let verify = fixture.execute(ProjectAction::Verify);
    assert_eq!(verify.result, Outcome::VerifiedWithinScope);
    assert_eq!(details(&verify)["history"], "valid");
}

#[test]
fn structure_embedding_and_external_copies_recheck_without_changing_source_bytes() {
    let fixture = Fixture::new();
    let png = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/png_clean.png");
    fs::copy(png, fixture.source.join("picture.png")).unwrap();
    let original = digest(&fs::read(fixture.source.join("picture.png")).unwrap());
    fixture.init(|config| {
        config.copy_external_files = true;
        config.rules.push(ProjectRule {
            pattern: "*.png".into(),
            mode: ProjectFileMode::Structure,
            ..Default::default()
        });
    });
    let first = fixture.execute(ProjectAction::Sync);
    let generation = fixture.generation(details(&first));
    assert!(generation.join("files/main.rs").is_file());
    assert!(generation.join("files/picture.png").is_file());
    assert_eq!(
        original,
        digest(&fs::read(fixture.source.join("picture.png")).unwrap())
    );
    assert_eq!(
        fixture.execute(ProjectAction::Verify).result,
        Outcome::VerifiedWithinScope
    );
    fs::write(fixture.source.join("main.rs"), b"different source\n").unwrap();
    let second = fixture.execute(ProjectAction::Sync);
    let current = fixture.generation(details(&second));
    assert_eq!(
        fs::read(generation.join("files/picture.png")).unwrap(),
        fs::read(current.join("files/picture.png")).unwrap()
    );
}

#[test]
fn corruption_cancellation_and_embedded_failures_cannot_publish_a_success_generation() {
    let fixture = Fixture::new();
    fixture.init(|config| {
        config.rules.push(ProjectRule {
            pattern: "*.rs".into(),
            mode: ProjectFileMode::Invisible,
            ..Default::default()
        })
    });
    assert!(
        run(
            &fixture.request(ProjectAction::Sync),
            &Limits::default(),
            &AtomicBool::new(false)
        )
        .is_err()
    );
    assert_eq!(
        details(&fixture.execute(ProjectAction::Status))["revision"],
        0
    );
    assert!(
        run(
            &fixture.request(ProjectAction::Sync),
            &Limits::default(),
            &AtomicBool::new(true)
        )
        .is_err()
    );
    assert_eq!(
        details(&fixture.execute(ProjectAction::Status))["revision"],
        0
    );
}

#[test]
fn directory_output_is_pruned_and_published_manifest_tampering_fails_closed() {
    let fixture = Fixture::new();
    fixture.init(|_| {});
    let report = fixture.execute(ProjectAction::Sync);
    let generation = fixture.generation(details(&report));
    fs::write(generation.join("manifest.json"), b"{}").unwrap();
    assert!(
        run(
            &fixture.request(ProjectAction::Verify),
            &Limits::default(),
            &AtomicBool::new(false)
        )
        .is_err()
    );
}

#[test]
fn unchanged_sync_uses_signed_index_cache_and_force_full_rechecks_every_byte() {
    let fixture = Fixture::new();
    fs::write(
        fixture.source.join("large.bin"),
        vec![0x9a; 8 * 1024 * 1024],
    )
    .unwrap();
    fixture.init(|_| {});
    let first = fixture.execute(ProjectAction::Sync);
    assert_eq!(details(&first)["fresh_hash_count"], 2);
    let second = fixture.execute(ProjectAction::Sync);
    assert_eq!(details(&second)["fresh_hash_count"], 0);
    assert_eq!(details(&second)["cached_hash_count"], 2);
    assert_eq!(details(&second)["fresh_hash_bytes"], 0);
    assert_eq!(details(&second)["source_sha256_assessed"], false);
    assert_eq!(
        details(&second)["source_assessment_scope"],
        "metadata_guarded_incremental"
    );
    let mut full = fixture.request(ProjectAction::Sync);
    full.options.force_full_scan = true;
    let full = run(&full, &Limits::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(details(&full)["fresh_hash_count"], 2);
    assert_eq!(details(&full)["cached_hash_count"], 0);
    assert_eq!(details(&full)["source_sha256_assessed"], true);
    assert_eq!(details(&full)["generation"], details(&first)["generation"]);
    let verified = fixture.execute(ProjectAction::Verify);
    assert_eq!(details(&verified)["fresh_hash_count"], 2);
}

#[test]
fn cache_corruption_cannot_replace_a_signed_digest_and_is_rebuilt() {
    let fixture = Fixture::new();
    fixture.init(|_| {});
    fixture.execute(ProjectAction::Sync);
    let cache = fixture.state.join("source-index.json");
    let mut data: Value = serde_json::from_slice(&fs::read(&cache).unwrap()).unwrap();
    data["files"]["main.rs"]["sha256"] = serde_json::json!("0".repeat(64));
    fs::write(&cache, serde_json::to_vec(&data).unwrap()).unwrap();
    let repaired = fixture.execute(ProjectAction::Sync);
    assert_eq!(details(&repaired)["fresh_hash_count"], 1);
    assert_eq!(details(&repaired)["cached_hash_count"], 0);
    fs::write(cache, b"{broken").unwrap();
    assert_eq!(
        details(&fixture.execute(ProjectAction::Sync))["fresh_hash_count"],
        1
    );
}

#[cfg(unix)]
#[test]
fn executable_mode_changes_are_versioned_with_unchanged_content_hash() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    fixture.init(|_| {});
    let first = fixture.execute(ProjectAction::Sync);
    fs::set_permissions(
        fixture.source.join("main.rs"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let changed = fixture.execute(ProjectAction::Sync);
    assert_eq!(details(&changed)["revision"], 2);
    assert_eq!(details(&changed)["modified"], 1);
    assert_ne!(
        details(&changed)["source_fingerprint"],
        details(&first)["source_fingerprint"]
    );
    assert_eq!(
        fixture.execute(ProjectAction::Verify).result,
        Outcome::VerifiedWithinScope
    );
}

#[cfg(unix)]
#[test]
fn links_are_rejected_and_restrictive_modes_security_attributes_survive_copy() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let fixture = Fixture::new();
    fs::set_permissions(
        fixture.source.join("main.rs"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    #[cfg(target_os = "macos")]
    xattr::set(
        fixture.source.join("main.rs"),
        "com.apple.quarantine",
        b"0081;00000000;FileVeil-test;",
    )
    .unwrap();
    fixture.init(|config| config.copy_external_files = true);
    let report = fixture.execute(ProjectAction::Sync);
    let copy = fixture.generation(details(&report)).join("files/main.rs");
    assert_eq!(
        fs::metadata(&copy).unwrap().permissions().mode() & 0o777,
        0o600
    );
    #[cfg(target_os = "macos")]
    assert_eq!(
        xattr::get(&copy, "com.apple.quarantine").unwrap(),
        xattr::get(fixture.source.join("main.rs"), "com.apple.quarantine").unwrap()
    );
    symlink(&fixture.key, fixture.source.join("outside.key")).unwrap();
    assert!(
        run(
            &fixture.request(ProjectAction::Status),
            &Limits::default(),
            &AtomicBool::new(false)
        )
        .is_err()
    );
    fs::remove_file(fixture.source.join("outside.key")).unwrap();
    fs::hard_link(
        fixture.source.join("main.rs"),
        fixture.source.join("alias.rs"),
    )
    .unwrap();
    assert!(
        run(
            &fixture.request(ProjectAction::Status),
            &Limits::default(),
            &AtomicBool::new(false)
        )
        .is_err()
    );
}

#[test]
fn derived_outputs_are_signed_copied_verified_and_preserved_without_touching_originals() {
    let fixture = Fixture::new();
    fixture.init(|_| {});
    let binary = fixture._directory.path().join("compiled.bin");
    fs::write(&binary, b"example compiled artifact").unwrap();
    let mut request = fixture.request(ProjectAction::Sync);
    request.derived_artifacts = Some(vec![ProjectDerivedArtifact {
        path: binary.clone(),
        relative_name: "bin/example".into(),
        expected_sha256: digest(b"example compiled artifact"),
        source_sha256: Some(digest(b"fn main() {}\n")),
        method: "controlled_compiler_test".into(),
    }]);
    let first = run(&request, &Limits::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(first.result, Outcome::VerifiedWithinScope);
    assert_eq!(details(&first)["derived_artifacts_total"], 1);
    let marked = fixture
        .generation(details(&first))
        .join("derived/bin/example");
    assert_eq!(fs::read(&marked).unwrap(), fs::read(&binary).unwrap());
    fs::write(
        fixture.source.join("main.rs"),
        b"fn main() { println!(\"new\"); }\n",
    )
    .unwrap();
    let second = fixture.execute(ProjectAction::Sync);
    assert_eq!(details(&second)["derived_artifacts_total"], 1);
    assert_eq!(
        fixture.execute(ProjectAction::Verify).result,
        Outcome::VerifiedWithinScope
    );
    let output = fixture
        .generation(details(&second))
        .join("derived/bin/example");
    fs::write(output, b"tampered").unwrap();
    assert_eq!(
        fixture.execute(ProjectAction::Verify).result,
        Outcome::Failed
    );
    assert_eq!(fs::read(binary).unwrap(), b"example compiled artifact");
}

#[test]
fn interrupted_verified_release_recovers_its_exact_private_checkpoint() {
    let fixture = Fixture::new();
    fixture.init(|_| {});
    let first = fixture.execute(ProjectAction::Sync);
    let generation = fixture.generation(details(&first));
    fs::remove_file(generation.join("COMMITTED")).unwrap();
    let retry = fixture.execute(ProjectAction::Sync);
    assert_eq!(retry.result, Outcome::VerifiedWithinScope);
    assert_eq!(details(&retry)["generation"], details(&first)["generation"]);
    assert_eq!(details(&retry)["published"], true);
    assert!(generation.join("COMMITTED").exists());
}

#[test]
fn restoring_project_identity_requires_active_key_and_keeps_original_root_pin() {
    let fixture = Fixture::new();
    fixture.init(|_| {});
    fixture.execute(ProjectAction::Sync);
    let rotated = fixture._directory.path().join("private/rotated.key");
    SigningKey::generate().unwrap().save_new(&rotated).unwrap();
    let mut rotate = fixture.request(ProjectAction::Sync);
    rotate.options.rotate_to = Some(ProjectKey::File {
        path: rotated.clone(),
    });
    let latest = run(&rotate, &Limits::default(), &AtomicBool::new(false)).unwrap();
    let original_root = SigningKey::load(&fixture.key).unwrap().public_key();
    let stored: ProjectConfig =
        serde_json::from_slice(&fs::read(&fixture.config).unwrap()).unwrap();
    let recovered_config = fixture.source.join("recovered.project.json");
    let recovered_state = fixture._directory.path().join("private/recovered-state");
    let mut restore = ProjectRequest {
        action: ProjectAction::Init,
        config_path: recovered_config.clone(),
        state_directory: Some(recovered_state.clone()),
        init: Some(stored),
        key: Some(ProjectKey::File {
            path: fixture.key.clone(),
        }),
        ..Default::default()
    };
    assert!(run(&restore, &Limits::default(), &AtomicBool::new(false)).is_err());
    assert!(!recovered_config.exists());
    restore.key = Some(ProjectKey::File { path: rotated });
    let restored = run(&restore, &Limits::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(details(&restored)["revision"], details(&latest)["revision"]);
    let state: Value =
        serde_json::from_slice(&fs::read(recovered_state.join("state.json")).unwrap()).unwrap();
    assert_eq!(state["initial_key"]["key_id"], original_root.key_id);
}

#[test]
fn case_aliases_are_rejected_before_any_release_is_committed() {
    let fixture = Fixture::new();
    fixture.init(|_| {});
    fs::write(fixture.source.join("A.txt"), b"first").unwrap();
    fs::write(fixture.source.join("a.txt"), b"second").unwrap();
    let distinct = fs::read_dir(&fixture.source)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| matches!(entry.file_name().to_str(), Some("A.txt" | "a.txt")))
        .count();
    if distinct < 2 {
        return;
    }
    assert!(
        run(
            &fixture.request(ProjectAction::Sync),
            &Limits::default(),
            &AtomicBool::new(false)
        )
        .is_err()
    );
    assert!(!fixture.output.exists());
}

#[test]
fn unlisted_release_payload_is_rejected_by_verification_and_recovery() {
    let fixture = Fixture::new();
    fixture.init(|_| {});
    let first = fixture.execute(ProjectAction::Sync);
    let generation = fixture.generation(details(&first));
    fs::write(
        generation.join("unlisted-secret.txt"),
        b"not in signed manifest",
    )
    .unwrap();
    assert_eq!(
        fixture.execute(ProjectAction::Verify).result,
        Outcome::Failed
    );
    fs::remove_file(generation.join("COMMITTED")).unwrap();
    // A pending release with additional bytes cannot regain a commit marker.
    let retry = run(
        &fixture.request(ProjectAction::Sync),
        &Limits::default(),
        &AtomicBool::new(false),
    );
    assert!(retry.is_err() || retry.unwrap().result == Outcome::Failed);
    assert!(!generation.join("COMMITTED").exists());
}

#[test]
fn derived_and_source_backslash_traversal_cannot_escape_the_release_stage() {
    let fixture = Fixture::new();
    fixture.init(|_| {});
    let artifact = fixture._directory.path().join("artifact.bin");
    fs::write(&artifact, b"artifact").unwrap();
    let mut request = fixture.request(ProjectAction::Sync);
    request.derived_artifacts = Some(vec![ProjectDerivedArtifact {
        path: artifact,
        relative_name: "..\\..\\escaped.bin".into(),
        expected_sha256: digest(b"artifact"),
        source_sha256: None,
        method: "regression".into(),
    }]);
    assert!(run(&request, &Limits::default(), &AtomicBool::new(false)).is_err());
    assert!(!fixture.output.join("escaped.bin").exists());
    #[cfg(unix)]
    {
        fs::write(
            fixture.source.join("..\\outside.txt"),
            b"malicious filename",
        )
        .unwrap();
        assert!(
            run(
                &fixture.request(ProjectAction::Sync),
                &Limits::default(),
                &AtomicBool::new(false)
            )
            .is_err()
        );
    }
}

#[test]
fn verify_report_binds_the_raw_evidence_bytes_that_were_cryptographically_checked() {
    let fixture = Fixture::new();
    fixture.init(|_| {});
    let first = fixture.execute(ProjectAction::Sync);
    let path = fixture.generation(details(&first)).join("evidence.json");
    let original = fs::read(&path).unwrap();
    let verify = fixture.execute(ProjectAction::Verify);
    assert_eq!(details(&verify)["evidence_sha256"], digest(&original));
    let package: Value = serde_json::from_slice(&original).unwrap();
    let formatted = serde_json::to_vec_pretty(&package).unwrap();
    assert_ne!(digest(&original), digest(&formatted));
    fs::write(&path, &formatted).unwrap();
    let reformatted = fixture.execute(ProjectAction::Verify);
    assert_eq!(reformatted.result, Outcome::VerifiedWithinScope);
    assert_eq!(details(&reformatted)["evidence_sha256"], digest(&formatted));
}

#[test]
fn changed_unsigned_project_declarations_are_partial_until_a_new_generation_binds_them() {
    let fixture = Fixture::new();
    fixture.init(|_| {});
    fixture.execute(ProjectAction::Sync);
    let mut config: ProjectConfig =
        serde_json::from_slice(&fs::read(&fixture.config).unwrap()).unwrap();
    config.work_id = "new-work-declaration".into();
    config.author = "New Author Declaration".into();
    fs::write(&fixture.config, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let report = fixture.execute(ProjectAction::Verify);
    assert_eq!(report.result, Outcome::PartiallyVerified);
    assert_eq!(details(&report)["integrity"], "valid");
    assert_eq!(details(&report)["signature"], "valid");
    assert_eq!(details(&report)["generation_config_match"], false);
    assert_eq!(
        details(&report)["published_declaration"]["work_id"],
        "project-example"
    );
    assert_eq!(
        details(&report)["published_declaration"]["author"],
        "Example Author"
    );
}

#[test]
fn contextless_config_retains_its_approved_canonical_hash_for_automatic_sync() {
    let fixture = Fixture::new();
    fixture.init(|_| {});
    let config: Value = serde_json::from_slice(&fs::read(&fixture.config).unwrap()).unwrap();
    assert!(config.get("provenance").is_none());
    let mut request = fixture.request(ProjectAction::Sync);
    request.options.automatic = true;
    assert_eq!(
        run(&request, &Limits::default(), &AtomicBool::new(false))
            .unwrap()
            .result,
        Outcome::VerifiedWithinScope
    );
}

#[test]
fn complete_history_export_freezes_the_verified_raw_metadata_of_each_generation() {
    let fixture = Fixture::new();
    fixture.init(|_| {});
    let first = fixture.execute(ProjectAction::Sync);
    fs::write(
        fixture.source.join("main.rs"),
        b"fn main() { println!(\"second\"); }\n",
    )
    .unwrap();
    let second = fixture.execute(ProjectAction::Sync);
    let cached = fixture.execute(ProjectAction::Sync);
    assert_eq!(
        details(&cached)["history_metadata_scope"],
        "current_tip_only"
    );
    assert_eq!(
        details(&cached)["history_metadata"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let verify = fixture.execute(ProjectAction::Verify);
    assert_eq!(
        details(&verify)["history_metadata_scope"],
        "complete_retained_manifest_chain"
    );
    let rows = details(&verify)["history_metadata"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for (row, report) in rows.iter().zip([&first, &second]) {
        let generation = fixture.generation(details(report));
        assert_eq!(row["generation"], details(report)["generation"]);
        assert_eq!(
            row["manifest_sha256"],
            digest(&fs::read(generation.join("manifest.json")).unwrap())
        );
        assert_eq!(
            row["evidence_sha256"],
            digest(&fs::read(generation.join("evidence.json")).unwrap())
        );
    }
}

#[test]
fn missing_marked_copies_are_regenerated_from_originals_after_metadata_only_history_restore() {
    let fixture = Fixture::new();
    let image = fixture.source.join("asset.png");
    image::RgbImage::from_pixel(16, 16, image::Rgb([20, 30, 40]))
        .save(&image)
        .unwrap();
    let original = fs::read(&image).unwrap();
    fixture.init(|config| {
        config.rules = vec![ProjectRule {
            pattern: "**/*.png".into(),
            mode: ProjectFileMode::Structure,
            ..Default::default()
        }]
    });
    let first = fixture.execute(ProjectAction::Sync);
    fs::remove_dir_all(fixture.generation(details(&first)).join("files")).unwrap();
    let recovered = fixture.execute(ProjectAction::Sync);
    assert_eq!(recovered.result, Outcome::VerifiedWithinScope);
    assert_eq!(details(&recovered)["revision"], 2);
    assert!(
        fixture
            .generation(details(&recovered))
            .join("files/asset.png")
            .is_file()
    );
    assert_eq!(fs::read(&image).unwrap(), original);
    assert_eq!(
        fixture.execute(ProjectAction::Verify).result,
        Outcome::VerifiedWithinScope
    );
}

#[test]
fn expected_source_snapshots_are_fresh_commit_preconditions_and_never_publish_mismatches() {
    let fixture = Fixture::new();
    fixture.init(|_| {});
    let mut request = fixture.request(ProjectAction::Sync);
    request
        .options
        .expected_source_sha256
        .insert("main.rs".into(), digest(b"different program"));
    assert!(matches!(
        run(&request, &Limits::default(), &AtomicBool::new(false)),
        Err(fileveil_core::Error::Verification(_))
    ));
    assert!(!fixture.output.exists());
    request
        .options
        .expected_source_sha256
        .insert("main.rs".into(), digest(b"fn main() {}\n").to_uppercase());
    let first = run(&request, &Limits::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(first.result, Outcome::VerifiedWithinScope);
    let repeated = run(&request, &Limits::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(details(&repeated)["published"], false);
    assert_eq!(details(&repeated)["fresh_hash_count"], 1);
    fs::write(
        fixture.source.join("main.rs"),
        b"replacement without the checked watermark\n",
    )
    .unwrap();
    assert!(matches!(
        run(&request, &Limits::default(), &AtomicBool::new(false)),
        Err(fileveil_core::Error::Verification(_))
    ));
    let committed = fs::read_dir(
        fixture
            .output
            .join(details(&first)["project_id"].as_str().unwrap()),
    )
    .unwrap()
    .filter_map(|entry| entry.ok())
    .filter(|entry| entry.path().join("COMMITTED").exists())
    .count();
    assert_eq!(committed, 1);
    request.options.expected_source_sha256.clear();
    request
        .options
        .expected_source_sha256
        .insert("../escape".into(), digest(b"x"));
    assert!(run(&request, &Limits::default(), &AtomicBool::new(false)).is_err());
}

// FVPROV1 29870 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJiZjU3NTMwNDc4YmU3ZGExNWRmZGZjMGY1ZDVhZmJkYjA5ODdmMGU2OThkNThhNmUzNGJlM2NjZmNlZjUxMmQ5IiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvdGVzdHMvcHJvamVjdF9waXBlbGluZS5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjBhOTc5MjA4YWU4M2M1MDI1OGY5MjkwZTMxZmFjN2Q0ZTE0ZTkxM2ZjMGVlM2ZhODI3OTExMTVmNjczOWVmZGM4NTJmMTI0YzgyNDI0NGU3MDlhNzg3NGJiNmJiNzllODlkZjc0NTEyMTNjOGM1ZmFhYzYwY2Q0NjJmNzU4NzAyIn1dfV0= FVPROV1-END
