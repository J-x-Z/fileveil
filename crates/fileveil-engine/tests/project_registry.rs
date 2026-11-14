// SPDX-License-Identifier: MPL-2.0
use fileveil_core::{Limits, Outcome};
use fileveil_engine::project::{self, registry::*};
use serde_json::Value;
use std::{fs, path::PathBuf, sync::atomic::AtomicBool};

struct Fixture {
    _temp: tempfile::TempDir,
    registry: PathBuf,
    private: PathBuf,
    source: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("game");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("Cargo.toml"),
            "[package]\nname=\"example\"\nversion=\"1.2.3\"\n",
        )
        .unwrap();
        fs::write(source.join("main.rs"), "fn main() {}\n").unwrap();
        Self {
            registry: temp.path().join("registry.json"),
            private: temp.path().join("private"),
            source,
            _temp: temp,
        }
    }
    fn request(&self, action: RegistryAction) -> RegistryRequest {
        RegistryRequest {
            action,
            registry_path: Some(self.registry.clone()),
            ..Default::default()
        }
    }
    fn execute(&self, request: RegistryRequest) -> fileveil_core::Report {
        run(&request, &Limits::default(), &AtomicBool::new(false)).unwrap()
    }
    fn init(&self) {
        let mut request = self.request(RegistryAction::Init);
        request.state_directory = Some(self.private.clone());
        request.defaults = Some(RegistryDefaults {
            author: "Example Author".into(),
            ..Default::default()
        });
        self.execute(request);
    }
    fn add(&self) -> String {
        let mut request = self.request(RegistryAction::Add);
        request.project_path = Some(self.source.clone());
        let report = self.execute(request);
        report.advanced.unwrap()["registry"]["projects"][0]["project_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}
fn details(report: &fileveil_core::Report) -> &Value {
    &report.advanced.as_ref().unwrap()["registry"]
}
#[test]
fn registry_registers_external_projects_and_keeps_incremental_evidence_private() {
    let fixture = Fixture::new();
    fixture.init();
    let before = fs::read(fixture.source.join("main.rs")).unwrap();
    let id = fixture.add();
    let list = fixture.execute(fixture.request(RegistryAction::List));
    assert_eq!(details(&list)["projects"][0]["kind"], "cargo");
    assert_eq!(
        details(&list)["projects"][0]["effective_policy"],
        "manifest_only"
    );
    assert!(!fixture.source.join("fileveil.project.json").exists());
    let mut sync = fixture.request(RegistryAction::Sync);
    sync.project_id = Some(id.clone());
    let first = fixture.execute(sync.clone());
    assert_eq!(first.result, Outcome::VerifiedWithinScope);
    assert_eq!(
        details(&first)["projects"][0]["report"]["advanced"]["project"]["published"],
        true
    );
    let second = fixture.execute(sync);
    assert_eq!(
        details(&second)["projects"][0]["report"]["advanced"]["project"]["cached_hash_count"],
        2
    );
    assert_eq!(fs::read(fixture.source.join("main.rs")).unwrap(), before);
    let mut verify = fixture.request(RegistryAction::Verify);
    verify.project_id = Some(id);
    assert_eq!(fixture.execute(verify).result, Outcome::VerifiedWithinScope);
    let serialized = fs::read_to_string(&fixture.registry).unwrap();
    assert!(!serialized.contains("FVED25519"));
}
#[test]
fn registry_global_defaults_and_per_project_overrides_apply_at_explicit_sync() {
    let fixture = Fixture::new();
    fixture.init();
    let id = fixture.add();
    let mut configure = fixture.request(RegistryAction::Configure);
    configure.defaults = Some(RegistryDefaults {
        author: "Updated Author".into(),
        copy_id: "release-2".into(),
        ..Default::default()
    });
    fixture.execute(configure);
    let mut sync = fixture.request(RegistryAction::Sync);
    sync.project_id = Some(id.clone());
    let report = fixture.execute(sync.clone());
    assert_eq!(
        details(&report)["projects"][0]["report"]["advanced"]["project"]["config"]["author"],
        "Updated Author"
    );
    let mut update = fixture.request(RegistryAction::Update);
    update.project_id = Some(id);
    update.overrides = Some(ProjectOverrides {
        author: Some("Independent Author".into()),
        ..Default::default()
    });
    fixture.execute(update);
    let report = fixture.execute(sync);
    assert_eq!(
        details(&report)["projects"][0]["report"]["advanced"]["project"]["config"]["author"],
        "Independent Author"
    );
}
#[test]
fn compiler_policy_cannot_publish_manifest_as_compiler_success() {
    let fixture = Fixture::new();
    fixture.init();
    let id = fixture.add();
    let mut update = fixture.request(RegistryAction::Update);
    update.project_id = Some(id.clone());
    update.overrides = Some(ProjectOverrides {
        policy: Some(RegistryPolicy::CompilerWatermark),
        ..Default::default()
    });
    fixture.execute(update);
    let mut sync = fixture.request(RegistryAction::Sync);
    sync.project_id = Some(id);
    let report = fixture.execute(sync);
    assert_eq!(report.result, Outcome::Failed);
    assert_eq!(details(&report)["projects"][0]["published"], false);
}
#[test]
fn legacy_registration_reuses_existing_private_history_without_modifying_old_config() {
    use fileveil_engine::heritage::signing::SigningKey;
    let fixture = Fixture::new();
    fixture.init();
    let config_path = fixture.source.join("fileveil.project.json");
    let state = fixture.private.join("legacy-state");
    fs::create_dir_all(&fixture.private).unwrap();
    let key = fixture.private.join("legacy.key");
    SigningKey::generate().unwrap().save_new(&key).unwrap();
    let mut request = project::ProjectRequest {
        action: project::ProjectAction::Init,
        config_path: config_path.clone(),
        state_directory: Some(state.clone()),
        init: Some(project::ProjectConfig {
            work_id: "legacy-work".into(),
            copy_id: "development".into(),
            author: "Legacy Author".into(),
            source_root: ".".into(),
            output_directory: fixture.source.join("dist"),
            ..Default::default()
        }),
        key: Some(project::ProjectKey::File { path: key }),
        ..Default::default()
    };
    project::run(&request, &Limits::default(), &AtomicBool::new(false)).unwrap();
    request.action = project::ProjectAction::Sync;
    request.init = None;
    project::run(&request, &Limits::default(), &AtomicBool::new(false)).unwrap();
    let before = fs::read(&config_path).unwrap();
    let mut migrate = fixture.request(RegistryAction::Migrate);
    migrate.config_path = Some(config_path.clone());
    migrate.legacy_state_directory = Some(state);
    let report = fixture.execute(migrate);
    let id = details(&report)["projects"][0]["project_id"]
        .as_str()
        .unwrap();
    let mut verify = fixture.request(RegistryAction::Verify);
    verify.project_id = Some(id.into());
    // Config migration makes the new project generation dirty until an explicit sync.
    let verify = fixture.execute(verify);
    assert_eq!(verify.result, Outcome::Failed);
    let mut sync = fixture.request(RegistryAction::Sync);
    sync.project_id = Some(id.into());
    assert_eq!(fixture.execute(sync).result, Outcome::VerifiedWithinScope);
    assert_eq!(fs::read(&config_path).unwrap(), before);
}

#[test]
fn uppercase_camera_assets_use_real_structure_marking_and_source_versions_are_scoped() {
    let fixture = Fixture::new();
    fixture.init();
    let image = fixture.source.join("CAMERA.PNG");
    image::RgbImage::from_pixel(24, 24, image::Rgb([70, 80, 90]))
        .save(&image)
        .unwrap();
    let original = fs::read(&image).unwrap();
    let id = fixture.add();
    let mut update = fixture.request(RegistryAction::Update);
    update.project_id = Some(id.clone());
    update.overrides = Some(ProjectOverrides {
        policy: Some(RegistryPolicy::AssetWatermark),
        ..Default::default()
    });
    fixture.execute(update);
    let mut sync = fixture.request(RegistryAction::Sync);
    sync.project_id = Some(id);
    let report = fixture.execute(sync);
    let project = &details(&report)["projects"][0]["report"]["advanced"]["project"];
    assert_eq!(report.result, Outcome::VerifiedWithinScope);
    assert!(
        project["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["path"] == "CAMERA.PNG"
                && file["mode"] == "structure"
                && file["output_sha256"].is_string())
    );
    assert_eq!(project["observations"]["source_version"]["value"], "1.2.3");
    assert_eq!(
        project["observations"]["source_version"]["scope"],
        "project_manifest_declaration"
    );
    assert_eq!(fs::read(image).unwrap(), original);
}

#[test]
#[ignore = "Requires explicitly selected native LLVM toolchain and FileVeil pass plugin"]
fn native_compiler_registry_publishes_authenticated_artifacts_and_reuses_unchanged_versions() {
    let fixture = Fixture::new();
    fixture.init();
    let source = fixture.source.join("main.c");
    let original=b"#include <stdio.h>\nint transform(int x) { return x * 3 + 7; }\nint main(int argc, char **argv) { (void)argv; printf(\"%d\\n\", transform(argc)); return 0; }\n";
    fs::write(&source, original).unwrap();
    let id = fixture.add();
    let mut update = fixture.request(RegistryAction::Update);
    update.project_id = Some(id.clone());
    update.overrides = Some(ProjectOverrides {
        policy: Some(RegistryPolicy::CompilerWatermark),
        ..Default::default()
    });
    update.compiler = Some(RegistryCompilerConfig {
        targets: vec![RegistryCompilerTarget {
            input: "main.c".into(),
            output: PathBuf::from("bin").join(format!("example{}", std::env::consts::EXE_SUFFIX)),
            backend: CompilerBackend::ClangSource,
        }],
        llvm_directory: Some(
            std::env::var_os("FILEVEIL_LLVM_DIR")
                .expect("FILEVEIL_LLVM_DIR required")
                .into(),
        ),
        plugin_path: Some(
            std::env::var_os("FILEVEIL_SOFTWARE_PLUGIN")
                .expect("FILEVEIL_SOFTWARE_PLUGIN required")
                .into(),
        ),
        allow_execution: true,
        test_arguments: vec![vec![], vec!["one".into()]],
        ..Default::default()
    });
    fixture.execute(update);
    let mut sync = fixture.request(RegistryAction::Sync);
    sync.project_id = Some(id.clone());
    let first = fixture.execute(sync.clone());
    assert_eq!(
        first.result,
        Outcome::VerifiedWithinScope,
        "{}",
        serde_json::to_string_pretty(&first).unwrap()
    );
    let first_project = &details(&first)["projects"][0]["report"]["advanced"]["project"];
    assert_eq!(first_project["derived_artifacts_total"], 1);
    assert_eq!(first_project["compiler"]["performed"], true);
    assert_eq!(
        first_project["compiler"]["artifacts"][0]["signature"],
        "valid"
    );
    let second = fixture.execute(sync);
    let second_project = &details(&second)["projects"][0]["report"]["advanced"]["project"];
    assert_eq!(second.result, Outcome::VerifiedWithinScope);
    assert_eq!(second_project["published"], false);
    assert_eq!(second_project["compiler"]["performed"], false);
    assert_eq!(second_project["generation"], first_project["generation"]);
    let mut verify = fixture.request(RegistryAction::Verify);
    verify.project_id = Some(id);
    assert_eq!(fixture.execute(verify).result, Outcome::VerifiedWithinScope);
    assert_eq!(fs::read(source).unwrap(), original);
}

// FVPROV1 11776 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI5NjU1Yjg0NjJkMGIwMzQwNTFiMDkzOWM1MWFmZWY4NDk0NzQ5ODg0M2NjMDZhY2QzZjA1YTgzNDRlYjFmNDcwIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvdGVzdHMvcHJvamVjdF9yZWdpc3RyeS5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6ImI4ZGFiNTk3MTk4MWVjZWUxZjU5YjU1ZmNlZDNkZDVmY2MxN2M2MDE0ZGI1Yzk4ZTgyYTc5ZmYyMzI2YTg4M2Y1Nzg5NmU5N2Q3OWM3YzBkNDk1MWY3M2QzMGJmMzk3YjlkY2MwNmYzNzAzZWVlNmU1MjNhOGExYmY4ZDg2NTAyIn1dfV0= FVPROV1-END
