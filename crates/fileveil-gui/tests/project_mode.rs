// SPDX-License-Identifier: MPL-2.0
//! Project operations through the real desktop worker protocol.
use fileveil_core::{Outcome, Report};
use fileveil_engine::project::{ProjectAction, ProjectConfig, ProjectKey, ProjectRequest};
use fileveil_gui::jobs::{JobHandle, JobKind, JobRequest};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

fn worker(request: ProjectRequest, after: Option<Vec<String>>) -> Report {
    let handle = JobHandle::spawn_with_executable(
        JobRequest::new(JobKind::Project {
            request: Box::new(request),
            after,
        }),
        PathBuf::from(env!("CARGO_BIN_EXE_fileveil-gui")),
        Arc::new(|| {}),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(result) = handle.try_recv() {
            assert!(
                !matches!(
                    result.report.result,
                    Outcome::Failed | Outcome::Blocked | Outcome::Unsupported
                ),
                "{:?}",
                result.report.warnings
            );
            return result.report;
        }
        assert!(Instant::now() < deadline, "Project worker did not complete");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn gui_worker_build_sync_verify_and_metadata_probe_preserve_source_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    std::fs::create_dir(&source).unwrap();
    let original = b"fn main() { println!(\"project fixture\"); }\n";
    std::fs::write(source.join("main.rs"), original).unwrap();
    let key = directory.path().join("owner.key");
    fileveil_engine::heritage::keygen(&key).unwrap();
    let config_path = source.join("fileveil.project.json");
    let private_state = directory.path().join("private-state");
    let mut request = ProjectRequest {
        action: ProjectAction::Init,
        config_path: config_path.clone(),
        state_directory: Some(private_state),
        key: Some(ProjectKey::File { path: key }),
        init: Some(ProjectConfig {
            work_id: "gui-project-fixture".into(),
            author: "Synthetic fixture".into(),
            copy_id: "desktop-test".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    let initialized = worker(request.clone(), None);
    assert_eq!(
        initialized.advanced.as_ref().unwrap()["project"]["action"],
        "init"
    );
    let config_text = std::fs::read_to_string(&config_path).unwrap();
    assert!(!config_text.contains("owner.key"));
    assert!(!config_text.contains("private-state"));
    request.action = ProjectAction::Sync;
    request.init = None;
    request.key = None;
    let built = worker(
        request.clone(),
        Some(vec![
            env!("CARGO_BIN_EXE_fileveil-gui").into(),
            "--version".into(),
        ]),
    );
    let project = &built.advanced.as_ref().unwrap()["project"];
    assert_eq!(project["published"], true);
    assert_eq!(project["build"]["exit_code"], 0);
    assert_eq!(project["signature"], "valid");
    assert_eq!(project["integrity"], "valid");
    let revision = project["revision"].clone();
    let unchanged = worker(request.clone(), None);
    assert_eq!(
        unchanged.advanced.as_ref().unwrap()["project"]["published"],
        false
    );
    assert_eq!(
        unchanged.advanced.as_ref().unwrap()["project"]["revision"],
        revision
    );
    request.action = ProjectAction::Verify;
    let verified = worker(request.clone(), None);
    let checked = &verified.advanced.as_ref().unwrap()["project"];
    for key in ["signature", "integrity", "history"] {
        assert_eq!(checked[key], "valid", "{key}");
    }
    request.action = ProjectAction::WatchProbe;
    request.options.automatic = true;
    let probe = worker(request, None);
    assert_eq!(probe.result, Outcome::NotAssessed);
    assert_eq!(
        probe.advanced.as_ref().unwrap()["project"]["source_sha256_assessed"],
        false
    );
    assert_eq!(std::fs::read(source.join("main.rs")).unwrap(), original);
}
