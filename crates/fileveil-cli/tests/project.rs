// SPDX-License-Identifier: MPL-2.0
//! Project automation through the public CLI and its confined worker entry.
use fileveil_engine::heritage::signing::SigningKey;
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

struct Project {
    _directory: tempfile::TempDir,
    source: PathBuf,
    config: PathBuf,
    state: PathBuf,
    output: PathBuf,
    key: PathBuf,
}
impl Project {
    fn new() -> Self {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let source = directory.path().join("project/src");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("main.rs"), "fn main() {}\n").unwrap();
        let config = directory.path().join("project/fileveil.project.json");
        let state = directory.path().join("private-state");
        let output = directory.path().join("release");
        let key = directory.path().join("owner.key");
        SigningKey::generate().unwrap().save_new(&key).unwrap();
        Self {
            _directory: directory,
            source,
            config,
            state,
            output,
            key,
        }
    }
    fn command(&self, action: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fileveil"));
        command
            .args(["--json", "--timeout-seconds", "30", "project", action])
            .arg(&self.config)
            .arg("--state-directory")
            .arg(&self.state);
        command
    }
    fn init(&self, build: Option<Value>) {
        let mut command = self.command("init");
        command
            .args([
                "--work-id",
                "synthetic-project",
                "--author",
                "Synthetic author",
                "--source",
                "src",
            ])
            .arg("--output")
            .arg(&self.output)
            .arg("--key")
            .arg(&self.key);
        if let Some(build) = build {
            command.arg("--build-argv-json").arg(build.to_string());
        }
        success(command);
    }
}
fn execute(mut command: Command) -> (i32, Value) {
    let result = command.output().unwrap();
    let report = serde_json::from_slice(&result.stdout).unwrap_or_else(|_| {
        panic!(
            "CLI JSON missing, status={:?}, stderr={}",
            result.status,
            String::from_utf8_lossy(&result.stderr)
        )
    });
    (result.status.code().unwrap_or(-1), report)
}
fn success(command: Command) -> Value {
    let (code, report) = execute(command);
    assert!(matches!(code, 0 | 4), "{report}");
    assert!(
        matches!(
            report["result"].as_str(),
            Some("verified_within_scope" | "partially_verified")
        ),
        "{report}"
    );
    report
}

#[test]
fn public_project_cli_is_incremental_and_preserves_development_sources() {
    let project = Project::new();
    project.init(None);
    let original = fs::read(project.source.join("main.rs")).unwrap();
    let first = success(project.command("sync"));
    let first = &first["advanced"]["project"];
    assert_eq!(first["published"], true, "{first}");
    assert_eq!(first["added"], 1);
    assert_eq!(fs::read(project.source.join("main.rs")).unwrap(), original);
    let second = success(project.command("sync"));
    let second = &second["advanced"]["project"];
    assert_eq!(second["published"], false, "{second}");
    assert_eq!(second["manifest_sha256"], first["manifest_sha256"]);
    assert_eq!(second["generation"], first["generation"]);
    fs::write(
        project.source.join("main.rs"),
        "fn main() { println!(\"changed\"); }\n",
    )
    .unwrap();
    let changed = success(project.command("sync"));
    assert_eq!(changed["advanced"]["project"]["modified"], 1, "{changed}");
    fs::rename(
        project.source.join("main.rs"),
        project.source.join("renamed.rs"),
    )
    .unwrap();
    let renamed = success(project.command("sync"));
    assert_eq!(renamed["advanced"]["project"]["renamed"], 1, "{renamed}");
    let verified = success(project.command("verify"));
    assert_eq!(
        verified["advanced"]["project"]["integrity"], "valid",
        "{verified}"
    );
    assert_eq!(
        verified["advanced"]["project"]["signature"], "valid",
        "{verified}"
    );
    assert_eq!(
        verified["advanced"]["project"]["history"], "valid",
        "{verified}"
    );
    let public = fs::read_to_string(&project.config).unwrap();
    assert!(!public.contains("owner.key"));
    assert!(!public.contains("private-state"));
}

#[test]
fn explicit_and_saved_builds_gate_project_publication() {
    let project = Project::new();
    let executable = env!("CARGO_BIN_EXE_fileveil");
    project.init(Some(json!([executable, "--version"])));
    let mut failed = project.command("sync");
    failed
        .arg("--after")
        .args([executable, "invalid-fileveil-command"]);
    let (code, report) = execute(failed);
    assert_eq!(code, 5, "{report}");
    let status = success(project.command("status"));
    assert_eq!(status["advanced"]["project"]["revision"], 0, "{status}");
    let mut built = project.command("sync");
    built.arg("--build");
    let report = success(built);
    assert_eq!(report["advanced"]["project"]["published"], true, "{report}");
    assert_eq!(
        report["advanced"]["project"]["build"]["exit_code"], 0,
        "{report}"
    );
    let mut watch = project.command("watch");
    watch.args(["--max-runs", "1", "--poll-ms", "100", "--debounce-ms", "50"]);
    let report = success(watch);
    assert_eq!(
        report["advanced"]["project"]["published"], false,
        "{report}"
    );
}

#[test]
fn project_git_resolution_does_not_run_repository_filters_or_hooks() {
    let project = Project::new();
    let root = project.config.parent().unwrap();
    let git = |arguments: &[&str]| {
        let status = Command::new("git")
            .arg("-C")
            .arg(root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env(
                "GIT_CONFIG_GLOBAL",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
            )
            .args(arguments)
            .status()
            .unwrap();
        assert!(status.success());
    };
    git(&["init", "-q"]);
    git(&["add", "src/main.rs"]);
    git(&[
        "-c",
        "user.name=Synthetic",
        "-c",
        "user.email=synthetic@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        "synthetic",
    ]);
    let sentinel = root.join("unexpected-filter-execution");
    git(&[
        "config",
        "core.fsmonitor",
        "echo unexpected > unexpected-filter-execution",
    ]);
    fs::write(root.join(".gitattributes"), "*.rs filter=synthetic\n").unwrap();
    git(&[
        "config",
        "filter.synthetic.clean",
        "echo unexpected > unexpected-filter-execution",
    ]);
    project.init(None);
    let mut synchronize = project.command("sync");
    synchronize.args(["--git-ref", "HEAD"]);
    let report = success(synchronize);
    let git = &report["advanced"]["project"]["git"];
    assert_eq!(git["reference"], "HEAD", "{report}");
    assert!(
        matches!(git["commit"].as_str().map(str::len), Some(40 | 64)),
        "{report}"
    );
    assert!(git["tracked_worktree_dirty"].is_null());
    assert!(!sentinel.exists());
}

#[test]
fn watch_debounces_a_saved_file_and_ignores_its_own_release_tree() {
    let mut project = Project::new();
    project.output = project.source.join("release");
    project.init(None);
    let mut command = project.command("watch");
    command
        .args([
            "--max-runs",
            "2",
            "--poll-ms",
            "100",
            "--debounce-ms",
            "150",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, reports) = mpsc::channel();
    thread::spawn(move || {
        for value in serde_json::Deserializer::from_reader(stdout).into_iter::<Value>() {
            let Ok(value) = value else { return };
            if sender.send(value).is_err() {
                return;
            }
        }
    });
    let result = || {
        let first = reports
            .recv_timeout(Duration::from_secs(45))
            .expect("Initial watch synchronization");
        assert_eq!(first["advanced"]["project"]["published"], true, "{first}");
        // Give the watch loop enough time to observe its own output changes.
        assert!(reports.recv_timeout(Duration::from_millis(700)).is_err());
        fs::write(
            project.source.join("main.rs"),
            "fn main() { println!(\"saved\"); }\n",
        )
        .unwrap();
        let next = reports
            .recv_timeout(Duration::from_secs(45))
            .expect("Debounced save synchronization");
        assert_eq!(next["advanced"]["project"]["modified"], 1, "{next}");
        assert_eq!(next["advanced"]["project"]["published"], true, "{next}");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(matches!(status.code(), Some(0 | 4)), "{status}");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "Watch max-runs completion deadline"
            );
            thread::sleep(Duration::from_millis(20));
        }
    };
    // Reap the owned driver even when an assertion unwinds.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(result));
    let _ = child.kill();
    let _ = child.wait();
    if let Err(error) = outcome {
        std::panic::resume_unwind(error);
    }
}

#[test]
fn project_init_template_restores_fixed_identity_and_public_provenance() {
    use fileveil_engine::project::ProjectConfig;
    let project = Project::new();
    let template = project._directory.path().join("template.json");
    let config = ProjectConfig {
        project_id: "1234567890abcdef1234567890abcdef".into(),
        work_id: "synthetic-template-work".into(),
        copy_id: "release".into(),
        author: "Template author".into(),
        source_root: "src".into(),
        output_directory: project.output.clone(),
        provenance: json!({"release_pipeline":"synthetic"}),
        ..Default::default()
    };
    fs::write(&template, serde_json::to_vec(&config).unwrap()).unwrap();
    let mut command = project.command("init");
    command
        .arg("--template")
        .arg(&template)
        .args(["--author", "Explicit author"])
        .arg("--key")
        .arg(&project.key);
    let initialized = success(command);
    assert_eq!(
        initialized["advanced"]["project"]["project_id"],
        config.project_id
    );
    let stored: ProjectConfig =
        serde_json::from_slice(&fs::read(&project.config).unwrap()).unwrap();
    assert_eq!(stored.work_id, config.work_id);
    assert_eq!(stored.author, "Explicit author");
    assert_eq!(stored.provenance, config.provenance);
    let synchronized = success(project.command("sync"));
    assert_eq!(
        synchronized["advanced"]["project"]["project_id"],
        config.project_id
    );
    success(project.command("verify"));
    let invalid = project._directory.path().join("invalid-template.json");
    let mut encoded = serde_json::to_value(&config).unwrap();
    encoded["key"] = "private-key-bytes-must-not-be-accepted".into();
    fs::write(&invalid, serde_json::to_vec(&encoded).unwrap()).unwrap();
    let mut rejected = Command::new(env!("CARGO_BIN_EXE_fileveil"));
    rejected
        .args(["--json", "project", "init"])
        .arg(project._directory.path().join("rejected.json"))
        .arg("--template")
        .arg(invalid);
    let (code, _) = execute(rejected);
    assert_ne!(code, 0);
    assert!(!project._directory.path().join("rejected.json").exists());
}

#[test]
fn expected_source_hashes_gate_publication_before_a_generation_is_committed() {
    let project = Project::new();
    project.init(None);
    let config: Value = serde_json::from_slice(&fs::read(&project.config).unwrap()).unwrap();
    let namespace = project.output.join(config["project_id"].as_str().unwrap());
    let committed = || {
        fs::read_dir(&namespace)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .filter(|entry| entry.path().join("COMMITTED").is_file())
                    .count()
            })
            .unwrap_or(0)
    };
    let source = project.source.join("main.rs");
    let original = fs::read(&source).unwrap();
    let expected = json!({"main.rs":fileveil_core::digest(&original)});
    for invalid in [
        json!({"main.rs":123}),
        json!([]),
        json!(null),
        json!({"main.rs":"invalid"}),
        json!({"../outside":"a".repeat(64)}),
    ] {
        let mut request = project.command("sync");
        request
            .arg("--expected-sources-json")
            .arg(invalid.to_string());
        let (code, report) = execute(request);
        assert_ne!(code, 0, "{report}");
        assert!(
            matches!(report["result"].as_str(), Some("failed" | "blocked")),
            "{report}"
        );
        assert_eq!(committed(), 0);
        assert_eq!(fs::read(&source).unwrap(), original);
    }
    let mut request = project.command("sync");
    request
        .arg("--expected-sources-json")
        .arg(expected.to_string());
    let accepted = success(request);
    assert_eq!(accepted["advanced"]["project"]["published"], true);
    assert_eq!(committed(), 1);
    fs::write(
        &source,
        "fn main() { println!(\"changed after authentication\"); }\n",
    )
    .unwrap();
    let mut request = project.command("sync");
    request
        .arg("--expected-sources-json")
        .arg(expected.to_string());
    let (code, report) = execute(request);
    assert_ne!(code, 0, "{report}");
    assert!(
        matches!(report["result"].as_str(), Some("failed" | "blocked")),
        "{report}"
    );
    assert_eq!(
        committed(),
        1,
        "A rejected source must leave the existing signed generation intact"
    );
    let mut request = project.command("sync");
    request
        .arg("--expected-sources-json")
        .arg(json!({"main.rs":fileveil_core::digest(&fs::read(&source).unwrap())}).to_string());
    assert_eq!(success(request)["advanced"]["project"]["published"], true);
    assert_eq!(committed(), 2);
    success(project.command("verify"));
}

// FVPROV1 14834 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJjYzA1YTI4ZTQyZDYwYWI5YjVkZGVkYzU5ZDMxZWEyZTJmYmE1MWRlNDI3NTgxMTE2ODMwYzc0MjNmMzNlYTAzIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1jbGkvdGVzdHMvcHJvamVjdC5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6ImIxNjk4NmYzNDAwMmQzNDU1M2FmNGZiZGNjOTVmZjgzZDQ0YjdhNTBlNTY3Yzg4ZDZjNjI1MDM0NmQzM2JiOWI0MTcyMTE5NjQxNjAyZGRhYTI5NjNjMDUwMzBmM2U5ODE2NTY2NzkxMWMxNDMxZTQ2M2VhZWMyY2NhZTcyNTA5In1dfV0= FVPROV1-END
