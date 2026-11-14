// SPDX-License-Identifier: MPL-2.0
//! Unified registry operations through the actual CLI worker transport.
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};

fn command(action: &str, registry: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fileveil"));
    command
        .args(["--json", "--timeout-seconds", "30", "registry", action])
        .arg("--registry")
        .arg(registry);
    command
}
fn execute(mut command: Command) -> (i32, Value) {
    let output = command.output().unwrap();
    let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "Missing CLI report {:?}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code().unwrap_or(-1), value)
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
fn registry_registration_batch_sync_defaults_and_independent_keys_are_real() {
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let registry = root.path().join("registry.json");
    let private = root.path().join("private");
    let mut init = command("init", &registry);
    init.arg("--state-directory")
        .arg(&private)
        .args(["--author", "Synthetic author"]);
    success(init);
    let mut ids = Vec::new();
    let mut public_keys = Vec::new();
    for name in ["cargo-project", "godot-project"] {
        let source = root.path().join(name);
        fs::create_dir(&source).unwrap();
        let (file, bytes) = if name.starts_with("cargo") {
            (
                "Cargo.toml",
                "[package]\nname=\"synthetic\"\nversion=\"0.1.0\"\n",
            )
        } else {
            ("project.godot", "config_version=5\n")
        };
        fs::write(source.join(file), bytes).unwrap();
        let mut add = command("add", &registry);
        add.arg(&source);
        let result = success(add);
        let entry = &result["advanced"]["registry"]["projects"][0];
        ids.push(entry["project_id"].as_str().unwrap().to_owned());
        let mut sync = command("sync", &registry);
        sync.arg(ids.last().unwrap());
        let synced = success(sync);
        let detail =
            &synced["advanced"]["registry"]["projects"][0]["report"]["advanced"]["project"];
        assert_eq!(detail["published"], true, "{synced}");
        let key = fileveil_engine::heritage::signing::SigningKey::load(
            &private
                .join("keys")
                .join(format!("{}.key", ids.last().unwrap())),
        )
        .unwrap();
        public_keys.push(serde_json::to_value(key.public_key()).unwrap());
        assert_eq!(fs::read(source.join(file)).unwrap(), bytes.as_bytes());
    }
    assert_ne!(ids[0], ids[1]);
    assert_ne!(public_keys[0], public_keys[1]);
    let listed = success(command("list", &registry));
    assert_eq!(listed["advanced"]["registry"]["registered_projects"], 2);
    let projects = listed["advanced"]["registry"]["projects"]
        .as_array()
        .unwrap();
    assert!(projects.iter().any(|entry| entry["kind"] == "cargo"));
    assert!(projects.iter().any(|entry| entry["kind"] == "godot"));
    let mut batch = command("sync", &registry);
    batch.arg("--all");
    let synced = success(batch);
    for entry in synced["advanced"]["registry"]["projects"]
        .as_array()
        .unwrap()
    {
        assert_eq!(
            entry["report"]["advanced"]["project"]["published"], false,
            "{entry}"
        );
    }
    let mut verify = command("verify", &registry);
    verify.arg("--all");
    success(verify);
    let mut configure = command("configure", &registry);
    configure
        .arg("--defaults-json")
        .arg(json!({"author":"New synthetic author","copy_id":"release-2"}).to_string());
    success(configure);
    let mut sync = command("sync", &registry);
    sync.arg(&ids[0]);
    let updated = success(sync);
    assert_eq!(
        updated["advanced"]["registry"]["projects"][0]["report"]["advanced"]["project"]["published"],
        true,
        "{updated}"
    );
    let mut remove = command("remove", &registry);
    remove.arg(&ids[1]);
    success(remove);
    assert_eq!(
        success(command("list", &registry))["advanced"]["registry"]["registered_projects"],
        1
    );
}

#[test]
fn compiler_policy_cannot_publish_without_a_real_compiler_target() {
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let registry = root.path().join("registry.json");
    let private = root.path().join("private");
    let source = root.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("main.c"), "int main(void){return 0;}\n").unwrap();
    let mut init = command("init", &registry);
    init.arg("--state-directory")
        .arg(private)
        .args(["--author", "Synthetic"]);
    success(init);
    let mut add = command("add", &registry);
    add.arg(&source).args(["--policy", "compiler-watermark"]);
    let report = success(add);
    let id = report["advanced"]["registry"]["projects"][0]["project_id"]
        .as_str()
        .unwrap();
    let mut sync = command("sync", &registry);
    sync.arg(id);
    let (code, report) = execute(sync);
    assert_ne!(code, 0);
    assert_eq!(report["advanced"]["registry"]["failed"], true, "{report}");
    assert!(!source.join("dist/fileveil-release/current.json").exists());
}

#[test]
fn registry_ci_generates_portable_configuration_without_executing_or_overwriting() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("generated");
    let invocation = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fileveil"));
        command
            .args([
                "--json",
                "registry",
                "ci",
                "--name",
                "Synthetic project",
                "--work-id",
                "synthetic-ci",
                "--author",
                "Synthetic author",
                "--artifacts",
                "dist",
                "--output",
                "fileveil-release",
                "--build-argv-json",
                "[\"program-that-must-not-be-executed\",\"--build\"]",
                "--test-argv-json",
                "[\"program-that-must-not-be-executed\",\"--test\"]",
                "--engine-ref",
                "0123456789012345678901234567890123456789",
                "--runner",
                "windows-latest",
                "--write-directory",
            ])
            .arg(&output);
        command
    };
    let (code, bundle) = execute(invocation());
    assert_eq!(code, 0, "{bundle}");
    assert!(
        bundle["workflow_yaml"]
            .as_str()
            .unwrap()
            .contains("windows-latest")
    );
    assert!(
        bundle["local_command"]
            .as_str()
            .unwrap()
            .contains("fileveil")
    );
    let config = fs::read(output.join("fileveil-ci.json")).unwrap();
    let workflow = fs::read(output.join(".github/workflows/fileveil-release.yml")).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&config).unwrap()["work_id"],
        "synthetic-ci"
    );
    let exported: Value = serde_json::from_slice(&config).unwrap();
    assert_eq!(exported["policy"], "manifest_only");
    assert_eq!(exported["rules"].as_array().unwrap().len(), 6);
    let (code, _) = execute(invocation());
    assert_ne!(code, 0);
    assert_eq!(fs::read(output.join("fileveil-ci.json")).unwrap(), config);
    assert_eq!(
        fs::read(output.join(".github/workflows/fileveil-release.yml")).unwrap(),
        workflow
    );
}

#[test]
fn registry_ci_preserves_selected_policy_rules_and_compiler_configuration() {
    let rules = json!([{"pattern":"images/**/*.png","mode":"invisible","strength":12}]);
    let compiler = json!({"targets":[{"input":"original.ll","output":"marked.bin","backend":"llvm_ir"}],"optimization":"O2"});
    let mut command = Command::new(env!("CARGO_BIN_EXE_fileveil"));
    command
        .args([
            "--json",
            "registry",
            "ci",
            "--work-id",
            "synthetic-ci-policy",
            "--author",
            "Synthetic",
            "--policy",
            "hybrid",
            "--rules-json",
        ])
        .arg(rules.to_string())
        .arg("--compiler-json")
        .arg(compiler.to_string());
    let (code, bundle) = execute(command);
    assert_eq!(code, 0, "{bundle}");
    let config: Value = serde_json::from_str(bundle["config_json"].as_str().unwrap()).unwrap();
    assert_eq!(config["policy"], "hybrid");
    assert_eq!(config["rules"], rules);
    assert_eq!(config["compiler"]["targets"], compiler["targets"]);
    for (flag, invalid) in [
        (
            "--compiler-json",
            json!({"private_key":"synthetic-private-value"}),
        ),
        ("--rules-json", json!({"pattern":"**"})),
    ] {
        let mut rejected = Command::new(env!("CARGO_BIN_EXE_fileveil"));
        rejected
            .args([
                "--json",
                "registry",
                "ci",
                "--work-id",
                "synthetic-ci-policy",
                "--author",
                "Synthetic",
            ])
            .arg(flag)
            .arg(invalid.to_string());
        let (code, report) = execute(rejected);
        assert_ne!(code, 0);
        assert!(!report.to_string().contains("synthetic-private-value"));
    }
}
