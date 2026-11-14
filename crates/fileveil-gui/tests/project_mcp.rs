// SPDX-License-Identifier: MPL-2.0
//! Project operations through the shipped MCP transport and capability broker.
use fileveil_core::Limits;
use fileveil_engine::{
    heritage::signing::SigningKey,
    project::{ProjectAction, ProjectConfig, ProjectKey, ProjectRequest},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        atomic::AtomicBool,
        mpsc::{self, Receiver},
    },
    thread,
    time::{Duration, Instant},
};

struct Client {
    child: Child,
    input: Option<ChildStdin>,
    responses: Receiver<Value>,
    next: u32,
}
impl Client {
    fn new(root: &Path, write: bool, key: Option<&Path>) -> Self {
        let keys: Vec<_> = key.into_iter().map(Path::to_path_buf).collect();
        Self::with_keys(root, write, &keys)
    }
    fn with_keys(root: &Path, write: bool, keys: &[PathBuf]) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fileveil-gui"));
        command.args(["--mcp", "--mcp-read-root"]).arg(root);
        if write {
            command.arg("--mcp-write-root").arg(root);
        }
        for key in keys {
            command.arg("--mcp-signing-key").arg(key);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (sender, responses) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                if sender
                    .send(serde_json::from_str(&line).expect("MCP JSON"))
                    .is_err()
                {
                    return;
                }
            }
        });
        let mut client = Self {
            child,
            input,
            responses,
            next: 1,
        };
        let initialized=client.request("initialize",json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"project-test","version":"1"}}));
        assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
        client.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        client
    }
    fn send(&mut self, value: Value) {
        let input = self.input.as_mut().unwrap();
        serde_json::to_writer(&mut *input, &value).unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
    }
    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        let response = self
            .responses
            .recv_timeout(Duration::from_secs(45))
            .expect("MCP project response deadline");
        assert_eq!(response["id"], id, "{response}");
        response
    }
    fn project(&mut self, name: &str, config: &Path, state: &Path, extra: Value) -> Value {
        let mut arguments = json!({"config":config,"state_directory":state});
        arguments
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        self.request("tools/call", json!({"name":name,"arguments":arguments}))
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.input.take();
        let started = Instant::now();
        while self.child.try_wait().ok().flatten().is_none() {
            if started.elapsed() > Duration::from_secs(5) {
                let _ = self.child.kill();
                let _ = self.child.wait();
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}
struct Project {
    _directory: tempfile::TempDir,
    root: PathBuf,
    config: PathBuf,
    state: PathBuf,
    key: PathBuf,
}
impl Project {
    fn new() -> Self {
        let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let root = directory.path().to_owned();
        let source = root.join("project/src");
        fs::create_dir_all(&source).unwrap();
        // More files than the ordinary descriptor soft limit would support if
        // every source held several broker descriptors simultaneously.
        for index in 0..160 {
            fs::write(
                source.join(format!("file-{index}.rs")),
                format!("// synthetic {index}\n"),
            )
            .unwrap();
        }
        let config = root.join("project/fileveil.project.json");
        let state = root.join("state");
        let key = root.join("owner.key");
        SigningKey::generate().unwrap().save_new(&key).unwrap();
        let report = fileveil_engine::project::run(
            &ProjectRequest {
                action: ProjectAction::Init,
                config_path: config.clone(),
                state_directory: Some(state.clone()),
                key: Some(ProjectKey::File { path: key.clone() }),
                init: Some(ProjectConfig {
                    work_id: "synthetic-mcp".into(),
                    author: "Synthetic".into(),
                    copy_id: "original".into(),
                    source_root: "src".into(),
                    output_directory: root.join("release"),
                    ..Default::default()
                }),
                ..Default::default()
            },
            &Limits::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(matches!(
            report.result,
            fileveil_core::Outcome::VerifiedWithinScope | fileveil_core::Outcome::PartiallyVerified
        ));
        Self {
            _directory: directory,
            root,
            config,
            state,
            key,
        }
    }
}

#[test]
fn mcp_project_permissions_separate_read_write_and_signing() {
    let project = Project::new();
    let mut read = Client::new(&project.root, false, None);
    let tools = read.request("tools/list", json!({}));
    for name in [
        "fileveil_project_sync",
        "fileveil_project_status",
        "fileveil_project_verify",
    ] {
        assert!(
            tools["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["name"] == name)
        );
    }
    let status = read.project(
        "fileveil_project_status",
        &project.config,
        &project.state,
        json!({}),
    );
    assert_eq!(status["result"]["isError"], false, "{status}");
    let denied = read.project(
        "fileveil_project_sync",
        &project.config,
        &project.state,
        json!({}),
    );
    assert_eq!(
        denied["result"]["structuredContent"]["result"], "blocked",
        "{denied}"
    );
    drop(read);
    let mut unsigned = Client::new(&project.root, true, None);
    let denied = unsigned.project(
        "fileveil_project_sync",
        &project.config,
        &project.state,
        json!({}),
    );
    assert_eq!(
        denied["result"]["structuredContent"]["result"], "blocked",
        "{denied}"
    );
    drop(unsigned);
    let mut signed = Client::new(&project.root, true, Some(&project.key));
    let result = signed.project(
        "fileveil_project_sync",
        &project.config,
        &project.state,
        json!({}),
    );
    assert_eq!(result["result"]["isError"], false, "{result}");
    assert_eq!(
        result["result"]["structuredContent"]["advanced"]["project"]["published"], true,
        "{result}"
    );
    let again = signed.project(
        "fileveil_project_sync",
        &project.config,
        &project.state,
        json!({}),
    );
    assert_eq!(
        again["result"]["structuredContent"]["advanced"]["project"]["published"], false,
        "{again}"
    );
    let rejected = signed.project(
        "fileveil_project_sync",
        &project.config,
        &project.state,
        json!({"after":["any-program"]}),
    );
    assert_eq!(rejected["result"]["isError"], true, "{rejected}");
    let rejected = signed.project(
        "fileveil_project_sync",
        &project.config,
        &project.state,
        json!({"options_json":"{\"git_ref\":\"HEAD\"}"}),
    );
    assert_eq!(rejected["result"]["isError"], true, "{rejected}");
    drop(signed);
    let mut independent = Client::new(&project.root, false, None);
    let verified = independent.project(
        "fileveil_project_verify",
        &project.config,
        &project.state,
        json!({}),
    );
    assert_eq!(verified["result"]["isError"], false, "{verified}");
    assert_eq!(
        verified["result"]["structuredContent"]["advanced"]["project"]["signature"], "valid",
        "{verified}"
    );
}

#[test]
fn version_controlled_configuration_cannot_expand_mcp_authority() {
    let project = Project::new();
    let outside = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    fs::write(
        outside.path().join("private.txt"),
        "synthetic out-of-grant content",
    )
    .unwrap();
    let mut config: ProjectConfig =
        serde_json::from_slice(&fs::read(&project.config).unwrap()).unwrap();
    config.source_root = outside.path().to_owned();
    fs::write(&project.config, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let mut client = Client::new(&project.root, true, Some(&project.key));
    let denied = client.project(
        "fileveil_project_sync",
        &project.config,
        &project.state,
        json!({}),
    );
    assert_eq!(
        denied["result"]["structuredContent"]["result"], "blocked",
        "{denied}"
    );
    assert!(
        !denied
            .to_string()
            .contains("synthetic out-of-grant content")
    );
}

#[test]
fn registry_mcp_registers_syncs_and_verifies_with_separate_signing_grants() {
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let root = directory.path();
    let registry = root.join("registry.json");
    let private = root.join("private");
    let source = root.join("game");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("project.godot"), "config_version=5\n").unwrap();
    let key = root.join("owner.key");
    SigningKey::generate().unwrap().save_new(&key).unwrap();
    let mut client = Client::new(root, true, Some(&key));
    let init=client.request("tools/call",json!({"name":"fileveil_registry_init","arguments":{"registry":registry,"state_directory":private,"defaults_json":"{\"author\":\"Synthetic\"}"}}));
    assert_eq!(init["result"]["isError"], false, "{init}");
    let add=client.request("tools/call",json!({"name":"fileveil_registry_add","arguments":{"registry":registry,"project_path":source,"key":key}}));
    assert_eq!(add["result"]["isError"], false, "{add}");
    let id =
        add["result"]["structuredContent"]["advanced"]["registry"]["projects"][0]["project_id"]
            .as_str()
            .unwrap();
    let arguments = json!({"registry":registry,"project_id":id});
    let sync = client.request(
        "tools/call",
        json!({"name":"fileveil_registry_sync","arguments":arguments}),
    );
    assert_eq!(sync["result"]["isError"], false, "{sync}");
    assert_eq!(
        sync["result"]["structuredContent"]["advanced"]["registry"]["projects"][0]["report"]["advanced"]
            ["project"]["published"],
        true,
        "{sync}"
    );
    drop(client);
    let mut client = Client::new(root, false, None);
    let verified = client.request(
        "tools/call",
        json!({"name":"fileveil_registry_verify","arguments":arguments}),
    );
    assert_eq!(verified["result"]["isError"], false, "{verified}");
    let denied = client.request(
        "tools/call",
        json!({"name":"fileveil_registry_sync","arguments":arguments}),
    );
    assert_eq!(
        denied["result"]["structuredContent"]["result"], "blocked",
        "{denied}"
    );
    assert_eq!(
        fs::read(source.join("project.godot")).unwrap(),
        b"config_version=5\n"
    );
}

#[test]
fn software_mcp_inspects_bytes_and_rejects_execution_and_unauthorized_decoding_keys() {
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let root = directory.path();
    let binary = root.join("sample.bin");
    fs::copy(control_binary(), &binary).unwrap();
    let key = root.join("owner.key");
    SigningKey::generate().unwrap().save_new(&key).unwrap();
    let original = fs::read(&binary).unwrap();
    let mut client = Client::new(root, true, None);
    let report = client.request(
        "tools/call",
        json!({"name":"fileveil_software_inspect","arguments":{"path":binary,"max_file_mib":512}}),
    );
    assert_eq!(report["result"]["isError"], false, "{report}");
    assert_eq!(
        report["result"]["structuredContent"]["operation"],
        "software"
    );
    for options in [
        json!({"allow_execution":true}),
        json!({"llvm_directory":root}),
        json!({"plugin_path":binary}),
        json!({"compiler_arguments":["-include","private.h"]}),
        json!({"key":{"kind":"file","path":key}}),
    ] {
        let denied=client.request("tools/call",json!({"name":"fileveil_software_verify","arguments":{"path":binary,"options_json":options.to_string(),"max_file_mib":512}}));
        assert_eq!(
            denied["result"]["structuredContent"]["result"], "blocked",
            "{denied}"
        );
    }
    drop(client);
    let mut granted = Client::new(root, false, Some(&key));
    let inspected = granted.request("tools/call", json!({
        "name":"fileveil_software_inspect",
        "arguments":{"path":binary,"max_file_mib":512,"options_json":json!({"key":{"kind":"file","path":key}}).to_string()}
    }));
    assert_eq!(inspected["result"]["isError"], false, "{inspected}");
    assert_eq!(fs::read(binary).unwrap(), original);
}

fn control_binary() -> std::path::PathBuf {
    #[cfg(unix)]
    let candidate = std::path::PathBuf::from("/usr/bin/true");
    #[cfg(windows)]
    let candidate = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_default())
        .join("System32/where.exe");
    if candidate.is_file() {
        candidate
    } else {
        std::env::current_exe().unwrap()
    }
}

#[test]
fn software_mcp_decodes_only_with_a_granted_key_and_cleans_into_a_verified_new_copy() {
    use fileveil_engine::software::{SoftwareAction, SoftwareMode, SoftwareRequest};
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let root = directory.path();
    let original = root.join("original.elf");
    fs::write(&original, elf_container()).unwrap();
    let before = fs::read(&original).unwrap();
    let key = root.join("owner.key");
    SigningKey::generate().unwrap().save_new(&key).unwrap();
    let marked = root.join("marked.elf");
    let report = fileveil_engine::software::run(
        &SoftwareRequest {
            action: SoftwareAction::Mark,
            mode: SoftwareMode::Structure,
            input_path: original.clone(),
            output_path: Some(marked.clone()),
            key: Some(ProjectKey::File { path: key.clone() }),
            work_id: "synthetic-mcp-software".into(),
            copy_id: "first".into(),
            ..Default::default()
        },
        &Limits::default(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert!(
        matches!(
            report.result,
            fileveil_core::Outcome::VerifiedWithinScope | fileveil_core::Outcome::PartiallyVerified
        ),
        "{report:?}"
    );
    let marked_bytes = fs::read(&marked).unwrap();
    let options = json!({"key":{"kind":"file","path":key}}).to_string();
    let mut denied = Client::new(root, true, None);
    let refusal=denied.request("tools/call",json!({"name":"fileveil_software_verify","arguments":{"path":marked,"options_json":options}}));
    assert_eq!(
        refusal["result"]["structuredContent"]["result"], "blocked",
        "{refusal}"
    );
    drop(denied);
    let mut granted = Client::new(root, true, Some(&key));
    let verified=granted.request("tools/call",json!({"name":"fileveil_software_verify","arguments":{"path":marked,"options_json":options}}));
    assert_eq!(verified["result"]["isError"], false, "{verified}");
    assert!(
        contains_field(&verified, "decoded", &json!(true)),
        "{verified}"
    );
    assert!(
        !verified.to_string().contains("synthetic-mcp-software"),
        "Private claims must remain redacted"
    );
    let cleaned = root.join("cleaned.elf");
    let clean = granted.request(
        "tools/call",
        json!({"name":"fileveil_software_clean","arguments":{"path":marked,"output":cleaned}}),
    );
    assert_eq!(clean["result"]["isError"], false, "{clean}");
    assert!(cleaned.is_file());
    assert_eq!(fs::read(&cleaned).unwrap(), before);
    assert_eq!(fs::read(&original).unwrap(), before);
    assert_eq!(fs::read(&marked).unwrap(), marked_bytes);
    let rechecked = granted.request(
        "tools/call",
        json!({"name":"fileveil_software_inspect","arguments":{"path":cleaned}}),
    );
    assert_eq!(rechecked["result"]["isError"], false, "{rechecked}");
    assert!(
        !contains_field(&rechecked, "decoded", &json!(true)),
        "{rechecked}"
    );
    let overwrite = granted.request(
        "tools/call",
        json!({"name":"fileveil_software_clean","arguments":{"path":marked,"output":cleaned}}),
    );
    assert_eq!(overwrite["result"]["isError"], true, "{overwrite}");
}
fn contains_field(value: &Value, name: &str, expected: &Value) -> bool {
    match value {
        Value::Object(map) => {
            map.get(name) == Some(expected)
                || map
                    .values()
                    .any(|value| contains_field(value, name, expected))
        }
        Value::Array(items) => items
            .iter()
            .any(|value| contains_field(value, name, expected)),
        _ => false,
    }
}
fn elf_container() -> Vec<u8> {
    // A bounded ELF64 container with one executable segment. This fixture is
    // parsed as bytes and is never launched by this test or the MCP server.
    let mut bytes = vec![0u8; 121];
    bytes[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x400078u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[88..96].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&121u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&121u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[120] = 0xc3;
    bytes
}

#[test]
fn registry_mcp_batch_supports_more_than_eight_explicit_independent_signing_keys() {
    use fileveil_engine::project::registry::{
        self, RegistryAction, RegistryDefaults, RegistryRequest,
    };
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let root = directory.path();
    let path = root.join("registry.json");
    let private = root.join("private");
    let call = |request: RegistryRequest| {
        registry::run(&request, &Limits::default(), &AtomicBool::new(false)).unwrap()
    };
    call(RegistryRequest {
        action: RegistryAction::Init,
        registry_path: Some(path.clone()),
        state_directory: Some(private.clone()),
        defaults: Some(RegistryDefaults {
            author: "Synthetic".into(),
            ..Default::default()
        }),
        ..Default::default()
    });
    let mut keys = Vec::new();
    for index in 0..9 {
        let project = root.join(format!("project-{index}"));
        fs::create_dir(&project).unwrap();
        fs::write(project.join("source.txt"), format!("Synthetic {index}\n")).unwrap();
        let registered = call(RegistryRequest {
            action: RegistryAction::Add,
            registry_path: Some(path.clone()),
            project_path: Some(project),
            ..Default::default()
        });
        let id = registered.advanced.as_ref().unwrap()["registry"]["projects"][0]["project_id"]
            .as_str()
            .unwrap();
        keys.push(private.join("keys").join(format!("{id}.key")));
    }
    let mut client = Client::with_keys(root, true, &keys);
    let synced = client.request(
        "tools/call",
        json!({"name":"fileveil_registry_sync","arguments":{"registry":path,"all":true}}),
    );
    assert_eq!(synced["result"]["isError"], false, "{synced}");
    let projects = synced["result"]["structuredContent"]["advanced"]["registry"]["projects"]
        .as_array()
        .unwrap();
    assert_eq!(projects.len(), 9);
    for project in projects {
        assert_eq!(
            project["report"]["advanced"]["project"]["published"], true,
            "{project}"
        );
    }
}
