// SPDX-License-Identifier: MPL-2.0
//! End-to-end signing permissions through the shipped stdio MCP entry point.
use fileveil_core::digest;
use fileveil_engine::heritage::signing::SigningKey;
use serde_json::{Value, json};
use std::{
    fmt::Write as _,
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

// The same newline-delimited initialize/tools/call protocol used by mcp.rs.
struct Client {
    process: Child,
    input: Option<ChildStdin>,
    responses: Receiver<Value>,
    next_id: u32,
}
impl Client {
    fn new(directory: &Path, signing_keys: &[&Path]) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fileveil-gui"));
        command.args(["--mcp", "--mcp-read-root"]).arg(directory);
        command.arg("--mcp-write-root").arg(directory);
        for path in signing_keys {
            command.arg("--mcp-signing-key").arg(path);
        }
        let mut process = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = process.stdin.take();
        let stdout = process.stdout.take().unwrap();
        let (sender, responses) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                let response = serde_json::from_str(&line).expect("MCP stdout must contain JSON");
                if sender.send(response).is_err() {
                    return;
                }
            }
        });
        let mut client = Self {
            process,
            input,
            responses,
            next_id: 1,
        };
        let initialized = client.request(
            "initialize",
            json!({
                "protocolVersion":"2025-11-25", "capabilities":{},
                "clientInfo":{"name":"fileveil-heritage-security-test","version":"1"}
            }),
        );
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

    fn request(&mut self, method: &str, parameters: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":parameters}));
        let response = self
            .responses
            .recv_timeout(Duration::from_secs(45))
            .expect("MCP response deadline");
        assert_eq!(response["id"], id, "{response}");
        response
    }

    fn heritage(
        &mut self,
        input: &Path,
        action: &str,
        output: Option<&Path>,
        options: Value,
    ) -> Value {
        let mut arguments =
            json!({"path":input,"action":action,"options_json":options.to_string()});
        if let Some(output) = output {
            arguments["output"] = json!(output);
        }
        self.request(
            "tools/call",
            json!({"name":"fileveil_heritage","arguments":arguments}),
        )
    }

    fn close(&mut self) {
        self.input.take();
        let start = Instant::now();
        loop {
            if let Some(status) = self.process.try_wait().unwrap() {
                assert!(status.success(), "MCP EOF shutdown failed");
                return;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "MCP EOF shutdown deadline"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.input.take();
        let start = Instant::now();
        while self.process.try_wait().ok().flatten().is_none() {
            if start.elapsed() > Duration::from_secs(5) {
                let _ = self.process.kill();
                let _ = self.process.wait();
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
}

fn original(directory: &Path) -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/png_clean.png");
    let target = directory.join("original.png");
    fs::copy(source, &target).unwrap();
    target
}

fn fresh_key(path: &Path) {
    SigningKey::generate().unwrap().save_new(path).unwrap();
}

fn mark_options(key: &Path) -> Value {
    json!({
        "key_paths":[key],
        "mark":{
            "work_id":"private-work-claim-42",
            "author":"Private Author Claim Unique 5271",
            "edition":"private-edition-38",
            "version":"1",
            "created_at":"2026-11-12T00:00:00Z"
        }
    })
}

fn successful_report(response: &Value) -> &Value {
    assert_eq!(response["result"]["isError"], false, "{response}");
    &response["result"]["structuredContent"]
}

fn permission_denied(response: &Value) {
    assert_eq!(response["result"]["isError"], true, "{response}");
    let report = &response["result"]["structuredContent"];
    assert_eq!(report["result"], "blocked", "{response}");
    assert_eq!(
        report["findings"][0]["code"], "mcp.permission_denied",
        "{response}"
    );
}

fn no_value_contains(value: &Value, private: &str) {
    match value {
        Value::String(text) => assert!(
            !text.contains(private),
            "A private value leaked into the MCP response"
        ),
        Value::Array(values) => {
            for value in values {
                no_value_contains(value, private);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                no_value_contains(value, private);
            }
        }
        _ => {}
    }
}

fn assert_redacted(response: &Value, directory: &Path, key: &Path) {
    no_value_contains(response, directory.to_str().unwrap());
    no_value_contains(response, key.to_str().unwrap());
    for claim in [
        "Private Author Claim Unique 5271",
        "private-work-claim-42",
        "private-edition-38",
        "FILEVEIL-ED25519-KEY-V1",
    ] {
        no_value_contains(response, claim);
    }
    let bytes = fs::read(key).unwrap();
    let mut seed_hex = String::new();
    for byte in &bytes[bytes.len() - 32..] {
        write!(&mut seed_hex, "{byte:02x}").unwrap();
    }
    no_value_contains(response, &seed_hex);
}

#[test]
fn directory_grants_do_not_implicitly_authorize_signing_or_key_generation() {
    let directory = tempdir();
    let input = original(directory.path());
    let key = directory.path().join("author.key");
    fresh_key(&key);
    let before = digest(&fs::read(&input).unwrap());
    let output = directory.path().join("denied.png");
    let mut client = Client::new(directory.path(), &[]);
    let denied = client.heritage(&input, "mark", Some(&output), mark_options(&key));
    permission_denied(&denied);
    assert_redacted(&denied, directory.path(), &key);
    assert!(!output.exists());
    assert_eq!(digest(&fs::read(&input).unwrap()), before);
    let listed = client.request("tools/list", json!({}));
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert!(tools.iter().any(|tool| tool["name"] == "fileveil_heritage"));
    assert!(
        tools
            .iter()
            .all(|tool| !tool["name"].as_str().unwrap().contains("keygen"))
    );
    let rejected = client.request("tools/call", json!({"name":"fileveil_heritage_keygen","arguments":{"output":directory.path().join("forbidden.key")}}));
    assert_eq!(rejected["error"]["code"], -32602);
    assert!(!directory.path().join("forbidden.key").exists());
    client.close();
}

#[test]
fn explicit_signing_key_completes_mark_verify_with_redacted_reports() {
    let directory = tempdir();
    let input = original(directory.path());
    let key = directory.path().join("author.key");
    fresh_key(&key);
    let original_hash = digest(&fs::read(&input).unwrap());
    let key_hash = digest(&fs::read(&key).unwrap());
    let output = directory.path().join("marked.png");
    let mut client = Client::new(directory.path(), &[&key]);
    let marked = client.heritage(&input, "mark", Some(&output), mark_options(&key));
    let report = successful_report(&marked);
    assert_eq!(report["operation"], "heritage");
    assert_eq!(report["integrity"]["original_unchanged"], true);
    assert_eq!(report["integrity"]["pixel_equal"], true);
    assert!(output.exists());
    assert_redacted(&marked, directory.path(), &key);
    let verified = client.heritage(&output, "verify", None, json!({}));
    let verification = &successful_report(&verified)["advanced"]["heritage"]["verification"];
    for field in ["signature", "content_binding", "chain"] {
        assert_eq!(verification[field], "valid", "{verified}");
    }
    assert_eq!(verification["trust"], "not_assessed");
    assert_redacted(&verified, directory.path(), &key);
    assert_eq!(digest(&fs::read(&input).unwrap()), original_hash);
    assert_eq!(digest(&fs::read(&key).unwrap()), key_hash);
    client.close();
}

#[test]
fn signing_grants_retain_other_key_path_output_and_resource_boundaries() {
    let directory = tempdir();
    let outside = tempdir();
    let input = original(directory.path());
    let key = directory.path().join("allowed.key");
    let other = directory.path().join("other.key");
    fresh_key(&key);
    fresh_key(&other);
    let original_hash = digest(&fs::read(&input).unwrap());
    let output = directory.path().join("rejected.png");
    let mut client = Client::new(directory.path(), &[&key]);
    permission_denied(&client.heritage(&input, "mark", Some(&output), mark_options(&other)));
    assert!(!output.exists());
    let reference = original(outside.path());
    permission_denied(&client.heritage(&input, "verify", None, json!({"reference":reference})));
    fs::write(&output, b"existing output must survive").unwrap();
    permission_denied(&client.heritage(&input, "mark", Some(&output), mark_options(&key)));
    assert_eq!(fs::read(&output).unwrap(), b"existing output must survive");
    let impossible_control = outside.path().join("not-present.png");
    let controls = vec![impossible_control; 9];
    let excess = client.heritage(&input, "lab", None, json!({"controls":controls}));
    assert_eq!(excess["result"]["isError"], true, "{excess}");
    assert!(
        excess["result"]["structuredContent"]["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|message| message.as_str().unwrap_or_default().contains("8 controls")),
        "Counts must be checked before opening the out-of-root controls"
    );
    assert_eq!(digest(&fs::read(&input).unwrap()), original_hash);
    client.close();
}

#[cfg(unix)]
#[test]
fn replacing_the_whitelisted_key_inode_does_not_authorize_a_new_key() {
    use std::os::unix::fs::MetadataExt;
    let directory = tempdir();
    let input = original(directory.path());
    let key = directory.path().join("author.key");
    fresh_key(&key);
    let original_inode = fs::metadata(&key).unwrap().ino();
    let original_hash = digest(&fs::read(&input).unwrap());
    let mut client = Client::new(directory.path(), &[&key]);
    let replacement = directory.path().join("replacement.key");
    fresh_key(&replacement);
    fs::rename(&replacement, &key).unwrap();
    assert_ne!(fs::metadata(&key).unwrap().ino(), original_inode);
    let output = directory.path().join("must-not-be-signed.png");
    let rejected = client.heritage(&input, "mark", Some(&output), mark_options(&key));
    permission_denied(&rejected);
    assert!(!output.exists());
    assert_eq!(digest(&fs::read(&input).unwrap()), original_hash);
    assert_eq!(client.request("ping", json!({}))["result"], json!({}));
    client.close();
}

// FVPROV1 12277 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIxNmY3NTkyMjA4YzkwM2Q5MGM4ZDBmYzBiMjFhODM1MTJhNjk2MWY2ZjkzYjEyYWUzMGI1NjQzZjU5OTViYWUwIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvdGVzdHMvaGVyaXRhZ2VfbWNwLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiNjhiYzE5ZjZkZDI5NWY2Nzc1MzFjZTA2MmYxNjJiNmJiMTQ4ZTg0YTQ3YjRmNjAwN2Q2MGQ3OWM0MDA5MjBiYjQxM2ZjNmM0MGUzNjU1ZTNjN2YxZDU0MDRhZjhjNTljNDI5ZDA3MWFmN2Y0NjY2NWJjZDg2ZGRiYjA4NzExMDEifV19XQ== FVPROV1-END
