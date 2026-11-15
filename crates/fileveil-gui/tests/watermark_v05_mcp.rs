// SPDX-License-Identifier: MPL-2.0
//! Public 0.5 aliases and credential boundaries through the shipped stdio server.
use fileveil_core::digest;
use fileveil_engine::heritage::{
    container, custody,
    signing::{self, SigningKey},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

struct Client {
    child: Child,
    stdin: Option<ChildStdin>,
    responses: Receiver<Value>,
    next_id: u32,
}
impl Client {
    fn new(root: &Path, signing_keys: &[&Path]) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fileveil-gui"));
        command
            .args(["--mcp", "--mcp-read-root"])
            .arg(root)
            .arg("--mcp-write-root")
            .arg(root);
        for key in signing_keys {
            command.arg("--mcp-signing-key").arg(key);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (sender, responses) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                let value = serde_json::from_str(&line).expect("MCP stdout must be JSON");
                if sender.send(value).is_err() {
                    return;
                }
            }
        });
        let mut client = Self {
            child,
            stdin,
            responses,
            next_id: 1,
        };
        let initialized = client.request(
            "initialize",
            json!({
                "protocolVersion":"2025-11-25", "capabilities":{},
                "clientInfo":{"name":"fileveil-watermark-v05-test","version":"1"}
            }),
        );
        assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
        client.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        client
    }
    fn send(&mut self, value: Value) {
        let stdin = self.stdin.as_mut().unwrap();
        serde_json::to_writer(&mut *stdin, &value).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }
    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        let response = self
            .responses
            .recv_timeout(Duration::from_secs(150))
            .expect("MCP response deadline");
        assert_eq!(response["id"], id, "{response}");
        response
    }
    fn call(
        &mut self,
        tool: &str,
        input: &Path,
        output: Option<&Path>,
        action: Option<&str>,
        options: Value,
    ) -> Value {
        let mut arguments = json!({"path":input,"options_json":options.to_string()});
        if let Some(output) = output {
            arguments["output"] = json!(output);
        }
        if let Some(action) = action {
            arguments["action"] = json!(action);
        }
        self.request("tools/call", json!({"name":tool,"arguments":arguments}))
    }
    fn close(&mut self) {
        self.stdin.take();
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "MCP EOF shutdown failed");
                return;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "MCP shutdown deadline"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.stdin.take();
        let start = Instant::now();
        while self.child.try_wait().ok().flatten().is_none() {
            if start.elapsed() > Duration::from_secs(5) {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}
fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
}
fn image(root: &Path, natural: bool) -> PathBuf {
    let fixture = if natural {
        "../fileveil-engine/tests/fixtures/watermark/astronaut.png"
    } else {
        "../../tests/fixtures/png_clean.png"
    };
    let input = root.join("input.png");
    fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join(fixture), &input).unwrap();
    input
}
fn fresh_key(path: &Path) -> SigningKey {
    let key = SigningKey::generate().unwrap();
    key.save_new(path).unwrap();
    key
}
fn successful(response: &Value) -> &Value {
    assert_eq!(response["result"]["isError"], false, "{response}");
    let report = &response["result"]["structuredContent"];
    assert_eq!(report["operation"], "heritage", "{response}");
    report
}
fn denied(response: &Value) -> &Value {
    assert_eq!(response["result"]["isError"], true, "{response}");
    let report = &response["result"]["structuredContent"];
    assert_eq!(report["operation"], "heritage", "{response}");
    assert_eq!(report["result"], "blocked", "{response}");
    assert_eq!(
        report["findings"][0]["code"], "mcp.permission_denied",
        "{response}"
    );
    report
}
fn private_values_absent(response: &Value, root: &Path, key: &Path) {
    let encoded = response.to_string();
    let key_bytes = fs::read(key).unwrap();
    let seed: String = key_bytes[key_bytes.len() - 32..]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    for private in [
        root.to_str().unwrap(),
        "private-work-v05-5271",
        "private-copy-v05-8432",
        "Private Author V05 Unique 7911",
        "private-edition-v05-2374",
        "FILEVEIL-ED25519-KEY-V1",
        &seed,
    ] {
        assert!(
            !encoded.contains(private),
            "MCP response exposed a private value"
        );
    }
}

#[test]
fn public_aliases_complete_keyed_mark_verify_trace_evidence_clean_and_recheck() {
    let directory = tempdir();
    let root = directory.path();
    let input = image(root, true);
    let key_path = root.join("author.key");
    let owner = fresh_key(&key_path);
    let original_hash = digest(&fs::read(&input).unwrap());
    let key_hash = digest(&fs::read(&key_path).unwrap());
    let marked = root.join("marked.png");
    let checkpoint = root.join("checkpoint.json");
    let evidence = root.join("evidence.json");
    let cleaned = root.join("cleaned.png");
    let mut client = Client::new(root, &[&key_path]);
    let listed = client.request("tools/list", json!({}));
    for name in [
        "fileveil_mark",
        "fileveil_verify_watermark",
        "fileveil_clean",
        "fileveil_trace",
        "fileveil_evidence",
    ] {
        assert!(
            listed["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .any(|tool| tool["name"] == name)
        );
    }
    let marked_response = client.call("fileveil_mark", &input, Some(&marked), None, json!({
        "key_paths":[key_path],
        "mark":{"work_id":"private-work-v05-5271","copy_id":"private-copy-v05-8432",
            "author":"Private Author V05 Unique 7911","edition":"private-edition-v05-2374",
            "created_at":"2026-11-13T00:00:00Z","watermark_version":2,"robust":true,"strength":16}
    }));
    let report = successful(&marked_response);
    assert_eq!(report["integrity"]["original_unchanged"], true);
    assert_eq!(
        report["advanced"]["heritage"]["robust"]["authenticated"],
        true
    );
    private_values_absent(&marked_response, root, &key_path);
    let carrier =
        container::extract(&fs::read(&marked).unwrap(), fileveil_core::Format::Png).unwrap();
    let history = signing::parse_records(carrier.manifest.as_ref().unwrap()).unwrap();
    assert_eq!(history[0].body.schema, signing::SCHEMA_V2);
    assert_eq!(
        history[0].body.copy_id.as_deref(),
        Some("private-copy-v05-8432")
    );

    let verified = client.call(
        "fileveil_verify_watermark",
        &marked,
        None,
        None,
        json!({"watermark_key":key_path}),
    );
    let details = &successful(&verified)["advanced"]["heritage"];
    assert_eq!(details["verification"]["signature"], "valid");
    assert_eq!(details["verification"]["content_binding"], "valid");
    assert_eq!(details["robust"]["frame_valid"], true);
    assert_eq!(details["robust"]["authenticated"], true);
    private_values_absent(&verified, root, &key_path);

    let checkpoint_response = client.call(
        "fileveil_evidence",
        &marked,
        Some(&checkpoint),
        Some("checkpoint"),
        json!({"key_paths":[key_path]}),
    );
    assert_eq!(
        successful(&checkpoint_response)["advanced"]["heritage"]["checkpoint_verification"]["history_binding"],
        "valid"
    );
    private_values_absent(&checkpoint_response, root, &key_path);
    let anchors = root.join("anchors.json");
    fs::write(
        &anchors,
        serde_json::to_vec(&vec![owner.public_key()]).unwrap(),
    )
    .unwrap();
    let traced = client.call(
        "fileveil_trace",
        &marked,
        None,
        None,
        json!({"watermark_key":key_path,"checkpoints":[checkpoint],"checkpoint_anchors":anchors}),
    );
    let details = &successful(&traced)["advanced"]["heritage"];
    assert_eq!(
        details["external_provenance"]["external_checkpoints"][0]["trust"],
        "valid"
    );
    assert_eq!(details["verification"]["chain"], "valid");
    private_values_absent(&traced, root, &key_path);

    let exported = client.call(
        "fileveil_evidence",
        &marked,
        Some(&evidence),
        Some("evidence_export"),
        json!({"key_paths":[key_path],"checkpoints":[checkpoint],"checkpoint_anchors":anchors}),
    );
    let details = &successful(&exported)["advanced"]["heritage"];
    assert_eq!(details["export_contains_claim_values"], true);
    private_values_absent(&exported, root, &key_path);
    let package = custody::parse_evidence(&fs::read(&evidence).unwrap()).unwrap();
    assert_eq!(
        package.body.records[0].body.author,
        "Private Author V05 Unique 7911"
    );
    let evidence_verified = client.call(
        "fileveil_evidence",
        &evidence,
        None,
        Some("evidence_verify"),
        json!({"reference":marked,"checkpoint_anchors":anchors}),
    );
    let details = &successful(&evidence_verified)["advanced"]["heritage"];
    assert_eq!(
        details["evidence_verification"]["package_signature"],
        "valid"
    );
    assert_eq!(details["evidence_verification"]["custody_signer"], "valid");
    assert_eq!(details["reference_asset_verified"], true);
    private_values_absent(&evidence_verified, root, &key_path);

    let cleaned_response = client.call(
        "fileveil_clean",
        &marked,
        Some(&cleaned),
        None,
        json!({"clean_signal":true,"watermark_key":key_path,"max_pixel_mse":200.0}),
    );
    let details = &successful(&cleaned_response)["advanced"]["heritage"];
    assert_eq!(details["modern_manifest_removed"], true);
    assert_eq!(details["standard_metadata_cleaned"], true);
    assert_eq!(details["robust_recheck"]["frame_valid"], false);
    private_values_absent(&cleaned_response, root, &key_path);
    assert!(
        container::extract(&fs::read(&cleaned).unwrap(), fileveil_core::Format::Png)
            .unwrap()
            .manifest
            .is_none()
    );
    let rechecked = client.call(
        "fileveil_verify_watermark",
        &cleaned,
        None,
        None,
        json!({"watermark_key":key_path}),
    );
    assert_eq!(
        successful(&rechecked)["advanced"]["heritage"]["robust"]["frame_valid"],
        false
    );
    private_values_absent(&rechecked, root, &key_path);
    assert_eq!(digest(&fs::read(&input).unwrap()), original_hash);
    assert_eq!(digest(&fs::read(&key_path).unwrap()), key_hash);
    client.close();
}

#[test]
fn system_references_are_denied_before_file_or_credential_access() {
    let directory = tempdir();
    let root = directory.path();
    let missing_input = root.join("must-not-be-opened.png");
    let fake_id = "a".repeat(64);
    let mut client = Client::new(root, &[]);
    for (tool, options, output) in [
        (
            "fileveil_mark",
            json!({"key_refs":[{"key_id":fake_id}]}),
            Some(root.join("denied.png")),
        ),
        (
            "fileveil_verify_watermark",
            json!({"watermark_key_ref":{"key_id":fake_id}}),
            None,
        ),
    ] {
        let response = client.call(tool, &missing_input, output.as_deref(), None, options);
        let report = denied(&response);
        assert!(
            report["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value
                    .as_str()
                    .unwrap_or_default()
                    .contains("system signing-key reference is not explicitly authorized")),
            "{response}"
        );
    }
    assert!(!root.join("denied.png").exists());
    assert_eq!(client.request("ping", json!({}))["result"], json!({}));
    client.close();
}

#[test]
fn watermark_secrets_and_all_checkpoint_timestamp_inputs_need_separate_grants() {
    let directory = tempdir();
    let outside = tempdir();
    let root = directory.path();
    let input = image(root, false);
    let signer = root.join("signer.key");
    let watermark = root.join("watermark.key");
    fresh_key(&signer);
    fresh_key(&watermark);
    let original_hash = digest(&fs::read(&input).unwrap());
    let mut client = Client::new(root, &[&signer]);
    let response = client.call(
        "fileveil_verify_watermark",
        &input,
        None,
        None,
        json!({"watermark_key":watermark}),
    );
    denied(&response);
    private_values_absent(&response, root, &watermark);
    let output = root.join("denied.png");
    denied(&client.call(
        "fileveil_mark",
        &input,
        Some(&output),
        None,
        json!({"key_paths":[signer],"watermark_key":watermark}),
    ));
    assert!(!output.exists());
    let auxiliary = outside.path().join("outside.dat");
    fs::write(&auxiliary, b"No parser should read this unauthorized input").unwrap();
    for field in [
        "checkpoints",
        "checkpoint_anchors",
        "timestamp_response",
        "timestamp_query",
        "timestamp_roots",
    ] {
        let mut options = json!({});
        options[field] = if field == "checkpoints" {
            json!([auxiliary])
        } else {
            json!(auxiliary)
        };
        let response = client.call("fileveil_trace", &input, None, None, options);
        denied(&response);
        private_values_absent(&response, root, &signer);
        assert!(
            !response
                .to_string()
                .contains(outside.path().to_str().unwrap())
        );
    }
    assert_eq!(digest(&fs::read(&input).unwrap()), original_hash);
    client.close();
}

// FVPROV1 15513 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJhNzMxNjYzMmFjMWM1YTBhNmEyNGM3MmUyYWMwYzhhMjFmOTkxMmNlYWMwMTdmOGUxMzY0YmE1MWQ0MGVkNWQ2IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvdGVzdHMvd2F0ZXJtYXJrX3YwNV9tY3AucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI3Y2FiMGNlMjRjYzY5Y2Q5MzFhMWQ0YmJiNjg1MzgxOWFhMDE3MDVlMTE3MzhlYWFhYjc2OTUzYTQ1ODA1MmY4NTVmMjVmOTdiNDVlNTE3YmVmZGRhNTBkMmVmNTNhNDRkNzc2ZmZmNTkxMzZlZjRjZTM5YmUwYTQ0ODFhYjQwNiJ9XX1d FVPROV1-END
