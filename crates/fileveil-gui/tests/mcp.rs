// SPDX-License-Identifier: MPL-2.0
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
    input: Option<ChildStdin>,
    output: Receiver<Value>,
    next_id: u64,
}
impl Client {
    fn new(version: &str) -> Self {
        Self::with_roots(version, &[], &[], 64)
    }
    fn authorized(version: &str, directory: &Path) -> Self {
        Self::with_roots(
            version,
            &[directory.to_path_buf()],
            &[directory.to_path_buf()],
            64,
        )
    }
    fn with_roots(version: &str, read: &[PathBuf], write: &[PathBuf], maximum: u32) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_fileveil-gui"));
        command
            .arg("--mcp")
            .arg("--mcp-max-operations")
            .arg(maximum.to_string());
        for root in read {
            command.arg("--mcp-read-root").arg(root);
        }
        for root in write {
            command.arg("--mcp-write-root").arg(root);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (sender, output) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let line = line.unwrap();
                let value = serde_json::from_str(&line).expect("stdout is MCP JSON only");
                if sender.send(value).is_err() {
                    return;
                }
            }
        });
        let mut client = Self {
            child,
            input,
            output,
            next_id: 1,
        };
        let initialized = client.request("initialize", json!({
            "protocolVersion":version,"capabilities":{},"clientInfo":{"name":"fileveil-test","version":"1"}
        }));
        assert_eq!(
            initialized["result"]["protocolVersion"],
            if version == "2025-06-18" {
                version
            } else {
                "2025-11-25"
            }
        );
        client.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        client
    }
    fn send(&mut self, message: Value) {
        let input = self.input.as_mut().unwrap();
        serde_json::to_writer(&mut *input, &message).unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
    }
    fn start(&mut self, method: &str, params: Value) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        id
    }
    fn receive(&self) -> Value {
        self.output
            .recv_timeout(Duration::from_secs(45))
            .expect("MCP reply deadline")
    }
    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.start(method, params);
        let response = self.receive();
        assert_eq!(response["id"], id, "{response}");
        response
    }
    fn call(&mut self, name: &str, arguments: Value) -> Value {
        self.request("tools/call", json!({"name":name,"arguments":arguments}))
    }
    fn close(&mut self) -> i32 {
        self.input.take();
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code().unwrap_or(-1);
            }
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "MCP EOF shutdown deadline"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.input.take();
        let started = Instant::now();
        loop {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            if started.elapsed() > Duration::from_secs(5) {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}
fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap()
}
fn report(response: &Value) -> &Value {
    assert_eq!(response["result"]["isError"], false, "{response}");
    &response["result"]["structuredContent"]
}
fn assert_permission_denied(response: &Value) {
    assert_eq!(response["result"]["isError"], true, "{response}");
    assert_eq!(
        response["result"]["structuredContent"]["result"], "blocked",
        "{response}"
    );
    assert_eq!(
        response["result"]["structuredContent"]["findings"][0]["code"], "mcp.permission_denied",
        "{response}"
    );
}

#[test]
fn default_denies_files_and_read_write_grants_are_independent() {
    let source = tempdir();
    let destination = tempdir();
    let input = source.path().join("original.jpg");
    fs::copy(fixture("jpeg_exif_gps_author.jpg"), &input).unwrap();
    let output = destination.path().join("copy.jpg");
    let mut denied = Client::new("2025-11-25");
    assert_permission_denied(&denied.call("fileveil_scan", json!({"path":input})));
    assert_eq!(
        report(&denied.call("fileveil_capabilities", json!({})))["mcp_access"]["read_root_count"],
        0
    );
    assert_eq!(denied.close(), 0);
    let mut readonly = Client::with_roots("2025-11-25", &[source.path().into()], &[], 64);
    assert_eq!(
        report(&readonly.call("fileveil_scan", json!({"path":input})))["operation"],
        "scan"
    );
    assert_permission_denied(
        &readonly.call("fileveil_sanitize", json!({"path":input,"output":output})),
    );
    assert_eq!(readonly.close(), 0);
    let mut writeonly = Client::with_roots("2025-11-25", &[], &[destination.path().into()], 64);
    assert_permission_denied(&writeonly.call("fileveil_scan", json!({"path":input})));
    assert_eq!(writeonly.close(), 0);
    let mut split = Client::with_roots(
        "2025-11-25",
        &[source.path().into()],
        &[destination.path().into()],
        64,
    );
    let cleaned = split.call("fileveil_sanitize", json!({"path":input,"output":output}));
    assert_eq!(report(&cleaned)["integrity"]["original_unchanged"], true);
    assert!(output.exists());
    assert_permission_denied(
        &split.call("fileveil_verify", json!({"original":input,"output":output})),
    );
    assert_permission_denied(&split.call("fileveil_sanitize", json!({"path":input})));
    assert_eq!(split.close(), 0);
}

#[test]
fn authorization_rejects_traversal_sensitive_paths_and_excess_operations() {
    let source = tempdir();
    let input = source.path().join("original.jpg");
    fs::copy(fixture("jpeg_exif_gps_author.jpg"), &input).unwrap();
    fs::create_dir(source.path().join("nested")).unwrap();
    fs::create_dir(source.path().join(".ssh")).unwrap();
    fs::copy(&input, source.path().join(".ssh/private.jpg")).unwrap();
    let mut client = Client::authorized("2025-11-25", source.path());
    assert_permission_denied(&client.call(
        "fileveil_scan",
        json!({"path":source.path().join("nested/../original.jpg")}),
    ));
    assert_permission_denied(&client.call(
        "fileveil_scan",
        json!({"path":source.path().join(".ssh/private.jpg")}),
    ));
    assert_permission_denied(&client.call(
        "fileveil_scan",
        json!({"path":fixture("jpeg_exif_gps_author.jpg")}),
    ));
    assert_eq!(client.close(), 0);
    let mut limited = Client::with_roots("2025-11-25", &[source.path().into()], &[], 1);
    assert_eq!(
        report(&limited.call("fileveil_scan", json!({"path":input})))["operation"],
        "scan"
    );
    assert_permission_denied(&limited.call("fileveil_scan", json!({"path":input})));
    assert_eq!(
        report(&limited.call("fileveil_capabilities", json!({})))["mcp_access"]["operations_used"],
        1
    );
    assert_eq!(limited.close(), 0);
}

#[cfg(unix)]
#[test]
fn links_cannot_escape_mcp_roots_and_outputs_remain_new_files() {
    use std::os::unix::fs::symlink;
    let source = tempdir();
    let outside = tempdir();
    let input = source.path().join("original.jpg");
    let outside_input = outside.path().join("outside.jpg");
    fs::copy(fixture("jpeg_exif_gps_author.jpg"), &input).unwrap();
    fs::copy(&input, &outside_input).unwrap();
    symlink(&outside_input, source.path().join("link.jpg")).unwrap();
    symlink(outside.path(), source.path().join("directory")).unwrap();
    let mut client = Client::authorized("2025-11-25", source.path());
    assert_permission_denied(&client.call(
        "fileveil_scan",
        json!({"path":source.path().join("link.jpg")}),
    ));
    assert_permission_denied(&client.call(
        "fileveil_scan",
        json!({"path":source.path().join("directory/outside.jpg")}),
    ));
    assert_permission_denied(&client.call(
        "fileveil_sanitize",
        json!({"path":input,"output":source.path().join("directory/escaped.jpg")}),
    ));
    assert_permission_denied(&client.call(
        "fileveil_sanitize",
        json!({"path":input,"output":source.path().join("link.jpg")}),
    ));
    fs::hard_link(&input, source.path().join("hardlink.jpg")).unwrap();
    assert_permission_denied(&client.call("fileveil_scan", json!({"path":input})));
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 1);
    assert_eq!(client.close(), 0);
}
#[test]
fn negotiation_tool_discovery_capabilities_and_protocol_errors() {
    for version in ["2025-06-18", "future-version"] {
        let mut client = Client::new(version);
        let listed = client.request("tools/list", json!({}));
        let tools = listed["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 8);
        for tool in tools {
            let read_only = matches!(
                tool["name"].as_str().unwrap(),
                "fileveil_scan"
                    | "fileveil_verify"
                    | "fileveil_capabilities"
                    | "fileveil_detect_watermark"
                    | "fileveil_lab"
                    | "fileveil_provenance"
            );
            assert_eq!(tool["annotations"]["readOnlyHint"], read_only);
            assert_eq!(tool["annotations"]["destructiveHint"], false);
            assert_eq!(tool["inputSchema"]["additionalProperties"], false);
        }
        let capabilities = client.call("fileveil_capabilities", json!({}));
        assert_eq!(report(&capabilities)["offline"], true);
        let unknown = client.call("unknown", json!({}));
        assert_eq!(unknown["error"]["code"], -32602);
        let unknown_method = client.request("unknown/method", json!({}));
        assert_eq!(unknown_method["error"]["code"], -32601);
        assert_eq!(client.request("ping", json!({}))["result"], json!({}));
        assert_eq!(client.close(), 0);
    }
}
#[test]
fn scan_sanitize_and_verify_share_engine_reports_and_protect_existing_outputs() {
    let directory = tempdir();
    let original = directory.path().join("合成 原件.jpg");
    fs::copy(fixture("jpeg_exif_gps_author.jpg"), &original).unwrap();
    let original_bytes = fs::read(&original).unwrap();
    let output = directory.path().join("净化副本.jpg");
    let mut client = Client::authorized("2025-11-25", directory.path());
    let scanned = client.call("fileveil_scan", json!({"path":original}));
    assert_eq!(report(&scanned)["operation"], "scan");
    assert!(
        !scanned
            .to_string()
            .contains(directory.path().to_str().unwrap())
    );
    let sanitized = client.call(
        "fileveil_sanitize",
        json!({"path":original,"output":output}),
    );
    assert_eq!(report(&sanitized)["integrity"]["original_unchanged"], true);
    assert_eq!(report(&sanitized)["integrity"]["pixel_equal"], true);
    let output_bytes = fs::read(&output).unwrap();
    let verified = client.call(
        "fileveil_verify",
        json!({"original":original,"output":output}),
    );
    assert_eq!(report(&verified)["integrity"]["content_equal"], true);
    let collision = client.call(
        "fileveil_sanitize",
        json!({"path":original,"output":output}),
    );
    assert_eq!(collision["result"]["isError"], true);
    assert_eq!(fs::read(&output).unwrap(), output_bytes);
    assert_eq!(fs::read(&original).unwrap(), original_bytes);
    assert_eq!(client.close(), 0);
}
#[test]
fn both_image_modes_produce_png_and_verify_with_explicit_processing_parameters() {
    let directory = tempdir();
    let input = directory.path().join("image.png");
    fs::copy(fixture("png_itxt_exif_icc.png"), &input).unwrap();
    let before = fs::read(&input).unwrap();
    let mut client = Client::authorized("2025-11-25", directory.path());
    for mode in ["low_bits", "signal"] {
        let output = directory.path().join(format!("{mode}.png"));
        let result = client.call(
            "fileveil_process_image",
            json!({"path":input,"output":output,"mode":mode,"low_bits":2}),
        );
        let processed = report(&result);
        assert_eq!(processed["image_processing"]["mode"], mode);
        assert_eq!(processed["integrity"]["original_unchanged"], true);
        assert!(fs::read(&output).unwrap().starts_with(b"\x89PNG\r\n\x1a\n"));
        let verification = client.call(
            "fileveil_verify",
            json!({"original":input,"output":output,"mode":mode,"low_bits":2}),
        );
        assert_eq!(report(&verification)["image_processing"]["mode"], mode);
    }
    assert_eq!(fs::read(&input).unwrap(), before);
    assert_eq!(client.close(), 0);
}
#[test]
fn invalid_arguments_return_actionable_tool_reports_without_creating_outputs() {
    let mut client = Client::new("2025-11-25");
    for arguments in [
        json!({}),
        json!({"path":"x","max_file_mib":513}),
        json!({"path":"x","timeout_seconds":0}),
        json!({"path":"x","mode":"unknown"}),
        json!({"path":"x","low_bits":4}),
        json!({"path":"x","unexpected":true}),
    ] {
        let response = client.call("fileveil_process_image", arguments);
        assert_eq!(response["result"]["isError"], true, "{response}");
        assert_eq!(response["result"]["structuredContent"]["result"], "failed");
    }
    let wrong_shape = client.request("tools/call", json!({"name":"fileveil_scan","arguments":[]}));
    assert_eq!(wrong_shape["error"]["code"], -32602);
    assert_eq!(client.close(), 0);
}
#[test]
fn busy_cancel_and_eof_reap_jobs_without_publishing_copies() {
    let directory = tempdir();
    let input = directory.path().join("large.png");
    image::RgbaImage::from_pixel(2400, 1800, image::Rgba([101, 103, 105, 127]))
        .save(&input)
        .unwrap();
    let output = directory.path().join("cancelled.png");
    let mut client = Client::authorized("2025-11-25", directory.path());
    let id = client.start("tools/call", json!({"name":"fileveil_process_image","arguments":{"path":input,"output":output,"mode":"signal"}}));
    let busy_id = client.start(
        "tools/call",
        json!({"name":"fileveil_scan","arguments":{"path":input}}),
    );
    let busy = client.receive();
    assert_eq!(busy["id"], busy_id, "{busy}");
    assert_eq!(busy["result"]["isError"], true);
    client.send(
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":id}}),
    );
    assert_eq!(client.request("ping", json!({}))["result"], json!({}));
    assert_eq!(client.close(), 0);
    assert!(!output.exists());
    let eof_output = directory.path().join("eof.png");
    let mut client = Client::authorized("2025-11-25", directory.path());
    client.start("tools/call", json!({"name":"fileveil_process_image","arguments":{"path":input,"output":eof_output,"mode":"signal"}}));
    assert_eq!(client.close(), 0);
    assert!(!eof_output.exists());
    assert!(!fs::read_dir(directory.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".fileveil")
    }));
}
