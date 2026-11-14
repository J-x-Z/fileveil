// SPDX-License-Identifier: MPL-2.0
//! Local MCP stdio transport. One event loop owns protocol output and one isolated job.
use crate::jobs::{JobHandle, JobKind, JobRequest};
use crate::mcp_access::{AccessPolicy, McpAccessConfig};
use fileveil_core::{
    Action, Confidence, Finding, FindingState, Format, ImageProcessMode, ImageProcessOptions,
    Limits, Outcome, Policy, Report, RiskLayer, SanitizeOptions,
};
use serde_json::{Map, Value, json};
use std::{
    io::{self, BufRead, Write},
    path::PathBuf,
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const PROTOCOL_VERSION: &str = "2025-11-25";
const COMPATIBLE_VERSION: &str = "2025-06-18";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    New,
    Negotiated,
    Ready,
}
struct ActiveCall {
    id: Value,
    handle: JobHandle,
    cancelled: bool,
}
enum Input {
    Message(Vec<u8>),
    End,
    Failed,
    TooLarge,
}
struct Server {
    writer: io::BufWriter<io::Stdout>,
    phase: Phase,
    active: Option<ActiveCall>,
    access: AccessPolicy,
}

/// Run the local newline-delimited JSON-RPC transport until stdin closes.
pub fn run() -> i32 {
    run_with_config(McpAccessConfig::default())
}

/// Run with user-configured read and write directory capabilities.
pub fn run_with_config(config: McpAccessConfig) -> i32 {
    let access = match AccessPolicy::new(&config) {
        Ok(access) => access,
        Err(error) => {
            eprintln!("{error}");
            return 2;
        }
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    if thread::Builder::new()
        .name("fileveil-mcp-input".into())
        .spawn(move || read_input(sender))
        .is_err()
    {
        eprintln!("Could not start MCP input reader");
        return 5;
    }
    let mut server = Server {
        writer: io::BufWriter::new(io::stdout()),
        phase: Phase::New,
        active: None,
        access,
    };
    let result = server.serve(receiver);
    // JobHandle drop cancels and reaps the owned worker before this process exits.
    drop(server.active.take());
    result.unwrap_or(1)
}

fn read_input(sender: mpsc::SyncSender<Input>) {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    loop {
        match read_message(&mut reader) {
            Ok(Some(message)) => {
                if sender.send(Input::Message(message)).is_err() {
                    return;
                }
            }
            Ok(None) => {
                let _ = sender.send(Input::End);
                return;
            }
            Err(error) => {
                let event = if error.kind() == io::ErrorKind::InvalidData {
                    Input::TooLarge
                } else {
                    Input::Failed
                };
                let _ = sender.send(event);
                return;
            }
        }
    }
}
fn read_message(reader: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut message = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok((!message.is_empty()).then_some(message));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let length = newline.map_or(available.len(), |index| index + 1);
        if message.len() + length > MAX_MESSAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MCP message exceeds 1 MiB",
            ));
        }
        message.extend_from_slice(&available[..length]);
        reader.consume(length);
        if newline.is_some() {
            return Ok(Some(message));
        }
    }
}

impl Server {
    fn serve(&mut self, receiver: mpsc::Receiver<Input>) -> io::Result<i32> {
        loop {
            self.complete_job()?;
            let input = if self.active.is_some() {
                match receiver.recv_timeout(Duration::from_millis(10)) {
                    Ok(input) => input,
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            } else {
                match receiver.recv() {
                    Ok(input) => input,
                    Err(_) => break,
                }
            };
            match input {
                Input::Message(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                    Ok(message) => self.dispatch(message)?,
                    Err(_) => self.error(Value::Null, -32700, "Invalid JSON message")?,
                },
                Input::End => break,
                Input::Failed => return Ok(1),
                Input::TooLarge => {
                    self.error(Value::Null, -32600, "MCP message exceeds 1 MiB")?;
                    return Ok(2);
                }
            }
        }
        Ok(0)
    }
    fn send(&mut self, message: Value) -> io::Result<()> {
        // Every reply is serialized here. Reader and worker threads never write protocol stdout.
        serde_json::to_writer(&mut self.writer, &message).map_err(io::Error::other)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }
    fn result(&mut self, id: Value, result: Value) -> io::Result<()> {
        self.send(json!({"jsonrpc":"2.0","id":id,"result":result}))
    }
    fn error(&mut self, id: Value, code: i32, message: &str) -> io::Result<()> {
        self.send(json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}))
    }
    fn complete_job(&mut self) -> io::Result<()> {
        let result = self.active.as_ref().and_then(|call| call.handle.try_recv());
        if let Some(result) = result {
            let call = self.active.take().expect("active result has its call");
            if !call.cancelled {
                let failed = !matches!(
                    result.report.result,
                    Outcome::VerifiedWithinScope | Outcome::PartiallyVerified
                );
                self.result(call.id, tool_result(json!(result.report), failed))?;
            }
        }
        Ok(())
    }
    fn dispatch(&mut self, message: Value) -> io::Result<()> {
        let Some(object) = message.as_object() else {
            return self.error(Value::Null, -32600, "Expected a JSON-RPC object");
        };
        let id = object.get("id").cloned();
        let valid_id = id
            .as_ref()
            .is_none_or(|id| id.is_string() || id.as_i64().is_some() || id.as_u64().is_some());
        let method = object.get("method").and_then(Value::as_str);
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || method.is_none()
            || !valid_id
        {
            return self.error(Value::Null, -32600, "Invalid JSON-RPC request");
        }
        let method = method.expect("validated method");
        let params = object.get("params");
        if id.is_none() {
            self.notification(method, params);
            return Ok(());
        }
        let id = id.expect("request id");
        if self.active.as_ref().is_some_and(|active| active.id == id) {
            return self.error(id, -32600, "Request id is already active");
        }
        match method {
            "ping" => self.result(id, json!({})),
            "initialize" => self.initialize(id, params),
            _ if self.phase != Phase::Ready => {
                self.error(id, -32002, "Complete MCP initialization before using tools")
            }
            "tools/list" => {
                if params.is_some_and(|value| !value.is_object()) {
                    return self.error(id, -32602, "Tool-list parameters must be an object");
                }
                if params.and_then(|value| value.get("cursor")).is_some() {
                    return self.error(id, -32602, "The tool list has a single page");
                }
                self.result(id, json!({"tools":tools()}))
            }
            "tools/call" => self.call_tool(id, params),
            _ => self.error(id, -32601, "Unknown MCP method"),
        }
    }
    fn notification(&mut self, method: &str, params: Option<&Value>) {
        match method {
            "notifications/initialized" if self.phase == Phase::Negotiated => {
                self.phase = Phase::Ready;
            }
            "notifications/cancelled" => {
                if let Some(id) = params.and_then(|params| params.get("requestId"))
                    && let Some(active) = &mut self.active
                    && active.id == *id
                    && active.handle.cancel()
                {
                    active.cancelled = true;
                }
            }
            _ => {}
        }
    }
    fn initialize(&mut self, id: Value, params: Option<&Value>) -> io::Result<()> {
        if self.phase != Phase::New {
            return self.error(id, -32600, "MCP initialization has already completed");
        }
        let Some(params) = params.and_then(Value::as_object) else {
            return self.error(id, -32602, "Initialization parameters must be an object");
        };
        let Some(version) = params.get("protocolVersion").and_then(Value::as_str) else {
            return self.error(id, -32602, "protocolVersion must be a string");
        };
        let client = params.get("clientInfo");
        if !params.get("capabilities").is_some_and(Value::is_object)
            || !client
                .and_then(|client| client.get("name"))
                .is_some_and(Value::is_string)
            || !client
                .and_then(|client| client.get("version"))
                .is_some_and(Value::is_string)
        {
            return self.error(
                id,
                -32602,
                "Provide capabilities and clientInfo name/version",
            );
        }
        let version = if version == COMPATIBLE_VERSION {
            COMPATIBLE_VERSION
        } else {
            PROTOCOL_VERSION
        };
        self.phase = Phase::Negotiated;
        self.result(id, json!({
            "protocolVersion":version,
            "capabilities":{"tools":{"listChanged":false}},
            "serverInfo":{"name":"fileveil","title":"FileVeil","version":env!("CARGO_PKG_VERSION")},
            "instructions":"File access requires configured read and write directories. Use absolute paths without symbolic links or traversal. Sanitization creates new copies. Image processing changes pixels and leaves keyed-watermark detection unassessed."
        }))
    }
    fn call_tool(&mut self, id: Value, params: Option<&Value>) -> io::Result<()> {
        let Some(params) = params.and_then(Value::as_object) else {
            return self.error(id, -32602, "Tool-call parameters must be an object");
        };
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return self.error(id, -32602, "Tool name must be a string");
        };
        let Some(definition) = tools().into_iter().find(|tool| tool["name"] == name) else {
            return self.error(id, -32602, "Unknown FileVeil tool");
        };
        if params.contains_key("task") {
            return self.error(id, -32602, "Task-augmented calls are unavailable");
        }
        let empty = Map::new();
        let arguments = match params.get("arguments") {
            Some(value) => match value.as_object() {
                Some(arguments) => arguments,
                None => return self.error(id, -32602, "Tool arguments must be an object"),
            },
            None => &empty,
        };
        if let Err(error) = validate_arguments(arguments, &definition["inputSchema"]) {
            if name == "fileveil_capabilities" {
                return self.error(id, -32602, &error);
            }
            return self.tool_error(id, name, &error);
        }
        if name == "fileveil_capabilities" {
            let mut capabilities = fileveil_engine::capabilities(&Limits::default());
            capabilities["mcp_access"] = self.access.summary();
            return self.result(id, tool_result(capabilities, false));
        }
        if self.active.is_some() {
            return self.tool_error(
                id,
                name,
                "Another file operation is active. Wait for completion or cancel it",
            );
        }
        if name == "fileveil_verify"
            && arguments.contains_key("low_bits")
            && !arguments.contains_key("mode")
        {
            return self.tool_error(id, name, "low_bits requires an image-processing mode");
        }
        if name == "fileveil_verify"
            && arguments.contains_key("mode")
            && (arguments.contains_key("profile") || arguments.contains_key("options_json"))
        {
            return self.tool_error(id,name,"Image verification parameters and document policy choices must be submitted as separate operations");
        }
        let kind = match job_kind(name, arguments) {
            Ok(kind) => kind,
            Err(error) => return self.tool_error(id, name, &error),
        };
        let mut request = JobRequest::new(kind);
        request.limits.max_file_bytes = integer(arguments, "max_file_mib", 64) * 1024 * 1024;
        request.timeout_seconds = integer(arguments, "timeout_seconds", 120);
        let authorization = match self.access.authorize(request) {
            Ok(authorization) => authorization,
            Err(error) => return self.permission_error(id, name, &error.to_string()),
        };
        self.active = Some(ActiveCall {
            id,
            handle: JobHandle::spawn_authorized(authorization, Arc::new(|| {})),
            cancelled: false,
        });
        Ok(())
    }
    fn tool_error(&mut self, id: Value, name: &str, message: &str) -> io::Result<()> {
        let operation = match name {
            "fileveil_detect_watermark" => "detect_watermark",
            "fileveil_lab" => "lab",
            "fileveil_provenance" => "provenance",
            "fileveil_heritage"
            | "fileveil_mark"
            | "fileveil_clean"
            | "fileveil_trace"
            | "fileveil_verify_watermark"
            | "fileveil_watermark_lab"
            | "fileveil_evidence" => "heritage",
            "fileveil_scan" => "scan",
            "fileveil_verify" => "verify",
            _ => "sanitize",
        };
        let mut report = Report::new(operation, Format::Unknown);
        report.result = Outcome::Failed;
        report.warnings.push(message.into());
        self.result(id, tool_result(json!(report), true))
    }
    fn permission_error(&mut self, id: Value, name: &str, message: &str) -> io::Result<()> {
        let operation = match name {
            "fileveil_detect_watermark" => "detect_watermark",
            "fileveil_lab" => "lab",
            "fileveil_provenance" => "provenance",
            "fileveil_heritage"
            | "fileveil_mark"
            | "fileveil_clean"
            | "fileveil_trace"
            | "fileveil_verify_watermark"
            | "fileveil_watermark_lab"
            | "fileveil_evidence" => "heritage",
            "fileveil_scan" => "scan",
            "fileveil_verify" => "verify",
            _ => "sanitize",
        };
        let mut report = Report::new(operation, Format::Unknown);
        report.result = Outcome::Blocked;
        let mut finding = Finding::new(
            "mcp.permission_denied",
            RiskLayer::Filesystem,
            "MCP authorization",
            message,
            Action::Unsupported,
        );
        finding.state = FindingState::Blocked;
        finding.confidence = Confidence::Verified;
        report.findings.push(finding);
        report.warnings.push(message.into());
        self.result(id, tool_result(json!(report), true))
    }
}

fn tool_result(data: Value, failed: bool) -> Value {
    json!({
        "content":[{"type":"text","text":data.to_string()}],
        "structuredContent":data,
        "isError":failed
    })
}
fn integer(arguments: &Map<String, Value>, name: &str, default: u64) -> u64 {
    arguments
        .get(name)
        .and_then(Value::as_f64)
        .map_or(default, |value| value as u64)
}
fn path(arguments: &Map<String, Value>, name: &str) -> PathBuf {
    PathBuf::from(arguments[name].as_str().expect("validated path parameter"))
}
fn job_kind(name: &str, arguments: &Map<String, Value>) -> Result<JobKind, String> {
    if matches!(
        name,
        "fileveil_heritage"
            | "fileveil_mark"
            | "fileveil_clean"
            | "fileveil_trace"
            | "fileveil_verify_watermark"
            | "fileveil_watermark_lab"
            | "fileveil_evidence"
    ) {
        let mut request: fileveil_engine::heritage::HeritageRequest = arguments
            .get("options_json")
            .and_then(Value::as_str)
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| "Invalid HeritageRequest JSON".to_string())?
            .unwrap_or_default();
        let action = match name {
            "fileveil_mark" if request.certificate.is_some() || request.private_key.is_some() => {
                "c2pa_mark"
            }
            "fileveil_mark" => "mark",
            "fileveil_clean" => "clean",
            "fileveil_trace" => "trace",
            "fileveil_verify_watermark" => "verify",
            "fileveil_watermark_lab" => "lab",
            _ => arguments["action"]
                .as_str()
                .ok_or("A watermark action is required")?,
        };
        request.action = serde_json::from_value(json!(action))
            .map_err(|_| "Unsupported watermark action".to_string())?;
        if name == "fileveil_mark" {
            request.mark.signature_v2 = true;
            let encoded: Value = arguments
                .get("options_json")
                .and_then(Value::as_str)
                .map(serde_json::from_str)
                .transpose()
                .map_err(|_| "Invalid watermark options".to_string())?
                .unwrap_or_default();
            if encoded["mark"].get("watermark_version").is_none() {
                request.mark.watermark_version = 2;
            }
            if encoded["mark"].get("strength").is_none() && request.mark.watermark_version == 2 {
                request.mark.strength = fileveil_engine::heritage::robust_v2::DEFAULT_STRENGTH;
            }
            if request.mark.copy_id.is_empty() {
                request.mark.copy_id = "original".into();
            }
        }
        if name == "fileveil_clean" {
            request.clean_metadata = true;
        }
        let output = arguments
            .get("output")
            .and_then(Value::as_str)
            .map(PathBuf::from);
        if output.is_some() && !request.writes_file() {
            return Err("Read-only Heritage actions do not accept an output path".into());
        }
        request.validate().map_err(|error| error.to_string())?;
        return Ok(JobKind::Heritage {
            path: path(arguments, "path"),
            output,
            request: Box::new(request),
        });
    }
    let output = arguments
        .get("output")
        .and_then(Value::as_str)
        .map(PathBuf::from);
    let options = ImageProcessOptions {
        mode: if arguments.get("mode").and_then(Value::as_str) == Some("signal") {
            ImageProcessMode::Signal
        } else {
            ImageProcessMode::LowBits
        },
        low_bits: integer(arguments, "low_bits", 2) as u8,
    };
    let mut choices: SanitizeOptions = arguments
        .get("options_json")
        .and_then(Value::as_str)
        .map(serde_json::from_str)
        .transpose()
        .map_err(|_| "Invalid SanitizeOptions JSON".to_string())?
        .unwrap_or_default();
    choices.policy = if arguments.get("profile").and_then(Value::as_str) == Some("deep") {
        Policy::Deep
    } else {
        Policy::Safe
    };
    let advanced = choices.policy != Policy::Safe || choices.any();
    Ok(match name {
        "fileveil_detect_watermark" => JobKind::DetectWatermark {
            path: path(arguments, "path"),
        },
        "fileveil_lab" => {
            let paths = arguments["paths"]
                .as_array()
                .expect("validated paths")
                .iter()
                .map(|path| PathBuf::from(path.as_str().expect("validated path")))
                .collect();
            match arguments.get("groups_json").and_then(Value::as_str) {
                Some(encoded) => JobKind::LabGrouped {
                    paths,
                    groups: serde_json::from_str(encoded)
                        .map_err(|_| "Invalid sample groups JSON".to_string())?,
                },
                None => JobKind::Lab { paths },
            }
        }
        "fileveil_provenance" => JobKind::Provenance {
            path: path(arguments, "path"),
            trust_roots: arguments
                .get("trust_roots")
                .and_then(Value::as_str)
                .map(PathBuf::from),
        },
        "fileveil_scan" => JobKind::Scan {
            path: path(arguments, "path"),
        },
        "fileveil_sanitize" if advanced => JobKind::SanitizeAdvanced {
            input: path(arguments, "path"),
            output,
            options: choices,
        },
        "fileveil_sanitize" => JobKind::Sanitize {
            input: path(arguments, "path"),
            output,
        },
        "fileveil_process_image" => JobKind::ProcessImage {
            input: path(arguments, "path"),
            output,
            options,
        },
        "fileveil_verify" if arguments.contains_key("mode") => JobKind::VerifyImage {
            original: path(arguments, "original"),
            output: path(arguments, "output"),
            options,
        },
        "fileveil_verify" if advanced => JobKind::VerifyAdvanced {
            original: path(arguments, "original"),
            output: path(arguments, "output"),
            options: choices,
        },
        "fileveil_verify" => JobKind::Verify {
            original: path(arguments, "original"),
            output: path(arguments, "output"),
        },
        _ => unreachable!("known file tool"),
    })
}
fn validate_arguments(arguments: &Map<String, Value>, schema: &Value) -> Result<(), String> {
    let properties = schema["properties"]
        .as_object()
        .expect("object tool schema");
    for name in schema["required"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if !arguments.contains_key(name) {
            return Err(format!("Required argument is missing ({name})"));
        }
    }
    for (name, value) in arguments {
        let Some(rule) = properties.get(name) else {
            return Err(format!("Unknown argument ({name})"));
        };
        let valid = match rule["type"].as_str() {
            Some("string") => value
                .as_str()
                .is_some_and(|text| !text.is_empty() && !text.contains('\0')),
            Some("integer") => value.as_f64().is_some_and(|number| {
                number.fract() == 0.0
                    && number >= rule["minimum"].as_f64().unwrap_or(0.0)
                    && number <= rule["maximum"].as_f64().unwrap_or(f64::MAX)
            }),
            Some("array") => value.as_array().is_some_and(|items| {
                (2..=8).contains(&items.len())
                    && items.iter().all(|item| {
                        item.as_str()
                            .is_some_and(|text| !text.is_empty() && !text.contains('\0'))
                    })
            }),
            _ => false,
        };
        if !valid
            || rule
                .get("enum")
                .and_then(Value::as_array)
                .is_some_and(|allowed| !allowed.contains(value))
        {
            return Err(format!("Argument has an invalid type or value ({name})"));
        }
    }
    Ok(())
}

fn tools() -> Vec<Value> {
    let file = json!({"type":"string","minLength":1,"description":"Explicit local file path"});
    let mode = json!({"type":"string","enum":["low_bits","signal"],"description":"Pixel-processing mode. Unknown keyed detectors remain unassessed"});
    let bits = json!({"type":"integer","minimum":1,"maximum":3,"default":2,"description":"RGB low bits to clear in low_bits mode"});
    let profile = json!({"type":"string","enum":["safe","deep"],"default":"safe"});
    let choices = json!({"type":"string","description":"Explicit SanitizeOptions JSON. Content-changing Office choices require profile deep"});
    let limits = json!({
        "max_file_mib":{"type":"integer","minimum":1,"maximum":512,"default":64},
        "timeout_seconds":{"type":"integer","minimum":1,"maximum":3600,"default":120}
    });
    let mut definitions = vec![
        (
            "fileveil_heritage",
            "Watermark Engine compatibility entry",
            "Offline legacy decode/clean, modern Ed25519 marking, verification, custody tracing and attack lab. Signing additionally requires an explicit server signing-key whitelist. All writes create new copies.",
            json!({"path":file,"action":{"type":"string","enum":["detect","mark","clean","verify","trace","lab","c2pa_mark","checkpoint","evidence_export","evidence_verify","timestamp_query","timestamp_verify","transfer_prepare","transfer_accept"]},"output":file,"options_json":{"type":"string","description":"HeritageRequest JSON. key_paths and PEM private_key are local paths, never secret key bytes."}}),
            vec!["path", "action"],
            false,
        ),
        (
            "fileveil_scan",
            "Scan file",
            "Read-only privacy audit of one explicit local file",
            json!({"path":file}),
            vec!["path"],
            true,
        ),
        (
            "fileveil_sanitize",
            "Sanitize file",
            "Create a new verified safe-profile metadata-cleaned copy. Existing paths are protected",
            json!({"path":file,"output":file,"profile":profile,"options_json":choices}),
            vec!["path"],
            false,
        ),
        (
            "fileveil_verify",
            "Verify copy",
            "Read-only comparison of an original and copy. Provide mode for a pixel-processed copy",
            json!({"original":file,"output":file,"mode":mode,"low_bits":bits,"profile":profile,"options_json":choices}),
            vec!["original", "output"],
            true,
        ),
        (
            "fileveil_process_image",
            "Process image",
            "Create a new PNG with explicit RGB low-bit clearing or resizing/smoothing/JPEG transformation. This changes pixels and leaves keyed-watermark detection unassessed",
            json!({"path":file,"output":file,"mode":mode,"low_bits":bits}),
            vec!["path"],
            false,
        ),
        (
            "fileveil_detect_watermark",
            "Detect public image watermarks",
            "Read-only public LSB and Stable Diffusion image detectors with named methods and explicit limitations",
            json!({"path":file}),
            vec!["path"],
            true,
        ),
        (
            "fileveil_lab",
            "Image difference lab",
            "Compare 2 to 8 authorized image control samples using pixel, LSB, entropy and frequency statistics",
            json!({"paths":{"type":"array","items":file,"minItems":2,"maxItems":8}, "groups_json":{"type":"string","description":"Optional reference groups JSON with labels and zero-based sample_indices"}}),
            vec!["paths"],
            true,
        ),
        (
            "fileveil_provenance",
            "AI provenance and C2PA",
            "Offline C2PA signature, asset binding and optional explicitly authorized local PEM trust roots",
            json!({"path":file,"trust_roots":file}),
            vec!["path"],
            true,
        ),
        (
            "fileveil_capabilities",
            "FileVeil capabilities",
            "Read available formats, processing modes and resource budgets",
            json!({}),
            vec![],
            true,
        ),
    ];
    for (name, title, read_only) in [
        ("fileveil_mark", "Mark", false),
        ("fileveil_clean", "Clean", false),
        ("fileveil_trace", "Trace", true),
        ("fileveil_verify_watermark", "Verify", true),
        ("fileveil_watermark_lab", "Lab", true),
    ] {
        definitions.push((name,title,"Versioned offline watermark and copyright operation. Key files and system key references require separate explicit grants.",
            json!({"path":file,"output":file,"options_json":{"type":"string","description":"HeritageRequest JSON with key paths, copy identifier and authorized external evidence paths. Secret key bytes are never supplied inline."}}),vec!["path"],read_only));
    }
    definitions.push(("fileveil_evidence","Trace evidence","Export and verify signed evidence, dual-party transfers, checkpoints and RFC3161 files offline.",
        json!({"path":file,"action":{"type":"string","enum":["checkpoint","evidence_export","evidence_verify","timestamp_query","timestamp_verify","transfer_prepare","transfer_accept"]},"output":file,"options_json":{"type":"string"}}),vec!["path","action"],false));
    definitions.into_iter().map(|(name, title, description, mut properties, required, read_only)| {
        if name != "fileveil_capabilities" {
            properties.as_object_mut().expect("tool properties").extend(limits.as_object().expect("limit properties").clone());
        }
        json!({
            "name":name,"title":title,"description":description,
            "inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false},
            "annotations":{"readOnlyHint":read_only,"destructiveHint":false,"idempotentHint":read_only,"openWorldHint":false}
        })
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn schemas_match_validation_and_keep_explicit_paths() {
        let definition = tools()
            .into_iter()
            .find(|tool| tool["name"] == "fileveil_process_image")
            .unwrap();
        let schema = &definition["inputSchema"];
        assert!(
            validate_arguments(
                json!({"path":"sample.png","mode":"low_bits","low_bits":2.0})
                    .as_object()
                    .unwrap(),
                schema
            )
            .is_ok()
        );
        for invalid in [
            json!({}),
            json!({"path":"x","low_bits":4}),
            json!({"path":"x","extra":true}),
            json!({"path":"x","mode":"unknown"}),
        ] {
            assert!(validate_arguments(invalid.as_object().unwrap(), schema).is_err());
        }
    }
    #[test]
    fn transport_rejects_oversized_messages_without_growing_the_buffer() {
        let mut reader = io::Cursor::new(vec![b'x'; MAX_MESSAGE_BYTES + 1]);
        assert_eq!(
            read_message(&mut reader).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

// FVPROV1 31275 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIxMjY3MjA2NDhkYmYyZmFhYTU1YjI2YjlkNzgxODU0ODVmMzU0MTJkMjdlZTFmMThiNTJiYWUyZDJiNzI0NjVlIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4yIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMiIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvc3JjL21jcC5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6ImVjMTVmMDVmNGI4ZDJlMjU1MzcxOGZiOWM4NDc5MzkxOGVhODNmNGE0MzA3ZmQyNmYwYWE0OGI5ZDRkOTZmYjAyODZjYzZkYTViMjhhM2NhZGFjYWZmMGZjMzYwM2IyYTVjZDM2MTQ0Nzg0NzQ2MWQ4ZjE1YjdlMjhiMWQwYzBhIn1dfV0= FVPROV1-END
