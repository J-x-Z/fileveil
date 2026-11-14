// SPDX-License-Identifier: MPL-2.0
//! Strict qpdf-backed full rewrites, with independent, bounded Poppler comparisons.
//! Paths supplied by clients never reach a backend. Inputs are immutable snapshot bytes.
use fileveil_core::{
    Action, Error, Finding, FindingState, Integrity, Limits, Outcome, PdfOptions, Result,
    RiskLayer, digest,
};
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

pub struct PdfInspection {
    pub findings: Vec<Finding>,
    pub blockers: Vec<String>,
    pub content_digest: String,
    pub details: Value,
}
pub struct PdfVerification {
    pub findings: Vec<Finding>,
    pub warnings: Vec<String>,
    pub integrity: Integrity,
    pub result: Outcome,
    pub details: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PdfCredentialSummary {
    /// Distinct embedded stream objects identified by parsed C2PA file specifications.
    pub store_count: usize,
    pub digital_signatures_present: bool,
    /// Incomplete C2PA file specifications remain protected even without a readable store.
    pub unresolved_credential_entries: usize,
    /// Previous-xref or raw marker clues do not prove every earlier revision was validated.
    pub incremental_history_clues: bool,
}

fn c2pa_mime(value: &Value) -> bool {
    matches!(
        value.as_str(),
        Some("/application/c2pa" | "u:application/c2pa")
    )
}
fn credential_summary_from(objects: &Map<String, Value>, signatures: bool) -> PdfCredentialSummary {
    let mut streams = BTreeSet::new();
    let mut unresolved = 0;
    for (key, record) in objects {
        if record.get("stream").is_some()
            && object_value(record).get("/Subtype").is_some_and(c2pa_mime)
        {
            streams.insert(key.clone());
        }
        credential_specs(object_value(record), objects, &mut streams, &mut unresolved);
    }
    PdfCredentialSummary {
        store_count: streams.len(),
        digital_signatures_present: signatures,
        unresolved_credential_entries: unresolved,
        incremental_history_clues: false,
    }
}
fn credential_specs(
    value: &Value,
    objects: &Map<String, Value>,
    streams: &mut BTreeSet<String>,
    unresolved: &mut usize,
) {
    match value {
        Value::Object(fields) => {
            let relationship = fields
                .get("/AFRelationship")
                .map(|value| resolve(value, objects))
                .and_then(Value::as_str)
                == Some("/C2PA_Manifest");
            let subtype = fields
                .get("/Subtype")
                .map(|value| resolve(value, objects))
                .is_some_and(c2pa_mime);
            if relationship || (subtype && fields.contains_key("/EF")) {
                let embedded = fields
                    .get("/EF")
                    .map(|value| resolve(value, objects))
                    .and_then(|value| value.get("/F"));
                let stream = embedded
                    .and_then(Value::as_str)
                    .and_then(reference)
                    .filter(|key| {
                        objects
                            .get(key)
                            .is_some_and(|record| record.get("stream").is_some())
                    });
                let incomplete = stream.is_none() || !relationship || !subtype;
                if let Some(stream) = stream {
                    streams.insert(stream);
                }
                if incomplete {
                    *unresolved += 1;
                }
            }
            for value in fields.values() {
                credential_specs(value, objects, streams, unresolved);
            }
        }
        Value::Array(values) => {
            for value in values {
                credential_specs(value, objects, streams, unresolved);
            }
        }
        _ => {}
    }
}

/// Structural preflight for the official SDK, including stores its first-AF reader can miss.
/// Counts and flags reveal no manifest bytes, attachment names, metadata values or paths.
pub fn credential_summary(data: &[u8], limits: &Limits) -> Result<PdfCredentialSummary> {
    let document = Document::open(data, limits)?;
    let mut summary = credential_summary_from(
        object_map(&document.json)?,
        document.inspection.details["signature_structures"]
            .as_u64()
            .is_some_and(|count| count > 0),
    );
    summary.incremental_history_clues = document.inspection.details["has_previous_xref"] == true
        || document.inspection.details["incremental_marker_count"]
            .as_u64()
            .is_some_and(|count| count > 1);
    Ok(summary)
}

const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const RENDER_DIMENSION: u64 = 1024;

/// Backend paths are trusted process configuration, never MCP operation arguments.
fn executable(variable: &str, name: &str) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(configured) = std::env::var_os(variable) {
        let configured = PathBuf::from(configured);
        return configured
            .is_absolute()
            .then(|| fs::canonicalize(configured).ok())
            .flatten()
            .filter(|p| p.is_file());
    }
    if let Ok(current) = std::env::current_exe()
        && let Some(parent) = current.parent()
    {
        let executable_name = if cfg!(windows) {
            format!("{name}.exe")
        } else {
            name.into()
        };
        candidates.push(parent.join("backends").join(&executable_name));
        candidates.push(parent.join("../Resources/backends").join(&executable_name));
    }
    for directory in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"] {
        candidates.push(Path::new(directory).join(name));
    }
    candidates
        .into_iter()
        .find_map(|path| fs::canonicalize(path).ok().filter(|p| p.is_file()))
}

pub fn capabilities() -> Value {
    let independent_available = [
        ("FILEVEIL_PDFINFO", "pdfinfo"),
        ("FILEVEIL_PDFTOTEXT", "pdftotext"),
        ("FILEVEIL_PDFTOPPM", "pdftoppm"),
    ]
    .iter()
    .all(|(variable, name)| executable(variable, name).is_some());
    let backend_available = executable("FILEVEIL_QPDF", "qpdf").is_some_and(|program| {
        run(&program, &args(&["--version"]), 4096, None, None)
            .is_ok_and(|output| output.status.success())
    });
    json!({"backend":"qpdf", "available":backend_available,
        "independent_validation_available": independent_available,
        "signature_validation":"not_assessed", "rewrite":"full_non_incremental", "offline":true})
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct ProcessOutput {
    status: ExitStatus,
    bytes: Vec<u8>,
}

fn run(
    program: &Path,
    arguments: &[OsString],
    cap: u64,
    watched: Option<(&Path, u64)>,
    working_directory: Option<&Path>,
) -> Result<ProcessOutput> {
    // Child processes inherit the worker process group, so cancellation kills the full tree.
    let mut command = Command::new(program);
    if let Some(directory) = working_directory {
        command.current_dir(directory);
    }
    let child = command
        .args(arguments)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error::Unsupported("PDF backend could not be started".into()))?;
    let mut child = ChildGuard(child);
    let stdout = child
        .0
        .stdout
        .take()
        .ok_or_else(|| Error::Io("PDF backend output pipe is unavailable".into()))?;
    let (sender, receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take(cap.saturating_add(1))
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = sender.send(result);
    });
    let started = Instant::now();
    let mut captured = None;
    let status = loop {
        if captured.is_none() {
            match receiver.try_recv() {
                Ok(Ok(bytes)) => {
                    if bytes.len() as u64 > cap {
                        return Err(Error::Blocked(
                            "PDF backend output exceeded its resource budget".into(),
                        ));
                    }
                    captured = Some(bytes);
                }
                Ok(Err(_)) => return Err(Error::Io("PDF backend output could not be read".into())),
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err(Error::Io("PDF backend output reader failed".into()));
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some((path, maximum)) = watched
            && fs::metadata(path).is_ok_and(|m| m.len() > maximum)
        {
            return Err(Error::Blocked(
                "Rewritten PDF exceeded the file byte limit".into(),
            ));
        }
        if started.elapsed() > COMMAND_TIMEOUT {
            return Err(Error::Interrupted(
                "PDF backend exceeded its execution time budget".into(),
            ));
        }
        if let Some(status) = child
            .0
            .try_wait()
            .map_err(|_| Error::Io("PDF backend status could not be read".into()))?
        {
            break status;
        }
        thread::sleep(Duration::from_millis(10));
    };
    if captured.is_none() {
        captured = Some(
            receiver
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| Error::Io("PDF backend output reader did not finish".into()))?
                .map_err(|_| Error::Io("PDF backend output could not be read".into()))?,
        );
    }
    let _ = reader.join();
    let bytes = captured.unwrap_or_default();
    if bytes.len() as u64 > cap {
        return Err(Error::Blocked(
            "PDF backend output exceeded its resource budget".into(),
        ));
    }
    Ok(ProcessOutput { status, bytes })
}
fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}
fn bounded_read(path: &Path, cap: u64) -> Result<Vec<u8>> {
    let file =
        File::open(path).map_err(|_| Error::Io("PDF intermediate could not be opened".into()))?;
    let mut bytes = Vec::new();
    file.take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Io("PDF intermediate could not be read".into()))?;
    if bytes.len() as u64 > cap {
        return Err(Error::Blocked(
            "PDF intermediate exceeded the byte budget".into(),
        ));
    }
    Ok(bytes)
}

struct Document {
    directory: tempfile::TempDir,
    backend: PathBuf,
    json: Value,
    inspection: PdfInspection,
}
impl Document {
    fn open(data: &[u8], limits: &Limits) -> Result<Self> {
        Self::open_selected(data, limits, false)
    }
    fn open_selected(data: &[u8], limits: &Limits, remove_provenance: bool) -> Result<Self> {
        if data.len() as u64 > limits.max_file_bytes {
            return Err(Error::Blocked("PDF exceeds the file byte limit".into()));
        }
        if !data.starts_with(b"%PDF-") {
            return Err(Error::Input("Input does not have a PDF header".into()));
        }
        let backend = executable("FILEVEIL_QPDF", "qpdf").ok_or_else(|| {
            Error::Unsupported("The trusted qpdf PDF backend is unavailable".into())
        })?;
        let mut staging = tempfile::Builder::new();
        staging.prefix("fileveil-pdf-");
        // A supervisor-owned root is removed even when a worker is forcibly killed.
        let directory = if let Some(root) = std::env::var_os("FILEVEIL_PDF_STAGING") {
            let root = PathBuf::from(root);
            if !root.is_absolute() {
                return Err(Error::Blocked(
                    "PDF staging root must be an absolute trusted directory".into(),
                ));
            }
            staging.tempdir_in(root)
        } else {
            staging.tempdir()
        }
        .map_err(|_| Error::Io("Private PDF staging could not be created".into()))?;
        let input = directory.path().join("snapshot.pdf");
        File::create(&input)
            .and_then(|mut file| file.write_all(data))
            .map_err(|_| Error::Io("Private PDF snapshot could not be written".into()))?;
        let mut encryption_args = args(&["--is-encrypted"]);
        encryption_args.push("snapshot.pdf".into());
        let encryption = run(
            &backend,
            &encryption_args,
            4096,
            None,
            Some(directory.path()),
        )?;
        if encryption.status.code() == Some(0) {
            return Err(Error::Blocked(
                "Encrypted PDF documents are protected from parsing and rewriting".into(),
            ));
        }
        let mut arguments = args(&[
            "--suppress-recovery",
            "--json-output=2",
            "--json-key=qpdf",
            "--json-key=pages",
            "--json-stream-data=inline",
            "--decode-level=none",
        ]);
        arguments.push("snapshot.pdf".into());
        let json_cap = limits
            .max_uncompressed_bytes
            .saturating_mul(2)
            .min(256 * 1024 * 1024);
        let output = run(&backend, &arguments, json_cap, None, Some(directory.path()))?;
        if !output.status.success() {
            return Err(Error::Blocked(
                "PDF strict parsing failed or required repair".into(),
            ));
        }
        let json: Value = serde_json::from_slice(&output.bytes)
            .map_err(|_| Error::Blocked("PDF backend returned an invalid structure".into()))?;
        let objects = object_map(&json)?;
        if objects.len().saturating_sub(1) > limits.max_members {
            return Err(Error::Blocked(
                "PDF object count exceeds the resource budget".into(),
            ));
        }
        let inspection = analyze(&json, data, limits, remove_provenance)?;
        Ok(Self {
            directory,
            backend,
            json,
            inspection,
        })
    }
}
fn object_map(json: &Value) -> Result<&Map<String, Value>> {
    if json.pointer("/qpdf/0/jsonversion").and_then(Value::as_u64) != Some(2) {
        return Err(Error::Unsupported(
            "PDF backend JSON version is unsupported".into(),
        ));
    }
    json.pointer("/qpdf/1")
        .and_then(Value::as_object)
        .ok_or_else(|| Error::Blocked("PDF object table is missing".into()))
}
fn object_value(record: &Value) -> &Value {
    record
        .get("value")
        .or_else(|| record.get("stream").and_then(|s| s.get("dict")))
        .unwrap_or(&Value::Null)
}
fn reference(value: &str) -> Option<String> {
    let mut fields = value.split(' ');
    let object = fields.next()?;
    let generation = fields.next()?;
    if fields.next()? != "R"
        || fields.next().is_some()
        || object.parse::<u32>().is_err()
        || generation.parse::<u16>().is_err()
    {
        return None;
    }
    Some(format!("obj:{object} {generation} R"))
}
fn resolve<'a>(value: &'a Value, objects: &'a Map<String, Value>) -> &'a Value {
    value
        .as_str()
        .and_then(reference)
        .and_then(|key| objects.get(&key))
        .map(object_value)
        .unwrap_or(value)
}

#[derive(Default)]
struct Counts {
    info: usize,
    custom: usize,
    metadata: usize,
    attachments: usize,
    scripts: usize,
    open_actions: usize,
    signatures: usize,
    hidden: usize,
    external: usize,
    private_data: usize,
    annotations: usize,
}
fn attachment_data_present(
    value: &Value,
    objects: &Map<String, Value>,
    remaining: &mut usize,
) -> bool {
    if *remaining == 0 {
        // Unresolved, cyclic or over-budget descriptors remain structural clues.
        return true;
    }
    *remaining -= 1;
    match resolve(value, objects) {
        Value::Null => false,
        Value::Array(values) => !values.is_empty(),
        Value::Object(fields) => fields
            .values()
            .any(|value| attachment_data_present(value, objects, remaining)),
        _ => true,
    }
}
fn walk_fields(
    value: &Value,
    objects: &Map<String, Value>,
    counts: &mut Counts,
    depth: usize,
) -> Result<()> {
    if depth > 96 {
        return Err(Error::Blocked(
            "PDF dictionary nesting exceeds the resource budget".into(),
        ));
    }
    match value {
        Value::Array(values) => {
            for value in values {
                walk_fields(value, objects, counts, depth + 1)?;
            }
        }
        Value::Object(fields) => {
            if fields.get("/Type").and_then(Value::as_str) == Some("/Annot")
                || fields
                    .get("/Subtype")
                    .and_then(Value::as_str)
                    .is_some_and(|subtype| {
                        matches!(
                            subtype,
                            "/Text"
                                | "/Link"
                                | "/FreeText"
                                | "/Line"
                                | "/Square"
                                | "/Circle"
                                | "/Polygon"
                                | "/PolyLine"
                                | "/Highlight"
                                | "/Underline"
                                | "/Squiggly"
                                | "/StrikeOut"
                                | "/Stamp"
                                | "/Caret"
                                | "/Ink"
                                | "/Popup"
                                | "/FileAttachment"
                                | "/Sound"
                                | "/Movie"
                                | "/Widget"
                                | "/Screen"
                                | "/PrinterMark"
                                | "/TrapNet"
                                | "/Watermark"
                                | "/3D"
                                | "/Redact"
                                | "/Projection"
                                | "/RichMedia"
                        )
                    })
            {
                counts.annotations += 1;
            }
            if fields.get("/Type").and_then(Value::as_str) == Some("/Metadata") {
                counts.metadata += 1;
            }
            if fields.get("/Type").and_then(Value::as_str) == Some("/EmbeddedFile")
                || ["/EmbeddedFiles", "/EF", "/AF"].iter().any(|key| {
                    fields
                        .get(*key)
                        .is_some_and(|value| attachment_data_present(value, objects, &mut 256))
                })
            {
                counts.attachments += 1;
            }
            if fields.contains_key("/JS")
                || fields.get("/S").and_then(Value::as_str) == Some("/JavaScript")
            {
                counts.scripts += 1;
            }
            if fields.contains_key("/OpenAction") || fields.contains_key("/AA") {
                counts.open_actions += 1;
            }
            if fields.get("/Type").and_then(Value::as_str) == Some("/Sig")
                || fields.get("/FT").and_then(Value::as_str) == Some("/Sig")
                || fields.contains_key("/ByteRange")
                || fields.contains_key("/DocMDP")
                || fields.contains_key("/Perms")
            {
                counts.signatures += 1;
            }
            if fields.contains_key("/OCProperties")
                || fields.get("/Type").and_then(Value::as_str) == Some("/OCG")
                || fields.contains_key("/OC")
                || fields
                    .get("/F")
                    .and_then(Value::as_u64)
                    .is_some_and(|flags| flags & 35 != 0)
            {
                counts.hidden += 1;
            }
            if fields.contains_key("/URI")
                || fields.get("/S").and_then(Value::as_str).is_some_and(|s| {
                    matches!(s, "/Launch" | "/GoToR" | "/SubmitForm" | "/ImportData")
                })
            {
                counts.external += 1;
            }
            if fields.contains_key("/PieceInfo") || fields.contains_key("/LastModified") {
                counts.private_data += 1;
            }
            for value in fields.values() {
                walk_fields(value, objects, counts, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn metadata_ref(value: &Value, found: &mut BTreeSet<String>) {
    match value {
        Value::Object(fields) => {
            if let Some(key) = fields
                .get("/Metadata")
                .and_then(Value::as_str)
                .and_then(reference)
            {
                found.insert(key);
            }
            for value in fields.values() {
                metadata_ref(value, found);
            }
        }
        Value::Array(values) => {
            for value in values {
                metadata_ref(value, found);
            }
        }
        _ => {}
    }
}
fn nonmetadata_reference(value: &Value, metadata: &BTreeSet<String>) -> bool {
    if value
        .as_str()
        .and_then(reference)
        .is_some_and(|key| metadata.contains(&key))
    {
        return true;
    }
    match value {
        Value::Object(fields) => fields
            .iter()
            .any(|(key, value)| key != "/Metadata" && nonmetadata_reference(value, metadata)),
        Value::Array(values) => values
            .iter()
            .any(|value| nonmetadata_reference(value, metadata)),
        _ => false,
    }
}
fn metadata_shared_with_content(objects: &Map<String, Value>, metadata: &BTreeSet<String>) -> bool {
    objects.iter().any(|(key, record)| {
        !metadata.contains(key) && nonmetadata_reference(object_value(record), metadata)
    })
}
fn finding(code: &str, summary: &str, action: Action) -> Finding {
    Finding::new(
        code,
        RiskLayer::ContainerStructure,
        "pdf/object_graph",
        summary,
        action,
    )
}

fn analyze(
    json: &Value,
    data: &[u8],
    limits: &Limits,
    remove_provenance: bool,
) -> Result<PdfInspection> {
    let objects = object_map(json)?;
    let trailer = objects
        .get("trailer")
        .map(object_value)
        .ok_or_else(|| Error::Blocked("PDF trailer is missing".into()))?;
    if trailer.get("/Encrypt").is_some() {
        return Err(Error::Blocked(
            "Encrypted PDF documents are protected".into(),
        ));
    }
    let mut counts = Counts::default();
    let mut metadata_objects = BTreeSet::new();
    for (key, record) in objects {
        walk_fields(object_value(record), objects, &mut counts, 0)?;
        metadata_ref(object_value(record), &mut metadata_objects);
        if object_value(record).get("/Type").and_then(Value::as_str) == Some("/Metadata") {
            metadata_objects.insert(key.clone());
        }
    }
    counts.metadata = metadata_objects.len();
    if let Some(info) = trailer.get("/Info") {
        let info = resolve(info, objects).as_object().ok_or_else(|| {
            Error::Blocked("PDF document information dictionary is invalid".into())
        })?;
        counts.info = info.len();
        counts.custom = info
            .keys()
            .filter(|key| {
                !matches!(
                    key.as_str(),
                    "/Title"
                        | "/Author"
                        | "/Subject"
                        | "/Keywords"
                        | "/Creator"
                        | "/Producer"
                        | "/CreationDate"
                        | "/ModDate"
                        | "/Trapped"
                )
            })
            .count();
        if serde_json::to_vec(info)
            .map_err(|_| Error::Blocked("PDF information dictionary is invalid".into()))?
            .len()
            > limits.max_metadata_bytes
        {
            return Err(Error::Blocked(
                "PDF information dictionary exceeds the metadata budget".into(),
            ));
        }
    }
    let pages = json
        .get("pages")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Blocked("PDF page tree could not be traversed".into()))?
        .len();
    if pages > limits.max_members {
        return Err(Error::Blocked(
            "PDF page count exceeds the resource budget".into(),
        ));
    }
    let previous_xref = trailer.get("/Prev").is_some();
    // Markers are clues only. Identical bytes can also occur inside a stream.
    let incremental_markers = data
        .windows(b"startxref".len())
        .filter(|part| *part == b"startxref")
        .count();
    let mut findings = Vec::new();
    if trailer.get("/Info").is_some() {
        findings.push(Finding::new(
            "pdf.document_info",
            RiskLayer::EmbeddedMetadata,
            "pdf/trailer/Info",
            "Document information and custom property dictionary is present",
            Action::Remove,
        ));
    }
    if counts.metadata > 0 {
        findings.push(Finding::new(
            "pdf.xmp",
            RiskLayer::EmbeddedMetadata,
            "pdf/metadata_objects",
            "XMP or metadata stream objects are present",
            Action::Remove,
        ));
    }
    if previous_xref || incremental_markers > 1 {
        findings.push(finding("pdf.incremental_history", "Incremental revision clues are present. Marker counts alone do not establish revision history", Action::Rebuild));
    }
    if counts.attachments > 0 {
        findings.push(finding(
            "pdf.attachments",
            "Embedded files or associated-file structures remain and may carry private content",
            Action::AskUser,
        ));
    }
    if counts.scripts > 0 || counts.open_actions > 0 {
        findings.push(finding("pdf.active_content", "JavaScript, automatic actions or action dictionaries are present. They are never executed", Action::AskUser));
    }
    if counts.hidden > 0 {
        findings.push(finding("pdf.hidden_content_clues", "Optional content or hidden-object flags are present. Visibility and intent require review", Action::AskUser));
    }
    if counts.external > 0 {
        findings.push(finding(
            "pdf.external_actions",
            "External links or remote-action structures are preserved",
            Action::AskUser,
        ));
    }
    if counts.private_data > 0 {
        findings.push(finding(
            "pdf.private_structure",
            "Application-specific dictionaries or modification fields are preserved",
            Action::AskUser,
        ));
    }
    if counts.annotations > 0 {
        findings.push(finding(
            "pdf.annotations",
            "Annotation objects and their author, date or embedded content fields are preserved",
            Action::AskUser,
        ));
    }
    let mut blockers = Vec::new();
    if metadata_shared_with_content(objects, &metadata_objects) {
        findings.push(finding("pdf.shared_metadata","A metadata object is also referenced outside metadata fields. Rewriting requires preservation of its content role",Action::Preserve));
        blockers.push(
            "Shared PDF metadata and content objects require a role-aware preservation backend"
                .into(),
        );
    }
    let credentials = credential_summary_from(objects, counts.signatures > 0);
    if credentials.store_count > 0 || credentials.unresolved_credential_entries > 0 {
        findings.push(Finding::new("pdf.provenance",RiskLayer::ProvenanceCredential,"pdf/associated_files","Parsed C2PA associated-file or embedded-store structures are present. Cryptographic validation is reported separately",Action::Preserve));
        if !remove_provenance {
            blockers.push("PDF Content Credentials require an explicit provenance-removal selection before rewriting".into());
        }
    }
    if counts.signatures > 0 {
        findings.push(Finding::unassessed("pdf.digital_signature", RiskLayer::ProvenanceCredential, "pdf/signature_structures", "Signature or certification structures are present. Cryptographic validity has not been checked"));
        blockers.push(
            "PDF signature or certification structures protect this document from rewriting".into(),
        );
    }
    findings.push(Finding::unassessed("pdf.opaque_content", RiskLayer::ContentWatermark, "pdf/content_streams", "Page content, font and image streams, annotations and arbitrary private fields are outside standard metadata removal scope"));
    let (content_digest, reachable) = content_fingerprint(objects, limits)?;
    let unreferenced = objects
        .keys()
        .filter(|key| key.starts_with("obj:") && !reachable.contains(*key))
        .count();
    let details = json!({"backend":"qpdf", "json_version":2, "pages":pages, "objects":objects.len().saturating_sub(1),
        "document_info_fields":counts.info, "custom_info_fields":counts.custom, "metadata_objects":counts.metadata,
        "attachment_structures":counts.attachments, "javascript_actions":counts.scripts, "automatic_actions":counts.open_actions, "annotation_structures":counts.annotations,
        "signature_structures":counts.signatures, "signature_validation":"not_assessed", "hidden_content_clues":counts.hidden,
        "c2pa_store_count":credentials.store_count,"c2pa_unresolved_entries":credentials.unresolved_credential_entries,
        "has_previous_xref":previous_xref, "incremental_marker_count":incremental_markers,
        "unreferenced_or_metadata_objects":unreferenced, "rewrite_scope":"document_info_and_xmp_full_rewrite",
        "independent_page_count_equal":null, "independent_text_equal":null, "independent_render_equal":null});
    Ok(PdfInspection {
        findings,
        blockers,
        content_digest,
        details,
    })
}

struct CanonicalGraph<'a> {
    objects: &'a Map<String, Value>,
    references: BTreeMap<String, usize>,
    reached: BTreeSet<String>,
    remaining: usize,
}
impl CanonicalGraph<'_> {
    fn value(&mut self, value: &Value, depth: usize) -> Result<Value> {
        if depth > 128 || self.remaining == 0 {
            return Err(Error::Blocked(
                "PDF content graph exceeds the traversal budget".into(),
            ));
        }
        self.remaining -= 1;
        if let Some(key) = value.as_str().and_then(reference) {
            let record = self.objects.get(&key).ok_or_else(|| {
                Error::Blocked("PDF contains an unresolved object reference".into())
            })?;
            if object_value(record).get("/Type").and_then(Value::as_str) == Some("/Metadata") {
                return Ok(Value::Null);
            }
            self.reached.insert(key.clone());
            // Scalar indirect objects have no identity relevant to page content.
            if record
                .get("value")
                .is_some_and(|v| !v.is_array() && !v.is_object())
            {
                return self.value(object_value(record), depth + 1);
            }
            if let Some(ordinal) = self.references.get(&key) {
                return Ok(json!({"reference":ordinal}));
            }
            let ordinal = self.references.len();
            self.references.insert(key, ordinal);
            let canonical = if let Some(stream) = record.get("stream") {
                json!({"dictionary":self.value(&stream["dict"],depth+1)?, "stream_bytes":stream.get("data").ok_or_else(|| Error::Blocked("PDF stream data is unavailable for comparison".into()))?})
            } else {
                self.value(object_value(record), depth + 1)?
            };
            return Ok(json!({"object":ordinal,"value":canonical}));
        }
        match value {
            Value::Object(fields) => {
                let mut result = Map::new();
                // serde_json's preserve_order feature can be enabled by other crates.
                // Canonical traversal must remain independent of map insertion/removal order.
                let ordered: BTreeMap<_, _> = fields.iter().collect();
                for (key, value) in ordered {
                    if key != "/Metadata" {
                        result.insert(key.clone(), self.value(value, depth + 1)?);
                    }
                }
                Ok(Value::Object(result))
            }
            Value::Array(values) => Ok(Value::Array(
                values
                    .iter()
                    .map(|v| self.value(v, depth + 1))
                    .collect::<Result<Vec<_>>>()?,
            )),
            _ => Ok(value.clone()),
        }
    }
}
fn content_fingerprint(
    objects: &Map<String, Value>,
    limits: &Limits,
) -> Result<(String, BTreeSet<String>)> {
    let root = objects
        .get("trailer")
        .map(object_value)
        .and_then(|v| v.get("/Root"))
        .ok_or_else(|| Error::Blocked("PDF catalog reference is missing".into()))?;
    let mut graph = CanonicalGraph {
        objects,
        references: BTreeMap::new(),
        reached: BTreeSet::new(),
        remaining: limits.max_members.saturating_mul(256).max(1),
    };
    let canonical = graph.value(root, 0)?;
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|_| Error::Blocked("PDF content graph serialization failed".into()))?;
    Ok((digest(&bytes), graph.reached))
}

pub fn inspect(data: &[u8], limits: &Limits) -> Result<PdfInspection> {
    Ok(Document::open(data, limits)?.inspection)
}
pub fn inspect_for_provenance_removal(data: &[u8], limits: &Limits) -> Result<PdfInspection> {
    Ok(Document::open_selected(data, limits, true)?.inspection)
}

fn remove_metadata(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            fields.remove("/Metadata");
            for value in fields.values_mut() {
                remove_metadata(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                remove_metadata(value);
            }
        }
        _ => {}
    }
}

fn prepare_rewrite(
    json: &mut Value,
    options: &PdfOptions,
    limits: &Limits,
    remove_provenance: bool,
) -> Result<String> {
    let objects = json
        .pointer_mut("/qpdf/1")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| Error::Blocked("PDF object table is unavailable".into()))?;
    let mut metadata = BTreeSet::new();
    for (key, record) in objects.iter() {
        metadata_ref(object_value(record), &mut metadata);
        if object_value(record).get("/Type").and_then(Value::as_str) == Some("/Metadata") {
            metadata.insert(key.clone());
        }
    }
    if metadata_shared_with_content(objects, &metadata) {
        return Err(Error::Blocked(
            "Shared PDF metadata and content objects cannot be discarded during metadata cleanup"
                .into(),
        ));
    }
    for record in objects.values_mut() {
        remove_metadata(record);
    }
    for key in metadata {
        objects.insert(key, json!({"value":null}));
    }
    if let Some(trailer) = objects
        .get_mut("trailer")
        .and_then(|v| v.get_mut("value"))
        .and_then(Value::as_object_mut)
    {
        trailer.remove("/Info");
        trailer.remove("/ID");
        trailer.remove("/Prev");
        trailer.remove("/XRefStm");
    }
    if remove_provenance {
        prune_credentials(objects)?;
    }
    prune_selected(objects, options)?;
    content_fingerprint(objects, limits).map(|(digest, _)| digest)
}

/// The qpdf writer performs a complete serialization and drops unreferenced objects.
/// This method never publishes a file or overwrites a client path.
pub fn sanitize(data: &[u8], limits: &Limits) -> Result<Vec<u8>> {
    sanitize_with_options(data, limits, &PdfOptions::default())
}

pub fn sanitize_with_options(
    data: &[u8],
    limits: &Limits,
    options: &PdfOptions,
) -> Result<Vec<u8>> {
    sanitize_selected(data, limits, options, false)
}
pub fn sanitize_with_provenance_removal(
    data: &[u8],
    limits: &Limits,
    options: &PdfOptions,
) -> Result<Vec<u8>> {
    sanitize_selected(data, limits, options, true)
}

fn protect_remote_credentials(data: &[u8], limits: &Limits) -> Result<()> {
    // The SDK recognizes the standard provenance property regardless of the URI's spelling.
    // Its PDF preflight uses credential_summary, which parses objects without calling this guard.
    if crate::provenance::inspect_mime(data, "application/pdf", limits, None)?.is_some() {
        return Err(Error::Blocked(
            "PDF provenance credentials or references require explicit provenance removal before rewriting"
                .into(),
        ));
    }
    Ok(())
}
fn sanitize_selected(
    data: &[u8],
    limits: &Limits,
    options: &PdfOptions,
    remove_provenance: bool,
) -> Result<Vec<u8>> {
    let mut document = Document::open_selected(data, limits, remove_provenance)?;
    if !document.inspection.blockers.is_empty() {
        return Err(Error::Blocked(document.inspection.blockers.join(". ")));
    }
    if !remove_provenance {
        protect_remote_credentials(data, limits)?;
    }
    let expected_digest = prepare_rewrite(&mut document.json, options, limits, remove_provenance)?;
    let patch_path = document.directory.path().join("metadata-patch.json");
    let patch = json!({"qpdf":document.json["qpdf"]});
    File::create(&patch_path)
        .and_then(|mut file| {
            serde_json::to_writer(&mut file, &patch).map_err(std::io::Error::other)
        })
        .map_err(|_| Error::Io("PDF rewrite instruction could not be staged".into()))?;
    let output_path = document.directory.path().join("rewritten.pdf");
    let mut arguments = args(&[
        "--suppress-recovery",
        "--stream-data=preserve",
        "--object-streams=preserve",
        "--deterministic-id",
    ]);
    // Only fixed names inside this owned workspace reach backend argument parsers.
    // Windows backends can misinterpret verbatim absolute paths from canonicalization.
    arguments.push("--update-from-json=metadata-patch.json".into());
    arguments.push("snapshot.pdf".into());
    arguments.push("rewritten.pdf".into());
    let output = run(
        &document.backend,
        &arguments,
        1024 * 1024,
        Some((&output_path, limits.max_file_bytes)),
        Some(document.directory.path()),
    )?;
    if !output.status.success() {
        return Err(Error::Blocked(
            "PDF full rewrite failed or required repair".into(),
        ));
    }
    let bytes = bounded_read(&output_path, limits.max_file_bytes)?;
    let after = inspect(&bytes, limits)?;
    if after.findings.iter().any(|f| f.action == Action::Remove)
        || after.details["has_previous_xref"] == true
    {
        return Err(Error::Verification(
            "PDF metadata or incremental references remain after rewriting".into(),
        ));
    }
    if after.content_digest != expected_digest {
        return Err(Error::Verification(
            "PDF retained object graph changed during metadata rewriting".into(),
        ));
    }
    check_selected_postconditions(&after, options)?;
    if remove_provenance
        && (after.details["c2pa_store_count"] != 0 || after.details["c2pa_unresolved_entries"] != 0)
    {
        return Err(Error::Verification(
            "PDF credential structures remain after explicitly selected removal".into(),
        ));
    }
    Ok(bytes)
}

struct Independent {
    pages: Option<bool>,
    text: Option<bool>,
    render: Option<bool>,
    warnings: Vec<String>,
}
fn independent(
    before: &Document,
    after: &Document,
    limits: &Limits,
    allow_annotation_changes: bool,
) -> Result<Independent> {
    let mut result = Independent {
        pages: None,
        text: None,
        render: None,
        warnings: Vec::new(),
    };
    let info = executable("FILEVEIL_PDFINFO", "pdfinfo");
    let text = executable("FILEVEIL_PDFTOTEXT", "pdftotext");
    let renderer = executable("FILEVEIL_PDFTOPPM", "pdftoppm");
    if let Some(info) = info {
        let parse = |document: &Document| -> Result<usize> {
            let output = run(
                &info,
                &args(&["snapshot.pdf"]),
                1024 * 1024,
                None,
                Some(document.directory.path()),
            )?;
            if !output.status.success() {
                return Err(Error::Verification(
                    "Independent PDF parser rejected a document".into(),
                ));
            }
            let page_count = std::str::from_utf8(&output.bytes).ok().and_then(|text| {
                text.lines().find_map(|line| {
                    line.strip_prefix("Pages:")
                        .and_then(|count| count.trim().parse::<usize>().ok())
                })
            });
            page_count.ok_or_else(|| {
                Error::Verification("Independent PDF page count is unavailable".into())
            })
        };
        let original_pages = parse(before)?;
        let output_pages = parse(after)?;
        let expected = before.inspection.details["pages"].as_u64().unwrap_or(0) as usize;
        if original_pages != output_pages || original_pages != expected {
            return Err(Error::Verification(
                "Independent PDF page count changed or disagrees with the structural parser".into(),
            ));
        }
        result.pages = Some(true);
    } else {
        result
            .warnings
            .push("Independent Poppler page-count verification is unavailable".into());
    }
    if let Some(text) = text {
        let extract = |document: &Document| -> Result<Vec<u8>> {
            let mut arguments = args(&["-enc", "UTF-8", "-layout"]);
            arguments.push("snapshot.pdf".into());
            arguments.push(OsString::from("-"));
            let output = run(
                &text,
                &arguments,
                limits.max_uncompressed_bytes,
                None,
                Some(document.directory.path()),
            )?;
            if !output.status.success() {
                return Err(Error::Verification(
                    "Independent PDF text extraction failed".into(),
                ));
            }
            Ok(output.bytes)
        };
        let equal = extract(before)? == extract(after)?;
        if !equal && !allow_annotation_changes {
            return Err(Error::Verification(
                "Independent PDF text comparison changed".into(),
            ));
        }
        result.text = Some(equal);
    } else {
        result
            .warnings
            .push("Independent Poppler text verification is unavailable".into());
    }
    if let Some(renderer) = renderer {
        let pages = before.inspection.details["pages"].as_u64().unwrap_or(0);
        if pages.saturating_mul(RENDER_DIMENSION * RENDER_DIMENSION) <= limits.max_pixels {
            let mut render_equal = true;
            for page in 1..=pages {
                let render = |document: &Document| -> Result<Vec<u8>> {
                    let mut arguments = args(&["-scale-to", "1024", "-f"]);
                    arguments.push(page.to_string().into());
                    arguments.push("-l".into());
                    arguments.push(page.to_string().into());
                    arguments.push("-singlefile".into());
                    arguments.push("snapshot.pdf".into());
                    let output = run(
                        &renderer,
                        &arguments,
                        (RENDER_DIMENSION * RENDER_DIMENSION * 3 + 4096)
                            .min(limits.max_uncompressed_bytes),
                        None,
                        Some(document.directory.path()),
                    )?;
                    if !output.status.success() || !output.bytes.starts_with(b"P6") {
                        return Err(Error::Verification(
                            "Independent PDF page rendering failed".into(),
                        ));
                    }
                    Ok(output.bytes)
                };
                if render(before)? != render(after)? {
                    if !allow_annotation_changes {
                        return Err(Error::Verification(
                            "Independent PDF rendered page comparison changed".into(),
                        ));
                    }
                    render_equal = false;
                }
            }
            result.render = Some(render_equal);
        } else {
            result.warnings.push(
                "Independent PDF rendering exceeded the total pixel budget and remains unassessed"
                    .into(),
            );
        }
    } else {
        result
            .warnings
            .push("Independent Poppler rendering verification is unavailable".into());
    }
    Ok(result)
}

pub fn verify(before: &[u8], after: &[u8], limits: &Limits) -> Result<PdfVerification> {
    verify_scoped(before, after, limits, &PdfOptions::default())
}

/// Heritage credentials can add metadata while retaining visible document content.
/// This comparison reuses the bounded, independent Poppler checks without
/// asserting that a metadata-removal or full-object-rewrite policy was applied.
pub fn verify_heritage_display(before: &[u8], after: &[u8], limits: &Limits) -> Result<Value> {
    let original = Document::open_selected(before, limits, true)?;
    let output = Document::open_selected(after, limits, true)?;
    let checks = independent(&original, &output, limits, false)?;
    let complete =
        checks.pages == Some(true) && checks.text == Some(true) && checks.render == Some(true);
    Ok(json!({
        "independent_page_count_equal": checks.pages,
        "independent_text_equal": checks.text,
        "independent_render_equal": checks.render,
        "result": if complete { "verified_within_scope" } else { "partially_verified" },
        "warnings": checks.warnings,
        "scope": "Independent page count, extracted text and bounded-resolution rendered pages. Credential trust, arbitrary streams and full graph identity are separately assessed."
    }))
}

pub fn verify_scoped(
    before: &[u8],
    after: &[u8],
    limits: &Limits,
    options: &PdfOptions,
) -> Result<PdfVerification> {
    verify_selected(before, after, limits, options, false)
}
pub fn verify_with_provenance_removal(
    before: &[u8],
    after: &[u8],
    limits: &Limits,
    options: &PdfOptions,
) -> Result<PdfVerification> {
    verify_selected(before, after, limits, options, true)
}
fn verify_selected(
    before: &[u8],
    after: &[u8],
    limits: &Limits,
    options: &PdfOptions,
    remove_provenance: bool,
) -> Result<PdfVerification> {
    let mut original = Document::open_selected(before, limits, remove_provenance)?;
    let output = Document::open(after, limits)?;
    if !original.inspection.blockers.is_empty() || !output.inspection.blockers.is_empty() {
        return Err(Error::Blocked(
            "Protected PDF credentials prevent rewriting verification".into(),
        ));
    }
    if !remove_provenance {
        protect_remote_credentials(before, limits)?;
    }
    protect_remote_credentials(after, limits)?;
    let expected_digest = prepare_rewrite(&mut original.json, options, limits, remove_provenance)?;
    if expected_digest != output.inspection.content_digest {
        return Err(Error::Verification(
            "PDF retained content graph differs".into(),
        ));
    }
    if output
        .inspection
        .findings
        .iter()
        .any(|f| f.action == Action::Remove)
        || output.inspection.details["has_previous_xref"] == true
    {
        return Err(Error::Verification(
            "Expected PDF metadata removal or full rewrite was not verified".into(),
        ));
    }
    check_selected_postconditions(&output.inspection, options)?;
    let checks = independent(
        &original,
        &output,
        limits,
        options.remove_annotations
            || options.remove_attachments
            || (remove_provenance
                && original.inspection.details["annotation_structures"]
                    .as_u64()
                    .is_some_and(|count| count > 0)),
    )?;
    let complete =
        checks.pages == Some(true) && checks.text == Some(true) && checks.render == Some(true);
    let mut details = output.inspection.details.clone();
    details["independent_page_count_equal"] = json!(checks.pages);
    details["independent_text_equal"] = json!(checks.text);
    details["independent_render_equal"] = json!(checks.render);
    details["render_max_dimension"] = json!(RENDER_DIMENSION);
    details["retained_object_graph_equal"] = json!(true);
    details["deep_options"] = json!(options);
    details["remove_provenance"] = json!(remove_provenance);
    if options.any() {
        details["rewrite_scope"] = json!("explicit_deep_options_and_standard_metadata");
    }
    let mut findings = output.inspection.findings;
    if options.remove_javascript
        && original.inspection.details["javascript_actions"]
            .as_u64()
            .is_some_and(|count| count > 0)
    {
        let mut found = finding(
            "pdf.javascript",
            "Selected JavaScript action structures were removed and the remaining graph was re-parsed",
            Action::Remove,
        );
        found.state = FindingState::RemovedVerified;
        found.confidence = fileveil_core::Confidence::Verified;
        findings.push(found);
    }
    for mut found in original.inspection.findings {
        if found.action == Action::Remove
            || (found.code == "pdf.provenance" && remove_provenance)
            || (found.code == "pdf.attachments"
                && (options.remove_attachments
                    || (remove_provenance && details["attachment_structures"] == 0)))
            || (found.code == "pdf.annotations" && options.remove_annotations)
        {
            found.state = FindingState::RemovedVerified;
            found.action = Action::Remove;
            found.confidence = fileveil_core::Confidence::Verified;
            findings.push(found);
        } else if found.code == "pdf.incremental_history" {
            found.state = FindingState::AppliedVerified;
            found.summary =
                "Full non-incremental serialization was verified without previous-xref references"
                    .into();
            findings.push(found);
        }
    }
    let residual = findings
        .iter()
        .any(|finding| finding.action == Action::AskUser);
    let integrity = Integrity {
        parseable: true,
        decodeable: checks.render.map(|_| true),
        pixel_equal: checks.render,
        content_equal: (complete && !options.any() && !remove_provenance).then_some(true),
        ..Integrity::default()
    };
    let mut warnings = checks.warnings;
    if options.any() {
        warnings.push("Explicit PDF Deep selections can change annotation appearance or embedded functionality. Only the selected graph edits and retained page structure are verified. Full content equivalence remains unassessed.".into());
    }
    warnings.push("Verification covers standard metadata, retained reachable objects, extracted text and bounded-resolution rendered pages. Arbitrary stream contents and signature trust are outside this scope.".into());
    Ok(PdfVerification {
        findings,
        warnings,
        integrity,
        result: if complete && !residual && !options.any() && !remove_provenance {
            Outcome::VerifiedWithinScope
        } else {
            Outcome::PartiallyVerified
        },
        details,
    })
}

fn attachment_dictionary(value: &Value) -> bool {
    value.get("/Type").and_then(Value::as_str) == Some("/EmbeddedFile")
        || value.get("/EF").is_some()
        || value.get("/Subtype").and_then(Value::as_str) == Some("/FileAttachment")
}
fn javascript_dictionary(value: &Value) -> bool {
    value.get("/JS").is_some() || value.get("/S").and_then(Value::as_str) == Some("/JavaScript")
}
fn has_chained_javascript(value: &Value) -> bool {
    match value {
        Value::Object(fields) => {
            (javascript_dictionary(value) && fields.contains_key("/Next"))
                || fields.values().any(has_chained_javascript)
        }
        Value::Array(values) => values.iter().any(has_chained_javascript),
        _ => false,
    }
}
fn contains_widget(value: &Value) -> bool {
    match value {
        Value::Object(fields) => {
            fields.get("/Subtype").and_then(Value::as_str) == Some("/Widget")
                || fields.values().any(contains_widget)
        }
        Value::Array(values) => values.iter().any(contains_widget),
        _ => false,
    }
}
fn names_references(value: &Value, found: &mut BTreeSet<String>) {
    match value {
        Value::Object(fields) => {
            if let Some(key) = fields
                .get("/Names")
                .and_then(Value::as_str)
                .and_then(reference)
            {
                found.insert(key);
            }
            for value in fields.values() {
                names_references(value, found);
            }
        }
        Value::Array(values) => {
            for value in values {
                names_references(value, found);
            }
        }
        _ => {}
    }
}
fn prune_value(
    value: &mut Value,
    options: &PdfOptions,
    deleted: &BTreeSet<String>,
    names: bool,
) -> bool {
    if value
        .as_str()
        .and_then(reference)
        .is_some_and(|key| deleted.contains(&key))
    {
        return false;
    }
    if (options.remove_attachments && attachment_dictionary(value))
        || (options.remove_javascript && javascript_dictionary(value))
    {
        return false;
    }
    match value {
        Value::Object(fields) => {
            if options.remove_attachments {
                fields.remove("/AF");
                if names {
                    fields.remove("/EmbeddedFiles");
                }
            }
            if options.remove_javascript && names {
                fields.remove("/JavaScript");
            }
            if options.remove_annotations {
                fields.remove("/Annots");
            }
            fields.retain(|key, child| prune_value(child, options, deleted, key == "/Names"));
            if fields
                .get("/AA")
                .is_some_and(|value| value.as_object().is_some_and(Map::is_empty))
            {
                fields.remove("/AA");
            }
        }
        Value::Array(values) => {
            values.retain_mut(|child| prune_value(child, options, deleted, false))
        }
        _ => {}
    }
    true
}
fn prune_selected(objects: &mut Map<String, Value>, options: &PdfOptions) -> Result<()> {
    if !options.any() {
        return Ok(());
    }
    if options.remove_annotations
        && objects
            .values()
            .any(|record| contains_widget(object_value(record)))
    {
        return Err(Error::Blocked("Removing annotations from an interactive form would affect widgets. Form-aware annotation rewriting is protected in this build".into()));
    }
    let mut deleted = BTreeSet::new();
    let mut names = BTreeSet::new();
    for (key, record) in objects.iter() {
        let value = object_value(record);
        if options.remove_javascript && has_chained_javascript(value) {
            return Err(Error::Blocked("JavaScript actions with chained follow-up actions require action-chain-aware rewriting and are protected in this build".into()));
        }
        if (options.remove_attachments && attachment_dictionary(value))
            || (options.remove_javascript && javascript_dictionary(value))
        {
            deleted.insert(key.clone());
        }
        names_references(value, &mut names);
    }
    for (key, record) in objects.iter_mut() {
        if deleted.contains(key) {
            *record = json!({"value":null});
            continue;
        }
        let value = if record.get("value").is_some() {
            record.get_mut("value")
        } else {
            record
                .get_mut("stream")
                .and_then(|stream| stream.get_mut("dict"))
        };
        if let Some(value) = value
            && !prune_value(value, options, &deleted, names.contains(key))
        {
            *record = json!({"value":null});
        }
    }
    Ok(())
}
fn check_selected_postconditions(inspection: &PdfInspection, options: &PdfOptions) -> Result<()> {
    if (options.remove_attachments
        && inspection.details["attachment_structures"].as_u64() != Some(0))
        || (options.remove_javascript
            && inspection.details["javascript_actions"].as_u64() != Some(0))
        || (options.remove_annotations
            && inspection.details["annotation_structures"].as_u64() != Some(0))
    {
        return Err(Error::Verification(
            "Selected PDF privacy structures remain after full rewriting".into(),
        ));
    }
    Ok(())
}

struct CredentialPruner {
    specs: BTreeSet<String>,
    streams: BTreeSet<String>,
    annotations: BTreeSet<String>,
    name_arrays: BTreeSet<String>,
    scalars: Map<String, Value>,
}
impl CredentialPruner {
    fn is_spec(&self, value: &Value) -> bool {
        let role = value
            .get("/AFRelationship")
            .map(|value| resolve(value, &self.scalars))
            .and_then(Value::as_str)
            == Some("/C2PA_Manifest");
        role || (value
            .get("/Subtype")
            .map(|value| resolve(value, &self.scalars))
            .is_some_and(c2pa_mime)
            && value.get("/EF").is_some())
    }
    fn is_spec_reference(&self, value: &Value) -> bool {
        value
            .as_str()
            .and_then(reference)
            .is_some_and(|key| self.specs.contains(&key))
            || self.is_spec(value)
    }
    fn is_annotation(&self, value: &Value) -> bool {
        value.get("/Subtype").and_then(Value::as_str) == Some("/FileAttachment")
            && value
                .get("/FS")
                .is_some_and(|value| self.is_spec_reference(value))
    }
    fn shared_stream(&self, value: &Value) -> bool {
        if self.is_spec(value) {
            return false;
        }
        if value
            .as_str()
            .and_then(reference)
            .is_some_and(|key| self.streams.contains(&key))
        {
            return true;
        }
        match value {
            Value::Object(fields) => fields.values().any(|value| self.shared_stream(value)),
            Value::Array(values) => values.iter().any(|value| self.shared_stream(value)),
            _ => false,
        }
    }
    fn names(&self, value: &mut Value) -> Result<()> {
        let Some(values) = value.as_array_mut() else {
            return Ok(());
        };
        if !values.len().is_multiple_of(2) {
            return Err(Error::Blocked(
                "An embedded-file name tree has an incomplete name/reference pair".into(),
            ));
        }
        let mut retained = Vec::with_capacity(values.len());
        for pair in std::mem::take(values).as_chunks::<2>().0 {
            if !self.is_spec_reference(&pair[1]) {
                retained.extend_from_slice(pair);
            }
        }
        *values = retained;
        Ok(())
    }
    fn prune(&self, value: &mut Value) -> Result<bool> {
        if value
            .as_str()
            .and_then(reference)
            .is_some_and(|key| self.specs.contains(&key) || self.annotations.contains(&key))
        {
            return Ok(false);
        }
        if self.is_spec(value) || self.is_annotation(value) {
            return Ok(false);
        }
        match value {
            Value::Object(fields) => {
                if let Some(names) = fields.get_mut("/Names") {
                    self.names(names)?;
                }
                let mut removed = Vec::new();
                for (key, child) in fields.iter_mut() {
                    if !self.prune(child)? {
                        removed.push(key.clone());
                    }
                }
                for key in removed {
                    fields.remove(&key);
                }
            }
            Value::Array(values) => {
                let mut retained = Vec::with_capacity(values.len());
                for mut value in std::mem::take(values) {
                    if self.prune(&mut value)? {
                        retained.push(value);
                    }
                }
                *values = retained;
            }
            _ => {}
        }
        Ok(true)
    }
}
fn prune_credentials(objects: &mut Map<String, Value>) -> Result<()> {
    let scalars = objects
        .iter()
        .filter(|(_, record)| {
            record
                .get("value")
                .and_then(Value::as_str)
                .is_some_and(|value| value.len() <= 128)
        })
        .map(|(key, record)| (key.clone(), record.clone()))
        .collect();
    let mut pruner = CredentialPruner {
        specs: BTreeSet::new(),
        streams: BTreeSet::new(),
        annotations: BTreeSet::new(),
        name_arrays: BTreeSet::new(),
        scalars,
    };
    let mut unresolved = 0;
    for (key, record) in objects.iter() {
        let value = object_value(record);
        if pruner.is_spec(value) {
            pruner.specs.insert(key.clone());
        }
        credential_specs(value, objects, &mut pruner.streams, &mut unresolved);
        if record.get("stream").is_some() && value.get("/Subtype").is_some_and(c2pa_mime) {
            pruner.streams.insert(key.clone());
        }
    }
    for (key, record) in objects.iter() {
        let value = object_value(record);
        if pruner.is_annotation(value) {
            pruner.annotations.insert(key.clone());
        }
        collect_name_arrays(value, objects, &mut pruner.name_arrays);
        if !pruner.streams.contains(key) && pruner.shared_stream(value) {
            return Err(Error::Blocked("A C2PA store stream is shared with document content outside its file specification".into()));
        }
    }
    for (key, record) in objects.iter_mut() {
        if pruner.specs.contains(key)
            || pruner.streams.contains(key)
            || pruner.annotations.contains(key)
        {
            *record = json!({"value":null});
            continue;
        }
        let value = if record.get("value").is_some() {
            record.get_mut("value")
        } else {
            record
                .get_mut("stream")
                .and_then(|stream| stream.get_mut("dict"))
        };
        if let Some(value) = value {
            if pruner.name_arrays.contains(key) {
                pruner.names(value)?;
            }
            if !pruner.prune(value)? {
                *record = json!({"value":null});
            }
        }
    }
    Ok(())
}
fn collect_name_arrays(value: &Value, objects: &Map<String, Value>, arrays: &mut BTreeSet<String>) {
    match value {
        Value::Object(fields) => {
            if let Some(key) = fields
                .get("/Names")
                .and_then(Value::as_str)
                .and_then(reference)
                && objects
                    .get(&key)
                    .map(object_value)
                    .is_some_and(Value::is_array)
            {
                arrays.insert(key);
            }
            for value in fields.values() {
                collect_name_arrays(value, objects, arrays);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_name_arrays(value, objects, arrays);
            }
        }
        _ => {}
    }
}

// FVPROV1 64390 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI5N2U2Y2MwNTY5ZDViMWYxOTEwNTZiZjcxZjdiMzYzYTY5YjgxZGMzOGIwOGNjYjJiZmI0ZmQ0MjA5MGI1YTdhIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4yIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMiIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL3BkZi5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6ImIzMDU1OTdjNzI1Zjg1YWFiNWYzNDZiNzliYmY5YzE1OTFlNzhjY2VmOWQxNjk1ZDE1MzQ5ZWNmYzAzODQwODAwMmUyMzgzNGFiMGZjNDU5Y2E3MDZjZWI4MjQ2OTQ4NDgwNDdhOTRkMGZkZjY0NGVhNDZhZjlhMDQ1MmVjYzA3In1dfV0= FVPROV1-END
