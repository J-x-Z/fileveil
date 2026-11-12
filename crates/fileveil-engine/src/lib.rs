// SPDX-License-Identifier: MPL-2.0
//! Read-only audit and verified, no-clobber transformation pipeline.
pub mod access_guard;
pub mod advanced;
pub mod audits;
pub mod image_processing;
pub mod lab;
pub mod os;
pub mod pdf;
pub mod provenance;
pub mod watermark;
pub mod worker;
use fileveil_core::{
    Action, Confidence, Error, Finding, FindingState, Format, Inspection, Integrity, Limits,
    Outcome, Policy, Report, Result, RiskLayer, digest,
};
use image::{GenericImageView, ImageReader};
pub use image_processing::{process_image_in, publish_processed_staged, verify_processed_image};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
};

struct Snapshot {
    file: File,
    bytes: Vec<u8>,
    attributes: Vec<os::Attribute>,
}
impl Snapshot {
    fn open(path: &Path, limits: &Limits) -> Result<Self> {
        if let Some(file) = access_guard::open_bound(path)? {
            return Self::from_open_file(file, path, limits);
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|e| Error::Input(format!("Could not inspect input ({e})")))?;
        if !metadata.is_file() {
            return Err(Error::Input(
                "Input must be a regular file, with symbolic links resolved by the caller".into(),
            ));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(
                windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
            );
        }
        let file = options
            .open(path)
            .map_err(|e| Error::Io(format!("Could not open input ({e})")))?;
        Self::from_open_file(file, path, limits)
    }
    fn from_open_file(mut file: File, path: &Path, limits: &Limits) -> Result<Self> {
        let opened = file
            .metadata()
            .map_err(|_| Error::Io("Could not inspect open input".into()))?;
        if !opened.is_file() {
            return Err(Error::Input("Opened input must be a regular file".into()));
        }
        if opened.len() > limits.max_file_bytes {
            return Err(Error::Blocked(
                "Input exceeds the configured file byte limit".into(),
            ));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(limits.max_file_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Io("Could not read input".into()))?;
        if bytes.len() as u64 > limits.max_file_bytes {
            return Err(Error::Blocked(
                "Input grew beyond the file byte limit".into(),
            ));
        }
        let attributes = os::read(&file, path, limits)?;
        Ok(Self {
            file,
            bytes,
            attributes,
        })
    }
    fn unchanged(&self, path: &Path, limits: &Limits) -> Result<bool> {
        let current = Self::open(path, limits)?;
        Ok(self.bytes == current.bytes && self.attributes == current.attributes)
    }
}

fn unassessed(format: Format) -> Vec<Finding> {
    let mut findings = vec![Finding::unassessed(
        "watermark.statistical",
        RiskLayer::StatisticalWatermark,
        "content",
        "Keyed statistical watermark detection was not performed",
    )];
    if format.is_image() {
        findings.push(Finding::unassessed(
            "image.content_watermark",
            RiskLayer::ContentWatermark,
            "image_data",
            "Pixel-domain and frequency-domain watermark detection was not performed",
        ));
    }
    findings
}
fn has_residual(inspection: &Inspection, attributes: &[os::Attribute]) -> bool {
    inspection.limited_support
        || inspection
            .findings
            .iter()
            .chain(os::findings(attributes).iter())
            .any(|f| f.action == Action::AskUser)
}
fn inspect_snapshot(data: &[u8], hint: &Path, limits: &Limits) -> Result<Inspection> {
    if fileveil_formats::identify(data, hint) == Format::Pdf {
        let parsed = pdf::inspect(data, limits)?;
        let mut inspection = Inspection::new(Format::Pdf, parsed.content_digest);
        inspection.findings = parsed.findings;
        inspection.blockers = parsed.blockers;
        inspection.limited_support = inspection
            .findings
            .iter()
            .any(|f| f.action == Action::AskUser);
        return Ok(inspection);
    }
    fileveil_formats::inspect(data, hint, limits)
}

fn attach_provenance(
    report: &mut Report,
    snapshot: &Snapshot,
    format: Format,
    limits: &Limits,
) -> Result<()> {
    if let Some(credentials) = provenance::inspect(&snapshot.bytes, format, limits)? {
        report.provenance = Some(
            serde_json::to_value(credentials)
                .map_err(|_| Error::Io("Could not serialize provenance evidence".into()))?,
        );
        report.warnings.push("C2PA signature and asset binding are evaluated offline. Certificate root trust, online revocation and identity assertions require their separately reported verification scopes.".into());
    }
    Ok(())
}
fn report_for(operation: &str, inspection: &Inspection, snapshot: &Snapshot) -> Report {
    let mut report = Report::new(operation, inspection.format);
    report.input_sha256 = Some(digest(&snapshot.bytes));
    report.findings = inspection.findings.clone();
    report.findings.extend(os::findings(&snapshot.attributes));
    report.findings.extend(unassessed(inspection.format));
    report.integrity.parseable = inspection.format != Format::Unknown;
    report.warnings.push("Coverage is limited to the listed fields. Content watermarks, privileged platform attributes, ACLs and filesystem timestamps are outside verification scope.".into());
    report.result = if inspection.format == Format::Unknown {
        Outcome::Unsupported
    } else if !inspection.blockers.is_empty() {
        Outcome::Blocked
    } else if has_residual(inspection, &snapshot.attributes) {
        Outcome::PartiallyVerified
    } else {
        Outcome::VerifiedWithinScope
    };
    report.warnings.extend(inspection.blockers.clone());
    report
}

fn extension_warning(path: &Path, format: Format) -> Option<String> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    let hinted = match extension.as_str() {
        "jpg" | "jpeg" => Format::Jpeg,
        "png" => Format::Png,
        "docx" => Format::Docx,
        "xlsx" => Format::Xlsx,
        "pptx" => Format::Pptx,
        "txt" | "md" | "markdown" => Format::Text,
        "html" | "htm" => Format::Html,
        "pdf" => Format::Pdf,
        _ => return None,
    };
    (hinted != format).then(|| "Filename extension disagrees with the parsed file format".into())
}
pub fn scan(path: &Path, limits: &Limits) -> Result<Report> {
    let snapshot = Snapshot::open(path, limits)?;
    let inspection = inspect_snapshot(&snapshot.bytes, path, limits)?;
    let mut report = report_for("scan", &inspection, &snapshot);
    if inspection.format == Format::Pdf {
        report.pdf = Some(pdf::inspect(&snapshot.bytes, limits)?.details);
    }
    attach_provenance(&mut report, &snapshot, inspection.format, limits)?;
    report
        .warnings
        .extend(extension_warning(path, inspection.format));
    report.integrity.original_unchanged = Some(snapshot.unchanged(path, limits)?);
    if report.integrity.original_unchanged == Some(false) {
        return Err(Error::Blocked(
            "Input changed during the read-only audit".into(),
        ));
    }
    if report.result == Outcome::Unsupported {
        report.findings.push(Finding::unassessed(
            "format.unsupported",
            RiskLayer::ContainerStructure,
            "file",
            "This format has no supported offline parser in this build",
        ));
    }
    Ok(report)
}

fn decode_pixels(data: &[u8], limits: &Limits) -> Result<image::DynamicImage> {
    let reader = ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .map_err(|_| Error::Verification("Image decoder could not identify format".into()))?;
    let (width, height) = reader
        .into_dimensions()
        .map_err(|_| Error::Verification("Image dimensions could not be decoded".into()))?;
    if u64::from(width) * u64::from(height) > limits.max_pixels {
        return Err(Error::Blocked("Image exceeds the pixel budget".into()));
    }
    let mut reader = ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .map_err(|_| Error::Verification("Image decoder could not identify format".into()))?;
    let mut decode_limits = image::Limits::default();
    decode_limits.max_image_width = Some(width);
    decode_limits.max_image_height = Some(height);
    decode_limits.max_alloc = Some(limits.max_pixels * 16);
    reader.limits(decode_limits);
    reader
        .decode()
        .map_err(|_| Error::Verification("Independent image decoding failed".into()))
}

fn compare(
    original: &Snapshot,
    output: &Snapshot,
    original_hint: &Path,
    output_hint: &Path,
    limits: &Limits,
) -> Result<Report> {
    // Both adapters parse their own fresh input. No sanitizer bookkeeping is consumed here.
    let before = inspect_snapshot(&original.bytes, original_hint, limits)?;
    let after = inspect_snapshot(&output.bytes, output_hint, limits)?;
    if original
        .attributes
        .iter()
        .any(|a| a.name == "com.apple.ResourceFork")
    {
        return Err(Error::Blocked(
            "Resource-fork transformation verification is unavailable".into(),
        ));
    }
    if !before.rewrite_supported || !after.rewrite_supported {
        return Err(Error::Unsupported(
            "Verification of safe rewriting is unavailable for this format".into(),
        ));
    }
    if before.format != after.format || !before.blockers.is_empty() || !after.blockers.is_empty() {
        return Err(Error::Blocked(
            "Format or protected-credential checks prevent transformation verification".into(),
        ));
    }
    if before.content_digest != after.content_digest {
        return Err(Error::Verification(
            "Retained content, color data or container structures changed".into(),
        ));
    }
    if original.attributes != output.attributes {
        return Err(Error::Verification(
            "Platform metadata or security markers differ".into(),
        ));
    }
    if before.format == Format::Pdf {
        let verified = pdf::verify(&original.bytes, &output.bytes, limits)?;
        let mut report = Report::new("verify", Format::Pdf);
        report.findings = verified.findings;
        report.findings.extend(os::findings(&original.attributes));
        report.findings.extend(unassessed(Format::Pdf));
        report.warnings = verified.warnings;
        report.integrity = verified.integrity;
        report.integrity.security_markers_preserved = Some(true);
        report.input_sha256 = Some(digest(&original.bytes));
        report.output_sha256 = Some(digest(&output.bytes));
        report.pdf = Some(verified.details);
        report.result = verified.result;
        return Ok(report);
    }
    let mut integrity = Integrity {
        parseable: true,
        content_equal: Some(true),
        security_markers_preserved: Some(true),
        ..Integrity::default()
    };
    if before.format.is_image() {
        let first = decode_pixels(&original.bytes, limits)?;
        let second = decode_pixels(&output.bytes, limits)?;
        // Native decoded sample bytes preserve bit depth, alpha and exact pixel values.
        if first.dimensions() != second.dimensions()
            || first.color() != second.color()
            || first.as_bytes() != second.as_bytes()
        {
            return Err(Error::Verification(
                "Independent decoded pixel comparison failed".into(),
            ));
        }
        integrity.decodeable = Some(true);
        integrity.pixel_equal = Some(true);
    }
    let mut report = report_for("verify", &after, original);
    report
        .warnings
        .extend(extension_warning(original_hint, before.format));
    report.findings.clear();
    for finding in before
        .findings
        .iter()
        .chain(os::findings(&original.attributes).iter())
    {
        let mut finding = finding.clone();
        if matches!(finding.action, Action::Remove | Action::Normalize) {
            let remains = after.findings.iter().any(|f| {
                f.code == finding.code && matches!(f.action, Action::Remove | Action::Normalize)
            });
            finding.state = if remains {
                FindingState::Remains
            } else {
                FindingState::RemovedVerified
            };
            if finding.state == FindingState::RemovedVerified {
                finding.confidence = Confidence::Verified;
            }
        } else if finding.state != FindingState::NotAssessed {
            finding.state = FindingState::Remains;
        }
        report.findings.push(finding);
    }
    for finding in &after.findings {
        if !before
            .findings
            .iter()
            .any(|old| old.code == finding.code && old.location == finding.location)
        {
            let mut new_finding = finding.clone();
            new_finding.state = FindingState::Remains;
            report.findings.push(new_finding);
        }
    }
    report.findings.extend(unassessed(after.format));
    report.integrity = integrity;
    report.output_sha256 = Some(digest(&output.bytes));
    let removable_remains = after
        .findings
        .iter()
        .any(|f| matches!(f.action, Action::Remove | Action::Normalize));
    report.result = if removable_remains {
        Outcome::Failed
    } else if has_residual(&after, &output.attributes) {
        Outcome::PartiallyVerified
    } else {
        Outcome::VerifiedWithinScope
    };
    if removable_remains {
        report
            .warnings
            .push("One or more supported privacy fields remain in the output".into());
    }
    Ok(report)
}
pub fn verify(original: &Path, output: &Path, limits: &Limits) -> Result<Report> {
    let first = Snapshot::open(original, limits)?;
    let second = Snapshot::open(output, limits)?;
    let mut report = compare(&first, &second, original, output, limits)?;
    let unchanged = first.unchanged(original, limits)? && second.unchanged(output, limits)?;
    report.integrity.original_unchanged = Some(unchanged);
    if !unchanged {
        return Err(Error::Blocked(
            "A verification input changed during the operation".into(),
        ));
    }
    Ok(report)
}

pub fn output_directory(input: &Path, output: Option<&Path>) -> PathBuf {
    output
        .unwrap_or(input)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .to_path_buf()
}
fn default_output(input: &Path, counter: usize) -> PathBuf {
    let mut name = input
        .file_stem()
        .unwrap_or(input.as_os_str())
        .to_os_string();
    name.push(if counter == 0 {
        OsString::from(".clean")
    } else {
        OsString::from(format!(".clean.{counter}"))
    });
    if let Some(extension) = input.extension() {
        name.push(".");
        name.push(extension);
    }
    output_directory(input, None).join(name)
}
fn ensure_new_path(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(Error::Input(
            "Output already exists; choose a new path".into(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Error::Input("Output path could not be inspected".into())),
    }
}
pub fn sanitize(input: &Path, output: Option<&Path>, limits: &Limits) -> Result<Report> {
    sanitize_in(input, output, limits, None)
}
pub fn sanitize_in(
    input: &Path,
    output: Option<&Path>,
    limits: &Limits,
    staging_directory: Option<&Path>,
) -> Result<Report> {
    let snapshot = Snapshot::open(input, limits)?;
    let before = inspect_snapshot(&snapshot.bytes, input, limits)?;
    if snapshot
        .attributes
        .iter()
        .any(|a| a.name == "com.apple.ResourceFork")
    {
        return Err(Error::Blocked(
            "Resource-fork files require a semantic-preservation backend".into(),
        ));
    }
    if !before.rewrite_supported {
        return Err(Error::Unsupported(
            "Safe rewriting is unavailable for this format".into(),
        ));
    }
    if !before.blockers.is_empty() {
        return Err(Error::Blocked(before.blockers.join(". ")));
    }
    if let Some(path) = output {
        ensure_new_path(path)?;
    }
    let transformed = if before.format == Format::Pdf {
        pdf::sanitize(&snapshot.bytes, limits)?
    } else {
        fileveil_formats::sanitize(&snapshot.bytes, before.format, limits)?
    };
    if transformed.len() as u64 > limits.max_file_bytes {
        return Err(Error::Blocked(
            "Output exceeds the configured file byte limit".into(),
        ));
    }
    let directory = output_directory(input, output);
    let mut temporary = tempfile::Builder::new()
        .prefix(".fileveil-")
        .tempfile_in(staging_directory.unwrap_or(&directory))
        .map_err(|_| {
            Error::Io("Could not create private staging file in the output filesystem".into())
        })?;
    temporary
        .write_all(&transformed)
        .map_err(|_| Error::Io("Could not write staging file".into()))?;
    os::write(temporary.as_file(), temporary.path(), &snapshot.attributes)?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| Error::Io("Could not synchronize staging file".into()))?;
    let staged = Snapshot::open(temporary.path(), limits)?;
    let mut report = compare(&snapshot, &staged, input, input, limits)?;
    if report.result == Outcome::Failed {
        return Err(Error::Verification(
            "Supported privacy fields remain; output was discarded".into(),
        ));
    }
    if !snapshot.unchanged(input, limits)? {
        return Err(Error::Blocked(
            "Original changed during sanitization; output was discarded".into(),
        ));
    }
    // Keep the original descriptor alive until the private output has passed all checks.
    let _original_descriptor = &snapshot.file;
    let target = publish(temporary.into_temp_path(), input, output)?;
    report.operation = "sanitize".into();
    report.output_name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned());
    report.integrity.original_unchanged = Some(true);
    Ok(report)
}

fn publish(
    mut temporary: tempfile::TempPath,
    input: &Path,
    output: Option<&Path>,
) -> Result<PathBuf> {
    let mut counter = 0usize;
    loop {
        let target = output
            .map(Path::to_path_buf)
            .unwrap_or_else(|| default_output(input, counter));
        match temporary.persist_noclobber(&target) {
            Ok(()) => return Ok(target),
            Err(error)
                if output.is_none()
                    && error.error.kind() == std::io::ErrorKind::AlreadyExists
                    && counter < 10_000 =>
            {
                temporary = error.path;
                counter += 1;
            }
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(Error::Input(
                    "Output already exists; choose a new path".into(),
                ));
            }
            Err(_) => return Err(Error::Io("Could not atomically publish output".into())),
        }
    }
}

/// Publish a worker's private verified artifact after checking the report-bound snapshots.
/// The CLI supervisor owns the containing directory and calls this only after worker completion.
pub fn publish_staged(
    input: &Path,
    staged: &Path,
    output: Option<&Path>,
    report: &mut Report,
    limits: &Limits,
) -> Result<()> {
    if report.operation != "sanitize"
        || report.policy != Policy::Safe
        || report.image_processing.is_some()
        || !matches!(
            report.result,
            Outcome::VerifiedWithinScope | Outcome::PartiallyVerified
        )
        || !(report.integrity.content_equal == Some(true)
            || (report.input_format == Format::Pdf.mime()
                && report.pdf.as_ref().is_some_and(|details| {
                    details["retained_object_graph_equal"] == true
                        && details["has_previous_xref"] == false
                })))
        || report.integrity.original_unchanged != Some(true)
        || report.integrity.security_markers_preserved != Some(true)
    {
        return Err(Error::Verification(
            "Worker report does not authorize artifact publication".into(),
        ));
    }
    let original = Snapshot::open(input, limits)?;
    let artifact = Snapshot::open(staged, limits)?;
    if report.input_sha256.as_deref() != Some(digest(&original.bytes).as_str())
        || report.output_sha256.as_deref() != Some(digest(&artifact.bytes).as_str())
        || original.attributes != artifact.attributes
    {
        return Err(Error::Blocked(
            "Input or private artifact changed before publication".into(),
        ));
    }
    let path = tempfile::TempPath::try_from_path(staged)
        .map_err(|_| Error::Io("Could not acquire staged artifact".into()))?;
    drop(artifact);
    let target = publish(path, input, output)?;
    report.output_name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned());
    Ok(())
}

/// Shared capability table for CLI, desktop clients and MCP tools.
pub fn capabilities(limits: &Limits) -> serde_json::Value {
    serde_json::json!({
        "schema_version": fileveil_core::SCHEMA_VERSION, "tool": "FileVeil", "version": env!("CARGO_PKG_VERSION"),
        "offline": true, "telemetry": false, "profiles": {"safe": "available", "deep": "selective", "research": "experimental_signal_processing"},
        "pdf": pdf::capabilities(), "provenance": provenance::capabilities(), "watermark_detectors": watermark::detectors(),
        "difference_lab":{"available":true,"min_samples":2,"max_samples":8,"methods":["pixel_difference","rgb_lsb","entropy","dct","dft"],"oem_attribution":"not_assessed"},
        "image_processing": {"low_bits": "available", "signal": "experimental", "input": ["jpeg", "png"], "output": "png", "unknown_keyed_watermark_verification": "not_assessed", "changes_pixels": true},
        "formats": [
            {"format": "jpeg", "scan": "available", "safe": "available", "verify": "parse_and_independent_pixel_comparison", "limitations": ["nontrivial_orientation_blocks_rewrite", "unknown_segments_preserved", "provenance_blocks_rewrite"]},
            {"format": "png", "scan": "available", "safe": "available", "verify": "crc_and_independent_pixel_comparison", "limitations": ["apng_rewrite_unavailable", "unknown_chunks_preserved", "provenance_blocks_rewrite"]},
            {"format": "docx_xlsx_pptx", "scan": "available", "safe": "available", "deep":"selective", "verify": "opc_relations_crc_retained_parts_independent_xml", "limitations": ["utf8_xml_only", "signed_macro_encrypted_blocked", "complex_content_dependencies_blocked", "office_application_compatibility_not_assessed"]},
            {"format": "utf8_text_markdown_html", "scan": "available", "safe": "explicit_options", "verify": "selected_transform_and_retained_spans", "limitations":["zwj_zwnj_and_bidi_preserved","complex_html_blocked"]},
            {"format": "pdf", "scan": "requires_qpdf", "safe": "requires_qpdf", "verify": "qpdf_graph_and_optional_independent_poppler"},
            {"format":"heic_heif_avif_mp4_mov","scan":"structural_audit","safe":"unavailable","verify":"not_assessed","limitations":["codec_payload_not_decoded","unknown_vendor_fields_unattributed"]}
        ],
        "platform_attributes": if cfg!(windows) { "selective_private_stream_removal_motw_preserved" } else if cfg!(unix) { "selective_privacy_attributes_quarantine_preserved_resource_forks_block_rewrite" } else { "unavailable" },
        "c2pa_signature_verification": "offline_available", "content_watermark_detection": "synthetic_lsb_v1_only", "statistical_watermark_detection": "not_assessed",
        "limits": limits, "timeout_enforcement": "isolated_worker_process", "overwrite": false
    })
}
