// SPDX-License-Identifier: MPL-2.0
//! Explicit transformations and their report-bound publication contract.
use super::*;
use fileveil_core::{FilesystemOptions, SanitizeOptions};
use std::time::{Duration, SystemTime};

fn retained_attributes(
    attributes: &[os::Attribute],
    options: &FilesystemOptions,
) -> Vec<os::Attribute> {
    attributes
        .iter()
        .filter(|attribute| {
            let name = attribute.name.to_string_lossy();
            match name.as_ref() {
                name if name.eq_ignore_ascii_case(":Zone.Identifier:$DATA") => true,
                "com.apple.metadata:kMDItemWhereFroms" => !options.remove_download_origin,
                "com.apple.metadata:_kMDItemUserTags" => !options.remove_finder_tags,
                "com.apple.quarantine" | "com.apple.ResourceFork" | ":Zone.Identifier:$DATA" => {
                    true
                }
                _ if name.starts_with("user.") => !options.remove_user_attributes,
                _ if cfg!(windows) && name.starts_with(':') && name.ends_with(":$DATA") => {
                    !options.remove_ntfs_private_streams
                }
                _ => true,
            }
        })
        .cloned()
        .collect()
}

fn validate_options(options: &SanitizeOptions) -> Result<()> {
    if options.pdf.any() && options.policy != Policy::Deep {
        return Err(Error::Input(
            "PDF content changes require the Deep policy".into(),
        ));
    }
    if options.policy == Policy::Safe && options.deep.any() {
        return Err(Error::Input(
            "Office content changes require the Deep policy".into(),
        ));
    }
    if options.policy == Policy::Research {
        return Err(Error::Input("Research processing requires explicit image processing parameters through process-image".into()));
    }
    Ok(())
}

fn validate_format_options(format: Format, options: &SanitizeOptions) -> Result<()> {
    if options.pdf.any() && format != Format::Pdf {
        return Err(Error::Unsupported(
            "Selected PDF content choices require a PDF file".into(),
        ));
    }
    if options.deep.any() && !format.is_office() {
        return Err(Error::Unsupported(
            "Selected Office content choices require DOCX, XLSX or PPTX".into(),
        ));
    }
    if options.text.any() && !matches!(format, Format::Text | Format::Html) {
        return Err(Error::Unsupported(
            "Selected text choices require a supported UTF-8 text or HTML file".into(),
        ));
    }
    Ok(())
}

fn compare_advanced(
    original: &Snapshot,
    output: &Snapshot,
    hint: &Path,
    options: &SanitizeOptions,
    limits: &Limits,
) -> Result<Report> {
    validate_options(options)?;
    let expected_attributes = retained_attributes(&original.attributes, &options.filesystem);
    if output.attributes != expected_attributes {
        return Err(Error::Verification(
            "Selected platform attribute policy was not preserved".into(),
        ));
    }
    if original
        .attributes
        .iter()
        .any(|a| a.name == "com.apple.ResourceFork")
    {
        return Err(Error::Blocked(
            "Resource-fork transformation requires a semantic-preservation backend".into(),
        ));
    }
    let before = inspect_snapshot(&original.bytes, hint, limits)?;
    let after = inspect_snapshot(&output.bytes, hint, limits)?;
    validate_format_options(before.format, options)?;
    let mut report = Report::new("verify", before.format);
    if before.format != after.format {
        return Err(Error::Verification("Output format changed".into()));
    }
    if before.format == Format::Pdf {
        let verified = pdf::verify_scoped(&original.bytes, &output.bytes, limits, &options.pdf)?;
        report.findings = verified.findings;
        report.warnings = verified.warnings;
        report.integrity = verified.integrity;
        report.result = verified.result;
        report.pdf = Some(verified.details);
    } else if before.format.is_image() {
        let selected_original = Snapshot {
            file: original
                .file
                .try_clone()
                .map_err(|_| Error::Io("Could not retain original image descriptor".into()))?,
            bytes: original.bytes.clone(),
            attributes: expected_attributes.clone(),
        };
        report = compare(&selected_original, output, hint, hint, limits)?;
        report.findings.retain(|finding| {
            finding.layer != RiskLayer::Filesystem
                && finding.code != "watermark.statistical"
                && finding.code != "image.content_watermark"
        });
    } else {
        let verified = fileveil_formats::verify_scoped(
            &original.bytes,
            &output.bytes,
            before.format,
            limits,
            options,
        )?;
        report.findings = verified.findings;
        report.warnings = verified.warnings;
        report.integrity = verified.integrity;
        report.result = verified.result;
    }
    for (attribute, mut finding) in original
        .attributes
        .iter()
        .zip(os::findings(&original.attributes))
    {
        finding.state = if expected_attributes.contains(attribute) {
            FindingState::Remains
        } else {
            FindingState::RemovedVerified
        };
        if finding.state == FindingState::RemovedVerified {
            finding.action = Action::Remove;
            finding.confidence = Confidence::Verified;
        }
        report.findings.push(finding);
    }
    report.findings.extend(unassessed(before.format));
    report.integrity.security_markers_preserved = Some(true);
    report.input_sha256 = Some(digest(&original.bytes));
    report.output_sha256 = Some(digest(&output.bytes));
    report.policy = options.policy;
    report.advanced = Some(
        serde_json::json!({"options":options,"selected_scope_verified":true,
        "timestamp_scope":if options.filesystem.normalize_output_timestamps {"output_modification_only_verified"} else {"not_assessed"}}),
    );
    if options.filesystem.normalize_output_timestamps {
        let metadata = output
            .file
            .metadata()
            .map_err(|_| Error::Io("Could not verify output timestamps".into()))?;
        if metadata.modified().ok() != Some(normalized_time()) {
            return Err(Error::Verification(
                "Output modification timestamp normalization failed".into(),
            ));
        }
        report.warnings.push("The output modification time is verified as 2000-01-01 UTC. Access time is set initially and can change during reading. Access and creation times, filesystem journals, snapshots and backups remain outside the verification scope.".into());
    }
    if report
        .findings
        .iter()
        .any(|f| f.state == FindingState::Remains && f.action == Action::AskUser)
    {
        report.result = Outcome::PartiallyVerified;
    }
    Ok(report)
}

fn normalized_time() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(946_684_800)
}

pub fn sanitize_with_options(
    input: &Path,
    output: Option<&Path>,
    limits: &Limits,
    options: &SanitizeOptions,
) -> Result<Report> {
    sanitize_with_options_in(input, output, limits, options, None)
}

pub fn sanitize_with_options_in(
    input: &Path,
    output: Option<&Path>,
    limits: &Limits,
    options: &SanitizeOptions,
    staging_directory: Option<&Path>,
) -> Result<Report> {
    validate_options(options)?;
    let snapshot = Snapshot::open(input, limits)?;
    let inspection = inspect_snapshot(&snapshot.bytes, input, limits)?;
    validate_format_options(inspection.format, options)?;
    if !inspection.blockers.is_empty() {
        return Err(Error::Blocked(inspection.blockers.join(". ")));
    }
    if snapshot
        .attributes
        .iter()
        .any(|a| a.name == "com.apple.ResourceFork")
    {
        return Err(Error::Blocked(
            "Resource-fork transformation requires a semantic-preservation backend".into(),
        ));
    }
    if let Some(path) = output {
        ensure_new_path(path)?;
    }
    let transformed = if inspection.format == Format::Pdf {
        pdf::sanitize_with_options(&snapshot.bytes, limits, &options.pdf)?
    } else {
        fileveil_formats::sanitize_with_options(
            &snapshot.bytes,
            inspection.format,
            limits,
            options,
        )?
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
        .map_err(|_| Error::Io("Could not create private staging file".into()))?;
    temporary
        .write_all(&transformed)
        .map_err(|_| Error::Io("Could not write private output".into()))?;
    os::write(
        temporary.as_file(),
        temporary.path(),
        &retained_attributes(&snapshot.attributes, &options.filesystem),
    )?;
    if options.filesystem.normalize_output_timestamps {
        temporary
            .as_file()
            .set_times(
                fs::FileTimes::new()
                    .set_accessed(normalized_time())
                    .set_modified(normalized_time()),
            )
            .map_err(|_| {
                Error::Unsupported(
                    "Output timestamp normalization is unavailable on this filesystem".into(),
                )
            })?;
    }
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| Error::Io("Could not synchronize private output".into()))?;
    let staged = Snapshot::open(temporary.path(), limits)?;
    let mut report = compare_advanced(&snapshot, &staged, input, options, limits)?;
    if !matches!(
        report.result,
        Outcome::VerifiedWithinScope | Outcome::PartiallyVerified
    ) {
        return Err(Error::Verification(
            "Selected transformation failed verification".into(),
        ));
    }
    if !snapshot.unchanged(input, limits)? {
        return Err(Error::Blocked(
            "Original changed during sanitization".into(),
        ));
    }
    drop(staged);
    let target = publish(temporary.into_temp_path(), input, output)?;
    report.operation = "sanitize".into();
    report.output_name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned());
    report.integrity.original_unchanged = Some(true);
    Ok(report)
}

pub fn verify_with_options(
    original: &Path,
    output: &Path,
    limits: &Limits,
    options: &SanitizeOptions,
) -> Result<Report> {
    let first = Snapshot::open(original, limits)?;
    let second = Snapshot::open(output, limits)?;
    let mut report = compare_advanced(&first, &second, original, options, limits)?;
    if !first.unchanged(original, limits)? || !second.unchanged(output, limits)? {
        return Err(Error::Blocked("Verification input changed".into()));
    }
    report.integrity.original_unchanged = Some(true);
    Ok(report)
}

pub fn publish_advanced_staged(
    input: &Path,
    staged: &Path,
    output: Option<&Path>,
    report: &mut Report,
    limits: &Limits,
    options: &SanitizeOptions,
) -> Result<()> {
    validate_options(options)?;
    let expected = serde_json::to_value(options)
        .map_err(|_| Error::Verification("Invalid option report".into()))?;
    if report.operation != "sanitize"
        || report.policy != options.policy
        || report.image_processing.is_some()
        || !matches!(
            report.result,
            Outcome::VerifiedWithinScope | Outcome::PartiallyVerified
        )
        || !report.integrity.parseable
        || report.integrity.original_unchanged != Some(true)
        || report.integrity.security_markers_preserved != Some(true)
        || !report.advanced.as_ref().is_some_and(|details| {
            details["selected_scope_verified"] == true && details["options"] == expected
        })
    {
        return Err(Error::Verification(
            "Worker report does not authorize the requested transformation".into(),
        ));
    }
    let original = Snapshot::open(input, limits)?;
    let artifact = Snapshot::open(staged, limits)?;
    let original_path = fs::canonicalize(input)
        .map_err(|_| Error::Blocked("Original path is unavailable before publication".into()))?;
    let staged_path = fs::canonicalize(staged)
        .map_err(|_| Error::Blocked("Staged path is unavailable before publication".into()))?;
    if original_path == staged_path {
        return Err(Error::Blocked(
            "The staged artifact must be a new copy".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if artifact
            .file
            .metadata()
            .map_err(|_| Error::Io("Could not inspect staged artifact links".into()))?
            .nlink()
            != 1
        {
            return Err(Error::Blocked(
                "The staged artifact has multiple filesystem links".into(),
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe {
            GetFileInformationByHandle(artifact.file.as_raw_handle() as _, &mut information)
        } == 0
            || information.nNumberOfLinks != 1
        {
            return Err(Error::Blocked(
                "Could not establish a single-link staged artifact".into(),
            ));
        }
    }
    if report.input_sha256.as_deref() != Some(digest(&original.bytes).as_str())
        || report.output_sha256.as_deref() != Some(digest(&artifact.bytes).as_str())
        || artifact.attributes != retained_attributes(&original.attributes, &options.filesystem)
    {
        return Err(Error::Blocked(
            "Input or private artifact changed before publication".into(),
        ));
    }
    if options.filesystem.normalize_output_timestamps
        && artifact
            .file
            .metadata()
            .ok()
            .and_then(|metadata| metadata.modified().ok())
            != Some(normalized_time())
    {
        return Err(Error::Verification(
            "Staged output modification time changed before publication".into(),
        ));
    }
    drop(artifact);
    let path = tempfile::TempPath::try_from_path(staged)
        .map_err(|_| Error::Io("Could not acquire staged artifact".into()))?;
    let target = publish(path, input, output)?;
    report.output_name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned());
    Ok(())
}
