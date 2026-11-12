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
    if options.remove_provenance && options.policy != Policy::Deep {
        return Err(Error::Input(
            "Removing provenance credentials requires the Deep policy".into(),
        ));
    }
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
    if options.remove_provenance
        && !format.is_image()
        && !matches!(format, Format::Pdf | Format::Text)
    {
        return Err(Error::Unsupported(
            "Credential removal supports JPEG, PNG, PDF and standard UTF-8 text wrappers".into(),
        ));
    }
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

fn inspect_selected(
    data: &[u8],
    hint: &Path,
    limits: &Limits,
    options: &SanitizeOptions,
) -> Result<Inspection> {
    if options.remove_provenance {
        let format = fileveil_formats::identify(data, hint);
        validate_format_options(format, options)?;
        if format == Format::Pdf {
            let parsed = pdf::inspect_for_provenance_removal(data, limits)?;
            let mut inspection = Inspection::new(Format::Pdf, parsed.content_digest);
            inspection.findings = parsed.findings;
            inspection.blockers = parsed.blockers;
            inspection.limited_support = true;
            return Ok(inspection);
        }
        return fileveil_formats::inspect_with_options(data, hint, limits, options);
    }
    if options.text.any() {
        let mut inspection = fileveil_formats::inspect_with_options(data, hint, limits, options)?;
        protect_text_credentials(&mut inspection, data, hint, limits)?;
        return Ok(inspection);
    }
    inspect_snapshot(data, hint, limits)
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
    let before = inspect_selected(&original.bytes, hint, limits, options)?;
    let after = inspect_snapshot(&output.bytes, hint, limits)?;
    validate_format_options(before.format, options)?;
    if !before.blockers.is_empty() || !after.blockers.is_empty() {
        return Err(Error::Blocked(
            "Protected input or output structures prevent scoped verification".into(),
        ));
    }
    let mut report = Report::new("verify", before.format);
    if before.format != after.format {
        return Err(Error::Verification("Output format changed".into()));
    }
    if before.format == Format::Pdf {
        let verified = if options.remove_provenance {
            pdf::verify_with_provenance_removal(
                &original.bytes,
                &output.bytes,
                limits,
                &options.pdf,
            )?
        } else {
            pdf::verify_scoped(&original.bytes, &output.bytes, limits, &options.pdf)?
        };
        report.findings = verified.findings;
        report.warnings = verified.warnings;
        report.integrity = verified.integrity;
        report.result = verified.result;
        report.pdf = Some(verified.details);
    } else if before.format.is_image() || before.format.is_audio() {
        if before.content_digest != after.content_digest {
            return Err(Error::Verification(
                "Retained encoded image or color structures changed".into(),
            ));
        }
        let retained_bytes = if options.remove_provenance {
            crate::provenance::remove(&original.bytes, before.format, limits)?
        } else {
            original.bytes.clone()
        };
        let selected_original = Snapshot {
            file: original
                .file
                .try_clone()
                .map_err(|_| Error::Io("Could not retain original image descriptor".into()))?,
            bytes: retained_bytes,
            attributes: expected_attributes.clone(),
        };
        report = compare(&selected_original, output, hint, hint, limits)?;
        report.findings.retain(|finding| {
            finding.layer != RiskLayer::Filesystem
                && finding.code != "watermark.statistical"
                && finding.code != "image.content_watermark"
                && finding.code != "audio.signal_watermark"
        });
        if options.remove_provenance {
            let original_pixels = decode_pixels(&original.bytes, limits)?;
            let output_pixels = decode_pixels(&output.bytes, limits)?;
            if original_pixels.color() != output_pixels.color()
                || original_pixels.dimensions() != output_pixels.dimensions()
                || original_pixels.as_bytes() != output_pixels.as_bytes()
            {
                return Err(Error::Verification(
                    "Credential removal changed decoded image samples".into(),
                ));
            }
            for mut finding in before
                .findings
                .iter()
                .filter(|finding| finding.layer == RiskLayer::ProvenanceCredential)
                .cloned()
            {
                finding.action = Action::Remove;
                finding.state = FindingState::RemovedVerified;
                finding.confidence = Confidence::Verified;
                report.findings.push(finding);
            }
        }
    } else if before.format == Format::Text && options.remove_provenance {
        let mime = text_credential_mime(hint);
        let expected = crate::provenance::strip_text_wrappers(&original.bytes, mime, limits)?;
        if expected != output.bytes {
            return Err(Error::Verification(
                "Text credential removal changed bytes outside recognized wrapper ranges".into(),
            ));
        }
        let scope = crate::provenance::text_scope(&original.bytes, mime, limits)?;
        let after_scope = crate::provenance::text_scope(&output.bytes, mime, limits)?;
        if after_scope.wrapper_count != 0 {
            return Err(Error::Verification(
                "Text credential wrapper remains after removal".into(),
            ));
        }
        let mut found = Finding::new(
            "text.provenance",
            RiskLayer::ProvenanceCredential,
            "text/standard_credential_wrapper",
            "Recognized credential wrapper ranges were removed and all remaining UTF-8 bytes were retained",
            Action::Remove,
        );
        found.state = FindingState::RemovedVerified;
        found.confidence = Confidence::Verified;
        report.findings = after.findings.clone();
        if scope.wrapper_count > 0 {
            report.findings.push(found);
        }
        report.integrity = Integrity {
            parseable: true,
            content_equal: Some(true),
            ..Integrity::default()
        };
        report.result = Outcome::PartiallyVerified;
        report.warnings.push("Text verification compares every byte outside the selected standard wrapper. Unicode normalization is preserved. Statistical text watermarks remain unassessed.".into());
        report.provenance = crate::provenance::inspect_mime(&original.bytes, mime, limits, None)?
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| Error::Io("Could not serialize text provenance evidence".into()))?;
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
    if options.remove_provenance {
        let mime = if before.format == Format::Text {
            text_credential_mime(hint)
        } else {
            before.format.mime()
        };
        let before_credentials =
            crate::provenance::inspect_mime(&original.bytes, mime, limits, None)?;
        report.provenance = before_credentials
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| Error::Io("Could not serialize original provenance evidence".into()))?;
        if crate::provenance::inspect_mime(&output.bytes, mime, limits, None)?.is_some() {
            return Err(Error::Verification(
                "A credential store or source reference remains after removal".into(),
            ));
        }
        if let Some(details) = report.advanced.as_mut() {
            details["provenance_removal"] = serde_json::json!({
                "before": before_credentials,
                "after": null,
                "postcondition": "no_sdk_credential_or_reference_found",
                "signature_effect": "removable_credentials_and_their_signatures_discarded"
            });
        }
        report.result = Outcome::PartiallyVerified;
        report.warnings.push("User-selected credential removal discards removable Content Credentials and their signatures. Other source associations and unknown content watermarks remain unassessed.".into());
        neutralize_provenance_findings(&mut report);
    }
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
    let inspection = inspect_selected(&snapshot.bytes, input, limits, options)?;
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
    let transformed = if options.remove_provenance {
        match inspection.format {
            Format::Pdf => {
                let stripped =
                    crate::provenance::remove_store(&snapshot.bytes, "application/pdf", limits)?;
                pdf::sanitize_with_provenance_removal(&stripped, limits, &options.pdf)?
            }
            Format::Text => {
                let mime = text_credential_mime(input);
                let stripped = crate::provenance::remove_store(&snapshot.bytes, mime, limits)?;
                let expected =
                    crate::provenance::strip_text_wrappers(&snapshot.bytes, mime, limits)?;
                if stripped != expected {
                    return Err(Error::Verification(
                        "The text backend changed bytes outside credential wrappers".into(),
                    ));
                }
                if fileveil_formats::text::sanitize_with_options(
                    &stripped,
                    Format::Text,
                    limits,
                    &options.text,
                )? != stripped
                {
                    return Err(Error::Blocked("Exact-body credential removal cannot be combined with selected text edits that change the remaining body".into()));
                }
                stripped
            }
            _ => crate::provenance::remove(&snapshot.bytes, inspection.format, limits)?,
        }
    } else if inspection.format == Format::Pdf {
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
    ensure_new_artifact(&original.file, &artifact.file)?;
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
