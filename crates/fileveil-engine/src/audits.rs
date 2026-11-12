// SPDX-License-Identifier: MPL-2.0
//! Read-only advanced audits consume the same descriptor-bound snapshots as scans.
use super::*;

pub fn provenance(input: &Path, trust_roots: Option<&Path>, limits: &Limits) -> Result<Report> {
    let snapshot = Snapshot::open(input, limits)?;
    let inspection = inspect_snapshot(&snapshot.bytes, input, limits)?;
    let roots = trust_roots
        .map(|path| Snapshot::open(path, limits))
        .transpose()?;
    let pem = roots
        .as_ref()
        .map(|snapshot| {
            std::str::from_utf8(&snapshot.bytes)
                .map_err(|_| Error::Input("Local trust roots must be UTF-8 PEM".into()))
        })
        .transpose()?;
    let credentials = if inspection.format == Format::Text {
        crate::provenance::inspect_mime(&snapshot.bytes, text_credential_mime(input), limits, pem)?
    } else {
        crate::provenance::inspect_with_trust(&snapshot.bytes, inspection.format, limits, pem)?
    };
    let mut report = report_for("provenance", &inspection, &snapshot);
    report.provenance = credentials
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| Error::Io("Could not serialize provenance evidence".into()))?;
    neutralize_provenance_findings(&mut report);
    let watermark_detections =
        crate::watermark::detect_all(&snapshot.bytes, inspection.format, limits)?;
    let source_marker_codes: std::collections::BTreeSet<_> = inspection
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.code.as_str(),
                "text.invisible_unicode" | "html.meta" | "html.comment" | "text.control_character"
            )
        })
        .map(|finding| finding.code.as_str())
        .collect();
    report.advanced = Some(
        serde_json::json!({"capabilities":crate::provenance::capabilities(),
        "external_interfaces":crate::provenance::external_interfaces(),
        "watermark_detections":watermark_detections,
        "source_marker_codes":source_marker_codes,
        "public_payload_authentication":"not_assessed",
        "credential_found":report.provenance.as_ref().is_some_and(|value|value["presence"]=="embedded"),
        "provenance_evidence_present":report.provenance.is_some(),"personal_identity_link":"not_assessed",
        "unknown_ai_watermarks":"not_assessed","model_source_validation":"not_assessed"}),
    );
    report.result = if report.provenance.as_ref().is_some_and(|value| {
        ["signature", "asset_binding", "manifest_validation"]
            .iter()
            .any(|field| value[field] == "invalid")
    }) {
        Outcome::Failed
    } else {
        Outcome::PartiallyVerified
    };
    report.warnings.push("The report separates source credentials, hidden markers and personal identity. Proprietary keyed text and image detectors require an actual supported detector and remain unassessed.".into());
    if !snapshot.unchanged(input, limits)?
        || roots
            .as_ref()
            .zip(trust_roots)
            .is_some_and(|(snapshot, path)| !snapshot.unchanged(path, limits).unwrap_or(false))
    {
        return Err(Error::Blocked(
            "A provenance audit input changed during the operation".into(),
        ));
    }
    report.integrity.original_unchanged = Some(true);
    Ok(report)
}

pub fn detect_watermark(input: &Path, limits: &Limits) -> Result<Report> {
    let snapshot = Snapshot::open(input, limits)?;
    let inspection = inspect_snapshot(&snapshot.bytes, input, limits)?;
    let (detections, signal_analysis) =
        crate::watermark::detect_with_signal(&snapshot.bytes, inspection.format, limits)?;
    let unsupported = detections
        .iter()
        .all(|detection| detection.status == crate::watermark::DetectionStatus::NotAssessed);
    let mut report = report_for("detect_watermark", &inspection, &snapshot);
    report.advanced = Some(
        serde_json::json!({"detection":detections.first(),"detections":detections,
            "signal_analysis":signal_analysis,"detectors":crate::watermark::detectors()}),
    );
    report.result = if unsupported {
        Outcome::Unsupported
    } else {
        Outcome::PartiallyVerified
    };
    report.warnings.push("Results cover the named public watermark protocols. Public messages can be copied and do not authenticate a model, person or device. Negative results leave other schemes unassessed.".into());
    if !snapshot.unchanged(input, limits)? {
        return Err(Error::Blocked("Watermark input changed".into()));
    }
    report.integrity.original_unchanged = Some(true);
    Ok(report)
}

pub fn lab(inputs: &[PathBuf], limits: &Limits) -> Result<Report> {
    lab_with_groups(inputs, &[], limits)
}

pub fn lab_with_groups(
    inputs: &[PathBuf],
    groups: &[crate::lab::SampleGroup],
    limits: &Limits,
) -> Result<Report> {
    if !(2..=8).contains(&inputs.len()) {
        return Err(Error::Input(
            "The difference lab requires 2 to 8 explicit samples".into(),
        ));
    }
    crate::lab::validate_groups(groups, inputs.len())?;
    let mut total = 0u64;
    let mut snapshots = Vec::with_capacity(inputs.len());
    for input in inputs {
        let mut remaining_limits = limits.clone();
        remaining_limits.max_file_bytes = limits
            .max_file_bytes
            .min(limits.max_uncompressed_bytes.saturating_sub(total));
        let snapshot = Snapshot::open(input, &remaining_limits)?;
        total = total.saturating_add(snapshot.bytes.len() as u64);
        if total > limits.max_uncompressed_bytes {
            return Err(Error::Blocked(
                "Lab samples exceed the aggregate input byte budget".into(),
            ));
        }
        snapshots.push(snapshot);
    }
    let samples: Vec<_> = snapshots
        .iter()
        .zip(inputs)
        .map(|(snapshot, path)| crate::lab::LabSample {
            data: &snapshot.bytes,
            format: fileveil_formats::identify(&snapshot.bytes, path),
        })
        .collect();
    let analysis = crate::lab::analyze_with_groups(&samples, groups, limits)?;
    for (snapshot, path) in snapshots.iter().zip(inputs) {
        if !snapshot.unchanged(path, limits)? {
            return Err(Error::Blocked(
                "A lab sample changed during analysis".into(),
            ));
        }
    }
    let mut report = Report::new("lab", Format::Unknown);
    report.result = Outcome::PartiallyVerified;
    report.integrity.parseable = true;
    report.integrity.original_unchanged = Some(true);
    report.advanced = Some(serde_json::json!({"lab":analysis}));
    report.warnings.push("Statistical differences describe the supplied controls. Codec effects, sensor noise and image processing can create similar patterns. OEM attribution and watermark identity require separate evidence.".into());
    Ok(report)
}
