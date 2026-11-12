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
    let credentials =
        crate::provenance::inspect_with_trust(&snapshot.bytes, inspection.format, limits, pem)?;
    let mut report = report_for("provenance", &inspection, &snapshot);
    report.provenance = credentials
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| Error::Io("Could not serialize provenance evidence".into()))?;
    report.advanced = Some(
        serde_json::json!({"capabilities":crate::provenance::capabilities(),
        "credential_found":report.provenance.is_some(),"personal_identity_link":"not_assessed",
        "unknown_ai_watermarks":"not_assessed"}),
    );
    report.result = Outcome::PartiallyVerified;
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
    let detection = crate::watermark::detect(&snapshot.bytes, inspection.format, limits)?;
    let mut report = report_for("detect_watermark", &inspection, &snapshot);
    report.advanced =
        Some(serde_json::json!({"detection":detection,"detectors":crate::watermark::detectors()}));
    report.result = Outcome::PartiallyVerified;
    report.warnings.push("Detection covers the named synthetic packet protocol. A negative result leaves other schemes unassessed.".into());
    if !snapshot.unchanged(input, limits)? {
        return Err(Error::Blocked("Watermark input changed".into()));
    }
    report.integrity.original_unchanged = Some(true);
    Ok(report)
}

pub fn lab(inputs: &[PathBuf], limits: &Limits) -> Result<Report> {
    if !(2..=8).contains(&inputs.len()) {
        return Err(Error::Input(
            "The difference lab requires 2 to 8 explicit samples".into(),
        ));
    }
    let mut total = 0u64;
    let mut snapshots = Vec::with_capacity(inputs.len());
    for input in inputs {
        let snapshot = Snapshot::open(input, limits)?;
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
    let analysis = crate::lab::analyze(&samples, limits)?;
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
