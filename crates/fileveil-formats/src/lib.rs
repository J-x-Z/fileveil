// SPDX-License-Identifier: MPL-2.0
//! Offline format adapters. Identification uses signatures and validated container structure.
pub mod audio;
pub mod bmff;
pub mod jpeg;
pub mod ooxml;
pub mod png;
pub mod text;
use fileveil_core::{
    Error, Finding, Format, FormatAdapter, Inspection, Integrity, Limits, Outcome, Policy, Result,
    SanitizeOptions,
};
use std::path::Path;

pub fn identify(data: &[u8], hint: &Path) -> Format {
    if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WAVE" {
        return Format::Wav;
    }
    if data.starts_with(b"fLaC") {
        return Format::Flac;
    }
    if audio::mp3_signature(data) {
        return Format::Mp3;
    }
    if data.starts_with(&[0xff, 0xd8]) {
        return Format::Jpeg;
    }
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Format::Png;
    }
    if data.starts_with(b"%PDF-") {
        return Format::Pdf;
    }
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        // OPC identification requires reading the package, never an extension guess.
        return Format::Unknown;
    }
    if let Some(format) = bmff::identify(data, hint) {
        return format;
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let extension = hint
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let head = text
            .chars()
            .take(1024)
            .collect::<String>()
            .to_ascii_lowercase();
        if head.contains("<html")
            || head.contains("<!doctype html")
            || matches!(extension.as_str(), "html" | "htm")
        {
            return Format::Html;
        }
        if matches!(extension.as_str(), "txt" | "md" | "markdown") && !data.contains(&0) {
            return Format::Text;
        }
    }
    Format::Unknown
}

pub fn inspect(data: &[u8], hint: &Path, limits: &Limits) -> Result<Inspection> {
    if data.len() as u64 > limits.max_file_bytes {
        return Err(Error::Blocked(
            "Input exceeds the configured byte limit".into(),
        ));
    }
    let mut result = match identify(data, hint) {
        format if format.is_audio() => audio::inspect(data, format, limits),
        Format::Jpeg => jpeg::JpegAdapter.inspect(data, limits),
        Format::Png => png::PngAdapter.inspect(data, limits),
        Format::Text => text::inspect(data, Format::Text, limits),
        Format::Html => text::inspect(data, Format::Html, limits),
        format if format.is_media_container() => bmff::inspect(data, format, limits),
        _ if data.starts_with(b"PK") => ooxml::OoxmlAdapter.inspect(data, limits),
        format => {
            let mut result = Inspection::new(format, fileveil_core::digest(data));
            result.rewrite_supported = false;
            result.limited_support = true;
            Ok(result)
        }
    }?;
    if result.findings.len() > limits.max_members {
        return Err(Error::Blocked(
            "Finding count exceeds the configured report limit".into(),
        ));
    }
    result.blockers.sort();
    result.blockers.dedup();
    Ok(result)
}
pub fn sanitize(data: &[u8], format: Format, limits: &Limits) -> Result<Vec<u8>> {
    match format {
        format if format.is_audio() => audio::sanitize(data, format, limits),
        Format::Jpeg => jpeg::JpegAdapter.sanitize(data, limits),
        Format::Png => png::PngAdapter.sanitize(data, limits),
        Format::Docx | Format::Xlsx | Format::Pptx => ooxml::OoxmlAdapter.sanitize(data, limits),
        _ => Err(Error::Unsupported(
            "Safe rewriting is unavailable for this format".into(),
        )),
    }
}

pub struct ScopedVerification {
    pub findings: Vec<Finding>,
    pub warnings: Vec<String>,
    pub integrity: Integrity,
    pub result: Outcome,
}

pub fn inspect_with_options(
    data: &[u8],
    hint: &Path,
    limits: &Limits,
    options: &SanitizeOptions,
) -> Result<Inspection> {
    if options.remove_provenance {
        if options.policy != Policy::Deep {
            return Err(Error::Blocked(
                "Provenance removal requires an explicit Deep selection".into(),
            ));
        }
        match identify(data, hint) {
            Format::Jpeg => return jpeg::JpegAdapter.inspect_with_options(data, limits, options),
            Format::Png => return png::PngAdapter.inspect_with_options(data, limits, options),
            _ => {}
        }
    }
    if options.text.remove_control_characters
        && matches!(
            hint.extension()
                .and_then(|s| s.to_str())
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("txt" | "md" | "markdown")
        )
        && std::str::from_utf8(data).is_ok()
    {
        return text::inspect_with_options(data, Format::Text, limits, &options.text);
    }
    let inspection = inspect(data, hint, limits)?;
    if inspection.format.is_office() && options.policy == Policy::Deep {
        return ooxml::inspect_with_options(data, limits, options);
    }
    if matches!(inspection.format, Format::Text | Format::Html) {
        return text::inspect_with_options(data, inspection.format, limits, &options.text);
    }
    Ok(inspection)
}

pub fn sanitize_with_options(
    data: &[u8],
    format: Format,
    limits: &Limits,
    options: &SanitizeOptions,
) -> Result<Vec<u8>> {
    if options.remove_provenance {
        if options.policy != Policy::Deep {
            return Err(Error::Blocked(
                "Provenance removal requires an explicit Deep selection".into(),
            ));
        }
        match format {
            Format::Jpeg => return jpeg::JpegAdapter.sanitize_with_options(data, limits, options),
            Format::Png => return png::PngAdapter.sanitize_with_options(data, limits, options),
            _ => {}
        }
    }
    if options.deep.any() && options.policy != Policy::Deep {
        return Err(Error::Blocked(
            "Office content-changing choices require the Deep policy".into(),
        ));
    }
    if format.is_office() && options.policy == Policy::Deep {
        return ooxml::sanitize_with_options(data, limits, options);
    }
    if matches!(format, Format::Text | Format::Html) {
        return text::sanitize_with_options(data, format, limits, &options.text);
    }
    sanitize(data, format, limits)
}

pub fn verify_scoped(
    before: &[u8],
    after: &[u8],
    format: Format,
    limits: &Limits,
    options: &SanitizeOptions,
) -> Result<ScopedVerification> {
    if format.is_office() {
        return ooxml::verify_scoped(before, after, limits, options);
    }
    if matches!(format, Format::Text | Format::Html) {
        return text::verify_scoped(before, after, format, limits, &options.text);
    }
    Err(Error::Unsupported(
        "Scoped verification is available for Office and UTF-8 text formats".into(),
    ))
}
