// SPDX-License-Identifier: MPL-2.0
//! Bounded JPEG marker parser. Encoded scan bytes are copied without recompression.
use fileveil_core::{
    Action, Error, Finding, Format, FormatAdapter, Inspection, Limits, Result, RiskLayer,
    SanitizeOptions, digest,
};

pub struct JpegAdapter;

struct Parsed<'a> {
    inspection: Inspection,
    retained: Vec<&'a [u8]>,
}

impl FormatAdapter for JpegAdapter {
    fn inspect(&self, data: &[u8], limits: &Limits) -> Result<Inspection> {
        Ok(parse(data, limits, false)?.inspection)
    }

    fn sanitize(&self, data: &[u8], limits: &Limits) -> Result<Vec<u8>> {
        let parsed = parse(data, limits, false)?;
        if !parsed.inspection.blockers.is_empty() {
            return Err(Error::Blocked(parsed.inspection.blockers.join("; ")));
        }
        Ok(parsed.retained.concat())
    }
}
impl JpegAdapter {
    pub(crate) fn inspect_with_options(
        &self,
        data: &[u8],
        limits: &Limits,
        options: &SanitizeOptions,
    ) -> Result<Inspection> {
        Ok(parse(data, limits, options.remove_provenance)?.inspection)
    }
    pub(crate) fn sanitize_with_options(
        &self,
        data: &[u8],
        limits: &Limits,
        options: &SanitizeOptions,
    ) -> Result<Vec<u8>> {
        let parsed = parse(data, limits, options.remove_provenance)?;
        if !parsed.inspection.blockers.is_empty() {
            return Err(Error::Blocked(parsed.inspection.blockers.join(". ")));
        }
        Ok(parsed.retained.concat())
    }
}

fn malformed(message: &str) -> Error {
    Error::Blocked(format!("Malformed JPEG: {message}"))
}

fn parse<'a>(data: &'a [u8], limits: &Limits, remove_provenance: bool) -> Result<Parsed<'a>> {
    if data.len() as u64 > limits.max_file_bytes {
        return Err(Error::Blocked("JPEG exceeds file-size limit".into()));
    }
    if !data.starts_with(&[0xff, 0xd8]) {
        return Err(malformed("missing SOI marker"));
    }
    let mut result = Inspection::new(Format::Jpeg, String::new());
    let mut retained = vec![&data[..2]];
    let mut offset = 2;
    let mut frame_seen = false;
    let mut scan_seen = false;
    let mut end_seen = false;
    let mut segments = 0;
    let mut credential_instances = std::collections::BTreeSet::new();
    while offset < data.len() {
        segments += 1;
        if segments > limits.max_members {
            return Err(Error::Blocked("JPEG segment-count limit exceeded".into()));
        }
        let start = offset;
        if data[offset] != 0xff {
            return Err(malformed("expected marker prefix"));
        }
        while offset < data.len() && data[offset] == 0xff {
            offset += 1;
        }
        let marker = *data
            .get(offset)
            .ok_or_else(|| malformed("truncated marker"))?;
        offset += 1;
        if marker == 0xd9 {
            if !frame_seen || !scan_seen {
                return Err(malformed("EOI precedes image frame or scan"));
            }
            retained.push(&data[start..offset]);
            if offset < data.len() {
                result.findings.push(Finding::new(
                    "jpeg.trailing_data",
                    RiskLayer::ContainerStructure,
                    "after EOI",
                    "Bytes follow the JPEG end marker and are retained",
                    Action::AskUser,
                ));
                retained.push(&data[offset..]);
            }
            end_seen = true;
            break;
        }
        if matches!(marker, 0x00 | 0xd8 | 0xd0..=0xd7) {
            return Err(malformed("unexpected standalone marker"));
        }
        if marker == 0x01 {
            retained.push(&data[start..offset]);
            continue;
        }
        let length_bytes = data
            .get(offset..offset + 2)
            .ok_or_else(|| malformed("truncated segment length"))?;
        let length = usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
        if length < 2 {
            return Err(malformed("segment length is smaller than its header"));
        }
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| malformed("segment extends beyond file"))?;
        let payload = &data[offset + 2..end];
        if remove_provenance
            && marker == 0xeb
            && payload.len() >= 8
            && payload.starts_with(b"JP")
            && payload[4..8] == [0, 0, 0, 1]
            && credential_instances.contains(&[payload[2], payload[3]])
            && !c2pa_first_fragment(payload)
        {
            return Err(Error::Blocked("Ambiguous reused JPEG JUMBF instance identifier prevents selective credential removal".into()));
        }
        if marker == 0xeb && c2pa_first_fragment(payload) {
            credential_instances.insert([payload[2], payload[3]]);
        }
        let recognized_credential = marker == 0xeb
            && payload.len() >= 8
            && payload.starts_with(b"JP")
            && credential_instances.contains(&[payload[2], payload[3]]);
        let remove = classify(
            marker,
            payload,
            start,
            &mut result,
            limits,
            remove_provenance,
            recognized_credential,
        )?;
        if matches!(marker, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf) {
            if frame_seen || payload.len() < 6 {
                return Err(malformed("invalid or repeated frame header"));
            }
            let height = u16::from_be_bytes([payload[1], payload[2]]);
            let width = u16::from_be_bytes([payload[3], payload[4]]);
            let components = usize::from(payload[5]);
            if width == 0 || height == 0 || components == 0 || payload.len() != 6 + 3 * components {
                return Err(malformed("invalid frame dimensions or component table"));
            }
            if u64::from(width) * u64::from(height) > limits.max_pixels {
                return Err(Error::Blocked("JPEG pixel-count limit exceeded".into()));
            }
            frame_seen = true;
        }
        if !remove {
            retained.push(&data[start..end]);
        }
        offset = end;
        if marker == 0xda {
            if !frame_seen
                || payload.is_empty()
                || payload[0] == 0
                || payload.len() != 4 + 2 * usize::from(payload[0])
            {
                return Err(malformed("invalid scan header"));
            }
            scan_seen = true;
            let entropy_start = offset;
            while offset < data.len() {
                if data[offset] != 0xff {
                    offset += 1;
                    continue;
                }
                let mut next = offset + 1;
                while next < data.len() && data[next] == 0xff {
                    next += 1;
                }
                let code = *data
                    .get(next)
                    .ok_or_else(|| malformed("truncated entropy marker"))?;
                if code == 0x00 || matches!(code, 0xd0..=0xd7) {
                    offset = next + 1;
                    continue;
                }
                break;
            }
            retained.push(&data[entropy_start..offset]);
        }
    }
    if !end_seen {
        return Err(malformed("missing EOI marker"));
    }
    result.content_digest = digest(&retained.concat());
    Ok(Parsed {
        inspection: result,
        retained,
    })
}

fn classify(
    marker: u8,
    payload: &[u8],
    offset: usize,
    result: &mut Inspection,
    limits: &Limits,
    remove_provenance: bool,
    recognized_credential: bool,
) -> Result<bool> {
    if !matches!(marker, 0xe0..=0xef | 0xfe) {
        return Ok(false);
    }
    if payload.len() > limits.max_metadata_bytes {
        return Err(Error::Blocked("JPEG metadata-field limit exceeded".into()));
    }
    let location = format!("marker 0xFF{marker:02X} at byte {offset}");
    if (marker == 0xeb
        && (payload.starts_with(b"JP")
            || contains_ascii(payload, b"jumb")
            || contains_ascii(payload, b"c2pa")))
        || (matches!(marker, 0xe1 | 0xed) && contains_ascii(payload, b"c2pa"))
    {
        let xmp = marker == 0xe1
            && (payload.starts_with(b"http://ns.adobe.com/xap/1.0/\0")
                || payload.starts_with(b"http://ns.adobe.com/xmp/extension/\0"));
        let exif = marker == 0xe1 && payload.starts_with(b"Exif\0\0");
        let iptc = marker == 0xed
            && payload.starts_with(b"Photoshop 3.0\0")
            && photoshop_metadata_only(payload)?;
        let authorized = remove_provenance && (recognized_credential || xmp || exif || iptc);
        result.findings.push(Finding::new("jpeg.provenance", RiskLayer::ProvenanceCredential,
            &location, "Potential JUMBF/C2PA provenance container is present; signature validity was not assessed", if authorized {Action::Remove}else{Action::Preserve}));
        if authorized {
            if xmp && contains_ascii(payload, b"orientation") {
                result
                    .blockers
                    .push("XMP orientation metadata requires semantic-preserving rewriting".into());
            }
            if exif {
                inspect_exif(&payload[6..], result)?;
            }
        } else {
            result.blockers.push("JPEG provenance container requires an explicit supported credential-removal selection or dedicated verifier".into());
        }
        return Ok(authorized);
    }
    let privacy = match marker {
        0xe1 if payload.starts_with(b"Exif\0\0") => {
            inspect_exif(&payload[6..], result)?;
            Some(("jpeg.exif", "EXIF metadata container is present"))
        }
        0xe1 if payload.starts_with(b"http://ns.adobe.com/xap/1.0/\0")
            || payload.starts_with(b"http://ns.adobe.com/xmp/extension/\0") =>
        {
            if contains_ascii(payload, b"orientation") {
                result
                    .blockers
                    .push("XMP orientation metadata requires semantic-preserving rewriting".into());
            }
            Some(("jpeg.xmp", "XMP metadata container is present"))
        }
        0xed if payload.starts_with(b"Photoshop 3.0\0") => {
            // Photoshop resource blocks can include clipping paths and display resources.
            // Only resources with a known metadata role are eligible for removal.
            if photoshop_metadata_only(payload)? {
                Some(("jpeg.iptc", "Photoshop metadata resources are present"))
            } else {
                result.findings.push(Finding::new(
                    "jpeg.photoshop_resources",
                    RiskLayer::ContainerStructure,
                    &location,
                    "Photoshop resources include retained non-metadata or unknown resources",
                    Action::AskUser,
                ));
                None
            }
        }
        0xfe => Some(("jpeg.comment", "JPEG comment metadata is present")),
        _ => None,
    };
    if let Some((code, summary)) = privacy {
        result.findings.push(Finding::new(
            code,
            RiskLayer::EmbeddedMetadata,
            &location,
            summary,
            Action::Remove,
        ));
        return Ok(true);
    }
    if marker == 0xe0 && (payload.starts_with(b"JFIF\0") || payload.starts_with(b"JFXX\0")) {
        if payload.starts_with(b"JFXX\0")
            || (payload.len() >= 14 && (payload[12] != 0 || payload[13] != 0))
        {
            result.findings.push(Finding::new(
                "jpeg.thumbnail",
                RiskLayer::ContainerStructure,
                &location,
                "JFIF/JFXX thumbnail data is retained",
                Action::AskUser,
            ));
        }
        return Ok(false);
    }
    if marker == 0xe2 && payload.starts_with(b"ICC_PROFILE\0") {
        result.findings.push(Finding::new(
            "jpeg.icc",
            RiskLayer::ContainerStructure,
            &location,
            "ICC color profile is preserved",
            Action::Preserve,
        ));
        return Ok(false);
    }
    if marker == 0xee && payload.starts_with(b"Adobe") {
        return Ok(false);
    }
    if marker != 0xed || !payload.starts_with(b"Photoshop 3.0\0") {
        result.findings.push(Finding::new(
            "jpeg.unknown_app",
            RiskLayer::ContainerStructure,
            &location,
            "Unclassified application segment is retained",
            Action::AskUser,
        ));
    }
    Ok(false)
}

fn c2pa_first_fragment(payload: &[u8]) -> bool {
    payload.len() >= 46
        && payload.starts_with(b"JP")
        && payload[4..8] == [0, 0, 0, 1]
        && &payload[12..16] == b"jumb"
        && &payload[20..24] == b"jumd"
        && &payload[24..40] == b"c2pa\x00\x11\x00\x10\x80\x00\x00\xaa\x00\x38\x9b\x71"
        && payload[41..46] == *b"c2pa\0"
}

fn contains_ascii(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Refuse EXIF transforms that could discard orientation or unknown TIFF substructures.
pub(crate) fn inspect_exif(tiff: &[u8], result: &mut Inspection) -> Result<()> {
    let little = match tiff.get(..2) {
        Some(b"II") => true,
        Some(b"MM") => false,
        _ => return Err(malformed("EXIF TIFF byte order is invalid")),
    };
    let read16 = |offset: usize| -> Result<u16> {
        let value = tiff
            .get(offset..offset + 2)
            .ok_or_else(|| malformed("truncated EXIF value"))?;
        Ok(if little {
            u16::from_le_bytes([value[0], value[1]])
        } else {
            u16::from_be_bytes([value[0], value[1]])
        })
    };
    let read32 = |offset: usize| -> Result<u32> {
        let value = tiff
            .get(offset..offset + 4)
            .ok_or_else(|| malformed("truncated EXIF offset"))?;
        let array = [value[0], value[1], value[2], value[3]];
        Ok(if little {
            u32::from_le_bytes(array)
        } else {
            u32::from_be_bytes(array)
        })
    };
    if read16(2)? != 42 {
        return Err(malformed("EXIF TIFF magic is invalid"));
    }
    let mut pending = vec![read32(4)? as usize];
    let mut visited = std::collections::BTreeSet::new();
    while let Some(offset) = pending.pop() {
        if offset == 0 {
            continue;
        }
        if !visited.insert(offset) || visited.len() > 16 {
            return Err(malformed("cyclic or excessively nested EXIF IFDs"));
        }
        let entries = usize::from(read16(offset)?);
        let table_end = offset
            .checked_add(2 + 12 * entries)
            .ok_or_else(|| malformed("EXIF table overflow"))?;
        read32(table_end)?;
        for index in 0..entries {
            let entry = offset + 2 + 12 * index;
            let tag = read16(entry)?;
            let kind = read16(entry + 2)?;
            let count = read32(entry + 4)? as usize;
            let size = match kind {
                1 | 2 | 6 | 7 => 1,
                3 | 8 => 2,
                4 | 9 | 11 | 13 => 4,
                5 | 10 | 12 => 8,
                _ => return Err(malformed("unknown EXIF TIFF value type")),
            };
            let byte_count = count
                .checked_mul(size)
                .ok_or_else(|| malformed("EXIF value overflow"))?;
            if byte_count > 4 {
                let value_offset = read32(entry + 8)? as usize;
                if value_offset
                    .checked_add(byte_count)
                    .filter(|end| *end <= tiff.len())
                    .is_none()
                {
                    return Err(malformed("EXIF field points beyond its container"));
                }
            }
            if matches!(tag, 0x8773 | 0xa500) {
                result.blockers.push(
                    "EXIF color profile or gamma requires color-preserving metadata rewriting"
                        .into(),
                );
            }
            if tag == 0xa001 && (kind != 3 || count != 1 || read16(entry + 8)? != 1) {
                result.blockers.push(
                    "Non-sRGB EXIF color space requires color-preserving metadata rewriting".into(),
                );
            }
            if tag == 0x0112 {
                if kind != 3 || count != 1 || !(1..=8).contains(&read16(entry + 8)?) {
                    return Err(malformed("invalid EXIF orientation"));
                }
                if read16(entry + 8)? != 1 {
                    result.blockers.push("Non-default EXIF orientation requires orientation-preserving metadata rewriting".into());
                }
            }
            if matches!(tag, 0x8769 | 0x8825 | 0xa005) {
                if kind != 4 || count != 1 {
                    return Err(malformed("invalid EXIF sub-IFD pointer"));
                }
                pending.push(read32(entry + 8)? as usize);
            }
            if tag == 0x8825 {
                result.findings.push(Finding::new(
                    "jpeg.exif.gps",
                    RiskLayer::EmbeddedMetadata,
                    "APP1/Exif/GPSInfo",
                    "EXIF GPS information directory is present",
                    Action::Remove,
                ));
            }
            if matches!(
                tag,
                0x010f | 0x0110 | 0x0131 | 0x0132 | 0x013b | 0x8298 | 0x9003 | 0x9004 | 0x9286
            ) {
                result.findings.push(Finding::new(
                    "jpeg.exif.identity",
                    RiskLayer::EmbeddedMetadata,
                    &format!("APP1/Exif/tag 0x{tag:04X}"),
                    "EXIF identity, device, software or time field is present",
                    Action::Remove,
                ));
            }
        }
        pending.push(read32(table_end)? as usize);
    }
    Ok(())
}

fn photoshop_metadata_only(payload: &[u8]) -> Result<bool> {
    let mut offset = 14;
    let mut all_metadata = true;
    while offset < payload.len() {
        if payload.get(offset..offset + 4) != Some(b"8BIM") {
            return Err(malformed("invalid Photoshop resource signature"));
        }
        let id = payload
            .get(offset + 4..offset + 6)
            .ok_or_else(|| malformed("truncated Photoshop resource"))?;
        let id = u16::from_be_bytes([id[0], id[1]]);
        let name_len = usize::from(
            *payload
                .get(offset + 6)
                .ok_or_else(|| malformed("truncated resource name"))?,
        );
        let name_size = (name_len + 2) & !1;
        let length_offset = offset + 6 + name_size;
        let bytes = payload
            .get(length_offset..length_offset + 4)
            .ok_or_else(|| malformed("truncated resource length"))?;
        let length = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let end = length_offset
            .checked_add(4)
            .and_then(|value| value.checked_add(length))
            .and_then(|value| value.checked_add(length & 1))
            .filter(|end| *end <= payload.len())
            .ok_or_else(|| malformed("resource extends beyond Photoshop segment"))?;
        all_metadata &= matches!(id, 0x0404 | 0x0424 | 0x0425);
        offset = end;
    }
    Ok(all_metadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::codecs::jpeg::JpegEncoder;
    use image::{ExtendedColorType, ImageEncoder};

    fn sample() -> Vec<u8> {
        let mut data = Vec::new();
        JpegEncoder::new(&mut data)
            .write_image(&[255, 12, 45], 1, 1, ExtendedColorType::Rgb8)
            .unwrap();
        data
    }
    fn add_segment(data: &mut Vec<u8>, marker: u8, payload: &[u8]) {
        let mut segment = vec![0xff, marker];
        segment.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        segment.extend_from_slice(payload);
        data.splice(2..2, segment);
    }
    #[test]
    fn comments_removed_and_encoded_structure_preserved() {
        let original = sample();
        let mut metadata = original.clone();
        add_segment(&mut metadata, 0xfe, b"Synthetic private author");
        let scan = JpegAdapter.inspect(&metadata, &Limits::default()).unwrap();
        assert!(scan.findings.iter().any(|item| item.code == "jpeg.comment"));
        assert_eq!(
            JpegAdapter.sanitize(&metadata, &Limits::default()).unwrap(),
            original
        );
    }
    #[test]
    fn unknown_and_color_segments_and_trailer_retained() {
        let mut data = sample();
        add_segment(&mut data, 0xe2, b"ICC_PROFILE\0\x01\x01synthetic profile");
        add_segment(&mut data, 0xe7, b"unknown payload");
        data.extend_from_slice(b"trailer");
        let scan = JpegAdapter.inspect(&data, &Limits::default()).unwrap();
        assert!(
            scan.findings
                .iter()
                .any(|item| item.code == "jpeg.unknown_app")
        );
        assert_eq!(
            JpegAdapter.sanitize(&data, &Limits::default()).unwrap(),
            data
        );
    }
    #[test]
    fn malformed_lengths_and_missing_end_rejected() {
        assert!(
            JpegAdapter
                .inspect(b"\xff\xd8\xff\xe1\xff\xff", &Limits::default())
                .is_err()
        );
        let mut data = sample();
        data.truncate(data.len() - 2);
        assert!(JpegAdapter.inspect(&data, &Limits::default()).is_err());
    }
    #[test]
    fn provenance_is_preserved_and_blocks_rewrite() {
        let mut data = sample();
        add_segment(&mut data, 0xeb, b"JP\x00\x01c2pa");
        assert!(
            !JpegAdapter
                .inspect(&data, &Limits::default())
                .unwrap()
                .blockers
                .is_empty()
        );
        assert!(JpegAdapter.sanitize(&data, &Limits::default()).is_err());
    }
    #[test]
    fn every_truncated_prefix_is_rejected_without_panicking() {
        let data = sample();
        for end in 0..data.len() {
            assert!(
                JpegAdapter
                    .inspect(&data[..end], &Limits::default())
                    .is_err()
            );
        }
    }
    #[test]
    fn minimal_exif_and_gps_pointer_are_detected_then_removed() {
        let original = sample();
        let mut data = original.clone();
        // IFD0 holds a GPS pointer to an empty GPS IFD. All data are synthetic.
        let exif = b"Exif\0\0II\x2a\0\x08\0\0\0\x01\0\x25\x88\x04\0\x01\0\0\0\x1a\0\0\0\0\0\0\0\0\0\0\0\0\0";
        add_segment(&mut data, 0xe1, exif);
        let scan = JpegAdapter.inspect(&data, &Limits::default()).unwrap();
        assert!(
            scan.findings
                .iter()
                .any(|finding| finding.code == "jpeg.exif.gps")
        );
        assert_eq!(
            JpegAdapter.sanitize(&data, &Limits::default()).unwrap(),
            original
        );
    }
    #[test]
    fn orientation_change_is_blocked() {
        let mut data = sample();
        let tiff = b"Exif\0\0II\x2a\0\x08\0\0\0\x01\0\x12\x01\x03\0\x01\0\0\0\x06\0\0\0\0\0\0\0";
        add_segment(&mut data, 0xe1, tiff);
        assert!(JpegAdapter.sanitize(&data, &Limits::default()).is_err());
    }
}
