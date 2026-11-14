// SPDX-License-Identifier: MPL-2.0
//! PNG chunk parser with CRC checks and byte-preserving ancillary metadata removal.
use fileveil_core::{
    Action, Error, Finding, Format, FormatAdapter, Inspection, Limits, Result, RiskLayer,
    SanitizeOptions, digest,
};
use flate2::read::ZlibDecoder;
use std::io::Read;

pub struct PngAdapter;
const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
struct Parsed<'a> {
    inspection: Inspection,
    retained: Vec<&'a [u8]>,
}
impl FormatAdapter for PngAdapter {
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
impl PngAdapter {
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
    Error::Blocked(format!("Malformed PNG: {message}"))
}
fn parse<'a>(data: &'a [u8], limits: &Limits, remove_provenance: bool) -> Result<Parsed<'a>> {
    if data.len() as u64 > limits.max_file_bytes {
        return Err(Error::Blocked("PNG exceeds file-size limit".into()));
    }
    if !data.starts_with(SIGNATURE) {
        return Err(malformed("invalid signature"));
    }
    let mut result = Inspection::new(Format::Png, String::new());
    let mut retained = vec![&data[..8]];
    let mut offset: usize = 8;
    let mut chunks = 0;
    let mut color = 0;
    let mut depth = 0;
    let mut palette = false;
    let mut idat = false;
    let mut idat_closed = false;
    let mut ended = false;
    let mut singleton = std::collections::BTreeSet::new();
    while offset < data.len() {
        chunks += 1;
        if chunks > limits.max_members {
            return Err(Error::Blocked("PNG chunk-count limit exceeded".into()));
        }
        let header = data
            .get(offset..offset + 8)
            .ok_or_else(|| malformed("truncated chunk header"))?;
        let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        if length > 0x7fff_ffff {
            return Err(malformed("chunk length exceeds PNG specification"));
        }
        let kind: [u8; 4] = header[4..8]
            .try_into()
            .map_err(|_| malformed("invalid chunk type"))?;
        if !kind.iter().all(u8::is_ascii_alphabetic) || !kind[2].is_ascii_uppercase() {
            return Err(malformed("invalid chunk type or reserved bit"));
        }
        let payload_end = offset
            .checked_add(8)
            .and_then(|value| value.checked_add(length))
            .filter(|end| *end <= data.len())
            .ok_or_else(|| malformed("chunk extends beyond file"))?;
        let end = payload_end
            .checked_add(4)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| malformed("truncated chunk CRC"))?;
        let crc = u32::from_be_bytes(
            data[payload_end..end]
                .try_into()
                .map_err(|_| malformed("invalid CRC"))?,
        );
        if crc32fast::hash(&data[offset + 4..payload_end]) != crc {
            return Err(malformed("chunk CRC mismatch"));
        }
        let payload = &data[offset + 8..payload_end];
        if chunks == 1 && kind != *b"IHDR" {
            return Err(malformed("IHDR must be the first chunk"));
        }
        if idat && kind != *b"IDAT" {
            idat_closed = true;
        }
        if matches!(
            &kind,
            b"IHDR"
                | b"PLTE"
                | b"IEND"
                | b"tRNS"
                | b"iCCP"
                | b"sRGB"
                | b"gAMA"
                | b"cHRM"
                | b"sBIT"
                | b"bKGD"
                | b"hIST"
                | b"pHYs"
                | b"tIME"
                | b"eXIf"
        ) && !singleton.insert(kind)
        {
            return Err(malformed("duplicate singleton chunk"));
        }
        let mut remove = false;
        match &kind {
            b"IHDR" => {
                if chunks != 1 || payload.len() != 13 {
                    return Err(malformed("invalid IHDR"));
                }
                let width = u32::from_be_bytes(
                    payload[..4]
                        .try_into()
                        .map_err(|_| malformed("invalid width"))?,
                );
                let height = u32::from_be_bytes(
                    payload[4..8]
                        .try_into()
                        .map_err(|_| malformed("invalid height"))?,
                );
                depth = payload[8];
                color = payload[9];
                let valid_depth = match color {
                    0 => matches!(depth, 1 | 2 | 4 | 8 | 16),
                    2 | 4 | 6 => matches!(depth, 8 | 16),
                    3 => matches!(depth, 1 | 2 | 4 | 8),
                    _ => false,
                };
                if width == 0
                    || height == 0
                    || width > 0x7fff_ffff
                    || height > 0x7fff_ffff
                    || !valid_depth
                    || payload[10] != 0
                    || payload[11] != 0
                    || payload[12] > 1
                {
                    return Err(malformed("invalid image dimensions, color type or methods"));
                }
                if u64::from(width) * u64::from(height) > limits.max_pixels {
                    return Err(Error::Blocked("PNG pixel-count limit exceeded".into()));
                }
            }
            b"PLTE" => {
                if idat
                    || matches!(color, 0 | 4)
                    || payload.is_empty()
                    || !payload.len().is_multiple_of(3)
                    || payload.len() > 768
                    || (color == 3 && payload.len() / 3 > 1 << depth)
                {
                    return Err(malformed("invalid palette or palette ordering"));
                }
                palette = true;
            }
            b"IDAT" => {
                if idat_closed || (color == 3 && !palette) {
                    return Err(malformed("nonconsecutive IDAT or missing palette"));
                }
                idat = true;
            }
            b"IEND" => {
                if !idat || !payload.is_empty() {
                    return Err(malformed("invalid IEND or missing image data"));
                }
                ended = true;
            }
            b"tEXt" | b"zTXt" | b"iTXt" => {
                let text = text_payload(&kind, payload, limits)?;
                if contains_ascii(&text, b"c2pa") || contains_ascii(&text, b"jumb") {
                    result.findings.push(Finding::new(
                        "png.provenance",
                        RiskLayer::ProvenanceCredential,
                        "PNG/text",
                        "Potential provenance data is present; signature validity was not assessed",
                        if remove_provenance {
                            Action::Remove
                        } else {
                            Action::Preserve
                        },
                    ));
                    if !remove_provenance {
                        result.blockers.push("PNG provenance metadata requires a dedicated offline credential verifier before rewriting".into());
                    }
                }
                if contains_ascii(&text, b"orientation") {
                    result.blockers.push(
                        "PNG text orientation metadata requires semantic-preserving rewriting"
                            .into(),
                    );
                }
                let code = match &kind {
                    b"tEXt" => "png.text",
                    b"zTXt" => "png.ztxt",
                    _ => "png.itxt",
                };
                result.findings.push(Finding::new(
                    code,
                    RiskLayer::EmbeddedMetadata,
                    &format!("PNG/{} at byte {offset}", String::from_utf8_lossy(&kind)),
                    "PNG text metadata is present",
                    Action::Remove,
                ));
                remove = true;
            }
            b"eXIf" => {
                if payload.len() > limits.max_metadata_bytes {
                    return Err(Error::Blocked("PNG EXIF exceeds metadata limit".into()));
                }
                let first = result.findings.len();
                super::jpeg::inspect_exif(payload, &mut result)
                    .map_err(|error| malformed(&format!("invalid EXIF container ({error})")))?;
                for finding in &mut result.findings[first..] {
                    finding.code = finding.code.replace("jpeg.", "png.");
                    finding.location = finding.location.replace("APP1/Exif", "PNG/eXIf");
                }
                result.findings.push(Finding::new(
                    "png.exif",
                    RiskLayer::EmbeddedMetadata,
                    "PNG/eXIf",
                    "EXIF metadata container is present",
                    Action::Remove,
                ));
                remove = true;
            }
            b"tIME" => {
                if payload.len() != 7 {
                    return Err(malformed("invalid modification time chunk"));
                }
                result.findings.push(Finding::new(
                    "png.time",
                    RiskLayer::EmbeddedMetadata,
                    "PNG/tIME",
                    "PNG modification timestamp is present",
                    Action::Remove,
                ));
                remove = true;
            }
            b"caBX" => {
                result.findings.push(Finding::new("png.provenance", RiskLayer::ProvenanceCredential,
                    "PNG/caBX", "JUMBF/C2PA provenance container is present; signature validity was not assessed", if remove_provenance {Action::Remove}else{Action::Preserve}));
                if remove_provenance {
                    remove = true;
                } else {
                    result.blockers.push("PNG provenance container requires a dedicated offline credential verifier before rewriting".into());
                }
            }
            b"acTL" | b"fcTL" | b"fdAT" => {
                if !result.limited_support {
                    result.limited_support = true;
                    result
                        .blockers
                        .push("APNG frame-preserving verification is unavailable".into());
                    result.findings.push(Finding::new(
                        "png.animation",
                        RiskLayer::ContainerStructure,
                        "PNG/APNG",
                        "Animated PNG requires verification of every frame",
                        Action::Preserve,
                    ));
                }
            }
            b"iCCP" => {
                if idat || singleton.contains(b"sRGB") {
                    return Err(malformed(
                        "invalid ICC profile ordering or conflicting sRGB",
                    ));
                }
                validate_iccp(payload, limits)?;
                result.findings.push(Finding::new(
                    "png.icc",
                    RiskLayer::ContainerStructure,
                    "PNG/iCCP",
                    "ICC color profile is preserved",
                    Action::Preserve,
                ));
            }
            b"sRGB" => {
                if idat
                    || palette
                    || singleton.contains(b"iCCP")
                    || payload.len() != 1
                    || payload[0] > 3
                {
                    return Err(malformed("invalid sRGB chunk"));
                }
            }
            b"gAMA" | b"cHRM" | b"sBIT" => {
                if idat || palette {
                    return Err(malformed("color metadata follows palette or image data"));
                }
                let valid = match &kind {
                    b"gAMA" => payload.len() == 4 && payload != [0, 0, 0, 0],
                    b"cHRM" => payload.len() == 32,
                    _ => {
                        payload.len()
                            == match color {
                                0 => 1,
                                2 | 3 => 3,
                                4 => 2,
                                _ => 4,
                            }
                    }
                };
                if !valid {
                    return Err(malformed("invalid color metadata length"));
                }
            }
            b"tRNS" => {
                let valid = !idat
                    && match color {
                        0 => payload.len() == 2,
                        2 => payload.len() == 6,
                        3 => palette && !payload.is_empty() && payload.len() <= 256,
                        _ => false,
                    };
                if !valid {
                    return Err(malformed("invalid transparency chunk"));
                }
            }
            b"pHYs" => {
                if idat || payload.len() != 9 || payload[8] > 1 {
                    return Err(malformed("invalid pixel-density chunk"));
                }
            }
            b"bKGD" | b"hIST" | b"sPLT" | b"cICP" | b"mDCV" | b"cLLI" => {
                // These carry rendering / palette semantics and remain byte-identical.
                if idat {
                    return Err(malformed("rendering metadata follows image data"));
                }
            }
            _ if kind[0].is_ascii_uppercase() => return Err(malformed("unknown critical chunk")),
            _ => result.findings.push(Finding::new(
                "png.unknown_ancillary",
                RiskLayer::ContainerStructure,
                &format!("PNG/{} at byte {offset}", String::from_utf8_lossy(&kind)),
                "Unclassified ancillary chunk is retained",
                Action::AskUser,
            )),
        }
        if !remove {
            retained.push(&data[offset..end]);
        }
        offset = end;
        if ended {
            if offset < data.len() {
                retained.push(&data[offset..]);
                result.findings.push(Finding::new(
                    "png.trailing_data",
                    RiskLayer::ContainerStructure,
                    "after IEND",
                    "Bytes follow the PNG end chunk and are retained",
                    Action::AskUser,
                ));
            }
            break;
        }
    }
    if !ended {
        return Err(malformed("missing IEND"));
    }
    result.content_digest = digest(&retained.concat());
    Ok(Parsed {
        inspection: result,
        retained,
    })
}

fn contains_ascii(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}
fn keyword_end(payload: &[u8]) -> Result<usize> {
    let end = payload
        .iter()
        .position(|value| *value == 0)
        .ok_or_else(|| malformed("missing text keyword terminator"))?;
    if end == 0
        || end > 79
        || !payload[..end]
            .iter()
            .all(|byte| matches!(byte, 32..=126 | 161..=255))
        || payload[0] == b' '
        || payload[end - 1] == b' '
        || payload[..end].windows(2).any(|pair| pair == b"  ")
    {
        return Err(malformed("invalid text keyword"));
    }
    Ok(end)
}
fn decompress_metadata(payload: &[u8], limits: &Limits) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ZlibDecoder::new(payload)
        .take(limits.max_metadata_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| malformed("invalid compressed metadata"))?;
    if bytes.len() > limits.max_metadata_bytes {
        return Err(Error::Blocked(
            "PNG decompressed metadata limit exceeded".into(),
        ));
    }
    Ok(bytes)
}
fn validate_iccp(payload: &[u8], limits: &Limits) -> Result<()> {
    if payload.len() > limits.max_metadata_bytes {
        return Err(Error::Blocked("PNG ICC exceeds metadata limit".into()));
    }
    let end = keyword_end(payload)?;
    if payload.get(end + 1) != Some(&0) || payload.len() <= end + 2 {
        return Err(malformed("invalid ICC compression method"));
    }
    let profile = decompress_metadata(&payload[end + 2..], limits)?;
    if profile.len() < 128 || profile.get(36..40) != Some(b"acsp") {
        return Err(malformed("invalid ICC profile header"));
    }
    Ok(())
}
fn text_payload(kind: &[u8; 4], payload: &[u8], limits: &Limits) -> Result<Vec<u8>> {
    if payload.len() > limits.max_metadata_bytes {
        return Err(Error::Blocked("PNG text-field limit exceeded".into()));
    }
    let keyword = keyword_end(payload)?;
    let rest = &payload[keyword + 1..];
    match kind {
        b"tEXt" => {
            if rest.contains(&0) {
                return Err(malformed("null byte in PNG text"));
            }
            Ok(rest.to_vec())
        }
        b"zTXt" => {
            if rest.first() != Some(&0) {
                return Err(malformed("invalid text compression method"));
            }
            decompress_metadata(&rest[1..], limits)
        }
        _ => {
            if rest.len() < 4 || rest[0] > 1 || rest[1] != 0 {
                return Err(malformed("invalid international text header"));
            }
            let language_end = rest[2..]
                .iter()
                .position(|byte| *byte == 0)
                .map(|value| value + 2)
                .ok_or_else(|| malformed("unterminated text language"))?;
            let translated_end = rest[language_end + 1..]
                .iter()
                .position(|byte| *byte == 0)
                .map(|value| value + language_end + 1)
                .ok_or_else(|| malformed("unterminated translated text keyword"))?;
            std::str::from_utf8(&rest[language_end + 1..translated_end])
                .map_err(|_| malformed("invalid translated UTF-8 keyword"))?;
            let text = if rest[0] == 1 {
                decompress_metadata(&rest[translated_end + 1..], limits)?
            } else {
                rest[translated_end + 1..].to_vec()
            };
            std::str::from_utf8(&text)
                .map_err(|_| malformed("invalid international UTF-8 text"))?;
            Ok(text)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::codecs::png::PngEncoder;
    use image::{ExtendedColorType, ImageEncoder};
    fn sample() -> Vec<u8> {
        let mut bytes = Vec::new();
        PngEncoder::new(&mut bytes)
            .write_image(&[20, 30, 40], 1, 1, ExtendedColorType::Rgb8)
            .unwrap();
        bytes
    }
    fn chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(kind);
        bytes.extend_from_slice(payload);
        let crc = crc32fast::hash(&bytes[4..]);
        bytes.extend_from_slice(&crc.to_be_bytes());
        bytes
    }
    #[test]
    fn text_removed_without_changing_other_chunks() {
        let original = sample();
        let mut metadata = original.clone();
        metadata.splice(33..33, chunk(b"tEXt", b"Author\0Synthetic user"));
        assert!(
            PngAdapter
                .inspect(&metadata, &Limits::default())
                .unwrap()
                .findings
                .iter()
                .any(|item| item.code == "png.text")
        );
        assert_eq!(
            PngAdapter.sanitize(&metadata, &Limits::default()).unwrap(),
            original
        );
    }
    #[test]
    fn unknown_ancillary_and_trailer_are_retained() {
        let mut bytes = sample();
        bytes.splice(33..33, chunk(b"fvEl", b"unclassified"));
        bytes.extend_from_slice(b"retained trailer");
        assert_eq!(
            PngAdapter.sanitize(&bytes, &Limits::default()).unwrap(),
            bytes
        );
    }
    #[test]
    fn invalid_crc_and_truncations_are_rejected() {
        let mut bytes = sample();
        bytes[29] ^= 1;
        assert!(PngAdapter.inspect(&bytes, &Limits::default()).is_err());
        for length in 0..33 {
            assert!(
                PngAdapter
                    .inspect(&bytes[..length], &Limits::default())
                    .is_err()
            );
        }
    }
    #[test]
    fn unknown_critical_and_duplicate_header_rejected() {
        let mut bytes = sample();
        bytes.splice(33..33, chunk(b"FVEl", b"unknown"));
        assert!(PngAdapter.inspect(&bytes, &Limits::default()).is_err());
        let mut bytes = sample();
        let header = bytes[8..33].to_vec();
        bytes.splice(33..33, header);
        assert!(PngAdapter.inspect(&bytes, &Limits::default()).is_err());
    }
    #[test]
    fn apng_and_provenance_block_rewriting() {
        let mut animated = sample();
        animated.splice(33..33, chunk(b"acTL", &[0; 8]));
        assert!(
            PngAdapter
                .inspect(&animated, &Limits::default())
                .unwrap()
                .limited_support
        );
        assert!(PngAdapter.sanitize(&animated, &Limits::default()).is_err());
        let mut credential = sample();
        credential.splice(33..33, chunk(b"caBX", b"synthetic provenance"));
        assert!(
            PngAdapter
                .sanitize(&credential, &Limits::default())
                .is_err()
        );
    }
    #[test]
    fn nonconsecutive_image_data_rejected() {
        let mut bytes = sample();
        let image_end = bytes.len() - 12;
        bytes.splice(
            image_end..image_end,
            [chunk(b"tEXt", b"Key\0value"), chunk(b"IDAT", b"")].concat(),
        );
        assert!(PngAdapter.inspect(&bytes, &Limits::default()).is_err());
    }
}

// FVPROV1 22733 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJjZTZjMTIwOWJhMGQzYzJiOWMwYTIzNDA1YWZjMTNiNzk2MjY0NTM2NTFlY2UzOWUwMzhiNWJkNTU3MWJhZTBhIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1mb3JtYXRzL3NyYy9wbmcucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI4MWI0NTZlMjVhNWExNjQzZjM1MzFmZTEyMjU1ODZmYzc4YTMyOTFlOGNkNzVjNTkwYzQ4YWRmMTg4MmVkYmEwOWNiYmY1YWJhYzhkNmQxYmZmNTk4Y2MyNzQzNmQwODJlZDYwM2VjMmUwY2FlYjAzZmVkOTM0NDVkNzQ0ZTEwMCJ9XX1d FVPROV1-END
