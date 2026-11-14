// SPDX-License-Identifier: MPL-2.0
//! Reversible native carriers. The signed binding covers the exact unwrapped bytes.
use base64::{Engine, engine::general_purpose::STANDARD};
use fileveil_core::{Error, Format, Result};

const MAGIC: &[u8; 8] = b"FVHERIT1";
const PDF_BEGIN: &[u8] = b"\n%FVHERIT1-BEGIN\n";
const PDF_END: &[u8] = b"%FVHERIT1-END\n";
pub const MAX_MANIFEST: usize = 256 * 1024;

pub struct Extracted {
    pub base: Vec<u8>,
    pub manifest: Option<Vec<u8>>,
    pub carrier: &'static str,
}
fn bad() -> Error {
    Error::Blocked("Malformed or oversized FileVeil Heritage carrier".into())
}
pub fn supported(format: Format) -> bool {
    matches!(
        format,
        Format::Jpeg
            | Format::Png
            | Format::Pdf
            | Format::Docx
            | Format::Xlsx
            | Format::Pptx
            | Format::Heic
            | Format::Avif
            | Format::Mp4
            | Format::Mov
            | Format::Text
    )
}
pub fn extract(data: &[u8], format: Format) -> Result<Extracted> {
    match format {
        Format::Jpeg => jpeg(data, None),
        Format::Png => png(data, None),
        Format::Pdf => pdf(data, None),
        Format::Docx | Format::Xlsx | Format::Pptx => office(data, None),
        Format::Heic | Format::Avif | Format::Mp4 | Format::Mov => bmff(data, None),
        Format::Text => super::source::extract(data),
        _ => Err(Error::Unsupported(
            "Watermark carriers support JPEG, PNG, PDF, Office and ISO media".into(),
        )),
    }
}
pub fn embed(data: &[u8], format: Format, manifest: &[u8]) -> Result<Vec<u8>> {
    if manifest.is_empty() || manifest.len() > MAX_MANIFEST {
        return Err(bad());
    }
    let clean = extract(data, format)?;
    let result = match format {
        Format::Jpeg => jpeg(&clean.base, Some(manifest)),
        Format::Png => png(&clean.base, Some(manifest)),
        Format::Pdf => pdf(&clean.base, Some(manifest)),
        Format::Docx | Format::Xlsx | Format::Pptx => office(&clean.base, Some(manifest)),
        Format::Heic | Format::Avif | Format::Mp4 | Format::Mov => {
            bmff(&clean.base, Some(manifest))
        }
        _ => return Err(Error::Unsupported("Unsupported Heritage carrier".into())),
    }?;
    Ok(result.base)
}

fn jpeg(data: &[u8], replacement: Option<&[u8]>) -> Result<Extracted> {
    if !data.starts_with(&[0xff, 0xd8]) {
        return Err(bad());
    }
    let mut base = data[..2].to_vec();
    let mut position = 2usize;
    let mut manifest = Vec::new();
    let mut expected_count = None;
    let mut next = 0u16;
    while position < data.len() {
        let start = position;
        if data.get(position) != Some(&0xff) {
            return Err(bad());
        }
        while data.get(position) == Some(&0xff) {
            position += 1;
        }
        let marker = *data.get(position).ok_or_else(bad)?;
        position += 1;
        if matches!(marker, 0xda | 0xd9) {
            base.extend_from_slice(&data[start..]);
            break;
        }
        if marker == 0x01 {
            base.extend_from_slice(&data[start..position]);
            continue;
        }
        let raw = data.get(position..position + 2).ok_or_else(bad)?;
        let length = u16::from_be_bytes([raw[0], raw[1]]) as usize;
        if length < 2 {
            return Err(bad());
        }
        let end = position
            .checked_add(length)
            .filter(|end| *end <= data.len())
            .ok_or_else(bad)?;
        let payload = &data[position + 2..end];
        if marker == 0xef && payload.starts_with(MAGIC) {
            if payload.len() < 12 {
                return Err(bad());
            }
            let index = u16::from_be_bytes([payload[8], payload[9]]);
            let count = u16::from_be_bytes([payload[10], payload[11]]);
            if count == 0
                || count > 8
                || index != next
                || expected_count.is_some_and(|value| value != count)
            {
                return Err(bad());
            }
            expected_count = Some(count);
            next += 1;
            manifest.extend_from_slice(&payload[12..]);
            if manifest.len() > MAX_MANIFEST {
                return Err(bad());
            }
        } else {
            base.extend_from_slice(&data[start..end]);
        }
        position = end;
    }
    if expected_count.is_some_and(|count| count != next) {
        return Err(bad());
    }
    if let Some(replacement) = replacement {
        let mut output = base[..2].to_vec();
        let count = replacement.len().div_ceil(60_000) as u16;
        for (index, bytes) in replacement.chunks(60_000).enumerate() {
            output.extend_from_slice(&[0xff, 0xef]);
            output.extend_from_slice(&((bytes.len() + 14) as u16).to_be_bytes());
            output.extend_from_slice(MAGIC);
            output.extend_from_slice(&(index as u16).to_be_bytes());
            output.extend_from_slice(&count.to_be_bytes());
            output.extend_from_slice(bytes);
        }
        output.extend_from_slice(&base[2..]);
        base = output;
    }
    Ok(Extracted {
        base,
        manifest: expected_count.map(|_| manifest),
        carrier: "jpeg_app15_fragments",
    })
}

fn png(data: &[u8], replacement: Option<&[u8]>) -> Result<Extracted> {
    if data.get(..8) != Some(b"\x89PNG\r\n\x1a\n") {
        return Err(bad());
    }
    let mut base = data[..8].to_vec();
    let mut position = 8usize;
    let mut manifest = None;
    let mut ended = false;
    while position < data.len() {
        let header = data.get(position..position + 8).ok_or_else(bad)?;
        let length = u32::from_be_bytes(header[..4].try_into().map_err(|_| bad())?) as usize;
        let end = position
            .checked_add(length)
            .and_then(|v| v.checked_add(12))
            .filter(|v| *v <= data.len())
            .ok_or_else(bad)?;
        let kind = &header[4..8];
        if kind == b"fvHl" {
            let payload = &data[position + 8..end - 4];
            let crc = u32::from_be_bytes(data[end - 4..end].try_into().map_err(|_| bad())?);
            if manifest.is_some()
                || !payload.starts_with(MAGIC)
                || payload.len() > MAX_MANIFEST + 8
                || crc32fast::hash(&data[position + 4..end - 4]) != crc
            {
                return Err(bad());
            }
            manifest = Some(payload[8..].to_vec());
        } else {
            if kind == b"IEND" {
                if let Some(replacement) = replacement {
                    let mut chunk = b"fvHl".to_vec();
                    chunk.extend_from_slice(MAGIC);
                    chunk.extend_from_slice(replacement);
                    base.extend_from_slice(&((replacement.len() + 8) as u32).to_be_bytes());
                    base.extend_from_slice(&chunk);
                    base.extend_from_slice(&crc32fast::hash(&chunk).to_be_bytes());
                }
                ended = true;
            }
            base.extend_from_slice(&data[position..end]);
        }
        position = end;
        if ended {
            base.extend_from_slice(&data[position..]);
            break;
        }
    }
    if !ended {
        return Err(bad());
    }
    Ok(Extracted {
        base,
        manifest,
        carrier: "png_private_ancillary_fvHl",
    })
}

fn office(data: &[u8], replacement: Option<&[u8]>) -> Result<Extracted> {
    let start = data.len().saturating_sub(65_557);
    let eocd = (start..data.len().saturating_sub(21))
        .rev()
        .find(|&p| {
            data.get(p..p + 4) == Some(b"PK\x05\x06")
                && data.get(p + 20..p + 22).is_some_and(|v| {
                    p + 22 + u16::from_le_bytes([v[0], v[1]]) as usize == data.len()
                })
        })
        .ok_or_else(bad)?;
    let comment = &data[eocd + 22..];
    let (original, manifest) = if comment.starts_with(MAGIC) {
        let size = comment
            .get(8..10)
            .map(|v| u16::from_le_bytes([v[0], v[1]]) as usize)
            .ok_or_else(bad)?;
        let end = 10usize
            .checked_add(size)
            .filter(|v| *v <= comment.len())
            .ok_or_else(bad)?;
        (&comment[10..end], Some(comment[end..].to_vec()))
    } else {
        (comment, None)
    };
    let mut new_comment = original.to_vec();
    if let Some(replacement) = replacement {
        new_comment = MAGIC.to_vec();
        new_comment.extend_from_slice(&(original.len() as u16).to_le_bytes());
        new_comment.extend_from_slice(original);
        new_comment.extend_from_slice(replacement);
    }
    if new_comment.len() > u16::MAX as usize
        || manifest.as_ref().is_some_and(|v| v.len() > MAX_MANIFEST)
    {
        return Err(bad());
    }
    let mut base = data[..eocd + 20].to_vec();
    base.extend_from_slice(&(new_comment.len() as u16).to_le_bytes());
    base.extend_from_slice(&new_comment);
    Ok(Extracted {
        base,
        manifest,
        carrier: "office_eocd_comment",
    })
}

fn pdf(data: &[u8], replacement: Option<&[u8]>) -> Result<Extracted> {
    if !data.starts_with(b"%PDF-") {
        return Err(bad());
    }
    let startxref = pdf_startxref(data)?;
    let mut base = data.to_vec();
    let mut manifest = None;
    // Carriers occupy the final contiguous comment section. A matching string
    // inside a stream or an older revision is outside this carrier location.
    let mut comment_start = startxref;
    while comment_start > 0 {
        let mut line_end = comment_start;
        while line_end > 0 && matches!(data[line_end - 1], b'\r' | b'\n') {
            line_end -= 1;
        }
        let line_start = data[..line_end]
            .iter()
            .rposition(|b| matches!(b, b'\r' | b'\n'))
            .map_or(0, |p| p + 1);
        let line = data[line_start..line_end].trim_ascii();
        if !line.is_empty() && !line.starts_with(b"%") {
            break;
        }
        comment_start = line_start;
    }
    let zone_start = comment_start.saturating_sub(1);
    let mut starts = data[zone_start..startxref]
        .windows(PDF_BEGIN.len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == PDF_BEGIN).then_some(zone_start + offset));
    let begin = starts.next();
    if starts.next().is_some() {
        return Err(bad());
    }
    if let Some(begin) = begin {
        let rest = &data[begin + PDF_BEGIN.len()..startxref];
        if !rest.ends_with(PDF_END) || rest.len() > MAX_MANIFEST * 2 {
            return Err(bad());
        }
        let body = &rest[..rest.len() - PDF_END.len()];
        let mut encoded = Vec::new();
        for line in body.split(|&b| b == b'\n').filter(|line| !line.is_empty()) {
            encoded.extend_from_slice(line.strip_prefix(b"% ").ok_or_else(bad)?);
        }
        let decoded = STANDARD.decode(encoded).map_err(|_| bad())?;
        if decoded.len() > MAX_MANIFEST {
            return Err(bad());
        }
        manifest = Some(decoded);
        base.drain(begin..startxref);
    }
    if let Some(replacement) = replacement {
        let tail = pdf_startxref(&base)?;
        let mut carrier = PDF_BEGIN.to_vec();
        for line in STANDARD.encode(replacement).as_bytes().chunks(72) {
            carrier.extend_from_slice(b"% ");
            carrier.extend_from_slice(line);
            carrier.push(b'\n');
        }
        carrier.extend_from_slice(PDF_END);
        base.splice(tail..tail, carrier);
    }
    Ok(Extracted {
        base,
        manifest,
        carrier: "pdf_pre_startxref_comments",
    })
}

fn pdf_startxref(data: &[u8]) -> Result<usize> {
    let end = data
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(0, |p| p + 1);
    let eof = end
        .checked_sub(5)
        .filter(|&p| data.get(p..end) == Some(b"%%EOF"))
        .ok_or_else(bad)?;
    let number_end = data[..eof]
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(0, |p| p + 1);
    let number_start = data[..number_end]
        .iter()
        .rposition(|b| !b.is_ascii_digit())
        .map_or(0, |p| p + 1);
    if number_start == number_end {
        return Err(bad());
    }
    let keyword_end = data[..number_start]
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(0, |p| p + 1);
    let keyword = keyword_end
        .checked_sub(9)
        .filter(|&p| data.get(p..keyword_end) == Some(b"startxref"))
        .ok_or_else(bad)?;
    let line_start = data[..keyword]
        .iter()
        .rposition(|b| matches!(b, b'\r' | b'\n'))
        .map_or(0, |p| p + 1);
    if !data[line_start..keyword]
        .iter()
        .all(u8::is_ascii_whitespace)
        || !data[keyword_end..number_start]
            .iter()
            .any(|b| matches!(b, b'\r' | b'\n'))
        || !data[number_end..eof]
            .iter()
            .any(|b| matches!(b, b'\r' | b'\n'))
    {
        return Err(bad());
    }
    let _offset = std::str::from_utf8(&data[number_start..number_end])
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&offset| offset < keyword)
        .ok_or_else(bad)?;
    // The normal PDF backend validates the referenced table or stream. Here the
    // bound only excludes impossible offsets while preserving exact base bytes.
    Ok(keyword)
}

// FileVeil structure carrier UUID. Offsets into the encoded media stay fixed.
const MEDIA_UUID: [u8; 16] = [
    0xc1, 0x2f, 0x95, 0x72, 0xd9, 0x5b, 0x4f, 0x2c, 0xa7, 0xb8, 0x1b, 0x38, 0x12, 0xf5, 0xe0, 0x02,
];

fn bmff(data: &[u8], replacement: Option<&[u8]>) -> Result<Extracted> {
    let mut position = 0usize;
    let mut carrier_start = None;
    let mut manifest = None;
    let mut terminal_open_box = false;
    while position < data.len() {
        let header = data.get(position..position + 8).ok_or_else(bad)?;
        let short_size = u32::from_be_bytes(header[..4].try_into().map_err(|_| bad())?);
        let (length, header_size) = match short_size {
            0 => {
                terminal_open_box = true;
                (data.len() - position, 8)
            }
            1 => {
                let size = data.get(position + 8..position + 16).ok_or_else(bad)?;
                (
                    usize::try_from(u64::from_be_bytes(size.try_into().map_err(|_| bad())?))
                        .map_err(|_| bad())?,
                    16,
                )
            }
            size => (size as usize, 8),
        };
        if length < header_size {
            return Err(bad());
        }
        let end = position
            .checked_add(length)
            .filter(|&v| v <= data.len())
            .ok_or_else(bad)?;
        if &header[4..8] == b"uuid" {
            if length < header_size + 16 {
                return Err(bad());
            }
            let payload = position + header_size;
            let uuid = data.get(payload..payload + 16).ok_or_else(bad)?;
            if uuid == MEDIA_UUID {
                if manifest.is_some() || end != data.len() || short_size == 0 {
                    return Err(bad());
                }
                let packet = data.get(payload + 16..end).ok_or_else(bad)?;
                if !packet.starts_with(MAGIC)
                    || packet.len() <= 8
                    || packet.len() > MAX_MANIFEST + 8
                {
                    return Err(bad());
                }
                manifest = Some(packet[8..].to_vec());
                carrier_start = Some(position);
            }
        }
        position = end;
    }
    if position != data.len() {
        return Err(bad());
    }
    let mut base = data[..carrier_start.unwrap_or(data.len())].to_vec();
    if let Some(replacement) = replacement {
        if terminal_open_box {
            return Err(Error::Blocked(
                "An open-ended ISO media box protects the payload from appending a carrier".into(),
            ));
        }
        let length = 32usize.checked_add(replacement.len()).ok_or_else(bad)?;
        base.extend_from_slice(&(length as u32).to_be_bytes());
        base.extend_from_slice(b"uuid");
        base.extend_from_slice(&MEDIA_UUID);
        base.extend_from_slice(MAGIC);
        base.extend_from_slice(replacement);
    }
    Ok(Extracted {
        base,
        manifest,
        carrier: "iso_media_terminal_uuid_v2",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Wire-format fixture only. Full PDF validity is checked by the PDF backend
    // in the normal Heritage entry point and the native PDF integration tests.
    const PDF_WIRE: &[u8] = b"%PDF-1.7\nxref\ntrailer <<>>\nstartxref\n9\n%%EOF\n";

    #[test]
    fn pdf_carrier_roundtrip_preserves_exact_tail_and_rejects_duplicate_blocks() {
        for source in [
            PDF_WIRE.to_vec(),
            PDF_WIRE
                .iter()
                .map(|&b| if b == b'\n' { b'\r' } else { b })
                .collect(),
        ] {
            let marked = embed(&source, Format::Pdf, b"[]").unwrap();
            let extracted = extract(&marked, Format::Pdf).unwrap();
            assert_eq!(extracted.base, source);
            assert_eq!(extracted.manifest.as_deref(), Some(b"[]".as_slice()));
            let start = marked
                .windows(PDF_BEGIN.len())
                .position(|v| v == PDF_BEGIN)
                .unwrap();
            let tail = pdf_startxref(&marked).unwrap();
            let mut duplicate = marked.clone();
            duplicate.splice(start..start, marked[start..tail].iter().copied());
            assert!(extract(&duplicate, Format::Pdf).is_err());
        }
    }

    #[test]
    fn pdf_tail_anchors_ignore_internal_words_and_reject_comment_decoys() {
        assert!(extract(b"%PDF-1.7\n% startxref\n9\n%%EOF\n", Format::Pdf).is_err());
        let mut decoy = PDF_WIRE.to_vec();
        decoy.extend_from_slice(b"% startxref\n");
        assert!(extract(&decoy, Format::Pdf).is_err());
        assert!(
            extract(
                b"%PDF-1.7\nstartxref\n999999999999999999999999999\n%%EOF\n",
                Format::Pdf
            )
            .is_err()
        );
        let mut internal =
            b"%PDF-1.7\n%FVHERIT1-BEGIN\nnot a carrier here\ntrailer <<>>\n".to_vec();
        internal.extend_from_slice(b"startxref\n9\n%%EOF\n");
        assert_eq!(extract(&internal, Format::Pdf).unwrap().base, internal);
    }
}

// FVPROV1 18500 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJjMDYwMzFlMjhmNTQzYTQyY2JjNWNlNWRkMjNkNTgzYjg1ZjI0YTczZDU3NGMwOTJkMDA3ZmVjYmNkMTdmM2MzIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4zIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMyIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL2hlcml0YWdlL2NvbnRhaW5lci5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjZmN2U3NzAyNjM4MDM5NTI2ZWQyZDA3NTlmZjdjMDczMTJmYjdmNDJiZWYwNjc2ZGYyMGI3MjE3M2I4Mjk5MDQwM2ZhNjRhNDFjNjI2ZDhhZmYwZmIxYmU5NzAyZDQ2YmExNzQ3MzI5YTA1OWM1NmE2ZTA5MTc5ZDUzODVjYjBhIn1dfV0= FVPROV1-END
