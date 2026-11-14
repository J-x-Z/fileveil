// SPDX-License-Identifier: MPL-2.0
//! Bounded audio-container metadata handling. Encoded samples are never decoded or modified.
use fileveil_core::{
    Action, Error, Finding, FindingState, Format, Inspection, Limits, Result, RiskLayer, digest,
};
use sha2::{Digest, Sha256};

struct Parsed {
    inspection: Inspection,
    output: Option<Vec<u8>>,
}
fn malformed() -> Error {
    Error::Blocked("Invalid or unsupported audio container structure".into())
}
fn finding(code: &str, location: &str, summary: &str, action: Action) -> Finding {
    Finding::new(code, RiskLayer::EmbeddedMetadata, location, summary, action)
}
fn base(format: Format) -> Inspection {
    let mut result = Inspection::new(format, String::new());
    result.limited_support = true;
    result.findings.push(Finding::unassessed("audio.signal_watermark",RiskLayer::ContentWatermark,"audio/encoded_frames","Audio decoding, signal-domain watermarks and arbitrary content inside retained frames were not assessed"));
    result
}
fn protect_provenance(result: &mut Inspection, code: &str, location: &str, summary: &str) {
    let mut found = Finding::new(
        code,
        RiskLayer::ProvenanceCredential,
        location,
        summary,
        Action::Preserve,
    );
    found.state = FindingState::Blocked;
    result.findings.push(found);
    result.blockers.push("Audio provenance structures are protected because metadata rewriting may invalidate their binding".into());
    result.rewrite_supported = false;
}
fn fingerprint(parts: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    for bytes in parts {
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    format!("{:x}", hash.finalize())
}
fn u32le(bytes: &[u8]) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes.try_into().map_err(|_| malformed())?,
    ))
}
fn wav(data: &[u8], limits: &Limits) -> Result<Parsed> {
    if data.len() < 12
        || &data[..4] != b"RIFF"
        || &data[8..12] != b"WAVE"
        || u32le(&data[4..8])? as usize != data.len() - 8
    {
        return Err(malformed());
    }
    let mut result = base(Format::Wav);
    let mut retained = Vec::new();
    let mut offset = 12;
    let mut count = 0;
    let mut fmt = false;
    let mut samples = false;
    let mut block_align = 0usize;
    while offset < data.len() {
        count += 1;
        if count > limits.max_members {
            return Err(Error::Blocked(
                "WAV chunk count exceeds the resource budget".into(),
            ));
        }
        let header = data.get(offset..offset + 8).ok_or_else(malformed)?;
        let length = u32le(&header[4..8])? as usize;
        let payload_end = offset
            .checked_add(8)
            .and_then(|n| n.checked_add(length))
            .filter(|end| *end <= data.len())
            .ok_or_else(malformed)?;
        let end = payload_end
            .checked_add(length % 2)
            .filter(|end| *end <= data.len())
            .ok_or_else(malformed)?;
        let payload = &data[offset + 8..payload_end];
        let kind = &header[..4];
        let removable =
            matches!(kind, b"bext" | b"iXML") || (kind == b"LIST" && payload.starts_with(b"INFO"));
        if removable {
            if payload.len() > limits.max_metadata_bytes {
                return Err(Error::Blocked(
                    "WAV metadata exceeds the byte budget".into(),
                ));
            }
            if kind == b"LIST" {
                validate_info(payload, limits)?;
            }
            let (code, summary) = match kind {
                b"bext" => (
                    "wav.broadcast_metadata",
                    "Broadcast author, origin and timing metadata is present",
                ),
                b"iXML" => ("wav.ixml", "Production-workflow XML metadata is present"),
                _ => (
                    "wav.info",
                    "RIFF INFO author, software and source metadata is present",
                ),
            };
            let mut found = finding(
                code,
                &format!("RIFF/chunk {count} at byte {offset}"),
                summary,
                Action::Remove,
            );
            if kind != b"LIST" {
                found.impact=Some("Broadcast timing, loudness or production workflow metadata is removed. Encoded audio samples stay unchanged".into());
            }
            result.findings.push(found);
        } else {
            match kind {
                b"C2PA"=>{
                    if payload.len()>limits.max_metadata_bytes{return Err(Error::Blocked("WAV credential chunk exceeds the metadata budget".into()));}
                    protect_provenance(&mut result,"wav.provenance",&format!("RIFF/chunk {count} at byte {offset}"),"A standard C2PA credential chunk is present. Cryptographic validation is reported separately");
                }
                b"fmt "=>{
                    if fmt||samples||payload.len()<16 {return Err(malformed());}
                    let channels=u16::from_le_bytes([payload[2],payload[3]]);let rate=u32le(&payload[4..8])?;block_align=u16::from_le_bytes([payload[12],payload[13]])as usize;
                    if channels==0||rate==0||block_align==0 {return Err(malformed());}fmt=true;
                }
                b"data"=>{if !fmt||samples||!payload.len().is_multiple_of(block_align){return Err(malformed());}samples=true;}
                b"fact"|b"cue "|b"smpl"=>result.findings.push(finding("wav.playback_structure",&format!("RIFF/chunk {count}"),"Playback, sample-position or cue structures are retained",Action::Preserve)),
                _=>result.findings.push(finding("wav.retained_chunk",&format!("RIFF/chunk {count} at byte {offset}"),"An additional or private chunk is retained. Its contents and metadata are outside the cleaning scope",Action::AskUser)),
            }
            retained.push(&data[offset..end]);
        }
        offset = end;
    }
    if !fmt || !samples {
        return Err(malformed());
    }
    result.content_digest = fingerprint(&retained);
    let mut output = b"RIFF\0\0\0\0WAVE".to_vec();
    for bytes in retained {
        output.extend_from_slice(bytes);
    }
    let size = u32::try_from(output.len() - 8).map_err(|_| malformed())?;
    output[4..8].copy_from_slice(&size.to_le_bytes());
    Ok(Parsed {
        inspection: result,
        output: Some(output),
    })
}
fn validate_info(payload: &[u8], limits: &Limits) -> Result<()> {
    let mut offset = 4;
    let mut count = 0;
    while offset < payload.len() {
        count += 1;
        if count > limits.max_members {
            return Err(Error::Blocked(
                "WAV INFO field count exceeds the resource budget".into(),
            ));
        }
        let header = payload.get(offset..offset + 8).ok_or_else(malformed)?;
        let size = u32le(&header[4..8])? as usize;
        offset = offset
            .checked_add(8)
            .and_then(|n| n.checked_add(size))
            .and_then(|n| n.checked_add(size % 2))
            .filter(|end| *end <= payload.len())
            .ok_or_else(malformed)?;
    }
    Ok(())
}

fn read_vorbis_string<'a>(payload: &'a [u8], offset: &mut usize) -> Result<&'a [u8]> {
    let length = u32le(
        payload
            .get(*offset..offset.saturating_add(4))
            .ok_or_else(malformed)?,
    )? as usize;
    *offset = offset.checked_add(4).ok_or_else(malformed)?;
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= payload.len())
        .ok_or_else(malformed)?;
    let value = &payload[*offset..end];
    *offset = end;
    std::str::from_utf8(value).map_err(|_| malformed())?;
    Ok(value)
}
fn clean_vorbis(payload: &[u8], limits: &Limits) -> Result<(Option<Vec<u8>>, bool)> {
    if payload.len() > limits.max_metadata_bytes {
        return Err(Error::Blocked(
            "FLAC comment metadata exceeds the byte budget".into(),
        ));
    }
    let mut offset = 0;
    let vendor = read_vorbis_string(payload, &mut offset)?;
    let count = u32le(payload.get(offset..offset + 4).ok_or_else(malformed)?)? as usize;
    offset += 4;
    if count > limits.max_members {
        return Err(Error::Blocked(
            "FLAC comment field count exceeds the resource budget".into(),
        ));
    }
    let mut technical = Vec::new();
    let mut changed = !vendor.is_empty();
    for _ in 0..count {
        let field = read_vorbis_string(payload, &mut offset)?;
        let name = field
            .split(|byte| *byte == b'=')
            .next()
            .ok_or_else(malformed)?;
        if name.is_empty()
            || name.len() == field.len()
            || !name
                .iter()
                .all(|byte| matches!(*byte,0x20..=0x3c|0x3e..=0x7e))
        {
            return Err(malformed());
        }
        let name = std::str::from_utf8(name)
            .map_err(|_| malformed())?
            .to_ascii_uppercase();
        if name == "WAVEFORMATEXTENSIBLE_CHANNEL_MASK"
            || name.starts_with("REPLAYGAIN_")
            || matches!(name.as_str(), "R128_TRACK_GAIN" | "R128_ALBUM_GAIN")
        {
            technical.push(field);
        } else {
            changed = true;
        }
    }
    if offset != payload.len() {
        return Err(malformed());
    }
    if technical.is_empty() {
        return Ok((None, changed));
    }
    let mut output = 0u32.to_le_bytes().to_vec();
    output.extend_from_slice(&(technical.len() as u32).to_le_bytes());
    for field in technical {
        output.extend_from_slice(&(field.len() as u32).to_le_bytes());
        output.extend_from_slice(field);
    }
    Ok((Some(output), changed))
}
fn flac(data: &[u8], limits: &Limits) -> Result<Parsed> {
    if !data.starts_with(b"fLaC") {
        return Err(malformed());
    }
    let mut result = base(Format::Flac);
    let mut offset = 4;
    let mut count = 0;
    let mut streaminfo = false;
    let mut comment = false;
    let mut seektable = false;
    let mut blocks: Vec<(u8, Vec<u8>)> = Vec::new();
    loop {
        count += 1;
        if count > limits.max_members {
            return Err(Error::Blocked(
                "FLAC metadata block count exceeds the resource budget".into(),
            ));
        }
        let header = data.get(offset..offset + 4).ok_or_else(malformed)?;
        let last = header[0] & 0x80 != 0;
        let kind = header[0] & 0x7f;
        let size = u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize;
        let end = offset
            .checked_add(4)
            .and_then(|n| n.checked_add(size))
            .filter(|end| *end <= data.len())
            .ok_or_else(malformed)?;
        let payload = &data[offset + 4..end];
        if count == 1 && kind != 0 {
            return Err(malformed());
        }
        let mut cleaned = None;
        let mut retain = true;
        match kind {
            0 => {
                if streaminfo || size != 34 {
                    return Err(malformed());
                }
                let minimum = u16::from_be_bytes([payload[0], payload[1]]);
                let maximum = u16::from_be_bytes([payload[2], payload[3]]);
                let packed =
                    u64::from_be_bytes(payload[10..18].try_into().map_err(|_| malformed())?);
                let rate = packed >> 44;
                let bits = ((packed >> 36) & 31) + 1;
                if minimum < 16 || maximum < minimum || rate == 0 || bits < 4 {
                    return Err(malformed());
                }
                streaminfo = true;
            }
            1 => {
                if payload.iter().any(|byte| *byte != 0) {
                    return Err(malformed());
                }
            }
            2 => {
                if size < 4 {
                    return Err(malformed());
                }
                if matches!(&payload[..4], b"c2pa" | b"C2PA") {
                    protect_provenance(
                        &mut result,
                        "flac.provenance_candidate",
                        &format!("FLAC/block {count} at byte {offset}"),
                        "An application block uses a C2PA-like identifier. Its private layout and authenticity are unassessed",
                    );
                } else {
                    result.findings.push(finding(
                        "flac.application",
                        &format!("FLAC/block {count} at byte {offset}"),
                        "Private application metadata is retained and remains unassessed",
                        Action::AskUser,
                    ));
                }
            }
            3 => {
                if seektable || !size.is_multiple_of(18) {
                    return Err(malformed());
                }
                seektable = true;
            }
            4 => {
                if comment {
                    return Err(malformed());
                }
                comment = true;
                let (replacement, changed) = clean_vorbis(payload, limits)?;
                retain = replacement.is_some();
                cleaned = replacement;
                if changed {
                    result.findings.push(finding("flac.vorbis_comment",&format!("FLAC/block {count} at byte {offset}"),"Human-readable tags and encoder metadata are present. Technical channel and playback-gain fields are preserved",Action::Remove));
                }
                if retain {
                    result.findings.push(finding("flac.playback_fields","FLAC/VORBIS_COMMENT","Technical channel mapping or playback-gain fields are retained without exposing their values",Action::Preserve));
                }
            }
            5 | 6 => result.findings.push(finding(
                "flac.retained_metadata",
                &format!("FLAC/block {count} at byte {offset}"),
                "Cuesheet or embedded artwork metadata is retained and may carry privacy data",
                Action::AskUser,
            )),
            127 => return Err(malformed()),
            _ => result.findings.push(finding(
                "flac.unknown_block",
                &format!("FLAC/block {count} at byte {offset}"),
                "Reserved or private metadata is retained without attribution",
                Action::AskUser,
            )),
        }
        if retain {
            blocks.push((kind, cleaned.unwrap_or_else(|| payload.to_vec())));
        }
        offset = end;
        if last {
            break;
        }
    }
    let frames = data.get(offset..).ok_or_else(malformed)?;
    if frames.len() < 6 || frames[0] != 0xff || frames[1] & 0xfe != 0xf8 {
        return Err(malformed());
    }
    let mut canonical = Vec::new();
    for (kind, payload) in &blocks {
        canonical.push(*kind);
        canonical.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        canonical.extend_from_slice(payload);
    }
    canonical.extend_from_slice(frames);
    result.content_digest = digest(&canonical);
    let mut output = b"fLaC".to_vec();
    let block_count = blocks.len();
    for (index, (kind, payload)) in blocks.into_iter().enumerate() {
        output.push(kind | if index + 1 == block_count { 0x80 } else { 0 });
        let length = (payload.len() as u32).to_be_bytes();
        output.extend_from_slice(&length[1..]);
        output.extend_from_slice(&payload);
    }
    output.extend_from_slice(frames);
    Ok(Parsed {
        inspection: result,
        output: Some(output),
    })
}

fn synchsafe(bytes: &[u8]) -> Result<usize> {
    if bytes.len() != 4 || bytes.iter().any(|byte| byte & 0x80 != 0) {
        return Err(malformed());
    }
    Ok(bytes
        .iter()
        .fold(0usize, |number, byte| (number << 7) | usize::from(*byte)))
}
pub fn mp3_signature(data: &[u8]) -> bool {
    (data.len() >= 10
        && data.starts_with(b"ID3")
        && matches!(data[3], 2..=4)
        && data[4] != 255
        && data[6..10].iter().all(|byte| byte & 0x80 == 0))
        || data.len() >= 4
            && data[0] == 0xff
            && data[1] & 0xe0 == 0xe0
            && data[1] & 6 == 2
            && data[1] & 0x18 != 8
            && data[2] & 0xf0 != 0xf0
            && data[2] & 0x0c != 0x0c
}
fn mp3(data: &[u8], limits: &Limits) -> Result<Parsed> {
    let mut result = base(Format::Mp3);
    result.rewrite_supported = false;
    let mut audio_offset = 0;
    if data.starts_with(b"ID3") {
        let header = data.get(..10).ok_or_else(malformed)?;
        let version = header[3];
        if !matches!(version, 2..=4) || header[4] == 255 {
            return Err(malformed());
        }
        let allowed_flags = match version {
            2 => 0xc0,
            3 => 0xe0,
            _ => 0xf0,
        };
        if header[5] & !allowed_flags != 0 {
            return Err(malformed());
        }
        let size = synchsafe(&header[6..10])?;
        if size > limits.max_metadata_bytes {
            return Err(Error::Blocked(
                "ID3 metadata exceeds the byte budget".into(),
            ));
        }
        audio_offset = 10usize
            .checked_add(size)
            .and_then(|n| {
                n.checked_add(if version == 4 && header[5] & 0x10 != 0 {
                    10
                } else {
                    0
                })
            })
            .filter(|end| *end <= data.len())
            .ok_or_else(malformed)?;
        if version == 4 && header[5] & 0x10 != 0 {
            let footer = &data[audio_offset - 10..audio_offset];
            if &footer[..3] != b"3DI" || footer[3..] != header[3..] {
                return Err(malformed());
            }
        }
        result.findings.push(finding(
            "mp3.id3v2",
            "MP3/ID3v2 header",
            "ID3v2 tag metadata is present. Its frame values are redacted and retained",
            Action::Preserve,
        ));
    }
    if !mp3_signature(data.get(audio_offset..).ok_or_else(malformed)?)
        || data.get(audio_offset..audio_offset + 3) == Some(b"ID3")
    {
        return Err(malformed());
    }
    if data.len() >= 128 && &data[data.len() - 128..data.len() - 125] == b"TAG" {
        result.findings.push(finding(
            "mp3.id3v1",
            "MP3/ID3v1 footer",
            "ID3v1 title, author and timestamp fields may be present and are retained",
            Action::Preserve,
        ));
    }
    result.findings.push(Finding::unassessed("mp3.frames",RiskLayer::ContainerStructure,"MP3/audio_frames","MPEG audio frames, ID3 flags and playback-related tags require a frame-aware backend. Rewriting is unavailable"));
    result.content_digest = digest(data);
    Ok(Parsed {
        inspection: result,
        output: None,
    })
}
fn parse(data: &[u8], format: Format, limits: &Limits) -> Result<Parsed> {
    if data.len() as u64 > limits.max_file_bytes {
        return Err(Error::Blocked("Audio exceeds the file byte budget".into()));
    }
    match format {
        Format::Wav => wav(data, limits),
        Format::Flac => flac(data, limits),
        Format::Mp3 => mp3(data, limits),
        _ => Err(Error::Unsupported(
            "Audio adapter does not support this format".into(),
        )),
    }
}
pub fn inspect(data: &[u8], format: Format, limits: &Limits) -> Result<Inspection> {
    Ok(parse(data, format, limits)?.inspection)
}
pub fn sanitize(data: &[u8], format: Format, limits: &Limits) -> Result<Vec<u8>> {
    let parsed = parse(data, format, limits)?;
    if !parsed.inspection.blockers.is_empty() {
        return Err(Error::Blocked(
            "Protected audio provenance prevents metadata rewriting".into(),
        ));
    }
    parsed.output.ok_or_else(|| {
        Error::Unsupported(
            "MP3 metadata rewriting requires a frame-aware backend and is unavailable".into(),
        )
    })
}

// FVPROV1 19900 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJkNGE1ODIyYTljOGFmMDc4NzVjYzIxY2I4OTFhYThjNzI4NDc5MGExODA3ODhiYWNiNjA0ODhmYzY3M2ZkMDk2IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4zIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMyIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1mb3JtYXRzL3NyYy9hdWRpby5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjY2Y2Y0MzU0ZjY3OTRlYTYwY2YzZGRkNGNlYmM4MjY3ZTc5YjgxY2UxN2E5NDU4ZjQ2NzUzYjk3YTMyODU5YjFlZjNjY2RhNmRhNTRkOGMzOTBiMWEyM2JiNTNiOTVkZDhiYTg3NjU5ZjRiYWYzNWQ1NzgxMzBiMjk4NWUyODA3In1dfV0= FVPROV1-END
