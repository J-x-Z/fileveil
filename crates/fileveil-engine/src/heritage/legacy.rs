// SPDX-License-Identifier: MPL-2.0
//! Bounded, independently implemented readers for published legacy media marks.
//!
//! Red Star's public samples use DES-ECB records followed by a little-endian
//! byte count and `EOF`. DOCX stores the same packet in local ZIP padding.
//! Woolim's published SELFSIGN structure has a 792-byte footer. NATISIGN is
//! recognized as an unverified structural candidate and is protected from edits.
use des::{
    Des,
    cipher::{Block, BlockCipherDecrypt, KeyInit},
};
use fileveil_core::{Error, Format, Limits, Result, digest};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroize;

const REDSTAR_KEY: [u8; 8] = [7, 6, 5, 4, 3, 2, 1, 0];
const ORIGINAL_BINARY_KEY: [u8; 8] = [0x13, 0x52, 0x07, 0x0d, 0x13, 0x3a, 0x08, 0x10];
const RECORD_BYTES: usize = 24;
const MAX_LAYERS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyStatus {
    Detected,
    NotDetected,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyKind {
    RedstarDes,
    WoolimSelfsign,
    WoolimNatisignCandidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyPlacement {
    Trailer,
    OoxmlLocalPadding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyLocation {
    pub kind: LegacyKind,
    pub placement: LegacyPlacement,
    pub offset: usize,
    pub bytes: usize,
    pub record_count: usize,
    pub evidence_status: String,
    pub crypto_status: String,
    pub payload_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_ciphertext_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyDecodedRecord {
    pub offset: usize,
    pub cipher_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext_sha256: Option<String>,
    pub plausible_serial: bool,
    pub key_profile: String,
    pub key_profile_evidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyReport {
    pub method_id: String,
    pub version: String,
    pub format: Format,
    pub status: LegacyStatus,
    pub locations: Vec<LegacyLocation>,
    pub decoded_records: Vec<LegacyDecodedRecord>,
    pub warnings: Vec<String>,
    pub offline: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyVerification {
    pub result: String,
    pub input_sha256: String,
    pub output_sha256: String,
    pub retained_bytes_unchanged: bool,
    pub removed_locations: usize,
    pub remaining_status: LegacyStatus,
    pub scope: String,
}

struct Parsed {
    report: LegacyReport,
    base_len: usize,
    zero_ranges: Vec<std::ops::Range<usize>>,
}

/// Detects supported wire structures, with identifiers withheld from the report.
pub fn detect(data: &[u8], limits: &Limits) -> Result<LegacyReport> {
    Ok(parse(data, limits, false)?.report)
}

/// DES is legacy decoding only. Its unauthenticated output proves no identity.
pub fn decode(data: &[u8], limits: &Limits, disclose_identifiers: bool) -> Result<LegacyReport> {
    Ok(parse(data, limits, disclose_identifiers)?.report)
}

/// Removes precisely bounded trailers or zeroes a confirmed local ZIP packet.
/// The caller publishes the returned bytes through its normal new-copy workflow.
pub fn clean(data: &[u8], limits: &Limits) -> Result<Vec<u8>> {
    let parsed = parse(data, limits, false)?;
    require_removable(&parsed.report)?;
    let output = apply(data, &parsed);
    let after = parse(&output, limits, false)?;
    if after.report.status != LegacyStatus::NotDetected {
        return Err(Error::Verification(
            "Legacy structures remain after cleaning".into(),
        ));
    }
    Ok(output)
}

pub fn verify(before: &[u8], after: &[u8], limits: &Limits) -> Result<LegacyVerification> {
    let parsed = parse(before, limits, false)?;
    require_removable(&parsed.report)?;
    let remaining = parse(after, limits, false)?;
    let retained = matches_plan(before, after, &parsed);
    let passed = retained && remaining.report.status == LegacyStatus::NotDetected;
    Ok(LegacyVerification {
        result: if passed { "verified_within_scope" } else { "failed" }.into(),
        input_sha256: digest(before),
        output_sha256: digest(after),
        retained_bytes_unchanged: retained,
        removed_locations: parsed.report.locations.len(),
        remaining_status: remaining.report.status,
        scope: "Exact supported legacy packet removal and byte preservation of every retained region. Signature authenticity, device identity, other watermark families and external copies are outside this scope.".into(),
    })
}

fn require_removable(report: &LegacyReport) -> Result<()> {
    if report.status != LegacyStatus::Detected {
        return Err(Error::Blocked("Cleaning requires a confirmed removable legacy structure. NATISIGN candidates are protected.".into()));
    }
    Ok(())
}

fn apply(data: &[u8], parsed: &Parsed) -> Vec<u8> {
    let mut output = data[..parsed.base_len].to_vec();
    for range in &parsed.zero_ranges {
        output[range.clone()].fill(0);
    }
    output
}

fn matches_plan(before: &[u8], after: &[u8], parsed: &Parsed) -> bool {
    if after.len() != parsed.base_len {
        return false;
    }
    let mut retained_start = 0;
    for range in &parsed.zero_ranges {
        if before[retained_start..range.start] != after[retained_start..range.start]
            || after[range.clone()].iter().any(|byte| *byte != 0)
        {
            return false;
        }
        retained_start = range.end;
    }
    before[retained_start..parsed.base_len] == after[retained_start..]
}

fn parse(data: &[u8], limits: &Limits, disclose: bool) -> Result<Parsed> {
    if data.len() as u64 > limits.max_file_bytes {
        return Err(Error::Blocked(
            "Legacy input exceeds the configured file limit".into(),
        ));
    }
    let mut report = LegacyReport {
        method_id: "legacy-redstar-woolim-v1".into(),
        version: "1.0.0".into(),
        format: Format::Unknown,
        status: LegacyStatus::NotDetected,
        locations: Vec::new(),
        decoded_records: Vec::new(),
        warnings: Vec::new(),
        offline: true,
    };
    let mut end = data.len();
    let mut metadata_bytes = 0usize;
    loop {
        let bytes = &data[..end];
        if bytes.ends_with(b"EOF") {
            let packet = redstar_packet(bytes, end, limits)?;
            add_redstar(
                data,
                packet.clone(),
                LegacyPlacement::Trailer,
                disclose,
                &mut report,
            )?;
            end = packet.start;
        } else if bytes.ends_with(b"SELFSIGN") || bytes.ends_with(b"NATISIGN") {
            end = woolim_footer(bytes, &mut report)?;
        } else {
            break;
        }
        check_budget(&report, data.len() - end, limits)?;
    }
    metadata_bytes += data.len() - end;
    let inspection = fileveil_formats::inspect(&data[..end], Path::new("legacy.docx"), limits)?;
    report.format = inspection.format;
    if !report.locations.is_empty()
        && !matches!(inspection.format, Format::Jpeg | Format::Png | Format::Docx)
    {
        return Err(Error::Unsupported(
            "Legacy trailer cleaning supports structurally validated JPEG, PNG and DOCX containers"
                .into(),
        ));
    }
    if !report.locations.is_empty()
        && inspection.findings.iter().any(|finding| {
            matches!(
                finding.code.as_str(),
                "jpeg.trailing_data" | "png.trailing_data"
            )
        })
    {
        return Err(Error::Blocked(
            "Unrecognized bytes precede the legacy trailer".into(),
        ));
    }
    let zero_ranges = if inspection.format == Format::Docx {
        docx_packets(
            &data[..end],
            limits,
            disclose,
            &mut metadata_bytes,
            &mut report,
        )?
    } else {
        Vec::new()
    };
    check_budget(&report, metadata_bytes, limits)?;
    if !report.locations.is_empty() {
        report.status = if report
            .locations
            .iter()
            .any(|location| location.kind == LegacyKind::WoolimNatisignCandidate)
        {
            LegacyStatus::Indeterminate
        } else {
            LegacyStatus::Detected
        };
        report.warnings.push("Legacy markers can be forged. Decoded serials are unauthenticated claims and do not establish a person, device or distribution history.".into());
        if report
            .decoded_records
            .iter()
            .any(|record| !record.plausible_serial)
        {
            report.warnings.push("Some structurally matched Red Star records could not be decoded to a plausible serial using the two published keys. Their identities remain unresolved. Removal covers only the bounded packet structure.".into());
        }
    }
    if report
        .locations
        .iter()
        .any(|location| location.kind != LegacyKind::RedstarDes)
    {
        report.warnings.push("Woolim RSA signatures and encrypted identity blocks were not cryptographically verified or decrypted. Removing their footer can prevent opening the copy on devices that enforce these signatures. SELFSIGN has a published structure but no original device specimen was available in this research set.".into());
    }
    Ok(Parsed {
        report,
        base_len: end,
        zero_ranges,
    })
}

fn check_budget(report: &LegacyReport, bytes: usize, limits: &Limits) -> Result<()> {
    if report.locations.len() > MAX_LAYERS.min(limits.max_members)
        || report.decoded_records.len() > limits.max_members
        || bytes > limits.max_metadata_bytes
    {
        return Err(Error::Blocked(
            "Legacy packet count or metadata budget exceeded".into(),
        ));
    }
    Ok(())
}

fn redstar_packet(data: &[u8], end: usize, limits: &Limits) -> Result<std::ops::Range<usize>> {
    let trailer = end
        .checked_sub(7)
        .ok_or_else(|| Error::Input("Truncated Red Star footer".into()))?;
    let size = le32(data, trailer)?;
    if size == 0
        || size % RECORD_BYTES != 0
        || size > limits.max_metadata_bytes
        || size / RECORD_BYTES > limits.max_members
    {
        return Err(Error::Input(
            "Invalid Red Star record count or byte length".into(),
        ));
    }
    let start = trailer
        .checked_sub(size)
        .ok_or_else(|| Error::Input("Red Star length extends before the container".into()))?;
    Ok(start..end)
}

fn add_redstar(
    data: &[u8],
    packet: std::ops::Range<usize>,
    placement: LegacyPlacement,
    disclose: bool,
    report: &mut LegacyReport,
) -> Result<()> {
    let cipher_end = packet.end - 7;
    let cipher = Des::new_from_slice(&REDSTAR_KEY)
        .map_err(|_| Error::Input("Invalid legacy DES key length".into()))?;
    let original_cipher = Des::new_from_slice(&ORIGINAL_BINARY_KEY)
        .map_err(|_| Error::Input("Invalid original DES key length".into()))?;
    for offset in (packet.start..cipher_end).step_by(RECORD_BYTES) {
        let ciphertext = &data[offset..offset + RECORD_BYTES];
        let mut plaintext = decrypt_record(&cipher, ciphertext);
        let mut serial_end = serial_length(&plaintext);
        let mut profile = "reference_sample";
        if serial_end.is_none() {
            plaintext.zeroize();
            plaintext = decrypt_record(&original_cipher, ciphertext);
            serial_end = serial_length(&plaintext);
            profile = "original_binary";
        }
        let plausible = serial_end.is_some();
        report.decoded_records.push(LegacyDecodedRecord {
            offset,
            cipher_sha256: digest(ciphertext),
            plaintext_sha256: plausible.then(|| digest(&plaintext)),
            plausible_serial: plausible,
            key_profile: if plausible { profile } else { "unresolved" }.into(),
            key_profile_evidence: if !plausible {
                "structure_only_unknown_key"
            } else if profile == "original_binary" {
                "static_binary_profile_only"
            } else {
                "matched_known_sample_profile"
            }
            .into(),
            identifier: if disclose && plausible {
                Some(String::from_utf8_lossy(&plaintext[..serial_end.unwrap_or(0)]).into_owned())
            } else {
                None
            },
        });
        plaintext.zeroize();
    }
    report.locations.push(LegacyLocation {
        kind: LegacyKind::RedstarDes,
        placement,
        offset: packet.start,
        bytes: packet.len(),
        record_count: (cipher_end - packet.start) / RECORD_BYTES,
        evidence_status: "reference_sample_confirmed_format".into(),
        crypto_status: if report
            .decoded_records
            .iter()
            .filter(|record| (packet.start..cipher_end).contains(&record.offset))
            .all(|record| record.plausible_serial)
        {
            "des_decoded_unauthenticated"
        } else {
            "des_identity_unresolved"
        }
        .into(),
        payload_sha256: digest(&data[packet.start..cipher_end]),
        identity_ciphertext_sha256: None,
    });
    Ok(())
}

fn decrypt_record(cipher: &Des, ciphertext: &[u8]) -> [u8; RECORD_BYTES] {
    let mut plaintext = [0u8; RECORD_BYTES];
    plaintext.copy_from_slice(ciphertext);
    for chunk in plaintext.as_chunks_mut::<8>().0 {
        let mut block = Block::<Des>::default();
        block.copy_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        chunk.copy_from_slice(&block);
        block.as_mut_slice().zeroize();
    }
    plaintext
}

fn serial_length(plaintext: &[u8; RECORD_BYTES]) -> Option<usize> {
    let end = plaintext.iter().position(|byte| *byte == 0)?;
    ((4..RECORD_BYTES).contains(&end)
        && plaintext[..end].iter().all(|byte| byte.is_ascii_graphic())
        && plaintext[end..].iter().all(|byte| *byte == 0))
    .then_some(end)
}

fn woolim_footer(data: &[u8], report: &mut LegacyReport) -> Result<usize> {
    let total = if data.ends_with(b"SELFSIGN") {
        792
    } else {
        272
    };
    let start = data
        .len()
        .checked_sub(total)
        .ok_or_else(|| Error::Input("Truncated Woolim footer".into()))?;
    if le32(data, data.len() - 16)? != total || data[data.len() - 12..data.len() - 8] != [0; 4] {
        return Err(Error::Input(
            "Woolim footer length or reserved padding is invalid".into(),
        ));
    }
    let selfsign = total == 792;
    report.locations.push(LegacyLocation {
        kind: if selfsign {
            LegacyKind::WoolimSelfsign
        } else {
            LegacyKind::WoolimNatisignCandidate
        },
        placement: LegacyPlacement::Trailer,
        offset: start,
        bytes: total,
        record_count: 1,
        evidence_status: if selfsign {
            "structure_confirmed"
        } else {
            "candidate_unverified"
        }
        .into(),
        crypto_status: "not_assessed".into(),
        payload_sha256: digest(&data[start..data.len() - 16]),
        identity_ciphertext_sha256: selfsign.then(|| digest(&data[start + 256..start + 776])),
    });
    if !selfsign {
        report.warnings.push("NATISIGN's 272-byte geometry is a narrow structural candidate derived from RSA-2048 and its trailer. A matching original specimen and authoritative fixed-length specification are unavailable. Cleaning this candidate is blocked.".into());
    }
    Ok(start)
}

fn docx_packets(
    data: &[u8],
    limits: &Limits,
    disclose: bool,
    metadata_bytes: &mut usize,
    report: &mut LegacyReport,
) -> Result<Vec<std::ops::Range<usize>>> {
    let minimum = data.len().saturating_sub(65_557);
    let eocd = (minimum..data.len().saturating_sub(21))
        .rev()
        .find(|offset| {
            data.get(*offset..*offset + 4) == Some(b"PK\x05\x06")
                && le16(data, *offset + 20).is_ok_and(|len| *offset + 22 + len == data.len())
        })
        .ok_or_else(|| Error::Input("ZIP end directory was not found".into()))?;
    if le32(data, eocd + 4)? != 0 || le16(data, eocd + 8)? != le16(data, eocd + 10)? {
        return Err(Error::Blocked(
            "Multi-disk ZIP is outside legacy DOCX scope".into(),
        ));
    }
    let count = le16(data, eocd + 10)?;
    let mut central = le32(data, eocd + 16)?;
    let directory_start = central;
    if count > limits.max_members || central.checked_add(le32(data, eocd + 12)?) != Some(eocd) {
        return Err(Error::Blocked(
            "ZIP directory count or bounds exceed legacy scope".into(),
        ));
    }
    let mut ranges = Vec::new();
    for _ in 0..count {
        if data.get(central..central + 4) != Some(b"PK\x01\x02") {
            return Err(Error::Input("Invalid ZIP central directory header".into()));
        }
        let local = le32(data, central + 42)?;
        if data.get(local..local + 4) != Some(b"PK\x03\x04") {
            return Err(Error::Input("Invalid ZIP local header reference".into()));
        }
        let extra_start = local
            .checked_add(30)
            .and_then(|offset| offset.checked_add(le16(data, local + 26).ok()?))
            .ok_or_else(|| Error::Input("ZIP local header overflow".into()))?;
        let extra_end = extra_start
            .checked_add(le16(data, local + 28)?)
            .filter(|end| *end <= directory_start && *end <= data.len())
            .ok_or_else(|| Error::Input("ZIP local extra extends outside member bounds".into()))?;
        *metadata_bytes = metadata_bytes
            .checked_add(extra_end - extra_start)
            .ok_or_else(|| Error::Blocked("ZIP local metadata length overflow".into()))?;
        if *metadata_bytes > limits.max_metadata_bytes {
            return Err(Error::Blocked(
                "ZIP local metadata exceeds the configured budget".into(),
            ));
        }
        padding_packets(
            data,
            extra_start..extra_end,
            limits,
            disclose,
            report,
            &mut ranges,
        )?;
        central = central
            .checked_add(
                46 + le16(data, central + 28)?
                    + le16(data, central + 30)?
                    + le16(data, central + 32)?,
            )
            .filter(|offset| *offset <= eocd)
            .ok_or_else(|| Error::Input("ZIP directory extends outside bounds".into()))?;
        check_budget(report, *metadata_bytes, limits)?;
    }
    if central != eocd {
        return Err(Error::Input("ZIP directory length is inconsistent".into()));
    }
    ranges.sort_by_key(|range| range.start);
    if ranges.windows(2).any(|pair| pair[0].end > pair[1].start) {
        return Err(Error::Blocked(
            "Overlapping ZIP watermark regions are ambiguous".into(),
        ));
    }
    Ok(ranges)
}

fn padding_packets(
    data: &[u8],
    extra: std::ops::Range<usize>,
    limits: &Limits,
    disclose: bool,
    report: &mut LegacyReport,
    ranges: &mut Vec<std::ops::Range<usize>>,
) -> Result<()> {
    let mut at = extra.start;
    while at < extra.end {
        let tag = le16(data, at)?;
        let end = at
            .checked_add(4 + le16(data, at + 2)?)
            .filter(|end| *end <= extra.end)
            .ok_or_else(|| Error::Input("Malformed ZIP local extra field".into()))?;
        // Only the wrapper and nested padding layout found in the public DOCX
        // reference are editable. Unknown extra fields retain all of their bytes.
        if tag == 0xa220
            && end >= at + 8
            && le16(data, at + 4)? == 0xa028
            && at + 8 + le16(data, at + 6)? == end
        {
            let padding = at + 8..end;
            if let Some(marker) = data[padding.clone()]
                .windows(3)
                .rposition(|bytes| bytes == b"EOF")
            {
                let packet = redstar_packet(data, padding.start + marker + 3, limits)?;
                if packet.start < padding.start
                    || !data[padding.start..packet.start]
                        .iter()
                        .all(|byte| *byte == 0)
                    || !data[packet.end..padding.end].iter().all(|byte| *byte == 0)
                {
                    return Err(Error::Blocked(
                        "Ambiguous non-padding bytes surround a DOCX legacy packet".into(),
                    ));
                }
                add_redstar(
                    data,
                    packet.clone(),
                    LegacyPlacement::OoxmlLocalPadding,
                    disclose,
                    report,
                )?;
                ranges.push(packet);
                check_budget(report, padding.len(), limits)?;
            }
        }
        at = end;
    }
    Ok(())
}

fn le16(data: &[u8], offset: usize) -> Result<usize> {
    let bytes = data
        .get(offset..offset.saturating_add(2))
        .ok_or_else(|| Error::Input("Truncated legacy u16 field".into()))?;
    Ok(usize::from(u16::from_le_bytes([bytes[0], bytes[1]])))
}

fn le32(data: &[u8], offset: usize) -> Result<usize> {
    let bytes = data
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| Error::Input("Truncated legacy u32 field".into()))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
}
