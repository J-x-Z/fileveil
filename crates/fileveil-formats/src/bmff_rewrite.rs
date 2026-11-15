// SPDX-License-Identifier: MPL-2.0
//! Offset-preserving BMFF privacy rewriting over bounded, parsed snapshots.
use super::*;
use fileveil_core::{FindingState, Integrity, Outcome};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};

pub(super) const C2PA_UUID: [u8; 16] = [
    0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81,
];
pub(super) const XMP_UUID: [u8; 16] = [
    0xbe, 0x7a, 0xcf, 0xcb, 0x97, 0xa9, 0x42, 0xe8, 0x9c, 0x71, 0x99, 0x94, 0x91, 0xe3, 0xaf, 0xac,
];

pub(super) struct Cleaned {
    pub bytes: Vec<u8>,
    pub codes: BTreeSet<&'static str>,
    pub extra_findings: Vec<Finding>,
}

fn blocked(message: &str) -> Error {
    Error::Blocked(message.into())
}

fn box_bytes(kind: [u8; 4], payload: &[u8]) -> Result<Vec<u8>> {
    let size = u32::try_from(
        payload
            .len()
            .checked_add(8)
            .ok_or_else(|| invalid("Rewritten box size overflow"))?,
    )
    .map_err(|_| invalid("Rewritten box exceeds the supported size"))?;
    let mut bytes = size.to_be_bytes().to_vec();
    bytes.extend_from_slice(&kind);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn install_box(output: &mut [u8], header: &Header, replacement: &[u8]) -> Result<()> {
    let available = header.end - header.start;
    if replacement.len() > available {
        return Err(blocked(
            "Metadata reconstruction would relocate encoded media",
        ));
    }
    let padding = available - replacement.len();
    if (1..8).contains(&padding) {
        return Err(blocked(
            "Metadata reconstruction leaves an unrepresentable padding box",
        ));
    }
    output[header.start..header.start + replacement.len()].copy_from_slice(replacement);
    if padding > 0 {
        let start = header.start + replacement.len();
        output[start..header.end].fill(0);
        output[start..start + 4].copy_from_slice(&(padding as u32).to_be_bytes());
        output[start + 4..start + 8].copy_from_slice(b"free");
    }
    Ok(())
}

fn wipe_box(output: &mut [u8], header: &Header) -> Result<()> {
    let length = header.end - header.start;
    let replacement = box_bytes(*b"free", &vec![0; length - 8])?;
    install_box(output, header, &replacement)
}

fn privacy_key(key: &[u8]) -> bool {
    let key = String::from_utf8_lossy(key).to_ascii_lowercase();
    // Playback intent, projection, orientation, stereo and content-pairing IDs
    // are retained. These keys can be required by Live Photos or slow motion.
    if [
        "playback",
        "orientation",
        "projection",
        "stereo",
        "content.identifier",
        "live-photo",
        "livephoto",
    ]
    .iter()
    .any(|technical| key.contains(technical))
    {
        return false;
    }
    [
        "location",
        "gps",
        "creationdate",
        "creationtime",
        "serial",
        "device",
        "software",
        "encoder",
        "author",
        "artist",
        "copyright",
        "comment",
        "description",
    ]
    .iter()
    .any(|private| key.contains(private))
        || key.ends_with(".make")
        || key.ends_with(".model")
        || key.ends_with(".identifier")
        || key.ends_with(".title")
}

fn xmp_is_removable(payload: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(payload).map_err(|_| {
        blocked("Compressed or non-UTF-8 XMP requires an additional credential-preserving backend")
    })?;
    let lower = text.to_ascii_lowercase();
    if lower.contains("provenance") || lower.contains("c2pa") {
        return Err(blocked(
            "Media source credentials or references require explicit credential removal",
        ));
    }
    if [
        "orientation",
        "hcropped",
        "hascrop",
        "croptop",
        "cropbottom",
        "cropleft",
        "cropright",
        "camera-raw-settings",
    ]
    .iter()
    .any(|technical| lower.contains(technical))
    {
        return Err(blocked(
            "XMP image presentation or editing instructions are protected during metadata cleanup",
        ));
    }
    Ok(())
}

fn child_indices(parser: &Parser<'_>, parent: usize) -> Vec<usize> {
    // The parser stores nodes in preorder. Descendants form one contiguous
    // range, so leaf processing never scans unrelated image properties/items.
    let start = parent + 1;
    let end = parser.nodes[parent].header.end;
    let descendants = parser.nodes[start..].partition_point(|node| node.header.start < end);
    parser.nodes[start..start + descendants]
        .iter()
        .enumerate()
        .filter_map(|(index, node)| (node.parent == Some(parent)).then_some(start + index))
        .collect()
}

fn range_for_location(
    location: &ItemLocation,
    idat: Option<&Range<usize>>,
    data_len: usize,
) -> Result<Vec<Range<usize>>> {
    if location.external || location.method > 1 {
        return Err(blocked(
            "External or item-relative media extents are protected during rewriting",
        ));
    }
    let source = if location.method == 1 {
        idat.cloned()
            .ok_or_else(|| invalid("Item references missing item-data storage"))?
    } else {
        0..data_len
    };
    location
        .ranges
        .iter()
        .map(|(offset, length)| {
            let offset = usize::try_from(*offset).map_err(|_| invalid("Item offset overflow"))?;
            let start = source
                .start
                .checked_add(offset)
                .filter(|start| *start <= source.end)
                .ok_or_else(|| invalid("Item extent starts outside its source"))?;
            let end = match length {
                None | Some(0) => source.end,
                Some(length) => start
                    .checked_add(
                        usize::try_from(*length).map_err(|_| invalid("Item length overflow"))?,
                    )
                    .filter(|end| *end <= source.end)
                    .ok_or_else(|| invalid("Item extent exceeds its source"))?,
            };
            Ok(start..end)
        })
        .collect()
}

fn overlaps(left: &Range<usize>, right: &Range<usize>) -> bool {
    left.start < right.end && right.start < left.end
}

fn rewrite_iinf(
    data: &[u8],
    parser: &Parser<'_>,
    index: usize,
    removed: &HashSet<u32>,
) -> Result<Vec<u8>> {
    let header = &parser.nodes[index].header;
    let payload = &data[header.payload..header.end];
    let width = if payload[0] == 0 { 2 } else { 4 };
    let mut kept = Vec::new();
    let mut count = 0u32;
    for child in child_indices(parser, index) {
        let child = &parser.nodes[child].header;
        if child.kind != *b"infe" {
            return Err(blocked(
                "Unknown item-information children are protected during rewriting",
            ));
        }
        let (id, _, _) = item_info(&data[child.payload..child.end])?;
        if !removed.contains(&id) {
            kept.extend_from_slice(&data[child.start..child.end]);
            count += 1;
        }
    }
    let mut rebuilt = payload[..4].to_vec();
    rebuilt.extend_from_slice(&count.to_be_bytes()[4 - width..]);
    rebuilt.extend_from_slice(&kept);
    box_bytes(*b"iinf", &rebuilt)
}

fn rewrite_iloc(payload: &[u8], removed: &HashSet<u32>, limits: &Limits) -> Result<Vec<u8>> {
    let locations = locations(payload, limits.max_members)?;
    let width = if payload[0] == 2 { 4 } else { 2 };
    let kept: Vec<_> = locations
        .iter()
        .filter(|location| !removed.contains(&location.id))
        .collect();
    let mut rebuilt = payload[..6].to_vec();
    rebuilt.extend_from_slice(&(kept.len() as u32).to_be_bytes()[4 - width..]);
    for location in kept {
        rebuilt.extend_from_slice(&payload[location.encoded.clone()]);
    }
    box_bytes(*b"iloc", &rebuilt)
}

fn rewrite_ipma(payload: &[u8], removed: &HashSet<u32>, limits: &Limits) -> Result<Vec<u8>> {
    let mut fields = Fields::new(payload);
    let full = fields.bytes(4)?;
    if full[0] > 1 || full[1..3] != [0, 0] || full[3] & !1 != 0 {
        return Err(blocked(
            "Unsupported item-property association version or flags",
        ));
    }
    let id_width = if full[0] == 0 { 2 } else { 4 };
    let association_width = if full[3] & 1 == 0 { 1 } else { 2 };
    let count = fields.number(4)? as usize;
    if count > limits.max_members {
        return Err(invalid(
            "Property association count exceeds the member limit",
        ));
    }
    let mut kept = Vec::new();
    let mut kept_count = 0u32;
    for _ in 0..count {
        let start = fields.cursor;
        let id = fields.number(id_width)? as u32;
        let associations = fields.number(1)? as usize;
        fields.bytes(associations * association_width)?;
        if !removed.contains(&id) {
            kept.extend_from_slice(&payload[start..fields.cursor]);
            kept_count += 1;
        }
    }
    fields.finish()?;
    let mut rebuilt = full.to_vec();
    rebuilt.extend_from_slice(&kept_count.to_be_bytes());
    rebuilt.extend_from_slice(&kept);
    box_bytes(*b"ipma", &rebuilt)
}

fn rewrite_iref(payload: &[u8], removed: &HashSet<u32>, limits: &Limits) -> Result<Vec<u8>> {
    let mut fields = Fields::new(payload);
    let version = fields.full_box()?;
    if version > 1 {
        return Err(blocked("Unsupported item-reference version"));
    }
    let width = if version == 0 { 2 } else { 4 };
    let mut rebuilt = payload[..4].to_vec();
    let mut count = 0;
    while fields.cursor < payload.len() {
        count += 1;
        if count > limits.max_members {
            return Err(invalid("Item references exceed the member limit"));
        }
        let header = Header::read(payload, fields.cursor, payload.len())?;
        let mut reference = Fields::new(&payload[header.payload..header.end]);
        let from = reference.number(width)? as u32;
        let to_count = reference.number(2)? as usize;
        if to_count > limits.max_members {
            return Err(invalid("Item reference targets exceed the member limit"));
        }
        let mut targets = Vec::new();
        let mut involved = removed.contains(&from);
        for _ in 0..to_count {
            let target = reference.number(width)? as u32;
            involved |= removed.contains(&target);
            if !removed.contains(&target) {
                targets.push(target);
            }
        }
        reference.finish()?;
        if involved && header.kind != *b"cdsc" {
            return Err(blocked(
                "A media item depends on selected metadata through a non-descriptive reference",
            ));
        }
        if !removed.contains(&from) && !targets.is_empty() {
            let mut retained = from.to_be_bytes()[4 - width..].to_vec();
            retained.extend_from_slice(&(targets.len() as u16).to_be_bytes());
            for target in targets {
                retained.extend_from_slice(&target.to_be_bytes()[4 - width..]);
            }
            rebuilt.extend_from_slice(&box_bytes(header.kind, &retained)?);
        }
        fields.cursor = header.end;
    }
    box_bytes(*b"iref", &rebuilt)
}

fn rebuild_tree(
    data: &[u8],
    parser: &Parser<'_>,
    index: usize,
    removed: &HashSet<u32>,
    limits: &Limits,
) -> Result<Vec<u8>> {
    let header = &parser.nodes[index].header;
    let payload = &data[header.payload..header.end];
    match &header.kind {
        b"iinf" => rewrite_iinf(data, parser, index, removed),
        b"iloc" => rewrite_iloc(payload, removed, limits),
        b"ipma" => rewrite_ipma(payload, removed, limits),
        b"iref" => rewrite_iref(payload, removed, limits),
        _ => {
            let children = child_indices(parser, index);
            if children.is_empty() {
                return Ok(data[header.start..header.end].to_vec());
            }
            let prefix_end = parser.nodes[children[0]].header.start;
            let mut rebuilt = data[header.payload..prefix_end].to_vec();
            for child in children {
                rebuilt.extend_from_slice(&rebuild_tree(data, parser, child, removed, limits)?);
            }
            box_bytes(header.kind, &rebuilt)
        }
    }
}

fn validate_dref(payload: &[u8], limits: &Limits) -> Result<()> {
    let mut fields = Fields::new(payload);
    if fields.full_box()? != 0 {
        return Err(blocked("Unsupported data-reference version"));
    }
    let count = fields.number(4)? as usize;
    if count > limits.max_members {
        return Err(invalid("Data references exceed the member limit"));
    }
    for _ in 0..count {
        let header = Header::read(payload, fields.cursor, payload.len())?;
        let value = &payload[header.payload..header.end];
        if !matches!(&header.kind, b"url " | b"alis") || value.get(..4) != Some(&[0, 0, 0, 1]) {
            return Err(blocked(
                "Externally referenced media is protected during rewriting",
            ));
        }
        fields.cursor = header.end;
    }
    fields.finish()
}

fn metadata_atom(kind: &[u8; 4]) -> bool {
    matches!(
        kind,
        b"XMP_"
            | b"xml "
            | b"Exif"
            | b"\xa9xyz"
            | b"loci"
            | b"\xa9day"
            | b"\xa9mak"
            | b"\xa9mod"
            | b"\xa9swr"
            | b"\xa9too"
            | b"\xa9ART"
            | b"\xa9aut"
            | b"auth"
            | b"cprt"
            | b"\xa9nam"
            | b"\xa9cmt"
            | b"\xa9des"
            | b"\xa9snm"
            | b"\xa9snb"
            | b"\xa9ser"
            | b"\xa9uid"
    )
}

fn rewrite_movie_meta(
    data: &[u8],
    parser: &Parser<'_>,
    index: usize,
    limits: &Limits,
) -> Result<Option<(Vec<u8>, BTreeSet<&'static str>)>> {
    let children = child_indices(parser, index);
    let key_nodes: Vec<_> = children
        .iter()
        .copied()
        .filter(|child| parser.nodes[*child].header.kind == *b"keys")
        .collect();
    if key_nodes.is_empty() {
        return Ok(None);
    }
    if key_nodes.len() != 1 {
        return Err(blocked(
            "Multiple QuickTime key tables are protected during rewriting",
        ));
    }
    let key_header = &parser.nodes[key_nodes[0]].header;
    let mut fields = Fields::new(&data[key_header.payload..key_header.end]);
    let full = fields.bytes(4)?;
    if full != [0, 0, 0, 0] {
        return Err(blocked("Unsupported QuickTime key-table version"));
    }
    let count = fields.number(4)? as usize;
    if count > limits.max_members {
        return Err(invalid("Metadata keys exceed the member limit"));
    }
    let mut kept = Vec::new();
    let mut mapping = BTreeMap::new();
    let mut retained_count = 0u32;
    let mut removed_codes = BTreeSet::from(["bmff.metadata.keys", "bmff.metadata.value"]);
    for old_index in 1..=count {
        let start = fields.cursor;
        let size = fields.number(4)? as usize;
        if size < 8 {
            return Err(invalid("Metadata key is smaller than its header"));
        }
        let namespace = fields.bytes(4)?;
        let name = fields.bytes(size - 8)?;
        if namespace != b"mdta" || !privacy_key(name) {
            retained_count += 1;
            mapping.insert(old_index as u32, retained_count);
            kept.extend_from_slice(&fields.data[start..fields.cursor]);
        } else {
            let key = String::from_utf8_lossy(name).to_ascii_lowercase();
            let code = if key.contains("location") || key.contains("gps") {
                "bmff.metadata.location"
            } else if key.contains("creationdate") || key.contains("creationtime") {
                "bmff.metadata.creation_time"
            } else if key.contains("serial") || key.contains("identifier") {
                "bmff.metadata.identifier"
            } else if key.ends_with(".make") || key.ends_with(".model") {
                "bmff.metadata.device"
            } else if key.contains("software") || key.contains("encoder") {
                "bmff.metadata.software"
            } else {
                "bmff.metadata.author"
            };
            removed_codes.insert(code);
        }
    }
    fields.finish()?;
    if retained_count as usize == count {
        return Ok(None);
    }
    let mut keys = full.to_vec();
    keys.extend_from_slice(&retained_count.to_be_bytes());
    keys.extend_from_slice(&kept);
    let header = &parser.nodes[index].header;
    let prefix_end = parser.nodes[*children
        .first()
        .ok_or_else(|| invalid("Empty metadata children"))?]
    .header
    .start;
    let mut rebuilt = data[header.payload..prefix_end].to_vec();
    for child in children {
        let child_header = &parser.nodes[child].header;
        match &child_header.kind {
            b"keys" => rebuilt.extend_from_slice(&box_bytes(*b"keys", &keys)?),
            b"ilst" => {
                let mut values = Vec::new();
                for value in child_indices(parser, child) {
                    let value_header = &parser.nodes[value].header;
                    let old = u32::from_be_bytes(value_header.kind);
                    if old == 0 || old as usize > count {
                        return Err(blocked(
                            "A QuickTime value has no corresponding metadata key",
                        ));
                    }
                    if let Some(new) = mapping.get(&old) {
                        values.extend_from_slice(&box_bytes(
                            new.to_be_bytes(),
                            &data[value_header.payload..value_header.end],
                        )?);
                    }
                }
                rebuilt.extend_from_slice(&box_bytes(*b"ilst", &values)?);
            }
            _ => rebuilt.extend_from_slice(&data[child_header.start..child_header.end]),
        }
    }
    Ok(Some((box_bytes(*b"meta", &rebuilt)?, removed_codes)))
}

fn timestamp_range(data: &[u8], header: &Header) -> Result<Range<usize>> {
    let version = *data
        .get(header.payload)
        .ok_or_else(|| invalid("Missing media-header version"))?;
    let width = match version {
        0 => 4,
        1 => 8,
        _ => return Err(blocked("Unsupported media-header version")),
    };
    let start = header.payload + 4;
    let end = start + 2 * width;
    if end > header.end {
        return Err(invalid("Truncated media timestamps"));
    }
    Ok(start..end)
}

fn validate_chunk_offsets(
    data: &[u8],
    header: &Header,
    media: &[Range<usize>],
    limits: &Limits,
) -> Result<()> {
    let mut fields = Fields::new(&data[header.payload..header.end]);
    if fields.full_box()? != 0 {
        return Err(blocked("Unsupported sample-offset table version"));
    }
    let count = fields.number(4)? as usize;
    if count > limits.max_members {
        return Err(invalid("Sample chunk offsets exceed the member limit"));
    }
    let width = if header.kind == *b"co64" { 8 } else { 4 };
    for _ in 0..count {
        let offset = usize::try_from(fields.number(width)?)
            .map_err(|_| invalid("Sample chunk offset overflow"))?;
        if !media.iter().any(|range| range.contains(&offset)) {
            return Err(blocked(
                "Media sample offsets outside media-data boxes are protected during rewriting",
            ));
        }
    }
    fields.finish()
}

pub(super) fn normalized(data: &[u8], format: Format, limits: &Limits) -> Result<Cleaned> {
    if data.len() as u64 > limits.max_file_bytes {
        return Err(invalid("Input exceeds the byte limit"));
    }
    let heif = matches!(format, Format::Heic | Format::Avif);
    let mut parser = Parser {
        data,
        limits,
        nodes: Vec::new(),
        items: 0,
        metadata_bytes: 0,
        heif,
    };
    parser.walk(0, data.len(), None, 0)?;
    let media: Vec<_> = parser
        .nodes
        .iter()
        .filter(|node| node.parent.is_none() && node.header.kind == *b"mdat")
        .map(|node| node.header.payload..node.header.end)
        .collect();
    if media.is_empty() && !parser.nodes.iter().any(|node| node.header.kind == *b"idat") {
        return Err(blocked(
            "Media rewriting requires locally stored encoded samples",
        ));
    }
    let mut result = Cleaned {
        bytes: data.to_vec(),
        codes: BTreeSet::new(),
        extra_findings: Vec::new(),
    };
    for node in &parser.nodes {
        let header = &node.header;
        match &header.kind {
            b"uuid" if data[header.payload - 16..header.payload] == C2PA_UUID => {
                return Err(blocked(
                    "C2PA media credentials protect the original asset binding from rewriting",
                ));
            }
            b"ipro" | b"sinf" | b"senc" | b"pssh" => {
                return Err(blocked("Encrypted or protected media is not rewritten"));
            }
            b"dref" => validate_dref(&data[header.payload..header.end], limits)?,
            b"stco" | b"co64" => validate_chunk_offsets(data, header, &media, limits)?,
            b"mvhd" | b"mdhd" | b"tkhd" => {
                let range = timestamp_range(data, header)?;
                if data[range.clone()].iter().any(|byte| *byte != 0) {
                    result.codes.insert("bmff.metadata.timestamps");
                }
                result.bytes[range].fill(0);
            }
            b"hdlr" if header.end - header.payload >= 24 => {
                let range = header.payload + 24..header.end;
                if data[range.clone()].iter().any(|byte| *byte != 0) {
                    result.extra_findings.push(finding(
                        header,
                        "bmff.metadata.handler_name",
                        "The optional media handler display name was selected for removal",
                        RiskLayer::EmbeddedMetadata,
                    ));
                    result.bytes[range].fill(0);
                }
            }
            b"stsd" => clean_sample_descriptions(&mut result, header, limits)?,
            b"free" | b"skip" => result.bytes[header.payload..header.end].fill(0),
            _ => {}
        }
    }
    // HEIF meta contains its image graph. Movie metadata has a separate key/value layout.
    // Clean descendants before reconstructing parents. A rebuilt key/value
    // metadata box must include the already-cleaned XMP and author children.
    for (index, node) in parser.nodes.iter().enumerate().rev() {
        let header = &node.header;
        if header.kind == *b"meta" && !heif {
            if let Some((rebuilt, codes)) =
                rewrite_movie_meta(&result.bytes, &parser, index, limits)?
            {
                install_box(&mut result.bytes, header, &rebuilt)?;
                result.codes.extend(codes);
            }
        } else if metadata_atom(&header.kind)
            || (header.kind == *b"uuid" && data[header.payload - 16..header.payload] == XMP_UUID)
        {
            if matches!(&header.kind, b"XMP_" | b"xml ") || header.kind == *b"uuid" {
                xmp_is_removable(&data[header.payload..header.end])?;
            }
            wipe_box(&mut result.bytes, header)?;
            result.codes.extend([
                "bmff.metadata.packet",
                "bmff.metadata.location",
                "bmff.metadata.creation_time",
                "bmff.metadata.device",
                "bmff.metadata.software",
                "bmff.metadata.author",
            ]);
        }
    }
    for finding in &mut result.extra_findings {
        finding.action = Action::Remove;
    }
    if heif {
        rewrite_heif(&mut result, &parser, &media, limits)?;
    }
    Ok(result)
}

fn sample_name_ranges(data: &[u8], header: &Header, limits: &Limits) -> Result<Vec<Range<usize>>> {
    let mut fields = Fields::new(&data[header.payload..header.end]);
    if fields.full_box()? != 0 {
        return Err(blocked("Unsupported sample-description version"));
    }
    let count = fields.number(4)? as usize;
    if count > limits.max_members {
        return Err(invalid("Sample descriptions exceed the member limit"));
    }
    let mut names = Vec::new();
    for _ in 0..count {
        let entry = Header::read(fields.data, fields.cursor, fields.data.len())?;
        if matches!(&entry.kind, b"encv" | b"enca") {
            return Err(blocked(
                "Encrypted media sample entries are protected during rewriting",
            ));
        }
        if matches!(
            &entry.kind,
            b"avc1"
                | b"avc3"
                | b"hvc1"
                | b"hev1"
                | b"av01"
                | b"vp09"
                | b"jpeg"
                | b"mjp2"
                | b"png "
                | b"raw "
        ) {
            if entry.end - entry.payload < 78 {
                return Err(invalid("Truncated visual sample entry"));
            }
            let range = header.payload + entry.payload + 42..header.payload + entry.payload + 74;
            if data[range.clone()].iter().any(|byte| *byte != 0) {
                names.push(range);
            }
        }
        fields.cursor = entry.end;
    }
    fields.finish()?;
    Ok(names)
}

fn clean_sample_descriptions(result: &mut Cleaned, header: &Header, limits: &Limits) -> Result<()> {
    let names = sample_name_ranges(&result.bytes, header, limits)?;
    if !names.is_empty() {
        result.extra_findings.push(finding(
            header,
            "bmff.metadata.encoder_name",
            "The optional visual sample compressor display name was selected for removal",
            RiskLayer::EmbeddedMetadata,
        ));
        for range in names {
            result.bytes[range].fill(0);
        }
    }
    Ok(())
}

fn rewrite_heif(
    result: &mut Cleaned,
    parser: &Parser<'_>,
    media: &[Range<usize>],
    limits: &Limits,
) -> Result<()> {
    let metas: Vec<_> = parser
        .nodes
        .iter()
        .enumerate()
        .filter_map(|(index, node)| {
            (node.parent.is_none() && node.header.kind == *b"meta").then_some(index)
        })
        .collect();
    if metas.len() != 1 {
        return Err(blocked(
            "Image rewriting requires exactly one top-level metadata container",
        ));
    }
    if parser
        .nodes
        .iter()
        .any(|node| node.parent.is_some() && node.header.kind == *b"meta")
    {
        return Err(blocked(
            "Nested image metadata namespaces require a namespace-aware rewrite backend",
        ));
    }
    let meta = metas[0];
    let mut kinds = BTreeMap::new();
    let mut located = BTreeMap::new();
    let mut idat = None;
    let mut removed = HashSet::new();
    for (index, node) in parser.nodes.iter().enumerate() {
        if parser.meta_parent(index) != Some(meta) {
            continue;
        }
        let header = &node.header;
        let payload = &parser.data[header.payload..header.end];
        match &header.kind {
            b"infe" => {
                let (id, kind, _) = item_info(payload)?;
                let id_width = if payload[0] == 2 { 2 } else { 4 };
                if payload[4 + id_width..6 + id_width] != [0, 0] {
                    return Err(blocked("Protected image items are not rewritten"));
                }
                if kinds.insert(id, kind).is_some() {
                    return Err(invalid("Duplicate item ID"));
                }
                let name_start = header.payload + 10 + id_width;
                let name_length = parser.data[name_start..header.end]
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or_else(|| invalid("Unterminated media item name"))?;
                if parser.data[name_start..name_start + name_length]
                    .iter()
                    .any(|byte| *byte != b' ')
                {
                    result.bytes[name_start..name_start + name_length].fill(b' ');
                    result.extra_findings.push(finding(
                        header,
                        "bmff.metadata.item_name",
                        "The optional image item display name was selected for removal",
                        RiskLayer::EmbeddedMetadata,
                    ));
                    result.extra_findings.last_mut().unwrap().action = Action::Remove;
                }
            }
            b"iloc" => {
                for location in locations(payload, limits.max_members)? {
                    if located.insert(location.id, location).is_some() {
                        return Err(invalid("Duplicate item location"));
                    }
                }
            }
            b"idat" if node.parent != Some(meta) => {
                return Err(blocked(
                    "Image item-data storage must be a direct metadata-container child",
                ));
            }
            b"idat" if idat.replace(header.payload..header.end).is_some() => {
                return Err(invalid("Multiple item-data containers"));
            }
            _ => {}
        }
    }
    if !kinds.values().any(|kind| *kind == ItemKind::Image) {
        return Err(blocked(
            "Image item graph does not contain a supported image item",
        ));
    }
    let mut protected = Vec::new();
    let mut selected = Vec::new();
    for (id, location) in &located {
        let kind = kinds
            .get(id)
            .ok_or_else(|| blocked("An item location has no supported item-information record"))?;
        let ranges = range_for_location(location, idat.as_ref(), parser.data.len())?;
        if location.method == 0
            && ranges.iter().any(|range| {
                !media
                    .iter()
                    .any(|payload| payload.start <= range.start && payload.end >= range.end)
            })
        {
            return Err(blocked(
                "Absolute image item extents outside media-data boxes are protected",
            ));
        }
        if matches!(kind, ItemKind::Exif | ItemKind::Xmp) {
            selected.push((*id, *kind, ranges));
        } else {
            protected.extend(ranges);
        }
    }
    for (id, kind) in &kinds {
        if matches!(kind, ItemKind::Exif | ItemKind::Xmp) && !located.contains_key(id) {
            return Err(blocked("Metadata item has no safely resolvable extent"));
        }
    }
    let all_selected: Vec<_> = selected
        .iter()
        .flat_map(|(_, _, ranges)| ranges.iter())
        .collect();
    for (index, range) in all_selected.iter().enumerate() {
        if protected.iter().any(|other| overlaps(range, other))
            || all_selected[..index]
                .iter()
                .any(|other| overlaps(range, other))
        {
            return Err(blocked(
                "Metadata shares encoded media or another metadata extent",
            ));
        }
    }
    for (id, kind, ranges) in selected {
        let payload: Vec<_> = ranges
            .iter()
            .flat_map(|range| parser.data[range.clone()].iter().copied())
            .collect();
        if payload.len() > limits.max_metadata_bytes {
            return Err(invalid("Metadata item exceeds the byte budget"));
        }
        if kind == ItemKind::Xmp {
            xmp_is_removable(&payload)?;
            removed.insert(id);
            result.codes.insert("bmff.metadata.xmp_item");
            for range in ranges {
                result.bytes[range].fill(0);
            }
        } else {
            let sanitized = technical_exif(&payload, limits)?;
            let mut retained = sanitized.unwrap_or_default();
            if retained.len() > payload.len() {
                return Err(blocked(
                    "Technical EXIF preservation exceeds the existing item extent",
                ));
            }
            retained.resize(payload.len(), 0);
            if retained != payload {
                result.codes.extend([
                    "bmff.metadata.exif_item",
                    "bmff.exif.identity",
                    "bmff.exif.gps",
                ]);
            }
            if retained.iter().all(|byte| *byte == 0) {
                removed.insert(id);
            }
            let mut cursor = 0;
            for range in ranges {
                let length = range.len();
                result.bytes[range].copy_from_slice(&retained[cursor..cursor + length]);
                cursor += length;
            }
        }
    }
    for node in &parser.nodes {
        if node.header.kind == *b"pitm" {
            let payload = &parser.data[node.header.payload..node.header.end];
            let mut fields = Fields::new(payload);
            let version = fields.full_box()?;
            let id = fields.number(if version == 0 {
                2
            } else if version == 1 {
                4
            } else {
                return Err(blocked("Unsupported primary item version"));
            })? as u32;
            fields.finish()?;
            if removed.contains(&id) {
                return Err(blocked("The primary image item is metadata-selected"));
            }
        }
    }
    if !removed.is_empty() {
        let rebuilt = rebuild_tree(&result.bytes, parser, meta, &removed, limits)?;
        install_box(&mut result.bytes, &parser.nodes[meta].header, &rebuilt)?;
    }
    Ok(())
}

/// Preserve presentation-sensitive EXIF fields while discarding identity,
/// capture data, MakerNotes, thumbnails and their old allocation bytes.
fn technical_exif(payload: &[u8], limits: &Limits) -> Result<Option<Vec<u8>>> {
    let offset = be32(
        payload
            .get(..4)
            .ok_or_else(|| invalid("EXIF item lacks a TIFF offset"))?,
    )? as usize;
    let tiff = payload
        .get(4 + offset..)
        .ok_or_else(|| invalid("EXIF TIFF offset is outside its item"))?;
    let mut inspected = Inspection::new(Format::Jpeg, String::new());
    crate::jpeg::inspect_exif(tiff, &mut inspected)?;
    let little = tiff.get(..2) == Some(b"II");
    let read16 = |start: usize| -> Result<u16> {
        let bytes: [u8; 2] = tiff
            .get(start..start + 2)
            .ok_or_else(|| invalid("Truncated TIFF field"))?
            .try_into()
            .unwrap();
        Ok(if little {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        })
    };
    let read32 = |start: usize| -> Result<u32> {
        let bytes: [u8; 4] = tiff
            .get(start..start + 4)
            .ok_or_else(|| invalid("Truncated TIFF field"))?
            .try_into()
            .unwrap();
        Ok(if little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    };
    let first = read32(4)? as usize;
    let mut pending = vec![first];
    let mut seen = BTreeSet::new();
    let mut values = BTreeMap::<u16, (u16, u32, Vec<u8>)>::new();
    while let Some(ifd) = pending.pop() {
        if !seen.insert(ifd) || seen.len() > 16 {
            return Err(invalid("Cyclic or excessive EXIF directories"));
        }
        let count = read16(ifd)? as usize;
        if count > limits.max_members {
            return Err(invalid("EXIF entries exceed the member limit"));
        }
        for index in 0..count {
            let start = ifd + 2 + index * 12;
            let tag = read16(start)?;
            let kind = read16(start + 2)?;
            let count = read32(start + 4)?;
            if tag == 0x8769 {
                pending.push(read32(start + 8)? as usize);
            }
            let value = match tag {
                0x0112 | 0xa001 => {
                    if kind != 3 || count != 1 {
                        return Err(blocked("Unsupported EXIF presentation field"));
                    }
                    read16(start + 8)?.to_le_bytes().to_vec()
                }
                0xa500 => {
                    if kind != 5 || count != 1 {
                        return Err(blocked("Unsupported EXIF gamma field"));
                    }
                    let offset = read32(start + 8)? as usize;
                    [
                        read32(offset)?.to_le_bytes(),
                        read32(offset + 4)?.to_le_bytes(),
                    ]
                    .concat()
                }
                0x8773 => {
                    if kind != 7 || count as usize > limits.max_metadata_bytes {
                        return Err(blocked("Unsupported EXIF color profile"));
                    }
                    let offset = if count <= 4 {
                        start + 8
                    } else {
                        read32(start + 8)? as usize
                    };
                    tiff.get(offset..offset + count as usize)
                        .ok_or_else(|| invalid("EXIF profile exceeds its container"))?
                        .to_vec()
                }
                _ => continue,
            };
            if let Some(previous) = values.insert(tag, (kind, count, value.clone()))
                && previous != (kind, count, value)
            {
                return Err(blocked("Conflicting EXIF presentation fields"));
            }
        }
    }
    if values.is_empty() {
        return Ok(None);
    }
    let mut primary = Vec::new();
    let mut exif = Vec::new();
    for (tag, entry) in values {
        if matches!(tag, 0xa001 | 0xa500) {
            exif.push((tag, entry));
        } else {
            primary.push((tag, entry));
        }
    }
    let primary_count = primary.len() + usize::from(!exif.is_empty());
    let exif_offset = 8 + 2 + primary_count * 12 + 4;
    if !exif.is_empty() {
        primary.push((0x8769, (4, 1, (exif_offset as u32).to_le_bytes().to_vec())));
    }
    primary.sort_by_key(|entry| entry.0);
    let data_offset = exif_offset
        + if exif.is_empty() {
            0
        } else {
            2 + exif.len() * 12 + 4
        };
    let mut tiff = b"II\x2a\0\x08\0\0\0".to_vec();
    let mut storage = Vec::new();
    for entries in [primary, exif] {
        if entries.is_empty() {
            continue;
        }
        tiff.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        for (tag, (kind, count, value)) in entries {
            tiff.extend_from_slice(&tag.to_le_bytes());
            tiff.extend_from_slice(&kind.to_le_bytes());
            tiff.extend_from_slice(&count.to_le_bytes());
            if value.len() <= 4 {
                tiff.extend_from_slice(&value);
                tiff.resize(tiff.len() + 4 - value.len(), 0);
            } else {
                tiff.extend_from_slice(&((data_offset + storage.len()) as u32).to_le_bytes());
                storage.extend_from_slice(&value);
            }
        }
        tiff.extend_from_slice(&0u32.to_le_bytes());
    }
    tiff.extend_from_slice(&storage);
    let mut result = vec![0; 4];
    result.extend_from_slice(&tiff);
    Ok(Some(result))
}

pub fn sanitize(data: &[u8], format: Format, limits: &Limits) -> Result<Vec<u8>> {
    inspect_structure(data, format, limits)?;
    normalized(data, format, limits).map(|result| result.bytes)
}

/// Hash media sample bytes and the presentation/codec fields independently of
/// the metadata reconstruction. No metadata-clearing operations run here.
pub fn retained_media_digest(data: &[u8], format: Format, limits: &Limits) -> Result<String> {
    inspect_structure(data, format, limits)?;
    let heif = matches!(format, Format::Heic | Format::Avif);
    let mut parser = Parser {
        data,
        limits,
        nodes: Vec::new(),
        items: 0,
        metadata_bytes: 0,
        heif,
    };
    parser.walk(0, data.len(), None, 0)?;
    let mut hash = Sha256::new();
    hash.update(b"FileVeil encoded media and presentation v1\0");
    let mut item_kinds = BTreeMap::new();
    let mut item_locations = BTreeMap::new();
    let mut item_data = BTreeMap::new();
    for (index, node) in parser.nodes.iter().enumerate() {
        let header = &node.header;
        let payload = &data[header.payload..header.end];
        if heif {
            match &header.kind {
                b"infe" => {
                    let (id, kind, _) = item_info(payload)?;
                    item_kinds.insert((parser.meta_parent(index), id), kind);
                }
                b"iloc" => {
                    for location in locations(payload, limits.max_members)? {
                        item_locations.insert((parser.meta_parent(index), location.id), location);
                    }
                }
                b"idat" => {
                    item_data.insert(parser.meta_parent(index), header.payload..header.end);
                }
                _ => {}
            }
        } else if header.kind == *b"mdat" {
            hash.update(b"mdat");
            hash.update((payload.len() as u64).to_be_bytes());
            hash.update(payload);
        }
        if matches!(
            &header.kind,
            b"ftyp"
                | b"ipco"
                | b"pitm"
                | b"stts"
                | b"ctts"
                | b"stsc"
                | b"stsz"
                | b"stz2"
                | b"stco"
                | b"co64"
                | b"stss"
                | b"sdtp"
                | b"elst"
                | b"tfhd"
                | b"tfdt"
                | b"trun"
                | b"sidx"
                | b"trex"
        ) {
            hash.update(header.kind);
            hash.update((payload.len() as u64).to_be_bytes());
            hash.update(payload);
        }
        if matches!(&header.kind, b"mvhd" | b"mdhd" | b"tkhd") {
            let times = timestamp_range(data, header)?;
            hash.update(header.kind);
            hash.update(&data[header.payload..times.start]);
            hash.update(&data[times.end..header.end]);
        }
        if header.kind == *b"hdlr" && payload.len() >= 24 {
            hash.update(b"handler-type");
            hash.update(&payload[..24]);
        }
        if header.kind == *b"stsd" {
            let mut descriptors = payload.to_vec();
            for range in sample_name_ranges(data, header, limits)? {
                descriptors[range.start - header.payload..range.end - header.payload].fill(0);
            }
            hash.update(b"sample-descriptions");
            hash.update(&descriptors);
        }
    }
    if heif {
        for (key, location) in item_locations {
            let kind = item_kinds
                .get(&key)
                .ok_or_else(|| invalid("Media location has no item description"))?;
            if matches!(kind, ItemKind::Exif | ItemKind::Xmp) {
                continue;
            }
            hash.update(b"item");
            hash.update(key.1.to_be_bytes());
            for range in range_for_location(&location, item_data.get(&key.0), data.len())? {
                hash.update((range.len() as u64).to_be_bytes());
                hash.update(&data[range]);
            }
        }
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub fn verify(
    before: &[u8],
    after: &[u8],
    format: Format,
    limits: &Limits,
) -> Result<crate::ScopedVerification> {
    let original = inspect(before, format, limits)?;
    let output = inspect(after, format, limits)?;
    if !original.rewrite_supported || !output.rewrite_supported {
        return Err(blocked(
            "Protected or unsupported media structures prevent rewrite verification",
        ));
    }
    let expected = sanitize(before, format, limits)?;
    if expected != after || original.content_digest != output.content_digest {
        return Err(Error::Verification("Media output differs from the selected metadata reconstruction or retained encoded payload".into()));
    }
    if retained_media_digest(before, format, limits)?
        != retained_media_digest(after, format, limits)?
    {
        return Err(Error::Verification(
            "Encoded media samples or presentation and codec fields changed".into(),
        ));
    }
    let mut findings = original.findings;
    for finding in &mut findings {
        if matches!(
            finding.action,
            Action::Remove | Action::Normalize | Action::Rebuild
        ) {
            finding.state = if output
                .findings
                .iter()
                .any(|remaining| remaining.code == finding.code)
            {
                FindingState::AppliedVerified
            } else {
                FindingState::RemovedVerified
            };
            finding.confidence = Confidence::Verified;
        } else if finding.state == FindingState::Present {
            finding.state = FindingState::Remains;
        }
    }
    Ok(crate::ScopedVerification {
        findings,
        warnings: vec!["Media verification checks the complete expected container reconstruction, unchanged encoded samples, image item presentation properties and video sample tables. Runtime decoding and unknown proprietary payload semantics are assessed separately.".into()],
        integrity: Integrity { parseable: true, content_equal: Some(true), ..Integrity::default() },
        result: Outcome::PartiallyVerified,
    })
}

// FVPROV1 45354 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJlOTZiNjE1ZDE1ODM0OWRlNzliODMwYmE2MjY4Y2U5MTRlNmZlZjdjYTNkODU3ZjRlMDA5ZjIyMGRkNTdiMjg1IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1mb3JtYXRzL3NyYy9ibWZmX3Jld3JpdGUucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI1YjYxYmI0YzQxYTE2OGViYTJkZDdhZGUxYTJiMzNkNWQyOTQwMDg2MWZkZjQ3NDI5OWY2ZDBhMGNjNjc0NzNkMjI5ZmM1ZWE0ODQwYzY5MTIxOTJlZjBjNDA3YjVjNTc0ODMwM2E0MTY0MWE1ZDFhMDc3ODRkYmJhMDg2YTEwNiJ9XX1d FVPROV1-END
