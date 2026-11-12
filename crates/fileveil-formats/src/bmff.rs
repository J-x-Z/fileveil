// SPDX-License-Identifier: MPL-2.0
//! Bounded, read-only ISO BMFF / QuickTime privacy structure inspection.
//! Brand registration follows MP4RA. Metadata layout follows Apple's QTFF and
//! HEIF item information/location boxes. No decoder, external URL or plugin runs.
use fileveil_core::{
    Action, Confidence, Error, Finding, Format, Inspection, Limits, Result, RiskLayer, digest,
};
use std::{collections::BTreeMap, ops::Range, path::Path};

#[path = "bmff_rewrite.rs"]
mod rewrite;
pub use rewrite::{retained_media_digest, sanitize, verify};

const MAX_DEPTH: usize = 32;

fn invalid(message: &str) -> Error {
    Error::Blocked(format!("Invalid or unsupported BMFF structure. {message}"))
}
fn be32(data: &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(
        data.try_into()
            .map_err(|_| invalid("Truncated 32-bit field"))?,
    ))
}

/// Inspect the declared brands, including compatible brands. Extensions never
/// override a contradictory file type declaration.
pub fn identify(data: &[u8], hint: &Path) -> Option<Format> {
    let header = Header::read(data, 0, data.len()).ok()?;
    if header.kind != *b"ftyp" {
        let legacy_mov = matches!(&header.kind, b"moov" | b"mdat" | b"wide")
            && hint
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("mov"));
        return legacy_mov.then_some(Format::Mov);
    }
    let payload = &data[header.payload..header.end];
    if payload.len() < 8 || !payload.len().is_multiple_of(4) {
        return None;
    }
    let brands = std::iter::once(&payload[..4]).chain(
        payload[8..]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|brand| brand.as_slice()),
    );
    if brands
        .clone()
        .any(|brand| matches!(brand, b"avif" | b"avis"))
    {
        return Some(Format::Avif);
    }
    if brands.clone().any(|brand| {
        matches!(
            brand,
            b"heic" | b"heix" | b"hevc" | b"hevx" | b"heim" | b"heis" | b"mif1" | b"msf1"
        )
    }) {
        return Some(Format::Heic);
    }
    if brands.clone().any(|brand| brand == b"qt  ") {
        return Some(Format::Mov);
    }
    if brands.clone().any(|brand| {
        matches!(
            brand,
            b"isom"
                | b"iso2"
                | b"iso3"
                | b"iso4"
                | b"iso5"
                | b"iso6"
                | b"iso7"
                | b"iso8"
                | b"iso9"
                | b"mp41"
                | b"mp42"
                | b"avc1"
                | b"M4V "
                | b"M4A "
                | b"3gp4"
                | b"3gp5"
                | b"3gp6"
        )
    }) {
        return Some(Format::Mp4);
    }
    None
}

#[derive(Clone)]
struct Header {
    kind: [u8; 4],
    start: usize,
    payload: usize,
    end: usize,
}
impl Header {
    fn read(data: &[u8], start: usize, end: usize) -> Result<Self> {
        let remaining = data
            .get(start..end)
            .ok_or_else(|| invalid("Box range is outside its parent"))?;
        if remaining.len() < 8 {
            return Err(invalid("Truncated header or unframed trailing bytes"));
        }
        let mut header_bytes = 8;
        let size = match be32(&remaining[..4])? {
            0 => remaining.len() as u64,
            1 => {
                header_bytes = 16;
                u64::from_be_bytes(
                    remaining
                        .get(8..16)
                        .ok_or_else(|| invalid("Truncated extended size"))?
                        .try_into()
                        .unwrap(),
                )
            }
            size => u64::from(size),
        };
        let kind = remaining[4..8].try_into().unwrap();
        if kind == *b"uuid" {
            header_bytes += 16;
        }
        let size =
            usize::try_from(size).map_err(|_| invalid("Box size exceeds addressable input"))?;
        if size < header_bytes || size > remaining.len() {
            return Err(invalid(
                "Box size is smaller than its header or exceeds its parent",
            ));
        }
        Ok(Self {
            kind,
            start,
            payload: start + header_bytes,
            end: start + size,
        })
    }
}

struct Node {
    header: Header,
    parent: Option<usize>,
}
struct Parser<'a> {
    data: &'a [u8],
    limits: &'a Limits,
    nodes: Vec<Node>,
    items: usize,
    metadata_bytes: usize,
    heif: bool,
}
impl<'a> Parser<'a> {
    fn charge(&mut self, count: usize) -> Result<()> {
        self.items = self
            .items
            .checked_add(count)
            .ok_or_else(|| invalid("Item count overflow"))?;
        if self.items > self.limits.max_members {
            return Err(invalid(
                "Box and item count exceeds the configured member limit",
            ));
        }
        Ok(())
    }
    fn metadata(&mut self, bytes: usize) -> Result<()> {
        self.metadata_bytes = self
            .metadata_bytes
            .checked_add(bytes)
            .ok_or_else(|| invalid("Metadata size overflow"))?;
        if self.metadata_bytes > self.limits.max_metadata_bytes {
            return Err(invalid(
                "Inspected metadata exceeds the configured metadata byte limit",
            ));
        }
        Ok(())
    }
    fn walk(
        &mut self,
        start: usize,
        end: usize,
        parent: Option<usize>,
        depth: usize,
    ) -> Result<usize> {
        if depth > MAX_DEPTH {
            return Err(invalid(
                "Container nesting exceeds the 32-level safety limit",
            ));
        }
        let mut cursor = start;
        let mut children = 0;
        while cursor < end {
            self.charge(1)?;
            let header = Header::read(self.data, cursor, end)?;
            let index = self.nodes.len();
            cursor = header.end;
            children += 1;
            let mut child_start = header.payload;
            let mut expected = None;
            let parent_is_list =
                parent.is_some_and(|parent| self.nodes[parent].header.kind == *b"ilst");
            let container = parent_is_list
                || matches!(
                    &header.kind,
                    b"moov"
                        | b"trak"
                        | b"mdia"
                        | b"minf"
                        | b"stbl"
                        | b"dinf"
                        | b"edts"
                        | b"udta"
                        | b"meta"
                        | b"ilst"
                        | b"mvex"
                        | b"moof"
                        | b"traf"
                        | b"mfra"
                        | b"iprp"
                        | b"ipco"
                        | b"iinf"
                );
            if header.kind == *b"meta" {
                let prefix = self
                    .data
                    .get(child_start..child_start + 4)
                    .filter(|_| child_start + 4 <= header.end)
                    .ok_or_else(|| invalid("Truncated metadata header"))?;
                if prefix == [0, 0, 0, 0] {
                    child_start += 4;
                } else if self.heif {
                    return Err(invalid(
                        "Unsupported HEIF metadata FullBox version or flags",
                    ));
                }
                // Older QuickTime meta atoms omit the FullBox prefix.
            }
            if header.kind == *b"iinf" {
                let payload = &self.data[header.payload..header.end];
                let mut reader = Fields::new(payload);
                let version = reader.full_box()?;
                expected = Some(match version {
                    0 => reader.number(2)? as usize,
                    1 => reader.number(4)? as usize,
                    _ => return Err(invalid("Unsupported item-information version")),
                });
                child_start += reader.cursor;
            }
            self.nodes.push(Node {
                header: header.clone(),
                parent,
            });
            if container {
                let actual = self.walk(child_start, header.end, Some(index), depth + 1)?;
                if expected.is_some_and(|expected| expected != actual) {
                    return Err(invalid(
                        "Item-information entry count does not match its children",
                    ));
                }
            }
        }
        Ok(children)
    }
    fn meta_parent(&self, node: usize) -> Option<usize> {
        let mut parent = self.nodes[node].parent;
        while let Some(index) = parent {
            if self.nodes[index].header.kind == *b"meta" {
                return Some(index);
            }
            parent = self.nodes[index].parent;
        }
        None
    }
    fn in_metadata_list(&self, node: usize) -> bool {
        let mut parent = self.nodes[node].parent;
        while let Some(index) = parent {
            if matches!(&self.nodes[index].header.kind, b"ilst" | b"udta") {
                return true;
            }
            parent = self.nodes[index].parent;
        }
        false
    }
}

struct Fields<'a> {
    data: &'a [u8],
    cursor: usize,
}
impl<'a> Fields<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, cursor: 0 }
    }
    fn bytes(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or_else(|| invalid("Field length overflow"))?;
        let bytes = self
            .data
            .get(self.cursor..end)
            .ok_or_else(|| invalid("Truncated box fields"))?;
        self.cursor = end;
        Ok(bytes)
    }
    fn number(&mut self, bytes: usize) -> Result<u64> {
        if bytes > 8 {
            return Err(invalid("Unsupported integer field width"));
        }
        Ok(self
            .bytes(bytes)?
            .iter()
            .fold(0, |value, byte| (value << 8) | u64::from(*byte)))
    }
    fn full_box(&mut self) -> Result<u8> {
        let header = self.bytes(4)?;
        if header[1..] != [0, 0, 0] {
            return Err(invalid("Unsupported FullBox flags"));
        }
        Ok(header[0])
    }
    fn terminated(&mut self) -> Result<&'a [u8]> {
        let end = self.data[self.cursor..]
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| invalid("Unterminated item-information text"))?;
        let value = self.bytes(end)?;
        self.bytes(1)?;
        Ok(value)
    }
    fn finish(&self) -> Result<()> {
        if self.cursor != self.data.len() {
            return Err(invalid("Unexpected trailing box fields"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ItemKind {
    Exif,
    Xmp,
    OtherMetadata,
    Image,
}
struct ItemLocation {
    id: u32,
    method: u64,
    external: bool,
    ranges: Vec<(u64, Option<u64>)>,
    encoded: Range<usize>,
}

fn item_info(payload: &[u8]) -> Result<(u32, ItemKind, bool)> {
    let mut fields = Fields::new(payload);
    let full_header = fields.bytes(4)?;
    let version = full_header[0];
    if full_header[1] != 0 || full_header[2] != 0 || full_header[3] & !1 != 0 {
        return Err(invalid("Unsupported item-information flags"));
    }
    let hidden = full_header[3] & 1 != 0;
    if !matches!(version, 2 | 3) {
        return Err(invalid(
            "Legacy item-information versions require an additional parser",
        ));
    }
    let id = fields.number(if version == 2 { 2 } else { 4 })? as u32;
    fields.number(2)?; // Item protection index is inspected separately by presence.
    let kind = fields.bytes(4)?;
    fields.terminated()?; // Item names are intentionally omitted from reports.
    let result = match kind {
        b"Exif" => ItemKind::Exif,
        b"mime" => {
            let content_type = fields.terminated()?;
            if fields.cursor < payload.len() {
                fields.terminated()?;
            }
            match content_type {
                b"application/rdf+xml" | b"application/xmp+xml" => ItemKind::Xmp,
                _ => ItemKind::OtherMetadata,
            }
        }
        b"uri " => {
            fields.terminated()?;
            ItemKind::OtherMetadata
        }
        b"hvc1" | b"av01" | b"grid" | b"iovl" | b"iden" | b"jpeg" | b"unci" => ItemKind::Image,
        _ => ItemKind::OtherMetadata,
    };
    fields.finish()?;
    Ok((id, result, hidden))
}

fn locations(payload: &[u8], maximum: usize) -> Result<Vec<ItemLocation>> {
    let mut fields = Fields::new(payload);
    let version = fields.full_box()?;
    if version > 2 {
        return Err(invalid("Unsupported item-location version"));
    }
    let sizes = fields.bytes(2)?;
    let offset_size = (sizes[0] >> 4) as usize;
    let length_size = (sizes[0] & 15) as usize;
    let base_size = (sizes[1] >> 4) as usize;
    let index_size = if version > 0 {
        (sizes[1] & 15) as usize
    } else {
        0
    };
    if [offset_size, length_size, base_size, index_size]
        .iter()
        .any(|size| *size > 8)
    {
        return Err(invalid("Item-location field width exceeds 64 bits"));
    }
    let count = fields.number(if version == 2 { 4 } else { 2 })? as usize;
    if count > maximum {
        return Err(invalid("Item-location count exceeds the member limit"));
    }
    let mut result = Vec::new();
    let mut extents = 0usize;
    for _ in 0..count {
        let encoded_start = fields.cursor;
        let id = fields.number(if version == 2 { 4 } else { 2 })? as u32;
        let method = if version > 0 { fields.number(2)? } else { 0 };
        if method > 2 {
            return Err(invalid(
                "Unsupported item construction method or reserved bits",
            ));
        }
        let external = fields.number(2)? != 0;
        let base = fields.number(base_size)?;
        let count = fields.number(2)? as usize;
        extents = extents
            .checked_add(count)
            .ok_or_else(|| invalid("Extent count overflow"))?;
        if extents > maximum {
            return Err(invalid("Item extents exceed the member limit"));
        }
        let mut ranges = Vec::new();
        for _ in 0..count {
            fields.number(index_size)?;
            let start = base
                .checked_add(fields.number(offset_size)?)
                .ok_or_else(|| invalid("Item-location offset overflow"))?;
            let length = if length_size == 0 {
                None
            } else {
                Some(fields.number(length_size)?)
            };
            ranges.push((start, length));
        }
        result.push(ItemLocation {
            id,
            method,
            external,
            ranges,
            encoded: encoded_start..fields.cursor,
        });
    }
    fields.finish()?;
    Ok(result)
}

fn finding(header: &Header, code: &str, summary: &str, layer: RiskLayer) -> Finding {
    let kind = header
        .kind
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let location = format!(
        "box@{}/type={kind}/bytes={}",
        header.start,
        header.end - header.start
    );
    let mut finding = Finding::new(code, layer, &location, summary, Action::Preserve);
    finding.confidence = Confidence::Verified;
    finding
}

fn keys(payload: &[u8], header: &Header, result: &mut Inspection, maximum: usize) -> Result<()> {
    let mut fields = Fields::new(payload);
    if fields.full_box()? != 0 {
        return Err(invalid("Unsupported metadata-key version"));
    }
    let count = fields.number(4)? as usize;
    if count > maximum {
        return Err(invalid("Metadata-key count exceeds the member limit"));
    }
    for _ in 0..count {
        let size = fields.number(4)? as usize;
        if size < 8 {
            return Err(invalid("Metadata-key entry is smaller than its header"));
        }
        fields.bytes(4)?; // Namespace.
        let key = fields.bytes(size - 8)?;
        let key = std::str::from_utf8(key)
            .map_err(|_| invalid("Metadata key is not UTF-8"))?
            .to_ascii_lowercase();
        let category = if key.contains("content.identifier") {
            Some((
                "bmff.metadata.content_pairing",
                "Content-pairing identifier is retained to preserve linked media playback",
            ))
        } else if key.contains("location") || key.contains("gps") {
            Some(("bmff.metadata.location", "Location metadata key is present"))
        } else if key.contains("creationdate") || key.contains("creationtime") {
            Some((
                "bmff.metadata.creation_time",
                "Capture or creation-time metadata key is present",
            ))
        } else if key.contains("serial") || key.contains("identifier") {
            Some((
                "bmff.metadata.identifier",
                "Device or content-identifier metadata key is present",
            ))
        } else if key.ends_with(".make") || key.ends_with(".model") {
            Some((
                "bmff.metadata.device",
                "Device manufacturer or model metadata key is present",
            ))
        } else if key.contains("software") || key.contains("encoder") {
            Some((
                "bmff.metadata.software",
                "Software or encoder metadata key is present",
            ))
        } else {
            None
        };
        if let Some((code, summary)) = category {
            result
                .findings
                .push(finding(header, code, summary, RiskLayer::EmbeddedMetadata));
        }
    }
    fields.finish()
}

/// Audit container structure and recognized metadata. Media samples, proprietary
/// payloads and encoded image signals remain outside the verification scope.
fn inspect_structure(data: &[u8], format: Format, limits: &Limits) -> Result<Inspection> {
    if data.len() as u64 > limits.max_file_bytes {
        return Err(invalid("Input exceeds the byte limit"));
    }
    if !matches!(
        format,
        Format::Heic | Format::Avif | Format::Mp4 | Format::Mov
    ) {
        return Err(Error::Unsupported(
            "BMFF inspection requires a supported media container".into(),
        ));
    }
    let mut parser = Parser {
        data,
        limits,
        nodes: Vec::new(),
        items: 0,
        metadata_bytes: 0,
        heif: matches!(format, Format::Heic | Format::Avif),
    };
    parser.walk(0, data.len(), None, 0)?;
    if !parser.nodes.iter().any(|node| match format {
        Format::Heic | Format::Avif => node.parent.is_none() && node.header.kind == *b"meta",
        _ => node.parent.is_none() && node.header.kind == *b"moov",
    }) {
        return Err(invalid(
            "Required top-level movie or image metadata container is missing",
        ));
    }
    let mut result = Inspection::new(format, digest(data));
    result.rewrite_supported = false;
    result.limited_support = true;
    let mut information = BTreeMap::new();
    let mut item_locations = BTreeMap::new();
    let mut idat = BTreeMap::<usize, Range<usize>>::new();
    for index in 0..parser.nodes.len() {
        let header = parser.nodes[index].header.clone();
        let payload = &data[header.payload..header.end];
        match &header.kind {
            b"ftyp" => {
                if payload.len() < 8 || !payload.len().is_multiple_of(4) {
                    return Err(invalid("Invalid file-type brand table"));
                }
                parser.metadata(payload.len())?;
            }
            b"infe" => {
                parser.metadata(payload.len())?;
                let parent = parser
                    .meta_parent(index)
                    .ok_or_else(|| invalid("Item information is outside a metadata container"))?;
                let (id, kind, hidden) = item_info(payload)?;
                if hidden {
                    result.findings.push(finding(&header, "bmff.structure.hidden_item", "An item is marked hidden by the container. This standard flag alone establishes no watermark", RiskLayer::ContainerStructure));
                }
                if information
                    .insert((parent, id), (kind, header.clone()))
                    .is_some()
                {
                    return Err(invalid("Duplicate item-information ID"));
                }
            }
            b"iloc" => {
                parser.metadata(payload.len())?;
                let parent = parser
                    .meta_parent(index)
                    .ok_or_else(|| invalid("Item locations are outside a metadata container"))?;
                for location in locations(payload, limits.max_members)? {
                    parser.charge(location.ranges.len() + 1)?;
                    if item_locations
                        .insert((parent, location.id), location)
                        .is_some()
                    {
                        return Err(invalid("Duplicate item-location ID"));
                    }
                }
            }
            b"idat" => {
                let parent = parser
                    .meta_parent(index)
                    .ok_or_else(|| invalid("Item data is outside a metadata container"))?;
                if idat.insert(parent, header.payload..header.end).is_some() {
                    return Err(invalid(
                        "Multiple item-data boxes in one metadata container",
                    ));
                }
            }
            b"keys" => {
                parser.metadata(payload.len())?;
                result.findings.push(finding(
                    &header,
                    "bmff.metadata.keys",
                    "Metadata key table is present. Field values are omitted",
                    RiskLayer::EmbeddedMetadata,
                ));
                keys(payload, &header, &mut result, limits.max_members)?;
            }
            b"mvhd" | b"tkhd" | b"mdhd" => {
                let mut fields = Fields::new(payload);
                let version = fields.full_box_version()?;
                if version > 1 {
                    return Err(invalid("Unsupported media-header version"));
                }
                let size = if version == 1 { 8 } else { 4 };
                let created = fields.number(size)?;
                let modified = fields.number(size)?;
                if created != 0 || modified != 0 {
                    result.findings.push(finding(
                        &header,
                        "bmff.metadata.timestamps",
                        "Container creation or modification timestamps are present",
                        RiskLayer::EmbeddedMetadata,
                    ));
                }
            }
            b"uuid" => {
                parser.metadata(payload.len())?;
                let uuid = &data[header.payload - 16..header.payload];
                if uuid == rewrite::C2PA_UUID {
                    result.findings.push(finding(&header, "bmff.provenance", "A standard C2PA UUID container is present. Cryptographic results are reported separately", RiskLayer::ProvenanceCredential));
                } else if uuid == rewrite::XMP_UUID {
                    result.findings.push(finding(
                        &header,
                        "bmff.metadata.packet",
                        "A standard XMP UUID metadata packet is present",
                        RiskLayer::EmbeddedMetadata,
                    ));
                } else {
                    result.findings.push(finding(&header, "bmff.structure.uuid", "UUID extension payload is present. Its private meaning and tracking capability are unassessed", RiskLayer::ContainerStructure));
                }
            }
            b"XMP_" | b"xml " | b"Exif" => {
                parser.metadata(payload.len())?;
                result.findings.push(finding(
                    &header,
                    "bmff.metadata.packet",
                    "Embedded XML, XMP or EXIF metadata packet is present",
                    RiskLayer::EmbeddedMetadata,
                ));
            }
            b"\xa9xyz" | b"loci" => {
                parser.metadata(payload.len())?;
                result.findings.push(finding(
                    &header,
                    "bmff.metadata.location",
                    "Geographic location metadata field is present",
                    RiskLayer::EmbeddedMetadata,
                ));
            }
            b"\xa9day" => {
                parser.metadata(payload.len())?;
                result.findings.push(finding(
                    &header,
                    "bmff.metadata.creation_time",
                    "Capture or creation-date metadata field is present",
                    RiskLayer::EmbeddedMetadata,
                ));
            }
            b"\xa9mak" | b"\xa9mod" => {
                parser.metadata(payload.len())?;
                result.findings.push(finding(
                    &header,
                    "bmff.metadata.device",
                    "Device manufacturer or model metadata field is present",
                    RiskLayer::EmbeddedMetadata,
                ));
            }
            b"\xa9swr" | b"\xa9too" => {
                parser.metadata(payload.len())?;
                result.findings.push(finding(
                    &header,
                    "bmff.metadata.software",
                    "Software or encoder metadata field is present",
                    RiskLayer::EmbeddedMetadata,
                ));
            }
            b"\xa9ART" | b"\xa9aut" | b"auth" | b"cprt" => {
                parser.metadata(payload.len())?;
                result.findings.push(finding(
                    &header,
                    "bmff.metadata.author",
                    "Author, artist or copyright metadata field is present",
                    RiskLayer::EmbeddedMetadata,
                ));
            }
            b"data" | b"name" | b"mean" if parser.in_metadata_list(index) => {
                parser.metadata(payload.len())?;
                result.findings.push(finding(
                    &header,
                    "bmff.metadata.value",
                    "Metadata value or custom field is present. Values are omitted",
                    RiskLayer::EmbeddedMetadata,
                ));
            }
            b"dref" | b"ipro" | b"sinf" => {
                result.findings.push(finding(&header, "bmff.structure.references_or_protection", "Data references or protection structures require additional interpretation. External resources are never opened", RiskLayer::ContainerStructure));
            }
            kind if !known_box(kind)
                && !parser.nodes[index]
                    .parent
                    .is_some_and(|parent| parser.nodes[parent].header.kind == *b"ilst") =>
            {
                result.findings.push(finding(&header, "bmff.structure.unknown_box", "Uninterpreted box is present. Structure and offset alone establish no watermark or manufacturer attribution", RiskLayer::ContainerStructure));
            }
            _ => {}
        }
    }
    for ((parent, id), location) in &item_locations {
        if location.external || location.method == 2 {
            let header = &parser.nodes[*parent].header;
            result.findings.push(finding(header, "bmff.structure.unresolved_item", "An externally referenced or item-relative extent is unassessed. No external resource was accessed", RiskLayer::ContainerStructure));
            continue;
        }
        let source = if location.method == 1 {
            idat.get(parent)
                .cloned()
                .ok_or_else(|| invalid("Item references missing item-data storage"))?
        } else {
            0..data.len()
        };
        let metadata = information.get(&(*parent, *id));
        let mut collected = Vec::new();
        for (offset, length) in &location.ranges {
            let offset = usize::try_from(*offset)
                .map_err(|_| invalid("Item offset exceeds addressable input"))?;
            let start = source
                .start
                .checked_add(offset)
                .filter(|start| *start <= source.end)
                .ok_or_else(|| invalid("Item extent starts outside its data source"))?;
            let end = match length {
                Some(0) | None => source.end,
                Some(length) => start
                    .checked_add(
                        usize::try_from(*length)
                            .map_err(|_| invalid("Item extent is too large"))?,
                    )
                    .filter(|end| *end <= source.end)
                    .ok_or_else(|| invalid("Item extent exceeds its data source"))?,
            };
            if metadata.is_some_and(|(kind, _)| !matches!(kind, ItemKind::Image)) {
                parser.metadata(end - start)?;
                collected.extend_from_slice(&data[start..end]);
            }
        }
        if let Some((kind, header)) = metadata {
            match kind {
                ItemKind::Exif => {
                    result.findings.push(finding(header, "bmff.metadata.exif_item", "HEIF EXIF metadata item is present", RiskLayer::EmbeddedMetadata));
                    let offset = be32(collected.get(..4).ok_or_else(|| invalid("EXIF item lacks its TIFF offset"))?)? as usize;
                    let start = 4usize.checked_add(offset).ok_or_else(|| invalid("EXIF TIFF offset overflow"))?;
                    let tiff = collected.get(start..).ok_or_else(|| invalid("EXIF TIFF offset is outside the metadata item"))?;
                    let mut exif = Inspection::new(format, String::new());
                    crate::jpeg::inspect_exif(tiff, &mut exif)?;
                    for mut entry in exif.findings {
                        entry.code = entry.code.replacen("jpeg.exif", "bmff.exif", 1);
                        entry.location = format!(
                            "box@{}/Exif/{}",
                            header.start,
                            entry.location.strip_prefix("APP1/Exif/").unwrap_or(&entry.location)
                        );
                        entry.action = Action::Preserve;
                        result.findings.push(entry);
                    }
                }
                ItemKind::Xmp => result.findings.push(finding(header, "bmff.metadata.xmp_item", "HEIF XMP metadata item is present", RiskLayer::EmbeddedMetadata)),
                ItemKind::OtherMetadata => result.findings.push(finding(header, "bmff.metadata.private_item", "A MIME, URI or unknown item type may carry private metadata. Its contents are unassessed", RiskLayer::EmbeddedMetadata)),
                ItemKind::Image => {}
            }
        }
    }
    for ((parent, id), (kind, header)) in &information {
        if !matches!(kind, ItemKind::Image) && !item_locations.contains_key(&(*parent, *id)) {
            result.findings.push(finding(
                header,
                "bmff.structure.unresolved_item",
                "Metadata item has no resolvable location. Its payload is unassessed",
                RiskLayer::ContainerStructure,
            ));
        }
    }
    result.findings.push(Finding::unassessed("bmff.audit.scope", RiskLayer::ContainerStructure, "container", "Read-only structure audit. Media decode, proprietary fields, timed tracks, signal watermarks and safe rewriting are unassessed"));
    if result.findings.len() > limits.max_members {
        return Err(invalid("Findings exceed the configured report limit"));
    }
    Ok(result)
}

/// Recognized privacy fields are rewritten without relocating encoded media.
/// Unsupported or protected layouts retain a read-only structural report.
pub fn inspect(data: &[u8], format: Format, limits: &Limits) -> Result<Inspection> {
    let mut result = inspect_structure(data, format, limits)?;
    match rewrite::normalized(data, format, limits) {
        Ok(cleaned) => {
            result.content_digest = digest(&cleaned.bytes);
            result.rewrite_supported = true;
            for finding in &mut result.findings {
                if cleaned.codes.contains(finding.code.as_str()) {
                    finding.action = if finding.code == "bmff.metadata.exif_item" {
                        Action::Rebuild
                    } else {
                        Action::Remove
                    };
                }
            }
            result.findings.extend(cleaned.extra_findings);
            result
                .findings
                .retain(|finding| finding.code != "bmff.audit.scope");
            result.findings.push(Finding::unassessed("bmff.audit.scope", RiskLayer::ContainerStructure,
                "container", "Metadata rewrite preserves encoded media, item presentation properties and sample tables. Proprietary payload meanings and signal watermarks remain unassessed"));
        }
        Err(error) => result.blockers.push(error.to_string()),
    }
    Ok(result)
}

impl Fields<'_> {
    fn full_box_version(&mut self) -> Result<u8> {
        Ok(self.bytes(4)?[0])
    }
}

fn known_box(kind: &[u8; 4]) -> bool {
    matches!(
        kind,
        b"ftyp"
            | b"moov"
            | b"trak"
            | b"mdia"
            | b"minf"
            | b"stbl"
            | b"dinf"
            | b"edts"
            | b"udta"
            | b"meta"
            | b"ilst"
            | b"mvex"
            | b"moof"
            | b"traf"
            | b"mfra"
            | b"iprp"
            | b"ipco"
            | b"iinf"
            | b"infe"
            | b"iloc"
            | b"idat"
            | b"pitm"
            | b"iref"
            | b"ipma"
            | b"ispe"
            | b"pixi"
            | b"hvcC"
            | b"av1C"
            | b"colr"
            | b"auxC"
            | b"clap"
            | b"irot"
            | b"imir"
            | b"mdat"
            | b"free"
            | b"skip"
            | b"wide"
            | b"hdlr"
            | b"stsd"
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
            | b"vmhd"
            | b"smhd"
            | b"nmhd"
            | b"hmhd"
            | b"mehd"
            | b"trex"
            | b"mfhd"
            | b"tfhd"
            | b"tfdt"
            | b"trun"
            | b"tfra"
            | b"mfro"
            | b"sidx"
            | b"ssix"
    )
}
