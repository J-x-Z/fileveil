// SPDX-License-Identifier: MPL-2.0
//! Bounded OPC/OOXML inspection and conservative property-only rewriting.
//! Package members are never extracted to the filesystem.
#[path = "deep.rs"]
mod deep;
pub use deep::{inspect_with_options, sanitize_with_options, verify_scoped};
use fileveil_core::{
    Action, Error, Finding, Format, FormatAdapter, Inspection, Limits, Result, RiskLayer,
};
use quick_xml::{XmlVersion, events::Event, name::ResolveResult, reader::NsReader};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Read, Write},
};
use unicode_normalization::UnicodeNormalization;
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter, write::SimpleFileOptions};

const CT_NS: &str = "http://schemas.openxmlformats.org/package/2006/content-types";
const REL_NS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
const CORE_NS: &str = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties";
const DC_NS: &str = "http://purl.org/dc/elements/1.1/";
const DCT_NS: &str = "http://purl.org/dc/terms/";
const APP_NS: &str = "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties";
const CUSTOM_NS: &str = "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties";
const OFFICE_REL: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument";
const STRICT_OFFICE_REL: &str =
    "http://purl.oclc.org/ooxml/officeDocument/relationships/officeDocument";
const CORE_CT: &str = "application/vnd.openxmlformats-package.core-properties+xml";
const APP_CT: &str = "application/vnd.openxmlformats-officedocument.extended-properties+xml";
const CUSTOM_CT: &str = "application/vnd.openxmlformats-officedocument.custom-properties+xml";

pub struct OoxmlAdapter;

struct Part {
    name: String,
    data: Vec<u8>,
    directory: bool,
    compression: CompressionMethod,
    permissions: u32,
}
struct Package {
    parts: Vec<Part>,
    zip_metadata: bool,
    blockers: Vec<String>,
}
#[derive(Clone, Copy)]
enum PropertyKind {
    Core,
    App,
    Custom,
}
struct PropertyResult {
    cleaned: Vec<u8>,
    fields: BTreeSet<String>,
    unknown: bool,
}
struct Relationship {
    kind: String,
    target: String,
    external: bool,
}
struct ContentTypes {
    defaults: BTreeMap<String, String>,
    overrides: BTreeMap<String, String>,
}

impl FormatAdapter for OoxmlAdapter {
    fn inspect(&self, data: &[u8], limits: &Limits) -> Result<Inspection> {
        let package = read_package(data, limits)?;
        inspect_package(&package, limits)
    }

    fn sanitize(&self, data: &[u8], limits: &Limits) -> Result<Vec<u8>> {
        let package = read_package(data, limits)?;
        let inspection = inspect_package(&package, limits)?;
        if !inspection.blockers.is_empty() {
            return Err(Error::Blocked(inspection.blockers.join(". ")));
        }
        let types = content_types(&package)?;
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for part in &package.parts {
            let options = SimpleFileOptions::default()
                .compression_method(part.compression)
                .last_modified_time(DateTime::default())
                .unix_permissions(part.permissions);
            if part.directory {
                writer
                    .add_directory(&part.name, options)
                    .map_err(zip_error)?;
                continue;
            }
            let cleaned;
            let bytes = if let Some(kind) = property_kind(types.for_part(&part.name)?) {
                cleaned = clean_properties(&part.data, kind, limits)?.cleaned;
                cleaned.as_slice()
            } else {
                &part.data
            };
            writer.start_file(&part.name, options).map_err(zip_error)?;
            writer
                .write_all(bytes)
                .map_err(|_| Error::Io("Could not write OOXML output".into()))?;
        }
        Ok(writer.finish().map_err(zip_error)?.into_inner())
    }
}

fn zip_error(_: zip::result::ZipError) -> Error {
    Error::Blocked("Invalid, encrypted, unsupported, or inconsistent ZIP structure".into())
}
fn xml_error() -> Error {
    Error::Blocked("Invalid or unsupported OOXML XML structure".into())
}

fn read_package(data: &[u8], limits: &Limits) -> Result<Package> {
    if data.len() as u64 > limits.max_file_bytes {
        return Err(Error::Blocked(
            "ZIP file exceeds the input byte limit".into(),
        ));
    }
    validate_end_record(data)?;
    let mut zip = ZipArchive::new(Cursor::new(data)).map_err(zip_error)?;
    if zip.len() > limits.max_members {
        return Err(Error::Blocked("ZIP member count exceeds the limit".into()));
    }
    if zip.offset() != 0
        || zip.has_duplicate_names()
        || zip.has_overlapping_entries().map_err(zip_error)?
    {
        return Err(Error::Blocked(
            "ZIP has a prefix, duplicate members, or overlapping entries".into(),
        ));
    }
    zip.validate_header_consistency().map_err(zip_error)?;
    let mut zip_metadata = !zip.comment().is_empty();
    let mut parts = Vec::with_capacity(zip.len());
    let mut aliases = BTreeSet::new();
    let mut total = 0_u64;
    let mut blockers = Vec::new();
    for index in 0..zip.len() {
        let mut file = zip.by_index(index).map_err(zip_error)?;
        let name = file.name().map_err(zip_error)?.into_owned();
        validate_name(&name, file.is_dir())?;
        let alias: String = name.nfkc().flat_map(char::to_lowercase).collect();
        if !aliases.insert(alias) {
            return Err(Error::Blocked(
                "ZIP contains case or Unicode-normalization collisions".into(),
            ));
        }
        if file.encrypted()
            || file
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err(Error::Blocked(
                "Encrypted ZIP members and symbolic links are unsupported".into(),
            ));
        }
        total = total
            .checked_add(file.size())
            .ok_or_else(|| Error::Blocked("ZIP expansion size overflow".into()))?;
        if total > limits.max_uncompressed_bytes
            || file.size()
                > file
                    .compressed_size()
                    .max(1)
                    .saturating_mul(limits.max_compression_ratio)
        {
            return Err(Error::Blocked(
                "ZIP expansion exceeds the byte or compression-ratio limit".into(),
            ));
        }
        zip_metadata |= file
            .last_modified()
            .is_some_and(|date| date != DateTime::default())
            || !file.comment().is_empty();
        if let Some(extra) = file.extra_data() {
            let mut offset = 0;
            while offset < extra.len() {
                if extra.len() - offset < 4 {
                    return Err(Error::Blocked("Truncated ZIP extra field".into()));
                }
                let tag = u16::from_le_bytes([extra[offset], extra[offset + 1]]);
                let len = u16::from_le_bytes([extra[offset + 2], extra[offset + 3]]) as usize;
                offset += 4;
                if len > extra.len() - offset {
                    return Err(Error::Blocked("Invalid ZIP extra-field length".into()));
                }
                if !matches!(tag, 0x0001 | 0x5455 | 0x000a | 0x7875 | 0x7075 | 0x6375) {
                    blockers.push("Unknown ZIP extra fields require an explicitly supported preservation strategy".into());
                } else if tag != 0x0001 {
                    zip_metadata = true;
                }
                offset += len;
            }
        }
        let expected = file.size();
        let mut bytes = Vec::new();
        (&mut file)
            .take(expected + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Blocked("ZIP decompression or CRC validation failed".into()))?;
        if bytes.len() as u64 != expected {
            return Err(Error::Blocked("ZIP member size mismatch".into()));
        }
        if name.ends_with(".xml") || name.ends_with(".rels") {
            validate_xml(&bytes)?;
        }
        parts.push(Part {
            name,
            data: bytes,
            directory: file.is_dir(),
            compression: file.compression(),
            permissions: file.unix_mode().unwrap_or(0o600) & 0o777,
        });
    }
    Ok(Package {
        parts,
        zip_metadata,
        blockers,
    })
}

fn validate_end_record(data: &[u8]) -> Result<()> {
    if !data.starts_with(b"PK\x03\x04") {
        return Err(Error::Unsupported(
            "Input is not an OOXML ZIP package".into(),
        ));
    }
    let start = data.len().saturating_sub(65_557);
    let offset = data[start..]
        .windows(4)
        .rposition(|w| w == b"PK\x05\x06")
        .map(|p| start + p)
        .ok_or_else(|| Error::Blocked("ZIP end record is missing".into()))?;
    if data.len() - offset < 22 {
        return Err(Error::Blocked("ZIP end record is truncated".into()));
    }
    let comment = u16::from_le_bytes([data[offset + 20], data[offset + 21]]) as usize;
    if offset + 22 + comment != data.len() {
        return Err(Error::Blocked("ZIP trailing data is unsupported".into()));
    }
    if data[offset + 4..offset + 8] != [0, 0, 0, 0] {
        return Err(Error::Blocked(
            "Multi-disk ZIP archives are unsupported".into(),
        ));
    }
    Ok(())
}

fn validate_name(name: &str, directory: bool) -> Result<()> {
    let path = if directory {
        name.strip_suffix('/').unwrap_or(name)
    } else {
        name
    };
    if path.is_empty()
        || path.starts_with('/')
        || path.contains(['\\', ':', '\0', '%', '?', '#'])
        || path.chars().any(char::is_control)
        || path.split('/').any(|piece| {
            piece.is_empty() || matches!(piece, "." | "..") || piece.ends_with([' ', '.'])
        })
    {
        return Err(Error::Blocked(
            "ZIP member path is unsafe or ambiguous".into(),
        ));
    }
    Ok(())
}

fn validate_xml(data: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(data)
        .map_err(|_| Error::Unsupported("OOXML XML must be UTF-8 in this version".into()))?;
    if text.chars().any(|c| !valid_xml_char(c)) {
        return Err(xml_error());
    }
    let mut reader = NsReader::from_str(text);
    let mut depth = 0_usize;
    let mut roots = 0;
    loop {
        let event = reader.read_event().map_err(|_| xml_error())?;
        match event {
            Event::Start(ref element) | Event::Empty(ref element) => {
                let (ns, _) = reader.resolver().resolve_element(element.name());
                if matches!(ns, ResolveResult::Unknown(_)) {
                    return Err(xml_error());
                }
                if depth == 0 {
                    roots += 1;
                }
                for attribute in element.attributes() {
                    let attribute = attribute.map_err(|_| xml_error())?;
                    if attribute.key.as_ref() != "xmlns"
                        && !attribute.key.as_ref().starts_with("xmlns:")
                    {
                        let (ns, _) = reader.resolver().resolve_attribute(attribute.key);
                        if matches!(ns, ResolveResult::Unknown(_)) {
                            return Err(xml_error());
                        }
                        attribute
                            .normalized_value(XmlVersion::Implicit1_0)
                            .map_err(|_| xml_error())?;
                    }
                }
                if matches!(event, Event::Start(_)) {
                    depth += 1;
                }
                if depth > 128 {
                    return Err(Error::Blocked("OOXML XML nesting exceeds the limit".into()));
                }
            }
            Event::End(_) => {
                depth = depth.checked_sub(1).ok_or_else(xml_error)?;
            }
            Event::DocType(_) => {
                return Err(Error::Blocked(
                    "OOXML DTD declarations are forbidden".into(),
                ));
            }
            Event::GeneralRef(reference) => {
                let value = reference.as_ref();
                if reference.is_char_ref() {
                    let value = reference
                        .resolve_char_ref()
                        .map_err(|_| xml_error())?
                        .ok_or_else(xml_error)?;
                    if !valid_xml_char(value) {
                        return Err(xml_error());
                    }
                } else if !matches!(value, "amp" | "lt" | "gt" | "apos" | "quot") {
                    return Err(Error::Blocked("OOXML custom entities are forbidden".into()));
                }
            }
            Event::Text(text)
                if depth == 0 && !text.as_ref().trim_matches('\u{feff}').trim().is_empty() =>
            {
                return Err(xml_error());
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if depth != 0 || roots != 1 {
        return Err(xml_error());
    }
    Ok(())
}

fn valid_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r') || (c >= ' ' && c != '\u{fffe}' && c != '\u{ffff}')
}

fn part<'a>(package: &'a Package, name: &str) -> Option<&'a Part> {
    package
        .parts
        .iter()
        .find(|part| part.name == name && !part.directory)
}
fn attributes(element: &quick_xml::events::BytesStart<'_>) -> Result<BTreeMap<String, String>> {
    element
        .attributes()
        .map(|attribute| {
            let attribute = attribute.map_err(|_| xml_error())?;
            Ok((
                attribute.key.as_ref().to_string(),
                attribute
                    .normalized_value(XmlVersion::Implicit1_0)
                    .map_err(|_| xml_error())?
                    .into_owned(),
            ))
        })
        .collect()
}

fn content_types(package: &Package) -> Result<ContentTypes> {
    let document = part(package, "[Content_Types].xml").ok_or_else(|| {
        Error::Unsupported("ZIP does not contain an OOXML content-type manifest".into())
    })?;
    let mut reader =
        NsReader::from_str(std::str::from_utf8(&document.data).map_err(|_| xml_error())?);
    let mut result = ContentTypes {
        defaults: BTreeMap::new(),
        overrides: BTreeMap::new(),
    };
    let mut depth = 0;
    loop {
        let event = reader.read_event().map_err(|_| xml_error())?;
        if let Event::Start(ref e) | Event::Empty(ref e) = event {
            let (ns, local) = reader.resolver().resolve_element(e.name());
            if ns != ResolveResult::Bound(quick_xml::name::Namespace(CT_NS)) {
                return Err(xml_error());
            }
            if depth == 0 && local.as_ref() != "Types" {
                return Err(xml_error());
            }
            if depth == 1 {
                let attrs = attributes(e)?;
                let ct = attrs
                    .get("ContentType")
                    .filter(|v| !v.is_empty())
                    .ok_or_else(xml_error)?
                    .clone();
                match local.as_ref() {
                    "Default" => {
                        let extension = attrs
                            .get("Extension")
                            .ok_or_else(xml_error)?
                            .to_ascii_lowercase();
                        if result.defaults.insert(extension, ct).is_some() {
                            return Err(xml_error());
                        }
                    }
                    "Override" => {
                        let name = attrs
                            .get("PartName")
                            .and_then(|v| v.strip_prefix('/'))
                            .ok_or_else(xml_error)?
                            .to_string();
                        validate_name(&name, false)?;
                        if part(package, &name).is_none()
                            || result.overrides.insert(name, ct).is_some()
                        {
                            return Err(xml_error());
                        }
                    }
                    _ => return Err(xml_error()),
                }
            }
        }
        match event {
            Event::Start(_) => depth += 1,
            Event::End(_) => depth -= 1,
            Event::Eof => break,
            _ => {}
        }
    }
    for item in package
        .parts
        .iter()
        .filter(|p| !p.directory && p.name != "[Content_Types].xml")
    {
        result.for_part(&item.name)?;
    }
    Ok(result)
}
impl ContentTypes {
    fn for_part(&self, name: &str) -> Result<&str> {
        if let Some(value) = self.overrides.get(name) {
            return Ok(value);
        }
        let extension = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        self.defaults
            .get(&extension)
            .map(String::as_str)
            .ok_or_else(|| Error::Blocked("OOXML part has no declared content type".into()))
    }
}
fn relationships(data: &[u8]) -> Result<Vec<Relationship>> {
    let mut reader = NsReader::from_str(std::str::from_utf8(data).map_err(|_| xml_error())?);
    let mut result = Vec::new();
    let mut ids = BTreeSet::new();
    let mut depth = 0;
    loop {
        let event = reader.read_event().map_err(|_| xml_error())?;
        if let Event::Start(ref e) | Event::Empty(ref e) = event {
            let (ns, local) = reader.resolver().resolve_element(e.name());
            if ns != ResolveResult::Bound(quick_xml::name::Namespace(REL_NS)) {
                return Err(xml_error());
            }
            if depth == 0 && local.as_ref() != "Relationships" {
                return Err(xml_error());
            }
            if depth == 1 {
                if local.as_ref() != "Relationship" {
                    return Err(xml_error());
                }
                let attrs = attributes(e)?;
                let id = attrs
                    .get("Id")
                    .filter(|v| !v.is_empty())
                    .ok_or_else(xml_error)?;
                if !ids.insert(id.clone()) {
                    return Err(xml_error());
                }
                let target = attrs
                    .get("Target")
                    .filter(|v| !v.is_empty())
                    .ok_or_else(xml_error)?
                    .clone();
                let kind = attrs
                    .get("Type")
                    .filter(|v| !v.is_empty())
                    .ok_or_else(xml_error)?
                    .clone();
                let mode = attrs
                    .get("TargetMode")
                    .map(String::as_str)
                    .unwrap_or("Internal");
                if !matches!(mode, "External" | "Internal") {
                    return Err(xml_error());
                }
                result.push(Relationship {
                    target,
                    kind,
                    external: mode == "External",
                });
            }
        }
        match event {
            Event::Start(_) => depth += 1,
            Event::End(_) => depth -= 1,
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(result)
}

fn relationship_source(name: &str) -> Result<String> {
    if name == "_rels/.rels" {
        return Ok(String::new());
    }
    let (parent, tail) = name.rsplit_once("/_rels/").ok_or_else(xml_error)?;
    let filename = tail
        .strip_suffix(".rels")
        .filter(|s| !s.is_empty())
        .ok_or_else(xml_error)?;
    Ok(format!("{parent}/{filename}"))
}
fn relationship_target(source: &str, target: &str) -> Result<String> {
    let target = target.split('#').next().unwrap_or("");
    if target.is_empty() {
        return Ok(source.to_string());
    }
    let mut decoded = Vec::new();
    let bytes = target.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let pair = bytes.get(index + 1..index + 3).ok_or_else(xml_error)?;
            let value = std::str::from_utf8(pair)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                .ok_or_else(xml_error)?;
            decoded.push(value);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    let decoded = String::from_utf8(decoded).map_err(|_| xml_error())?;
    if decoded.starts_with("//")
        || decoded.contains(['\\', ':', '\0', '?', '#'])
        || decoded.chars().any(char::is_control)
    {
        return Err(xml_error());
    }
    let mut pieces: Vec<&str> = if decoded.starts_with('/') {
        Vec::new()
    } else {
        source
            .rsplit_once('/')
            .map_or(Vec::new(), |(parent, _)| parent.split('/').collect())
    };
    for piece in decoded.trim_start_matches('/').split('/') {
        match piece {
            "" | "." => return Err(xml_error()),
            ".." => {
                if pieces.pop().is_none() {
                    return Err(Error::Blocked(
                        "OOXML relationship escapes the package".into(),
                    ));
                }
            }
            _ => pieces.push(piece),
        }
    }
    Ok(pieces.join("/"))
}

fn property_kind(content_type: &str) -> Option<PropertyKind> {
    match content_type {
        CORE_CT => Some(PropertyKind::Core),
        APP_CT => Some(PropertyKind::App),
        CUSTOM_CT => Some(PropertyKind::Custom),
        _ => None,
    }
}
fn clean_properties(data: &[u8], kind: PropertyKind, limits: &Limits) -> Result<PropertyResult> {
    validate_xml(data)?;
    if data.len() > limits.max_metadata_bytes {
        return Err(Error::Blocked(
            "OOXML property part exceeds the metadata limit".into(),
        ));
    }
    let text = std::str::from_utf8(data).map_err(|_| xml_error())?;
    let mut reader = NsReader::from_str(text);
    let mut depth = 0;
    let mut remove_start = None;
    let mut ranges = Vec::new();
    let mut fields = BTreeSet::new();
    let mut unknown = false;
    loop {
        let before = reader.buffer_position() as usize;
        let event = reader.read_event().map_err(|_| xml_error())?;
        let after = reader.buffer_position() as usize;
        if let Event::Start(ref element) | Event::Empty(ref element) = event {
            let (ns, local) = reader.resolver().resolve_element(element.name());
            let ns = match ns {
                ResolveResult::Bound(ns) => ns.0,
                _ => "",
            };
            let local = local.as_ref();
            if depth == 0 {
                let valid = match kind {
                    PropertyKind::Core => ns == CORE_NS && local == "coreProperties",
                    PropertyKind::App => ns == APP_NS && local == "Properties",
                    PropertyKind::Custom => ns == CUSTOM_NS && local == "Properties",
                };
                if !valid {
                    return Err(xml_error());
                }
            }
            if depth == 1 {
                let removable = match kind {
                    PropertyKind::Core => {
                        matches!(ns, CORE_NS | DC_NS | DCT_NS)
                            && matches!(
                                local,
                                "creator"
                                    | "lastModifiedBy"
                                    | "created"
                                    | "modified"
                                    | "title"
                                    | "subject"
                                    | "description"
                                    | "keywords"
                                    | "category"
                                    | "contentStatus"
                                    | "identifier"
                                    | "lastPrinted"
                                    | "revision"
                                    | "language"
                                    | "version"
                            )
                    }
                    PropertyKind::App => {
                        ns == APP_NS
                            && matches!(
                                local,
                                "Application"
                                    | "AppVersion"
                                    | "Company"
                                    | "Manager"
                                    | "Template"
                                    | "TotalTime"
                            )
                    }
                    PropertyKind::Custom => ns == CUSTOM_NS && local == "property",
                };
                if removable {
                    let field = match kind {
                        PropertyKind::Core => format!("core.{local}"),
                        PropertyKind::App => format!("app.{local}"),
                        PropertyKind::Custom => "custom.properties".into(),
                    };
                    fields.insert(field);
                    if matches!(event, Event::Empty(_)) {
                        ranges.push((before, after));
                    } else {
                        remove_start = Some(before);
                    }
                } else if !matches!(kind, PropertyKind::App)
                    || ns != APP_NS
                    || !matches!(
                        local,
                        "Pages"
                            | "Words"
                            | "Characters"
                            | "CharactersWithSpaces"
                            | "Lines"
                            | "Paragraphs"
                            | "Slides"
                            | "Notes"
                            | "HiddenSlides"
                            | "MMClips"
                            | "ScaleCrop"
                            | "HeadingPairs"
                            | "TitlesOfParts"
                            | "LinksUpToDate"
                            | "SharedDoc"
                            | "HyperlinksChanged"
                            | "DocSecurity"
                            | "HLinks"
                            | "DigSig"
                    )
                {
                    unknown = true;
                }
            }
        }
        match event {
            Event::Start(_) => depth += 1,
            Event::End(_) => {
                depth -= 1;
                if depth == 1
                    && let Some(start) = remove_start.take()
                {
                    ranges.push((start, after));
                }
            }
            Event::Comment(_) | Event::PI(_) => unknown = true,
            Event::Eof => break,
            _ => {}
        }
    }
    let mut cleaned = Vec::with_capacity(data.len());
    let mut offset = 0;
    for (start, end) in ranges {
        cleaned.extend_from_slice(&data[offset..start]);
        offset = end;
    }
    cleaned.extend_from_slice(&data[offset..]);
    Ok(PropertyResult {
        cleaned,
        fields,
        unknown,
    })
}

fn inspect_package(package: &Package, limits: &Limits) -> Result<Inspection> {
    let types = content_types(package)?;
    let root_rels = part(package, "_rels/.rels")
        .ok_or_else(|| Error::Blocked("OOXML package relationships are missing".into()))?;
    let root_relationships = relationships(&root_rels.data)?;
    let main_relationships: Vec<_> = root_relationships
        .iter()
        .filter(|r| matches!(r.kind.as_str(), OFFICE_REL | STRICT_OFFICE_REL))
        .collect();
    if main_relationships.len() != 1 || main_relationships[0].external {
        return Err(Error::Unsupported(
            "Package has no unique internal Office document root".into(),
        ));
    }
    let main = relationship_target("", &main_relationships[0].target)?;
    if part(package, &main).is_none() {
        return Err(Error::Blocked("OOXML document root is missing".into()));
    }
    let main_ct = types.for_part(&main)?;
    let format = match main_ct {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml" => {
            Format::Docx
        }
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml" => {
            Format::Xlsx
        }
        "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml" => {
            Format::Pptx
        }
        value if value.to_ascii_lowercase().contains("macroenabled") => {
            return Err(Error::Blocked(
                "Macro-enabled Office packages are audit-only and cannot be rewritten".into(),
            ));
        }
        _ => {
            return Err(Error::Unsupported(
                "Office package type is unsupported".into(),
            ));
        }
    };
    let mut inspection = Inspection::new(format, String::new());
    inspection.blockers = package.blockers.clone();
    let mut content = BTreeMap::new();
    let mut codes = BTreeSet::new();
    for (index, item) in package
        .parts
        .iter()
        .enumerate()
        .filter(|(_, p)| !p.directory)
    {
        if item.name == "[Content_Types].xml" {
            content.insert(&item.name, item.data.clone());
            continue;
        }
        let ct = types.for_part(&item.name)?;
        if ct.ends_with("+xml") || matches!(ct, "application/xml" | "text/xml") {
            validate_xml(&item.data)?;
        }
        let lower = item.name.to_ascii_lowercase();
        if lower.starts_with("_xmlsignatures/")
            || ct.contains("digital-signature")
            || lower.ends_with("vbaproject.bin")
            || ct.to_ascii_lowercase().contains("vba")
        {
            inspection.blockers.push("Office digital signatures or executable macros require preserving the entire package".into());
            codes.insert("ooxml.signature_or_macro");
        }
        if item.name.ends_with(".rels") {
            let source = relationship_source(&item.name)?;
            if !source.is_empty() && part(package, &source).is_none() {
                return Err(Error::Blocked(
                    "OOXML relationship source is missing".into(),
                ));
            }
            for relationship in relationships(&item.data)? {
                if relationship.external {
                    codes.insert("ooxml.external_relationship");
                } else if part(
                    package,
                    &relationship_target(&source, &relationship.target)?,
                )
                .is_none()
                {
                    return Err(Error::Blocked(
                        "OOXML internal relationship target is missing".into(),
                    ));
                }
                if relationship.kind.contains("digital-signature")
                    || relationship.kind.ends_with("/vbaProject")
                {
                    inspection
                        .blockers
                        .push("Office signature or macro relationship blocks rewriting".into());
                    codes.insert("ooxml.signature_or_macro");
                }
            }
        }
        if let Some(kind) = property_kind(ct) {
            let properties = clean_properties(&item.data, kind, limits)?;
            for field in properties.fields {
                inspection.findings.push(Finding::new(
                    &format!("ooxml.{field}"),
                    RiskLayer::EmbeddedMetadata,
                    &format!("OPC/properties/{field}"),
                    "Known Office privacy property is present; its value is redacted",
                    Action::Remove,
                ));
            }
            if properties.unknown {
                codes.insert("ooxml.unknown_property");
            }
            content.insert(&item.name, properties.cleaned);
        } else {
            content.insert(&item.name, item.data.clone());
        }
        if !known_part(&item.name, format) {
            inspection.findings.push(Finding::new(
                "ooxml.unknown_part",
                RiskLayer::ContainerStructure,
                &format!("ZIP member {}", index + 1),
                "Unknown package part is preserved; member name is redacted",
                Action::AskUser,
            ));
        }
        if lower.contains("comment") || deep::comments_type(ct) {
            codes.insert("ooxml.comments");
        }
        if lower.contains("/embeddings/") || ct.contains("oleObject") {
            codes.insert("ooxml.embedded_object");
        }
        if lower.contains("/media/") || lower.starts_with("docprops/thumbnail") {
            codes.insert("ooxml.embedded_media");
        }
        if lower.starts_with("customxml/") {
            codes.insert("ooxml.custom_xml");
        }
        if lower.starts_with("xl/revisions/") {
            codes.insert("ooxml.revisions");
        }
        if item.name.ends_with(".xml") {
            let xml = std::str::from_utf8(&item.data).map_err(|_| xml_error())?;
            let mut reader = NsReader::from_str(xml);
            loop {
                match reader.read_event().map_err(|_| xml_error())? {
                    Event::Start(e) | Event::Empty(e) => {
                        let (namespace, local) = reader.resolver().resolve_element(e.name());
                        let protected_signature = (local.as_ref() == "DigSig"
                            && namespace
                                == ResolveResult::Bound(quick_xml::name::Namespace(APP_NS)))
                            || (local.as_ref() == "Signature"
                                && namespace
                                    == ResolveResult::Bound(quick_xml::name::Namespace(
                                        "http://www.w3.org/2000/09/xmldsig#",
                                    )));
                        if protected_signature {
                            inspection.blockers.push(
                                "Office signature XML must be preserved without package rewriting"
                                    .into(),
                            );
                            codes.insert("ooxml.signature_or_macro");
                        }
                        let word_namespace = matches!(
                            namespace,
                            ResolveResult::Bound(quick_xml::name::Namespace(
                                "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
                                    | "http://purl.oclc.org/ooxml/wordprocessingml/main"
                            ))
                        );
                        let namespace_uri = match namespace {
                            ResolveResult::Bound(value) => value.0,
                            _ => "",
                        };
                        if deep::revision_element(namespace_uri, local.as_ref()) {
                            codes.insert("ooxml.revisions");
                        }
                        if deep::custom_xml_element(namespace_uri, local.as_ref()) {
                            codes.insert("ooxml.custom_xml");
                        }
                        if word_namespace
                            && matches!(e.local_name().as_ref(), "vanish" | "webHidden")
                        {
                            codes.insert("ooxml.hidden_content");
                        }
                        if matches!(
                            namespace,
                            ResolveResult::Bound(quick_xml::name::Namespace(
                                "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
                                    | "http://purl.oclc.org/ooxml/spreadsheetml/main"
                            ))
                        ) && local.as_ref() == "sheet"
                            && attributes(&e)?.get("state").is_some_and(|state| {
                                matches!(state.as_str(), "hidden" | "veryHidden")
                            })
                        {
                            codes.insert("ooxml.hidden_sheets");
                        }
                        if word_namespace && local.as_ref() == "rsids" {
                            codes.insert("ooxml.internal_identifiers");
                        }
                        for attribute in e.attributes() {
                            let attribute = attribute.map_err(|_| xml_error())?;
                            let (attribute_ns, attribute_local) =
                                reader.resolver().resolve_attribute(attribute.key);
                            if matches!(
                                attribute_ns,
                                ResolveResult::Bound(quick_xml::name::Namespace(
                                    "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
                                        | "http://purl.oclc.org/ooxml/wordprocessingml/main"
                                ))
                            ) && attribute_local.as_ref().starts_with("rsid")
                            {
                                codes.insert("ooxml.internal_identifiers");
                            }
                        }
                    }
                    Event::Eof => break,
                    _ => {}
                }
            }
        }
    }
    if package.zip_metadata {
        inspection.findings.push(Finding::new(
            "ooxml.zip_metadata",
            RiskLayer::ContainerStructure,
            "ZIP/member_headers",
            "ZIP timestamps, comments, or recognized auxiliary metadata are present",
            Action::Normalize,
        ));
    }
    for code in codes {
        let (summary, action, layer) = match code {
            "ooxml.signature_or_macro" => (
                "Office signature or macro is present; safe rewriting is blocked",
                Action::Preserve,
                RiskLayer::ProvenanceCredential,
            ),
            "ooxml.external_relationship" => (
                "External relationship or hyperlink is retained without being opened",
                Action::AskUser,
                RiskLayer::ContainerStructure,
            ),
            "ooxml.comments" => (
                "Comments may contain identities or history and are preserved",
                Action::AskUser,
                RiskLayer::ContainerStructure,
            ),
            "ooxml.revisions" => (
                "Tracked changes may contain prior content and author identities and are preserved",
                Action::AskUser,
                RiskLayer::ContainerStructure,
            ),
            "ooxml.hidden_content" => (
                "Hidden document content is retained",
                Action::AskUser,
                RiskLayer::ContainerStructure,
            ),
            "ooxml.hidden_sheets" => (
                "Hidden or very-hidden worksheet data is retained",
                Action::AskUser,
                RiskLayer::ContainerStructure,
            ),
            "ooxml.embedded_object" => (
                "Embedded objects are preserved and their internal metadata is unassessed",
                Action::AskUser,
                RiskLayer::ContainerStructure,
            ),
            "ooxml.embedded_media" => (
                "Embedded media or thumbnail bytes are preserved; their nested metadata is unassessed",
                Action::AskUser,
                RiskLayer::ContainerStructure,
            ),
            "ooxml.custom_xml" => (
                "Custom XML parts are retained and may contain private data",
                Action::AskUser,
                RiskLayer::ContainerStructure,
            ),
            "ooxml.internal_identifiers" => (
                "Document revision-session identifiers are preserved",
                Action::AskUser,
                RiskLayer::EmbeddedMetadata,
            ),
            "ooxml.unknown_property" => (
                "Unrecognized property content is preserved and requires review",
                Action::AskUser,
                RiskLayer::EmbeddedMetadata,
            ),
            _ => (
                "Unrecognized Office package parts are preserved and require review",
                Action::AskUser,
                RiskLayer::ContainerStructure,
            ),
        };
        inspection
            .findings
            .push(Finding::new(code, layer, "OPC/package", summary, action));
    }
    let mut hash = Sha256::new();
    for (name, bytes) in content {
        hash.update((name.len() as u64).to_le_bytes());
        hash.update(name.as_bytes());
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(&bytes);
    }
    inspection.content_digest = format!("{:x}", hash.finalize());
    inspection.blockers.sort();
    inspection.blockers.dedup();
    inspection.limited_support = inspection
        .findings
        .iter()
        .any(|f| f.action == Action::AskUser);
    Ok(inspection)
}

fn known_part(name: &str, format: Format) -> bool {
    if name == "[Content_Types].xml"
        || name == "_rels/.rels"
        || name.ends_with(".rels")
        || matches!(
            name,
            "docProps/core.xml"
                | "docProps/app.xml"
                | "docProps/custom.xml"
                | "docProps/thumbnail.jpg"
                | "docProps/thumbnail.jpeg"
                | "docProps/thumbnail.png"
                | "docProps/thumbnail.wmf"
                | "docProps/thumbnail.emf"
        )
    {
        return true;
    }
    let prefix = match format {
        Format::Docx => "word/",
        Format::Xlsx => "xl/",
        Format::Pptx => "ppt/",
        _ => return false,
    };
    let Some(tail) = name.strip_prefix(prefix) else {
        return false;
    };
    match format {
        Format::Docx => {
            matches!(
                tail,
                "document.xml"
                    | "styles.xml"
                    | "stylesWithEffects.xml"
                    | "settings.xml"
                    | "fontTable.xml"
                    | "numbering.xml"
                    | "footnotes.xml"
                    | "endnotes.xml"
                    | "webSettings.xml"
                    | "comments.xml"
                    | "commentsExtended.xml"
                    | "commentsIds.xml"
                    | "commentsExtensible.xml"
                    | "people.xml"
            ) || numbered_xml(tail, "header")
                || numbered_xml(tail, "footer")
                || [
                    "theme/",
                    "media/",
                    "embeddings/",
                    "charts/",
                    "diagrams/",
                    "glossary/",
                    "printerSettings/",
                ]
                .iter()
                .any(|p| tail.starts_with(p))
        }
        Format::Xlsx => {
            matches!(
                tail,
                "workbook.xml"
                    | "sharedStrings.xml"
                    | "styles.xml"
                    | "calcChain.xml"
                    | "connections.xml"
                    | "metadata.xml"
            ) || numbered_xml(tail, "comments")
                || [
                    "worksheets/",
                    "theme/",
                    "charts/",
                    "drawings/",
                    "media/",
                    "embeddings/",
                    "tables/",
                    "pivot",
                    "externalLinks/",
                    "queryTables/",
                    "richData/",
                    "persons/",
                    "threadedComments/",
                    "printerSettings/",
                ]
                .iter()
                .any(|p| tail.starts_with(p))
        }
        Format::Pptx => {
            matches!(
                tail,
                "presentation.xml"
                    | "viewProps.xml"
                    | "presProps.xml"
                    | "tableStyles.xml"
                    | "commentAuthors.xml"
            ) || [
                "slides/",
                "slideLayouts/",
                "slideMasters/",
                "notesSlides/",
                "notesMasters/",
                "theme/",
                "media/",
                "charts/",
                "embeddings/",
                "comments/",
                "authors/",
            ]
            .iter()
            .any(|p| tail.starts_with(p))
        }
        _ => false,
    }
}

fn numbered_xml(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(".xml"))
        .is_some_and(|number| {
            !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fileveil_core::digest;
    const ROOT_RELS: &str = r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="main" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="MAIN"/><Relationship Id="core" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>"#;
    const CORE: &str = r#"<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:creator>Fictional Author</dc:creator><cp:lastModifiedBy>Fictional Editor</cp:lastModifiedBy><dcterms:created xsi:type="dcterms:W3CDTF">2026-01-01T00:00:00Z</dcterms:created></cp:coreProperties>"#;
    fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, bytes) in entries {
            writer
                .start_file(
                    *name,
                    SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
                )
                .unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }
    fn fixture(format: Format, extra_entries: &[(&str, &[u8])]) -> Vec<u8> {
        let (main, ct, body) = match format {
            Format::Docx => (
                "word/document.xml",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
                r#"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Visible synthetic text</w:t></w:r></w:p></w:body></w:document>"#,
            ),
            Format::Xlsx => (
                "xl/workbook.xml",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
                r#"<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets/></workbook>"#,
            ),
            Format::Pptx => (
                "ppt/presentation.xml",
                "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
                r#"<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:sldIdLst/></p:presentation>"#,
            ),
            _ => unreachable!(),
        };
        let types = format!(
            r#"<Types xmlns="{CT_NS}"><Default Extension="xml" ContentType="application/xml"/><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Override PartName="/{main}" ContentType="{ct}"/><Override PartName="/docProps/core.xml" ContentType="{CORE_CT}"/></Types>"#
        );
        let rels = ROOT_RELS.replace("MAIN", main);
        let mut entries = vec![
            ("[Content_Types].xml", types.as_bytes()),
            ("_rels/.rels", rels.as_bytes()),
            (main, body.as_bytes()),
            ("docProps/core.xml", CORE.as_bytes()),
        ];
        entries.extend_from_slice(extra_entries);
        archive(&entries)
    }
    #[test]
    fn all_office_formats_remove_properties_preserve_parts() {
        for format in [Format::Docx, Format::Xlsx, Format::Pptx] {
            let input = fixture(format, &[]);
            let before = OoxmlAdapter.inspect(&input, &Limits::default()).unwrap();
            assert_eq!(before.format, format);
            assert!(
                before
                    .findings
                    .iter()
                    .any(|f| f.code == "ooxml.core.creator")
            );
            let output = OoxmlAdapter.sanitize(&input, &Limits::default()).unwrap();
            let after = OoxmlAdapter.inspect(&output, &Limits::default()).unwrap();
            assert_eq!(before.content_digest, after.content_digest);
            assert!(!after.findings.iter().any(|f| f.action == Action::Remove));
            assert!(!String::from_utf8_lossy(&output).contains("Fictional Author"));
        }
    }
    #[test]
    fn clean_negative_has_stable_semantics() {
        let input = fixture(Format::Docx, &[]);
        let clean = OoxmlAdapter.sanitize(&input, &Limits::default()).unwrap();
        let again = OoxmlAdapter.sanitize(&clean, &Limits::default()).unwrap();
        assert_eq!(clean, again);
    }
    #[test]
    fn comments_unknown_parts_and_revisions_are_retained() {
        let comments = br#"<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:comment w:author="Synthetic"/></w:comments>"#;
        let input = fixture(
            Format::Docx,
            &[
                ("word/comments.xml", comments),
                ("opaque.bin", b"opaque retained"),
            ],
        );
        // The unknown extension must have a content type; a malformed package is blocked.
        assert!(OoxmlAdapter.inspect(&input, &Limits::default()).is_err());
        let input = fixture(
            Format::Docx,
            &[
                ("word/comments.xml", comments),
                ("unknown.xml", b"<unknown/>"),
                ("docProps/private-account.xml", b"<unknown/>"),
            ],
        );
        let before = OoxmlAdapter.inspect(&input, &Limits::default()).unwrap();
        assert!(before.findings.iter().any(|f| f.code == "ooxml.comments"));
        assert!(
            before
                .findings
                .iter()
                .any(|f| f.code == "ooxml.unknown_part")
        );
        let unknown: Vec<_> = before
            .findings
            .iter()
            .filter(|f| f.code == "ooxml.unknown_part")
            .collect();
        assert_eq!(unknown.len(), 2);
        assert!(
            unknown
                .iter()
                .all(|f| f.location.starts_with("ZIP member "))
        );
        assert!(!format!("{:?}", before.findings).contains("private-account"));
        let output = OoxmlAdapter.sanitize(&input, &Limits::default()).unwrap();
        let after = OoxmlAdapter.inspect(&output, &Limits::default()).unwrap();
        assert_eq!(before.content_digest, after.content_digest);
    }
    #[test]
    fn signature_parts_block_sanitization() {
        let input = fixture(
            Format::Docx,
            &[("_xmlsignatures/sig1.xml", b"<Signature/>")],
        );
        assert!(
            !OoxmlAdapter
                .inspect(&input, &Limits::default())
                .unwrap()
                .blockers
                .is_empty()
        );
        assert!(matches!(
            OoxmlAdapter.sanitize(&input, &Limits::default()),
            Err(Error::Blocked(_))
        ));
    }
    #[test]
    fn unsafe_zip_paths_collisions_and_trailers_are_rejected() {
        for entries in [
            vec![("../evil.xml", b"<x/>".as_slice())],
            vec![("a.xml", b"<x/>".as_slice()), ("A.xml", b"<x/>".as_slice())],
            vec![("a\\b.xml", b"<x/>".as_slice())],
            vec![
                ("\u{00e9}.xml", b"<x/>".as_slice()),
                ("e\u{0301}.xml", b"<x/>".as_slice()),
            ],
        ] {
            let input = archive(&entries);
            assert!(matches!(
                OoxmlAdapter.inspect(&input, &Limits::default()),
                Err(Error::Blocked(_))
            ));
        }
        let mut input = fixture(Format::Docx, &[]);
        input.extend_from_slice(b"trailing payload");
        assert!(OoxmlAdapter.inspect(&input, &Limits::default()).is_err());
    }
    #[test]
    fn dtd_dangling_relations_and_compression_limits_are_rejected() {
        let bad = fixture(
            Format::Docx,
            &[(
                "bad.xml",
                br#"<!DOCTYPE x [<!ENTITY e SYSTEM "file:///secret">]><x>&e;</x>"#,
            )],
        );
        assert!(OoxmlAdapter.inspect(&bad, &Limits::default()).is_err());
        let bad_rels = br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="bad" Type="anything" Target="missing.xml"/></Relationships>"#;
        let bad = fixture(Format::Docx, &[("word/_rels/document.xml.rels", bad_rels)]);
        assert!(OoxmlAdapter.inspect(&bad, &Limits::default()).is_err());
        let input = fixture(Format::Docx, &[]);
        let limits = Limits {
            max_uncompressed_bytes: 10,
            ..Limits::default()
        };
        assert!(OoxmlAdapter.inspect(&input, &limits).is_err());
    }
    #[test]
    fn externally_linked_documents_are_audited_without_fetching() {
        let rels = br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="link" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.invalid/private" TargetMode="External"/></Relationships>"#;
        let input = fixture(Format::Docx, &[("word/_rels/document.xml.rels", rels)]);
        let inspection = OoxmlAdapter.inspect(&input, &Limits::default()).unwrap();
        assert!(
            inspection
                .findings
                .iter()
                .any(|f| f.code == "ooxml.external_relationship")
        );
        assert!(!format!("{:?}", inspection.findings).contains("example.invalid"));
    }
    #[test]
    fn hyperlink_base_is_preserved_and_requires_review() {
        let app = br#"<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>Synthetic Suite</Application><HyperlinkBase>relative-base/</HyperlinkBase><Pages>1</Pages></Properties>"#;
        let result = clean_properties(app, PropertyKind::App, &Limits::default()).unwrap();
        assert!(result.unknown);
        let clean = String::from_utf8(result.cleaned).unwrap();
        assert!(!clean.contains("Synthetic Suite"));
        assert!(clean.contains("<HyperlinkBase>relative-base/</HyperlinkBase>"));
        assert!(clean.contains("<Pages>1</Pages>"));
    }
    #[test]
    fn unicode_member_names_are_preserved() {
        let input = fixture(Format::Docx, &[("word/示例.xml", b"<unknown/>")]);
        let before = OoxmlAdapter.inspect(&input, &Limits::default()).unwrap();
        let clean = OoxmlAdapter.sanitize(&input, &Limits::default()).unwrap();
        let after = OoxmlAdapter.inspect(&clean, &Limits::default()).unwrap();
        assert_eq!(before.content_digest, after.content_digest);
    }
    #[test]
    fn property_removal_preserves_unknown_xml_exactly() {
        let core = br#"<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:x="urn:unknown"><dc:creator>private</dc:creator><x:opaque label="keep">unchanged</x:opaque></cp:coreProperties>"#;
        let result = clean_properties(core, PropertyKind::Core, &Limits::default()).unwrap();
        assert!(result.unknown);
        assert!(!String::from_utf8_lossy(&result.cleaned).contains("private"));
        assert!(
            String::from_utf8_lossy(&result.cleaned)
                .contains(r#"<x:opaque label="keep">unchanged</x:opaque>"#)
        );
        assert_eq!(
            digest(&result.cleaned),
            digest(
                &clean_properties(&result.cleaned, PropertyKind::Core, &Limits::default())
                    .unwrap()
                    .cleaned
            )
        );
    }
}

// FVPROV1 56801 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI0YjNhYTczZTcwMTJiNzk5NjA0NGNlYTM3ZTU2NjBiNzc2M2ZmZjY5YmFhMDI4ZGRiMmM1NTU5YTMyZDE3NjYwIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1mb3JtYXRzL3NyYy9vb3htbC5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjJiNDk0YmRlZTVkYmE1Mzc0ODg5NDhkY2FlZTNjODk5ZWY0ODRkODE0OTAwOTUwZTcwYmUzNDNmYTg3M2RhYzJmY2Y3ZDlhNWZkZGM0ZGFlMDVjNDEwNmI2YTFkNmQxY2U4NDY4YmQ3NzAwOGU2NDhkNGVlNzUxZmEyMzk5YjA3In1dfV0= FVPROV1-END
