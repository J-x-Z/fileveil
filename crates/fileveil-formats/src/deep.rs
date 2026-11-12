// SPDX-License-Identifier: MPL-2.0
//! Explicit OOXML edits retain every byte outside selected XML ranges and package parts.
use super::*;
use crate::ScopedVerification;
use fileveil_core::{DeepOptions, FindingState, Integrity, Outcome, Policy, SanitizeOptions};
use quick_xml::events::BytesStart;

const W_NS: &str = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
const W_STRICT: &str = "http://purl.oclc.org/ooxml/wordprocessingml/main";
const R_NS: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const R_STRICT: &str = "http://purl.oclc.org/ooxml/officeDocument/relationships";
const S_NS: &str = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
const S_STRICT: &str = "http://purl.oclc.org/ooxml/spreadsheetml/main";
const VML_NS: &str = "urn:schemas-microsoft-com:vml";
const EXCEL_NS: &str = "urn:schemas-microsoft-com:office:excel";

struct Attribute {
    namespace: String,
    local: String,
    value: String,
    qualified: String,
}
struct Node {
    namespace: String,
    local: String,
    attributes: Vec<Attribute>,
    parent: Option<usize>,
    start: usize,
    open_end: usize,
    close_start: usize,
    end: usize,
    empty: bool,
    opening: BytesStart<'static>,
}
impl Node {
    fn word(&self) -> bool {
        matches!(self.namespace.as_str(), W_NS | W_STRICT)
    }
    fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|a| a.namespace.is_empty() && a.local == name)
            .map(|a| a.value.as_str())
    }
    fn relationship_id(&self) -> Option<&str> {
        self.attributes
            .iter()
            .find(|a| {
                matches!(a.namespace.as_str(), R_NS | R_STRICT)
                    && matches!(a.local.as_str(), "id" | "embed" | "link")
            })
            .map(|a| a.value.as_str())
    }
}
fn nodes(data: &[u8], limits: &Limits) -> Result<Vec<Node>> {
    let mut reader = NsReader::from_str(std::str::from_utf8(data).map_err(|_| xml_error())?);
    let mut result: Vec<Node> = Vec::new();
    let mut stack = Vec::new();
    loop {
        let before = reader.buffer_position() as usize;
        let event = reader.read_event().map_err(|_| xml_error())?;
        let after = reader.buffer_position() as usize;
        match event {
            Event::Start(ref element) | Event::Empty(ref element) => {
                if result.len() >= limits.max_members.saturating_mul(128) {
                    return Err(Error::Blocked("OOXML XML node budget exceeded".into()));
                }
                let (namespace, local) = reader.resolver().resolve_element(element.name());
                let namespace = match namespace {
                    ResolveResult::Bound(value) => value.0.to_string(),
                    _ => String::new(),
                };
                let mut attrs = Vec::new();
                for attribute in element.attributes() {
                    let attribute = attribute.map_err(|_| xml_error())?;
                    let (namespace, local) = reader.resolver().resolve_attribute(attribute.key);
                    attrs.push(Attribute {
                        namespace: match namespace {
                            ResolveResult::Bound(value) => value.0.to_string(),
                            _ => String::new(),
                        },
                        local: local.as_ref().to_string(),
                        value: attribute
                            .normalized_value(XmlVersion::Implicit1_0)
                            .map_err(|_| xml_error())?
                            .into_owned(),
                        qualified: attribute.key.as_ref().to_string(),
                    });
                }
                let index = result.len();
                result.push(Node {
                    namespace,
                    local: local.as_ref().to_string(),
                    attributes: attrs,
                    parent: stack.last().copied(),
                    start: before,
                    open_end: after,
                    close_start: after,
                    end: after,
                    empty: matches!(event, Event::Empty(_)),
                    opening: element.clone().into_owned(),
                });
                if matches!(event, Event::Start(_)) {
                    stack.push(index);
                }
            }
            Event::End(_) => {
                let index = stack.pop().ok_or_else(xml_error)?;
                result[index].close_start = before;
                result[index].end = after;
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(result)
}
struct Edit {
    start: usize,
    end: usize,
    replacement: Vec<u8>,
}
fn remove(node: &Node) -> Edit {
    Edit {
        start: node.start,
        end: node.end,
        replacement: Vec::new(),
    }
}
fn unwrap(node: &Node, edits: &mut Vec<Edit>) {
    edits.push(Edit {
        start: node.start,
        end: node.open_end,
        replacement: Vec::new(),
    });
    if !node.empty {
        edits.push(Edit {
            start: node.close_start,
            end: node.end,
            replacement: Vec::new(),
        });
    }
}
fn apply(data: &[u8], edits: &mut [Edit]) -> Result<Vec<u8>> {
    edits.sort_by_key(|edit| (edit.start, std::cmp::Reverse(edit.end)));
    let mut result = Vec::with_capacity(data.len());
    let mut cursor = 0;
    for edit in edits {
        if edit.start < cursor {
            if edit.end <= cursor {
                continue;
            }
            return Err(Error::Blocked(
                "Overlapping Office edits require a more specific transformation".into(),
            ));
        }
        result.extend_from_slice(data.get(cursor..edit.start).ok_or_else(xml_error)?);
        result.extend_from_slice(&edit.replacement);
        cursor = edit.end;
    }
    result.extend_from_slice(data.get(cursor..).ok_or_else(xml_error)?);
    Ok(result)
}
fn ancestor(nodes: &[Node], index: usize, namespace: &str, local: &str) -> Option<usize> {
    let mut current = Some(index);
    while let Some(index) = current {
        let node = &nodes[index];
        if node.namespace == namespace && node.local == local {
            return Some(index);
        }
        current = node.parent;
    }
    None
}
fn comments_part(name: &str) -> bool {
    (name.starts_with("word/")
        && (name
            .strip_prefix("word/")
            .is_some_and(|tail| tail.starts_with("comments") && tail.ends_with(".xml"))
            || name == "word/people.xml"))
        || (name.starts_with("xl/")
            && (name.starts_with("xl/threadedComments/")
                || name.starts_with("xl/persons/")
                || name
                    .strip_prefix("xl/")
                    .is_some_and(|tail| tail.starts_with("comments") && tail.ends_with(".xml"))))
        || name.starts_with("ppt/comments/")
        || name == "ppt/commentAuthors.xml"
}
fn embedded_part(name: &str) -> bool {
    ["word/embeddings/", "xl/embeddings/", "ppt/embeddings/"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}
fn revision_part(name: &str) -> bool {
    name.starts_with("xl/revisions/")
}
fn custom_part(name: &str) -> bool {
    name.starts_with("customXml/")
}
fn relation_part_for_removed(name: &str, removed: &BTreeSet<String>) -> bool {
    name.ends_with(".rels")
        && relationship_source(name).is_ok_and(|source| removed.contains(&source))
}
fn is_revision(local: &str) -> bool {
    matches!(
        local,
        "ins"
            | "del"
            | "moveFrom"
            | "moveTo"
            | "moveFromRangeStart"
            | "moveFromRangeEnd"
            | "moveToRangeStart"
            | "moveToRangeEnd"
            | "rPrChange"
            | "pPrChange"
            | "sectPrChange"
            | "tblPrChange"
            | "trPrChange"
            | "tcPrChange"
            | "tblGridChange"
            | "numberingChange"
            | "cellIns"
            | "cellDel"
            | "cellMerge"
    )
}
fn hidden(node: &Node) -> bool {
    node.word()
        && matches!(node.local.as_str(), "vanish" | "webHidden")
        && !node.attributes.iter().any(|attribute| {
            matches!(attribute.namespace.as_str(), W_NS | W_STRICT)
                && attribute.local == "val"
                && matches!(attribute.value.as_str(), "0" | "false" | "off")
        })
}

struct Plan {
    removed: BTreeSet<String>,
    edits: BTreeMap<String, Vec<Edit>>,
    codes: BTreeSet<&'static str>,
}
fn spreadsheet(namespace: &str) -> bool {
    matches!(namespace, S_NS | S_STRICT)
}
fn replace_attributes(node: &Node, replacements: &BTreeMap<&str, String>) -> Result<Edit> {
    let retained = node
        .opening
        .attributes()
        .map(|attribute| attribute.map_err(|_| xml_error()))
        .collect::<Result<Vec<_>>>()?;
    let mut opening = node.opening.clone();
    opening.clear_attributes();
    for attribute in retained {
        if !replacements.contains_key(attribute.key.as_ref()) {
            opening.push_attribute(attribute);
        }
    }
    for (key, value) in replacements {
        opening.push_attribute((*key, value.as_str()));
    }
    let mut writer = quick_xml::Writer::new(Vec::new());
    writer
        .write_event(if node.empty {
            Event::Empty(opening)
        } else {
            Event::Start(opening)
        })
        .map_err(|_| xml_error())?;
    Ok(Edit {
        start: node.start,
        end: node.open_end,
        replacement: writer.into_inner(),
    })
}

/// The supported subset has literal cells and independent, ordinary worksheets.
fn plan_hidden_sheets(package: &Package, limits: &Limits, result: &mut Plan) -> Result<()> {
    let root = part(package, "_rels/.rels").ok_or_else(xml_error)?;
    let root_relationships = relationships(&root.data)?;
    let main = root_relationships
        .iter()
        .find(|relationship| matches!(relationship.kind.as_str(), OFFICE_REL | STRICT_OFFICE_REL))
        .ok_or_else(xml_error)?;
    let workbook_name = relationship_target("", &main.target)?;
    let workbook = part(package, &workbook_name).ok_or_else(xml_error)?;
    let types = content_types(package)?;
    if types.for_part(&workbook_name)?
        != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
    {
        return Ok(());
    }
    let workbook_nodes = nodes(&workbook.data, limits)?;
    let sheets: Vec<_> = workbook_nodes
        .iter()
        .filter(|node| spreadsheet(&node.namespace) && node.local == "sheet")
        .collect();
    let hidden_indices: BTreeSet<_> = sheets
        .iter()
        .enumerate()
        .filter(|(_, node)| {
            node.attribute("state")
                .is_some_and(|state| matches!(state, "hidden" | "veryHidden"))
        })
        .map(|(index, _)| index)
        .collect();
    if hidden_indices.is_empty() {
        return Ok(());
    }
    if sheets.iter().any(|sheet| {
        sheet
            .attribute("state")
            .is_some_and(|state| !matches!(state, "visible" | "hidden" | "veryHidden"))
    }) {
        return Err(xml_error());
    }
    let visible: Vec<_> = sheets
        .iter()
        .enumerate()
        .filter(|(index, _)| !hidden_indices.contains(index))
        .map(|(index, _)| index)
        .collect();
    if visible.is_empty() {
        return Err(Error::Blocked(
            "Hidden worksheet removal requires at least one retained visible worksheet".into(),
        ));
    }
    let workbook_relationships = package
        .parts
        .iter()
        .find(|item| {
            item.name.ends_with(".rels")
                && relationship_source(&item.name).is_ok_and(|source| source == workbook_name)
        })
        .ok_or_else(xml_error)?;
    let mut worksheet_targets = BTreeMap::new();
    for node in nodes(&workbook_relationships.data, limits)? {
        if node.namespace == REL_NS
            && node.local == "Relationship"
            && node.attribute("TargetMode") != Some("External")
            && node.attribute("Type").is_some_and(|kind| {
                matches!(kind.strip_suffix("/worksheet"), Some(R_NS | R_STRICT))
            })
        {
            worksheet_targets.insert(
                node.attribute("Id").ok_or_else(xml_error)?.to_string(),
                relationship_target(
                    &workbook_name,
                    node.attribute("Target").ok_or_else(xml_error)?,
                )?,
            );
        }
    }
    if sheets.iter().any(|sheet| {
        sheet
            .relationship_id()
            .is_none_or(|id| !worksheet_targets.contains_key(id))
    }) {
        return Err(Error::Blocked(
            "Hidden-sheet removal supports ordinary worksheet targets only".into(),
        ));
    }
    if worksheet_targets.values().any(|target| {
        !types.for_part(target).is_ok_and(|content_type| {
            content_type
                == "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"
        })
    }) {
        return Err(Error::Blocked(
            "Worksheet relationship targets must have the ordinary worksheet content type".into(),
        ));
    }
    let mut targets = BTreeSet::new();
    for index in &hidden_indices {
        let node = sheets[*index];
        let target = worksheet_targets
            .get(node.relationship_id().ok_or_else(xml_error)?)
            .ok_or_else(|| {
                Error::Blocked(
                    "Hidden sheet does not reference an ordinary internal worksheet".into(),
                )
            })?;
        // A worksheet shared with a retained sheet cannot be removed as a package part.
        if !targets.insert(target.clone())
            || visible.iter().any(|index| {
                sheets[*index]
                    .relationship_id()
                    .and_then(|id| worksheet_targets.get(id))
                    == Some(target)
            })
        {
            return Err(Error::Blocked(
                "Shared worksheet targets prevent selective hidden-sheet deletion".into(),
            ));
        }
        for relations in package.parts.iter().filter(|item| {
            item.name.ends_with(".rels")
                && relationship_source(&item.name).is_ok_and(|source| source == *target)
        }) {
            if !relationships(&relations.data)?.is_empty() {
                return Err(Error::Blocked("A hidden worksheet has dependent relationships. Dependency-aware removal is protected in this build".into()));
            }
        }
    }
    for relations in package
        .parts
        .iter()
        .filter(|item| item.name.ends_with(".rels"))
    {
        let source = relationship_source(&relations.name)?;
        for relationship in relationships(&relations.data)? {
            if !relationship.external
                && targets.contains(&relationship_target(&source, &relationship.target)?)
                && source != workbook_name
            {
                return Err(Error::Blocked("Other package parts reference a hidden worksheet and require dependency-aware removal".into()));
            }
        }
    }
    for item in package.parts.iter().filter(|item| {
        !item.directory
            && !targets.contains(&item.name)
            && !result.removed.contains(&item.name)
            && item.name != "[Content_Types].xml"
    }) {
        let lower = item.name.to_ascii_lowercase();
        let content_type = types.for_part(&item.name)?.to_ascii_lowercase();
        if lower.contains("sharedstrings")
            || lower.contains("/charts/")
            || lower.contains("/pivot")
            || lower.ends_with("calcchain.xml")
            || content_type.contains("sharedstrings")
            || content_type.contains("chart")
            || content_type.contains("pivot")
            || content_type.contains("calcchain")
        {
            return Err(Error::Blocked("Hidden-sheet removal with shared strings, charts, pivot structures or calculation chains requires dependency analysis".into()));
        }
        if item.name.ends_with(".xml") {
            let parsed = nodes(&item.data, limits)?;
            if parsed.iter().any(|node| {
                spreadsheet(&node.namespace)
                    && (matches!(
                        node.local.as_str(),
                        "f" | "formula"
                            | "formula1"
                            | "formula2"
                            | "calculatedColumnFormula"
                            | "totalsRowFormula"
                            | "definedNames"
                            | "definedName"
                    ) || (node.local == "c" && node.attribute("t") == Some("s")))
            }) {
                return Err(Error::Blocked("Hidden-sheet removal is limited to retained literal cells without formulas, defined names or shared-string references".into()));
            }
        }
    }
    result.removed.extend(targets);
    let edits = result.edits.entry(workbook_name).or_default();
    for index in &hidden_indices {
        edits.push(remove(sheets[*index]));
    }
    for node in workbook_nodes
        .iter()
        .filter(|node| spreadsheet(&node.namespace) && node.local == "workbookView")
    {
        let mut replacements = BTreeMap::new();
        for key in ["activeTab", "firstSheet"] {
            if let Some(value) = node.attribute(key) {
                let old = value.parse::<usize>().map_err(|_| xml_error())?;
                if old >= sheets.len() {
                    return Err(xml_error());
                }
                let retained = if hidden_indices.contains(&old) {
                    visible[0]
                } else {
                    old
                };
                let new = visible
                    .iter()
                    .position(|index| *index == retained)
                    .ok_or_else(xml_error)?;
                if new != old {
                    replacements.insert(key, new.to_string());
                }
            }
        }
        if !replacements.is_empty() {
            edits.push(replace_attributes(node, &replacements)?);
        }
    }
    result.codes.insert("ooxml.hidden_sheets");
    Ok(())
}
fn selected_relationship(kind: &str, choices: &DeepOptions) -> Option<&'static str> {
    if !kind.starts_with(&format!("{R_NS}/"))
        && !kind.starts_with(&format!("{R_STRICT}/"))
        && !kind.starts_with("http://schemas.microsoft.com/office/")
    {
        return None;
    }
    let name = kind.rsplit('/').next().unwrap_or("");
    if choices.remove_comments
        && matches!(
            name,
            "comments"
                | "commentAuthors"
                | "commentsExtended"
                | "commentsIds"
                | "commentsExtensible"
                | "people"
                | "threadedComment"
                | "threadedComments"
                | "person"
        )
    {
        return Some("ooxml.comments");
    }
    if choices.remove_custom_xml && matches!(name, "customXml" | "customXmlProps") {
        return Some("ooxml.custom_xml");
    }
    if choices.remove_embedded_objects && matches!(name, "oleObject" | "package") {
        return Some("ooxml.embedded_object");
    }
    if choices.accept_revisions && matches!(name, "revisionHeaders" | "revisionLog" | "usernames") {
        return Some("ooxml.revisions");
    }
    None
}
fn comments_type(content_type: &str) -> bool {
    let lower = content_type.to_ascii_lowercase();
    [
        "application/vnd.openxmlformats-officedocument.",
        "application/vnd.ms-word.",
        "application/vnd.ms-excel.",
        "application/vnd.ms-powerpoint.",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
        && (lower.contains("comment") || lower.ends_with(".person+xml"))
}
fn plan(package: &Package, options: &SanitizeOptions, limits: &Limits) -> Result<Plan> {
    if options.policy != Policy::Deep && options.deep.any() {
        return Err(Error::Blocked(
            "Office content-changing selections require the Deep policy".into(),
        ));
    }
    let choices = &options.deep;
    let mut result = Plan {
        removed: BTreeSet::new(),
        edits: BTreeMap::new(),
        codes: BTreeSet::new(),
    };
    let types = content_types(package)?;
    for part in package
        .parts
        .iter()
        .filter(|part| !part.directory && part.name != "[Content_Types].xml")
    {
        let code = if choices.remove_comments
            && (comments_part(&part.name) || comments_type(types.for_part(&part.name)?))
        {
            Some("ooxml.comments")
        } else if choices.remove_custom_xml && custom_part(&part.name) {
            Some("ooxml.custom_xml")
        } else if choices.remove_embedded_objects && embedded_part(&part.name) {
            Some("ooxml.embedded_object")
        } else if choices.accept_revisions && revision_part(&part.name) {
            Some("ooxml.revisions")
        } else {
            None
        };
        if let Some(code) = code {
            result.removed.insert(part.name.clone());
            result.codes.insert(code);
        }
    }
    // OPC relationship types identify privacy parts even when their member names differ.
    for part in package
        .parts
        .iter()
        .filter(|part| part.name.ends_with(".rels"))
    {
        let source = relationship_source(&part.name)?;
        for relationship in relationships(&part.data)? {
            if !relationship.external
                && let Some(code) = selected_relationship(&relationship.kind, choices)
            {
                result
                    .removed
                    .insert(relationship_target(&source, &relationship.target)?);
                result.codes.insert(code);
            }
        }
    }
    if choices.remove_hidden_sheets {
        plan_hidden_sheets(package, limits, &mut result)?;
    }
    for part in &package.parts {
        if relation_part_for_removed(&part.name, &result.removed) {
            result.removed.insert(part.name.clone());
        }
    }
    let mut external_ids: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for part in package
        .parts
        .iter()
        .filter(|part| part.name.ends_with(".rels") && !result.removed.contains(&part.name))
    {
        let source = relationship_source(&part.name)?;
        for node in nodes(&part.data, limits)? {
            if node.namespace != REL_NS || node.local != "Relationship" {
                continue;
            }
            let target = node.attribute("Target").ok_or_else(xml_error)?;
            let external = node.attribute("TargetMode") == Some("External");
            let remove_target = !external
                && result
                    .removed
                    .contains(&relationship_target(&source, target)?);
            if external && choices.remove_external_relationships {
                if !node
                    .attribute("Type")
                    .is_some_and(|kind| kind.ends_with("/hyperlink"))
                {
                    return Err(Error::Blocked("Deep external-relationship removal currently supports hyperlinks. External data, templates and linked media require format-specific dependency handling".into()));
                }
                external_ids
                    .entry(source.clone())
                    .or_default()
                    .insert(node.attribute("Id").ok_or_else(xml_error)?.into());
                result.codes.insert("ooxml.external_relationship");
            }
            if remove_target || (external && choices.remove_external_relationships) {
                result
                    .edits
                    .entry(part.name.clone())
                    .or_default()
                    .push(remove(&node));
            }
        }
    }
    for part in package
        .parts
        .iter()
        .filter(|part| !part.directory && !result.removed.contains(&part.name))
    {
        if part.name == "[Content_Types].xml" {
            for node in nodes(&part.data, limits)? {
                if node.namespace == CT_NS
                    && node.local == "Override"
                    && node
                        .attribute("PartName")
                        .and_then(|s| s.strip_prefix('/'))
                        .is_some_and(|name| result.removed.contains(name))
                {
                    result
                        .edits
                        .entry(part.name.clone())
                        .or_default()
                        .push(remove(&node));
                }
            }
            continue;
        }
        if !part.name.ends_with(".xml") && !part.name.ends_with(".vml") {
            continue;
        }
        let parsed = nodes(&part.data, limits)?;
        let edits = result.edits.entry(part.name.clone()).or_default();
        for (index, node) in parsed.iter().enumerate() {
            if choices.remove_comments
                && node.word()
                && matches!(
                    node.local.as_str(),
                    "commentRangeStart" | "commentRangeEnd" | "commentReference"
                )
            {
                edits.push(remove(node));
                result.codes.insert("ooxml.comments");
            }
            if choices.remove_comments
                && node.namespace == EXCEL_NS
                && node.local == "ClientData"
                && node.attribute("ObjectType") == Some("Note")
            {
                let shape = ancestor(&parsed, index, VML_NS, "shape").ok_or_else(|| {
                    Error::Blocked("Legacy spreadsheet note shape cannot be safely isolated".into())
                })?;
                edits.push(remove(&parsed[shape]));
                result.codes.insert("ooxml.comments");
            }
            if choices.accept_revisions && node.word() && is_revision(&node.local) {
                let parent = node.parent.map(|i| &parsed[i]);
                if matches!(
                    node.local.as_str(),
                    "cellIns" | "cellDel" | "cellMerge" | "tblGridChange" | "numberingChange"
                ) || (matches!(node.local.as_str(), "ins" | "del")
                    && parent.is_some_and(|parent| {
                        matches!(parent.local.as_str(), "rPr" | "trPr" | "tcPr")
                    }))
                {
                    return Err(Error::Blocked("Accepting tracked paragraph-mark, table-grid or numbering changes requires an Office layout-aware revision engine".into()));
                }
                if matches!(node.local.as_str(), "ins" | "moveTo") {
                    unwrap(node, edits);
                } else {
                    edits.push(remove(node));
                }
                result.codes.insert("ooxml.revisions");
            }
            if choices.remove_hidden_text && hidden(node) {
                if part.name.ends_with("styles.xml") || part.name.ends_with("stylesWithEffects.xml")
                {
                    return Err(Error::Blocked("Hidden text inherited through document styles requires style resolution and is protected in this build".into()));
                }
                let run = ancestor(&parsed, index, &node.namespace, "r").ok_or_else(|| {
                    Error::Blocked("Hidden text properties could not be isolated to a run".into())
                })?;
                edits.push(remove(&parsed[run]));
                result.codes.insert("ooxml.hidden_content");
            }
            if choices.remove_custom_xml && node.word() {
                if node.local == "customXml" {
                    unwrap(node, edits);
                    result.codes.insert("ooxml.custom_xml");
                }
                if matches!(node.local.as_str(), "dataBinding" | "customXmlPr") {
                    edits.push(remove(node));
                    result.codes.insert("ooxml.custom_xml");
                }
            }
            if choices.remove_embedded_objects {
                if node.word() && node.local == "object" {
                    edits.push(remove(node));
                    result.codes.insert("ooxml.embedded_object");
                }
                if node.namespace == S_NS && node.local == "oleObjects" {
                    edits.push(remove(node));
                    result.codes.insert("ooxml.embedded_object");
                }
                if node.local == "oleObj" && node.namespace.contains("presentationml") {
                    let frame=ancestor(&parsed,index,&node.namespace,"graphicFrame").ok_or_else(||Error::Blocked("Presentation embedded object could not be isolated to a graphics frame".into()))?;
                    edits.push(remove(&parsed[frame]));
                    result.codes.insert("ooxml.embedded_object");
                }
            }
            if external_ids
                .get(&part.name)
                .is_some_and(|ids| node.relationship_id().is_some_and(|id| ids.contains(id)))
            {
                if node.word() && node.local == "hyperlink" {
                    unwrap(node, edits);
                } else if matches!(node.local.as_str(), "hlinkClick" | "hlinkMouseOver")
                    || (node.namespace == S_NS && node.local == "hyperlink")
                {
                    edits.push(remove(node));
                } else {
                    return Err(Error::Blocked(
                        "An external hyperlink reference uses an unsupported document structure"
                            .into(),
                    ));
                }
            }
            if choices.remove_internal_identifiers && node.word() {
                if node.local == "rsids" {
                    edits.push(remove(node));
                    result.codes.insert("ooxml.internal_identifiers");
                    continue;
                }
                let retained: Vec<_> = node
                    .opening
                    .attributes()
                    .map(|a| a.map_err(|_| xml_error()))
                    .collect::<Result<Vec<_>>>()?
                    .into_iter()
                    .filter(|attr| {
                        !node.attributes.iter().any(|known| {
                            known.qualified == attr.key.as_ref()
                                && matches!(known.namespace.as_str(), W_NS | W_STRICT)
                                && known.local.starts_with("rsid")
                        })
                    })
                    .collect();
                if retained.len() != node.attributes.len() {
                    let mut opening = node.opening.clone();
                    opening.clear_attributes();
                    opening.extend_attributes(retained);
                    let mut writer = quick_xml::Writer::new(Vec::new());
                    writer
                        .write_event(if node.empty {
                            Event::Empty(opening)
                        } else {
                            Event::Start(opening)
                        })
                        .map_err(|_| xml_error())?;
                    edits.push(Edit {
                        start: node.start,
                        end: node.open_end,
                        replacement: writer.into_inner(),
                    });
                    result.codes.insert("ooxml.internal_identifiers");
                }
            }
        }
    }
    result.edits.retain(|_, edits| !edits.is_empty());
    Ok(result)
}

pub fn inspect_with_options(
    data: &[u8],
    limits: &Limits,
    options: &SanitizeOptions,
) -> Result<Inspection> {
    let package = read_package(data, limits)?;
    let mut inspection = inspect_package(&package, limits)?;
    match plan(&package, options, limits) {
        Ok(plan) => {
            for finding in &mut inspection.findings {
                if plan.codes.contains(finding.code.as_str()) {
                    finding.action = Action::Remove;
                    finding.impact=Some("Explicit Deep selection changes document structure or content. Full visual equivalence remains unassessed".into());
                }
            }
        }
        Err(Error::Blocked(reason)) => inspection.blockers.push(reason),
        Err(error) => return Err(error),
    }
    Ok(inspection)
}

pub fn sanitize_with_options(
    data: &[u8],
    limits: &Limits,
    options: &SanitizeOptions,
) -> Result<Vec<u8>> {
    let package = read_package(data, limits)?;
    let inspection = inspect_package(&package, limits)?;
    if !inspection.blockers.is_empty() {
        return Err(Error::Blocked(inspection.blockers.join(". ")));
    }
    let mut plan = plan(&package, options, limits)?;
    let types = content_types(&package)?;
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for part in &package.parts {
        if plan.removed.contains(&part.name) {
            continue;
        }
        let settings = SimpleFileOptions::default()
            .compression_method(part.compression)
            .last_modified_time(DateTime::default())
            .unix_permissions(part.permissions);
        if part.directory {
            writer
                .add_directory(&part.name, settings)
                .map_err(zip_error)?;
            continue;
        }
        let mut bytes = if let Some(kind) = property_kind(types.for_part(&part.name)?) {
            clean_properties(&part.data, kind, limits)?.cleaned
        } else {
            part.data.clone()
        };
        if let Some(edits) = plan.edits.get_mut(&part.name) {
            bytes = apply(&bytes, edits)?;
        }
        writer.start_file(&part.name, settings).map_err(zip_error)?;
        writer
            .write_all(&bytes)
            .map_err(|_| Error::Io("Could not write Deep Office output".into()))?;
    }
    let output = writer.finish().map_err(zip_error)?.into_inner();
    if output.len() as u64 > limits.max_file_bytes {
        return Err(Error::Blocked(
            "Deep Office output exceeds the file byte budget".into(),
        ));
    }
    independent_postconditions(&read_package(&output, limits)?, &options.deep, limits)?;
    Ok(output)
}

fn independent_postconditions(
    package: &Package,
    choices: &DeepOptions,
    limits: &Limits,
) -> Result<()> {
    let mut relation_ids: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for part in package.parts.iter().filter(|part| !part.directory) {
        if (choices.remove_comments && comments_part(&part.name))
            || (choices.remove_custom_xml && custom_part(&part.name))
            || (choices.remove_embedded_objects && embedded_part(&part.name))
            || (choices.accept_revisions && revision_part(&part.name))
        {
            return Err(Error::Verification(
                "Selected private Office package parts remain".into(),
            ));
        }
        if !part.name.ends_with(".xml")
            && !part.name.ends_with(".rels")
            && !part.name.ends_with(".vml")
        {
            continue;
        }
        let document = roxmltree::Document::parse_with_options(
            std::str::from_utf8(&part.data).map_err(|_| xml_error())?,
            roxmltree::ParsingOptions {
                allow_dtd: false,
                nodes_limit: limits
                    .max_members
                    .saturating_mul(256)
                    .min(u32::MAX as usize) as u32,
                ..Default::default()
            },
        )
        .map_err(|_| {
            Error::Verification("Independent XML parser rejected Deep Office output".into())
        })?;
        for node in document.descendants().filter(|node| node.is_element()) {
            let ns = node.tag_name().namespace().unwrap_or("");
            let local = node.tag_name().name();
            let word = matches!(ns, W_NS | W_STRICT);
            let selected = (choices.remove_comments
                && word
                && matches!(
                    local,
                    "commentRangeStart" | "commentRangeEnd" | "commentReference"
                ))
                || (choices.remove_hidden_sheets
                    && spreadsheet(ns)
                    && local == "sheet"
                    && node
                        .attribute("state")
                        .is_some_and(|state| matches!(state, "hidden" | "veryHidden")))
                || (choices.accept_revisions && word && is_revision(local))
                || (choices.remove_custom_xml
                    && word
                    && matches!(local, "customXml" | "customXmlPr" | "dataBinding"))
                || (choices.remove_embedded_objects
                    && ((word && local == "object")
                        || (ns == S_NS && local == "oleObjects")
                        || (ns.contains("presentationml") && local == "oleObj")))
                || (choices.remove_internal_identifiers && word && local == "rsids")
                || (choices.remove_hidden_text
                    && word
                    && matches!(local, "vanish" | "webHidden")
                    && !node.attributes().any(|attr| {
                        matches!(attr.namespace(), Some(W_NS | W_STRICT))
                            && attr.name() == "val"
                            && matches!(attr.value(), "0" | "false" | "off")
                    }));
            if selected
                || (choices.remove_internal_identifiers
                    && node.attributes().any(|attribute| {
                        matches!(attribute.namespace(), Some(W_NS | W_STRICT))
                            && attribute.name().starts_with("rsid")
                    }))
            {
                return Err(Error::Verification(
                    "Selected Office privacy structures remain after transformation".into(),
                ));
            }
            if part.name.ends_with(".rels") && ns == REL_NS && local == "Relationship" {
                if selected_relationship(node.attribute("Type").unwrap_or(""), choices).is_some() {
                    return Err(Error::Verification(
                        "Selected private Office part relationships remain".into(),
                    ));
                }
                if choices.remove_external_relationships
                    && node.attribute("TargetMode") == Some("External")
                {
                    return Err(Error::Verification(
                        "External Office relationships remain".into(),
                    ));
                }
                relation_ids
                    .entry(relationship_source(&part.name)?)
                    .or_default()
                    .insert(node.attribute("Id").ok_or_else(xml_error)?.into());
            }
        }
    }
    // This independent parser also checks that XML references still have relationship IDs.
    for part in package
        .parts
        .iter()
        .filter(|part| part.name.ends_with(".xml") && !part.directory)
    {
        let document = roxmltree::Document::parse(
            std::str::from_utf8(&part.data).map_err(|_| xml_error())?,
        )
        .map_err(|_| Error::Verification("Independent Office XML validation failed".into()))?;
        for attribute in document.descendants().flat_map(|node| node.attributes()) {
            if matches!(attribute.namespace(), Some(R_NS | R_STRICT))
                && matches!(attribute.name(), "id" | "embed" | "link")
                && !relation_ids
                    .get(&part.name)
                    .is_some_and(|ids| ids.contains(attribute.value()))
            {
                return Err(Error::Verification(
                    "Deep Office output has an unresolved relationship reference".into(),
                ));
            }
        }
    }
    Ok(())
}

pub fn verify_scoped(
    before: &[u8],
    after: &[u8],
    limits: &Limits,
    options: &SanitizeOptions,
) -> Result<ScopedVerification> {
    let original = read_package(before, limits)?;
    let output = read_package(after, limits)?;
    let before_inspection = inspect_package(&original, limits)?;
    let after_inspection = inspect_package(&output, limits)?;
    if before_inspection.format != after_inspection.format
        || !before_inspection.blockers.is_empty()
        || !after_inspection.blockers.is_empty()
    {
        return Err(Error::Blocked(
            "Office type or credential protections prevent scoped verification".into(),
        ));
    }
    let mut plan = plan(&original, options, limits)?;
    let types = content_types(&original)?;
    let expected_names: BTreeSet<_> = original
        .parts
        .iter()
        .filter(|part| !plan.removed.contains(&part.name))
        .map(|part| part.name.as_str())
        .collect();
    if expected_names != output.parts.iter().map(|part| part.name.as_str()).collect() {
        return Err(Error::Verification(
            "Office package membership differs outside the selected scope".into(),
        ));
    }
    for original_part in original
        .parts
        .iter()
        .filter(|part| !plan.removed.contains(&part.name))
    {
        let output_part = output
            .parts
            .iter()
            .find(|part| part.name == original_part.name)
            .ok_or_else(xml_error)?;
        let mut expected = if !original_part.directory {
            if let Some(kind) = property_kind(types.for_part(&original_part.name)?) {
                clean_properties(&original_part.data, kind, limits)?.cleaned
            } else {
                original_part.data.clone()
            }
        } else {
            original_part.data.clone()
        };
        if let Some(edits) = plan.edits.get_mut(&original_part.name) {
            expected = apply(&expected, edits)?;
        }
        if output_part.data != expected {
            return Err(Error::Verification(
                "Office bytes outside the exact selected edits changed".into(),
            ));
        }
    }
    independent_postconditions(&output, &options.deep, limits)?;
    if after_inspection
        .findings
        .iter()
        .any(|finding| finding.action == Action::Remove)
    {
        return Err(Error::Verification(
            "Standard Office properties remain after Deep cleaning".into(),
        ));
    }
    let mut findings = after_inspection.findings;
    for mut finding in before_inspection.findings {
        if finding.action == Action::Remove || plan.codes.contains(finding.code.as_str()) {
            finding.state = FindingState::RemovedVerified;
            finding.confidence = fileveil_core::Confidence::Verified;
            findings.push(finding);
        }
    }
    for code in plan.codes {
        if !findings.iter().any(|finding| finding.code == code) {
            let mut found = Finding::new(
                code,
                RiskLayer::ContainerStructure,
                "OPC/selected_scope",
                "Explicitly selected Office structure removal passed independent XML checks",
                Action::Remove,
            );
            found.state = FindingState::RemovedVerified;
            findings.push(found);
        }
    }
    Ok(ScopedVerification {findings,warnings:vec!["Deep verification checks exact selected XML edits, untouched package bytes, independent XML parsing and relationship references. Office rendering, formulas, charts and layout interoperability remain partially verified.".into()],integrity:Integrity {parseable:true,content_equal:None,..Integrity::default()},result:Outcome::PartiallyVerified})
}
