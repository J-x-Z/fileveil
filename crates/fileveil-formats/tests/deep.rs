// SPDX-License-Identifier: MPL-2.0
use fileveil_core::{
    Action, DeepOptions, Error, FindingState, Format, Limits, Outcome, Policy, SanitizeOptions,
    TextOptions, digest,
};
use fileveil_formats::{
    inspect, inspect_with_options, sanitize, sanitize_with_options, verify_scoped,
};
use std::{
    io::{Cursor, Read, Write},
    path::Path,
};
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};
const W: &str = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
const R: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const REL: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
fn package(format: Format, body: &str, extra: &[(&str, &[u8])]) -> Vec<u8> {
    let (main, ct) = match format {
        Format::Docx => (
            "word/document.xml",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
        ),
        Format::Xlsx => (
            "xl/workbook.xml",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
        ),
        Format::Pptx => (
            "ppt/presentation.xml",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
        ),
        _ => unreachable!(),
    };
    let types = format!(
        r#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="bin" ContentType="application/octet-stream"/><Override PartName="/{main}" ContentType="{ct}"/></Types>"#
    );
    let rels = format!(
        r#"<Relationships xmlns="{REL}"><Relationship Id="main" Type="{R}/officeDocument" Target="{main}"/></Relationships>"#
    );
    let mut entries = vec![
        ("[Content_Types].xml", types.as_bytes()),
        ("_rels/.rels", rels.as_bytes()),
        (main, body.as_bytes()),
    ];
    entries.extend_from_slice(extra);
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in entries {
        writer
            .start_file(
                name,
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        writer.write_all(data).unwrap();
    }
    writer.finish().unwrap().into_inner()
}
fn part(data: &[u8], name: &str) -> Option<Vec<u8>> {
    let mut zip = ZipArchive::new(Cursor::new(data)).unwrap();
    let mut file = zip.by_name(name).ok()?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    Some(data)
}
fn deep(choices: DeepOptions) -> SanitizeOptions {
    SanitizeOptions {
        policy: Policy::Deep,
        deep: choices,
        ..Default::default()
    }
}

#[test]
fn selected_word_privacy_structures_are_removed_and_independently_verified() {
    let body = format!(
        r#"<w:document xmlns:w="{W}" xmlns:r="{R}"><w:body><w:p w:rsidR="CAFE"><w:r><w:t>Keep visible</w:t></w:r><w:ins w:author="PRIVATE_REV"><w:r><w:t>Accepted insertion</w:t></w:r></w:ins><w:del w:author="PRIVATE_REV"><w:r><w:delText>PRIVATE_DELETED</w:delText></w:r></w:del><w:commentRangeStart w:id="1"/><w:commentRangeEnd w:id="1"/><w:r><w:commentReference w:id="1"/></w:r><w:r><w:rPr><w:vanish/></w:rPr><w:t>PRIVATE_HIDDEN</w:t></w:r><w:hyperlink r:id="url"><w:r><w:t>Keep link text</w:t></w:r></w:hyperlink><w:r><w:object r:id="ole"/></w:r><w:customXml w:element="PRIVATE_SCHEMA"><w:r><w:t>Keep custom cached text</w:t></w:r></w:customXml></w:p></w:body></w:document>"#
    );
    let rels = format!(
        r#"<Relationships xmlns="{REL}"><Relationship Id="comment" Type="{R}/comments" Target="comments.xml"/><Relationship Id="custom" Type="{R}/customXml" Target="../customXml/item1.xml"/><Relationship Id="ole" Type="{R}/oleObject" Target="embeddings/ole1.bin"/><Relationship Id="url" Type="{R}/hyperlink" Target="https://example.invalid/PRIVATE_URL" TargetMode="External"/></Relationships>"#
    );
    let comments = format!(
        r#"<w:comments xmlns:w="{W}"><w:comment w:author="PRIVATE_AUTHOR"><w:p/></w:comment></w:comments>"#
    );
    let original = package(
        Format::Docx,
        &body,
        &[
            ("word/_rels/document.xml.rels", rels.as_bytes()),
            ("word/comments.xml", comments.as_bytes()),
            ("customXml/item1.xml", b"<private>PRIVATE_CUSTOM</private>"),
            ("word/embeddings/ole1.bin", b"PRIVATE_EMBEDDED"),
        ],
    );
    let original_hash = digest(&original);
    let options = deep(DeepOptions {
        remove_comments: true,
        accept_revisions: true,
        remove_hidden_text: true,
        remove_custom_xml: true,
        remove_embedded_objects: true,
        remove_external_relationships: true,
        remove_internal_identifiers: true,
        ..Default::default()
    });
    let output =
        sanitize_with_options(&original, Format::Docx, &Limits::default(), &options).unwrap();
    let document = String::from_utf8(part(&output, "word/document.xml").unwrap()).unwrap();
    for text in [
        "Keep visible",
        "Accepted insertion",
        "Keep link text",
        "Keep custom cached text",
    ] {
        assert!(document.contains(text));
    }
    assert!(!String::from_utf8_lossy(&output).contains("PRIVATE_"));
    assert!(!document.contains("rsid"));
    assert!(part(&output, "word/comments.xml").is_none());
    assert!(part(&output, "word/embeddings/ole1.bin").is_none());
    let verified = verify_scoped(
        &original,
        &output,
        Format::Docx,
        &Limits::default(),
        &options,
    )
    .unwrap();
    assert_eq!(verified.result, Outcome::PartiallyVerified);
    assert_eq!(verified.integrity.content_equal, None);
    assert!(
        verified
            .findings
            .iter()
            .any(|finding| finding.code == "ooxml.revisions"
                && finding.state == FindingState::RemovedVerified)
    );
    assert_eq!(digest(&original), original_hash);
}

#[test]
fn deep_is_opt_in_and_safe_retains_comments_and_hidden_content() {
    let body = format!(
        r#"<w:document xmlns:w="{W}"><w:body><w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>Retain hidden</w:t></w:r></w:p></w:body></w:document>"#
    );
    let original = package(
        Format::Docx,
        &body,
        &[(
            "word/comments.xml",
            format!(r#"<w:comments xmlns:w="{W}"/>"#).as_bytes(),
        )],
    );
    let output = sanitize(&original, Format::Docx, &Limits::default()).unwrap();
    assert_eq!(
        part(&original, "word/document.xml"),
        part(&output, "word/document.xml")
    );
    assert!(part(&output, "word/comments.xml").is_some());
    let options = SanitizeOptions {
        deep: DeepOptions {
            remove_comments: true,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(matches!(
        sanitize_with_options(&original, Format::Docx, &Limits::default(), &options),
        Err(Error::Blocked(_))
    ));
}

#[test]
fn complex_revision_and_inherited_hidden_text_are_protected() {
    let body = format!(
        r#"<w:document xmlns:w="{W}"><w:body><w:p><w:pPr><w:rPr><w:del w:author="Synthetic"/></w:rPr></w:pPr></w:p></w:body></w:document>"#
    );
    let original = package(Format::Docx, &body, &[]);
    assert!(matches!(
        sanitize_with_options(
            &original,
            Format::Docx,
            &Limits::default(),
            &deep(DeepOptions {
                accept_revisions: true,
                ..Default::default()
            })
        ),
        Err(Error::Blocked(_))
    ));
    let body = format!(r#"<w:document xmlns:w="{W}"><w:body/></w:document>"#);
    let styles = format!(
        r#"<w:styles xmlns:w="{W}"><w:style><w:rPr><w:vanish/></w:rPr></w:style></w:styles>"#
    );
    let original = package(
        Format::Docx,
        &body,
        &[("word/styles.xml", styles.as_bytes())],
    );
    assert!(matches!(
        sanitize_with_options(
            &original,
            Format::Docx,
            &Limits::default(),
            &deep(DeepOptions {
                remove_hidden_text: true,
                ..Default::default()
            })
        ),
        Err(Error::Blocked(_))
    ));
}

#[test]
fn spreadsheet_hidden_sheets_and_external_formulas_remain_protected() {
    let body = r#"<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Secret" sheetId="1" state="hidden"/></sheets></workbook>"#;
    let original = package(Format::Xlsx, body, &[]);
    assert!(matches!(
        sanitize_with_options(
            &original,
            Format::Xlsx,
            &Limits::default(),
            &deep(DeepOptions {
                remove_hidden_sheets: true,
                ..Default::default()
            })
        ),
        Err(Error::Blocked(_))
    ));
    let rels = format!(
        r#"<Relationships xmlns="{REL}"><Relationship Id="data" Type="{R}/externalLinkPath" Target="file:///private.xlsx" TargetMode="External"/></Relationships>"#
    );
    let original = package(
        Format::Xlsx,
        body,
        &[("xl/_rels/workbook.xml.rels", rels.as_bytes())],
    );
    assert!(matches!(
        sanitize_with_options(
            &original,
            Format::Xlsx,
            &Limits::default(),
            &deep(DeepOptions {
                remove_external_relationships: true,
                ..Default::default()
            })
        ),
        Err(Error::Blocked(_))
    ));
}

#[test]
fn comment_parts_are_removable_in_all_three_office_families() {
    for (format,body,comments) in [(Format::Docx,format!(r#"<w:document xmlns:w="{W}"><w:body/></w:document>"#),"word/comments.xml"),(Format::Xlsx,r#"<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets/></workbook>"#.into(),"xl/comments1.xml"),(Format::Pptx,r#"<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:sldIdLst/></p:presentation>"#.into(),"ppt/comments/comment1.xml")] {
        let original=package(format,&body,&[(comments,b"<comments><author>PRIVATE_AUTHOR</author></comments>")]);
        let options=deep(DeepOptions{remove_comments:true,..Default::default()});let output=sanitize_with_options(&original,format,&Limits::default(),&options).unwrap();assert!(part(&output,comments).is_none());verify_scoped(&original,&output,format,&Limits::default(),&options).unwrap();
    }
}

#[test]
fn namespace_collisions_and_false_hidden_properties_are_preserved() {
    let body = format!(
        r#"<w:document xmlns:w="{W}" xmlns:x="urn:unrelated"><w:body><x:ins>Keep unrelated</x:ins><w:p><w:r><w:rPr><w:vanish w:val="false"/></w:rPr><w:t>Keep visible</w:t></w:r></w:p></w:body></w:document>"#
    );
    let original = package(Format::Docx, &body, &[]);
    let options = deep(DeepOptions {
        accept_revisions: true,
        remove_hidden_text: true,
        ..Default::default()
    });
    let output =
        sanitize_with_options(&original, Format::Docx, &Limits::default(), &options).unwrap();
    assert_eq!(
        part(&original, "word/document.xml"),
        part(&output, "word/document.xml")
    );
}

#[test]
fn deep_verification_rejects_unselected_visible_edits() {
    let body = format!(
        r#"<w:document xmlns:w="{W}"><w:body><w:p><w:r><w:t>Original visible text</w:t></w:r></w:p></w:body></w:document>"#
    );
    let original = package(Format::Docx, &body, &[]);
    let changed = package(Format::Docx, &body.replace("Original", "Modified"), &[]);
    let options = deep(DeepOptions::default());
    assert!(matches!(
        verify_scoped(
            &original,
            &changed,
            Format::Docx,
            &Limits::default(),
            &options
        ),
        Err(Error::Verification(_))
    ));
}

#[test]
fn text_cleanup_preserves_joiners_bidi_and_legal_whitespace() {
    let original="\u{feff}Persian \u{200c} Devanagari \u{200d} bidi \u{202e} line\u{85} page\u{c} hidden\u{1} end".as_bytes();
    let options = SanitizeOptions {
        text: TextOptions {
            remove_bom: true,
            remove_control_characters: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let output =
        sanitize_with_options(original, Format::Text, &Limits::default(), &options).unwrap();
    let text = std::str::from_utf8(&output).unwrap();
    assert!(!text.starts_with('\u{feff}'));
    assert!(!text.contains('\u{1}'));
    for character in ['\u{200c}', '\u{200d}', '\u{202e}', '\u{85}', '\u{c}'] {
        assert!(text.contains(character));
    }
    let verified = verify_scoped(
        original,
        &output,
        Format::Text,
        &Limits::default(),
        &options,
    )
    .unwrap();
    assert_eq!(verified.result, Outcome::PartiallyVerified);
    assert!(
        verified
            .findings
            .iter()
            .any(|finding| finding.code == "text.invisible_unicode"
                && finding.action == Action::Preserve)
    );
    let scanned = inspect_with_options(
        b"text\0control",
        Path::new("input.txt"),
        &Limits::default(),
        &options,
    )
    .unwrap();
    assert_eq!(scanned.format, Format::Text);
}

#[test]
fn html_cleaner_removes_only_real_identity_meta_and_comments() {
    let original=br#"<!doctype html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width"><meta name="referrer" content="no-referrer"><META NAME='AUTHOR' content='PRIVATE_AUTHOR'><meta name="generator" content="PRIVATE_GENERATOR"><style>/* <meta name="author"> */</style><script>const s="<meta name='author' content='keep'>";<!--keep-script--></script></head><body><!--PRIVATE_COMMENT--><textarea><meta name='author'>keep</textarea><p>Visible text</p></body></html>"#;
    let options = SanitizeOptions {
        text: TextOptions {
            remove_html_metadata: true,
            remove_html_comments: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let output =
        sanitize_with_options(original, Format::Html, &Limits::default(), &options).unwrap();
    let text = std::str::from_utf8(&output).unwrap();
    assert!(!text.contains("PRIVATE_"));
    for keep in [
        "charset=",
        "viewport",
        "no-referrer",
        "keep-script",
        "<textarea><meta name='author'>keep",
        "Visible text",
    ] {
        assert!(text.contains(keep), "missing {keep}");
    }
    verify_scoped(
        original,
        &output,
        Format::Html,
        &Limits::default(),
        &options,
    )
    .unwrap();
}

#[test]
fn html_ambiguous_and_malformed_inputs_fail_without_rewriting() {
    let options = SanitizeOptions {
        text: TextOptions {
            remove_html_comments: true,
            ..Default::default()
        },
        ..Default::default()
    };
    for original in [
        b"<html><svg><title>foreign</title></svg></html>".as_slice(),
        b"<html><!--[if IE]><p>visible</p><![endif]--></html>",
        b"<html><meta a='broken></html>",
    ] {
        assert!(matches!(
            sanitize_with_options(original, Format::Html, &Limits::default(), &options),
            Err(Error::Blocked(_))
        ));
    }
    assert!(
        !inspect(
            b"<html><p>Read only</p></html>",
            Path::new("input.html"),
            &Limits::default()
        )
        .unwrap()
        .rewrite_supported
    );
}

#[test]
fn namespace_alias_cannot_disable_a_real_hidden_run() {
    let body = format!(
        r#"<w:document xmlns:w="{W}" xmlns:x="urn:unrelated"><w:body><w:p><w:r><w:rPr><w:vanish x:val="false"/></w:rPr><w:t>PRIVATE_HIDDEN</w:t></w:r></w:p></w:body></w:document>"#
    );
    let original = package(Format::Docx, &body, &[]);
    let options = deep(DeepOptions {
        remove_hidden_text: true,
        ..Default::default()
    });
    let output =
        sanitize_with_options(&original, Format::Docx, &Limits::default(), &options).unwrap();
    assert!(
        !String::from_utf8_lossy(&part(&output, "word/document.xml").unwrap())
            .contains("PRIVATE_HIDDEN")
    );
    verify_scoped(
        &original,
        &output,
        Format::Docx,
        &Limits::default(),
        &options,
    )
    .unwrap();
}

#[test]
#[ignore = "requires FILEVEIL_TEST_PYTHON or a python3 interpreter for independent ZIP interoperability"]
fn independent_python_zip_and_xml_interoperability() {
    use std::process::{Command, Stdio};
    let body = format!(
        r#"<w:document xmlns:w="{W}"><w:body><w:p><w:r><w:t>Independent visible text</w:t></w:r><w:del><w:r><w:delText>PRIVATE_HISTORY</w:delText></w:r></w:del></w:p></w:body></w:document>"#
    );
    let original = package(
        Format::Docx,
        &body,
        &[(
            "word/comments.xml",
            format!(
                r#"<w:comments xmlns:w="{W}"><w:comment w:author="PRIVATE_AUTHOR"/></w:comments>"#
            )
            .as_bytes(),
        )],
    );
    let output = sanitize_with_options(
        &original,
        Format::Docx,
        &Limits::default(),
        &deep(DeepOptions {
            remove_comments: true,
            accept_revisions: true,
            ..Default::default()
        }),
    )
    .unwrap();
    let script = r#"import io,sys,zipfile,xml.etree.ElementTree as E
z=zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read()))
assert z.testzip() is None
assert 'word/comments.xml' not in z.namelist()
for name in z.namelist():
 if name.endswith(('.xml','.rels')): E.fromstring(z.read(name))
s=z.read('word/document.xml')
assert b'Independent visible text' in s
assert b'PRIVATE_' not in s
print('independent_zip_crc_and_xml_passed')
"#;
    let python = std::env::var_os("FILEVEIL_TEST_PYTHON").unwrap_or_else(|| "python3".into());
    let mut child = Command::new(python)
        .args(["-I", "-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&output).unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    assert_eq!(result.stdout, b"independent_zip_crc_and_xml_passed\n");
}

#[test]
fn relationship_types_identify_privacy_parts_with_arbitrary_member_names() {
    let body = format!(r#"<w:document xmlns:w="{W}"><w:body/></w:document>"#);
    let rels = format!(
        r#"<Relationships xmlns="{REL}"><Relationship Id="review" Type="{R}/comments" Target="unusual-review.xml"/><Relationship Id="custom" Type="{R}/customXml" Target="unusual-store.xml"/></Relationships>"#
    );
    let original = package(
        Format::Docx,
        &body,
        &[
            ("word/_rels/document.xml.rels", rels.as_bytes()),
            (
                "word/unusual-review.xml",
                b"<comments>PRIVATE_AUTHOR</comments>",
            ),
            ("word/unusual-store.xml", b"<store>PRIVATE_STORE</store>"),
        ],
    );
    let options = deep(DeepOptions {
        remove_comments: true,
        remove_custom_xml: true,
        ..Default::default()
    });
    let output =
        sanitize_with_options(&original, Format::Docx, &Limits::default(), &options).unwrap();
    assert!(part(&output, "word/unusual-review.xml").is_none());
    assert!(part(&output, "word/unusual-store.xml").is_none());
    verify_scoped(
        &original,
        &output,
        Format::Docx,
        &Limits::default(),
        &options,
    )
    .unwrap();
}

fn hidden_workbook(visible_sheet: &str, workbook_extra: &str, extra: &[(&str, &[u8])]) -> Vec<u8> {
    let ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
    let workbook = format!(
        r#"<workbook xmlns="{ns}" xmlns:r="{R}"><bookViews><workbookView activeTab="1" firstSheet="1"/></bookViews><sheets><sheet name="PRIVATE_HIDDEN_ONE" sheetId="1" state="hidden" r:id="hidden1"/><sheet name="Visible" sheetId="2" r:id="visible"/><sheet name="PRIVATE_HIDDEN_TWO" sheetId="3" state="veryHidden" r:id="hidden2"/></sheets>{workbook_extra}</workbook>"#
    );
    let rels = format!(
        r#"<Relationships xmlns="{REL}"><Relationship Id="hidden1" Type="{R}/worksheet" Target="worksheets/private1.xml"/><Relationship Id="visible" Type="{R}/worksheet" Target="worksheets/public.xml"/><Relationship Id="hidden2" Type="{R}/worksheet" Target="worksheets/private2.xml"/></Relationships>"#
    );
    let secret = format!(
        r#"<worksheet xmlns="{ns}"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>PRIVATE_HIDDEN_PAYLOAD</t></is></c></row></sheetData></worksheet>"#
    );
    let mut entries = vec![
        ("xl/_rels/workbook.xml.rels", rels.as_bytes()),
        ("xl/worksheets/private1.xml", secret.as_bytes()),
        ("xl/worksheets/private2.xml", secret.as_bytes()),
        ("xl/worksheets/public.xml", visible_sheet.as_bytes()),
    ];
    entries.extend_from_slice(extra);
    let initial = package(Format::Xlsx, &workbook, &entries);
    let mut zip = ZipArchive::new(Cursor::new(&initial)).unwrap();
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for index in 0..zip.len() {
        let mut file = zip.by_index(index).unwrap();
        let name = file.name().unwrap().into_owned();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        if name == "[Content_Types].xml" {
            let mut types = String::from_utf8(bytes).unwrap();
            let declarations=["private1","private2","public"].iter().map(|name|format!(r#"<Override PartName="/xl/worksheets/{name}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>"#)).collect::<String>();
            types = types.replace("</Types>", &format!("{declarations}</Types>"));
            bytes = types.into_bytes();
        }
        writer
            .start_file(
                name,
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        writer.write_all(&bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}
fn literal_sheet() -> &'static str {
    r#"<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Retained visible text</t></is></c><c r="B1"><v>42</v></c></row></sheetData></worksheet>"#
}

#[test]
fn simple_hidden_worksheets_are_removed_with_relationships_and_view_reindexing() {
    let original = hidden_workbook(literal_sheet(), "", &[]);
    let options = deep(DeepOptions {
        remove_hidden_sheets: true,
        ..Default::default()
    });
    let before = inspect_with_options(
        &original,
        Path::new("workbook.xlsx"),
        &Limits::default(),
        &options,
    )
    .unwrap();
    assert!(before.blockers.is_empty());
    assert!(
        before.findings.iter().any(
            |finding| finding.code == "ooxml.hidden_sheets" && finding.action == Action::Remove
        )
    );
    let output =
        sanitize_with_options(&original, Format::Xlsx, &Limits::default(), &options).unwrap();
    assert!(part(&output, "xl/worksheets/private1.xml").is_none());
    assert!(part(&output, "xl/worksheets/private2.xml").is_none());
    assert_eq!(
        part(&original, "xl/worksheets/public.xml"),
        part(&output, "xl/worksheets/public.xml")
    );
    assert!(!String::from_utf8_lossy(&output).contains("PRIVATE_HIDDEN"));
    // roxmltree independently verifies workbook references, namespace and view indices.
    let workbook = part(&output, "xl/workbook.xml").unwrap();
    let document = roxmltree::Document::parse(std::str::from_utf8(&workbook).unwrap()).unwrap();
    let sheets: Vec<_> = document
        .descendants()
        .filter(|node| node.tag_name().name() == "sheet")
        .collect();
    assert_eq!(sheets.len(), 1);
    assert_eq!(sheets[0].attribute("name"), Some("Visible"));
    let view = document
        .descendants()
        .find(|node| node.tag_name().name() == "workbookView")
        .unwrap();
    assert_eq!(view.attribute("activeTab"), Some("0"));
    assert_eq!(view.attribute("firstSheet"), Some("0"));
    let types = part(&output, "[Content_Types].xml").unwrap();
    let types = roxmltree::Document::parse(std::str::from_utf8(&types).unwrap()).unwrap();
    assert!(!types.descendants().any(|node| {
        node.attribute("PartName")
            .is_some_and(|name| name.contains("private"))
    }));
    let rels = part(&output, "xl/_rels/workbook.xml.rels").unwrap();
    let rels = roxmltree::Document::parse(std::str::from_utf8(&rels).unwrap()).unwrap();
    assert_eq!(
        rels.descendants()
            .filter(|node| node.tag_name().name() == "Relationship")
            .count(),
        1
    );
    let verified = verify_scoped(
        &original,
        &output,
        Format::Xlsx,
        &Limits::default(),
        &options,
    )
    .unwrap();
    assert_eq!(verified.result, Outcome::PartiallyVerified);
    assert_eq!(verified.integrity.content_equal, None);
    assert!(
        verified
            .findings
            .iter()
            .any(|finding| finding.code == "ooxml.hidden_sheets"
                && finding.state == FindingState::RemovedVerified)
    );
}

#[test]
fn hidden_sheet_deletion_blocks_calculation_and_shared_string_dependencies() {
    let options = deep(DeepOptions {
        remove_hidden_sheets: true,
        ..Default::default()
    });
    for tag in [
        "f",
        "formula",
        "formula1",
        "formula2",
        "calculatedColumnFormula",
        "totalsRowFormula",
    ] {
        let formula =
            literal_sheet().replace("<v>42</v>", &format!("<{tag}>SUM(A1:A2)</{tag}><v>42</v>"));
        let original = hidden_workbook(&formula, "", &[]);
        assert!(
            matches!(
                sanitize_with_options(&original, Format::Xlsx, &Limits::default(), &options),
                Err(Error::Blocked(_))
            ),
            "{tag}"
        );
    }
    let original = hidden_workbook(
        literal_sheet(),
        r#"<definedNames><definedName name="PrivateRange">PRIVATE_HIDDEN_ONE!A1</definedName></definedNames>"#,
        &[],
    );
    assert!(matches!(
        sanitize_with_options(&original, Format::Xlsx, &Limits::default(), &options),
        Err(Error::Blocked(_))
    ));
    for name in [
        "xl/sharedStrings.xml",
        "xl/calcChain.xml",
        "xl/charts/chart1.xml",
        "xl/pivotTables/pivotTable1.xml",
    ] {
        let original = hidden_workbook(literal_sheet(), "", &[(name, b"<dependency/>")]);
        assert!(
            matches!(
                sanitize_with_options(&original, Format::Xlsx, &Limits::default(), &options),
                Err(Error::Blocked(_))
            ),
            "{name}"
        );
    }
}

#[test]
fn hidden_sheet_deletion_blocks_complex_outbound_and_inbound_relationships() {
    let options = deep(DeepOptions {
        remove_hidden_sheets: true,
        ..Default::default()
    });
    let external = format!(
        r#"<Relationships xmlns="{REL}"><Relationship Id="link" Type="{R}/hyperlink" Target="https://example.invalid/private" TargetMode="External"/></Relationships>"#
    );
    let original = hidden_workbook(
        literal_sheet(),
        "",
        &[("xl/worksheets/_rels/private1.xml.rels", external.as_bytes())],
    );
    assert!(matches!(
        sanitize_with_options(&original, Format::Xlsx, &Limits::default(), &options),
        Err(Error::Blocked(_))
    ));
    let inbound = format!(
        r#"<Relationships xmlns="{REL}"><Relationship Id="other" Type="urn:unknown" Target="private1.xml"/></Relationships>"#
    );
    let original = hidden_workbook(
        literal_sheet(),
        "",
        &[("xl/worksheets/_rels/public.xml.rels", inbound.as_bytes())],
    );
    assert!(matches!(
        sanitize_with_options(&original, Format::Xlsx, &Limits::default(), &options),
        Err(Error::Blocked(_))
    ));
}
