// SPDX-License-Identifier: MPL-2.0
//! Deterministic, fictional inputs for format and security regression checks.
use flate2::{Compression, write::ZlibEncoder};
use image::{DynamicImage, ImageFormat, Rgb, RgbImage};
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let output = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("tests/fixtures"));
    if args.next().is_some() {
        return Err("usage: fixture-generator [output-directory]".into());
    }
    fs::create_dir_all(&output)?;
    let files = fixtures()?;
    for (name, _) in &files {
        if output.join(name).exists() {
            return Err(format!("fixture already exists: {name}").into());
        }
    }
    for (name, data) in &files {
        write_new(&output.join(name), data)?;
    }
    println!("Generated {} synthetic fixtures", files.len());
    Ok(())
}

fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut output = OpenOptions::new().create_new(true).write(true).open(path)?;
    output.write_all(data)?;
    Ok(())
}

fn fixtures() -> Result<Vec<(&'static str, Vec<u8>)>> {
    let image = DynamicImage::ImageRgb8(RgbImage::from_fn(8, 6, |x, y| {
        Rgb([(x * 31) as u8, (y * 43) as u8, ((x + y) * 17) as u8])
    }));
    let mut jpeg = Cursor::new(Vec::new());
    image.write_to(&mut jpeg, ImageFormat::Jpeg)?;
    let clean_jpeg = jpeg.into_inner();
    let mut png = Cursor::new(Vec::new());
    image.write_to(&mut png, ImageFormat::Png)?;
    let clean_png = png.into_inner();
    let icc = synthetic_icc();
    let exif = synthetic_exif();
    let mut jpeg = clean_jpeg[..2].to_vec();
    let mut exif_payload = b"Exif\0\0".to_vec();
    exif_payload.extend_from_slice(&exif);
    jpeg_segment(&mut jpeg, 0xe1, &exif_payload);
    jpeg_segment(&mut jpeg, 0xe1, b"http://ns.adobe.com/xap/1.0/\0<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description xmlns:dc=\"http://purl.org/dc/elements/1.1/\" dc:creator=\"Synthetic Author\"/></rdf:RDF></x:xmpmeta>");
    let mut iptc = b"Photoshop 3.0\0".to_vec();
    iptc.extend_from_slice(b"8BIM\x04\x04\0\0");
    let record = b"\x1c\x02\x50\0\x10Synthetic Author";
    iptc.extend_from_slice(&(record.len() as u32).to_be_bytes());
    iptc.extend_from_slice(record);
    if !record.len().is_multiple_of(2) {
        iptc.push(0);
    }
    jpeg_segment(&mut jpeg, 0xed, &iptc);
    jpeg_segment(&mut jpeg, 0xfe, b"Synthetic comment");
    let mut icc_payload = b"ICC_PROFILE\0\x01\x01".to_vec();
    icc_payload.extend_from_slice(&icc);
    jpeg_segment(&mut jpeg, 0xe2, &icc_payload);
    jpeg.extend_from_slice(&clean_jpeg[2..]);
    let mut unknown_jpeg = clean_jpeg[..2].to_vec();
    jpeg_segment(
        &mut unknown_jpeg,
        0xe7,
        b"Synthetic unknown application data",
    );
    unknown_jpeg.extend_from_slice(&clean_jpeg[2..]);
    let mut png = clean_png[..33].to_vec();
    png_chunk(&mut png, b"tEXt", b"Author\0Synthetic Author");
    png_chunk(
        &mut png,
        b"iTXt",
        b"Description\0\0\0\0\0Synthetic description",
    );
    png_chunk(&mut png, b"eXIf", &exif);
    let mut iccp = b"Synthetic RGB\0\0".to_vec();
    let mut zlib = ZlibEncoder::new(Vec::new(), Compression::default());
    zlib.write_all(&icc)?;
    iccp.extend_from_slice(&zlib.finish()?);
    png_chunk(&mut png, b"iCCP", &iccp);
    png.extend_from_slice(&clean_png[33..]);
    let mut bad_crc = clean_png.clone();
    bad_crc[29] ^= 1;
    let mut files = vec![
        ("jpeg_exif_gps_author.jpg", jpeg), ("jpeg_clean.jpg", clean_jpeg),
        ("jpeg_app_unknown.jpg", unknown_jpeg),
        ("png_itxt_exif_icc.png", png), ("png_clean.png", clean_png.clone()),
        ("png_bad_crc.png", bad_crc),
        ("unicode_invisible.txt", "Synthetic\u{200b} text\u{202e}\u{2066}\n".as_bytes().to_vec()),
        ("source_meta.html", b"<!doctype html><html><head><meta name=\"author\" content=\"Synthetic Author\"></head><body><!-- synthetic source -->Visible sample</body></html>".to_vec()),
        ("unknown.bin", vec![0, 255, 7, 3, 0, 1]),
        ("pdf_corrupt.pdf", b"%PDF-1.7\nSynthetic unsupported PDF fixture\n%%EOF\n".to_vec()),
    ];
    files.push((
        "docx_author_comments_rels.docx",
        office("word", &clean_png, false)?,
    ));
    files.push(("docx_signed.docx", office("word", &clean_png, true)?));
    files.push((
        "xlsx_author_custom_formula.xlsx",
        office("xl", &clean_png, false)?,
    ));
    files.push(("pptx_author_media.pptx", office("ppt", &clean_png, false)?));
    files.push((
        "zip_slip.zip",
        archive(&[("../escape.txt", b"Synthetic traversal")])?,
    ));
    files.push((
        "zip_case_collision.zip",
        archive(&[("part.xml", b"a"), ("PART.xml", b"b")])?,
    ));
    files.push((
        "zip_bomb.zip",
        archive(&[("large.xml", &vec![b'0'; 2 * 1024 * 1024])])?,
    ));
    Ok(files)
}

fn jpeg_segment(output: &mut Vec<u8>, marker: u8, payload: &[u8]) {
    output.extend_from_slice(&[0xff, marker]);
    output.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    output.extend_from_slice(payload);
}

fn png_chunk(output: &mut Vec<u8>, kind: &[u8; 4], payload: &[u8]) {
    output.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    output.extend_from_slice(kind);
    output.extend_from_slice(payload);
    let mut crc = crc32fast::Hasher::new();
    crc.update(kind);
    crc.update(payload);
    output.extend_from_slice(&crc.finalize().to_be_bytes());
}

fn tiff_entry(output: &mut Vec<u8>, tag: u16, kind: u16, count: u32, value: u32) {
    output.extend_from_slice(&tag.to_le_bytes());
    output.extend_from_slice(&kind.to_le_bytes());
    output.extend_from_slice(&count.to_le_bytes());
    output.extend_from_slice(&value.to_le_bytes());
}

fn synthetic_exif() -> Vec<u8> {
    let author = b"Synthetic Author\0";
    let make = b"Synthetic Camera\0";
    let date = b"2000:01:01 00:00:00\0";
    let values_start = 8 + 2 + 4 * 12 + 4;
    let gps_start = values_start + author.len() + make.len() + date.len();
    let rational_start = gps_start + 2 + 4 * 12 + 4;
    let mut output = b"II\x2a\0\x08\0\0\0".to_vec();
    output.extend_from_slice(&4u16.to_le_bytes());
    tiff_entry(
        &mut output,
        0x010f,
        2,
        make.len() as u32,
        (values_start + author.len()) as u32,
    );
    tiff_entry(
        &mut output,
        0x0132,
        2,
        date.len() as u32,
        (values_start + author.len() + make.len()) as u32,
    );
    tiff_entry(
        &mut output,
        0x013b,
        2,
        author.len() as u32,
        values_start as u32,
    );
    tiff_entry(&mut output, 0x8825, 4, 1, gps_start as u32);
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(author);
    output.extend_from_slice(make);
    output.extend_from_slice(date);
    output.extend_from_slice(&4u16.to_le_bytes());
    tiff_entry(&mut output, 1, 2, 2, u32::from_le_bytes(*b"N\0\0\0"));
    tiff_entry(&mut output, 2, 5, 3, rational_start as u32);
    tiff_entry(&mut output, 3, 2, 2, u32::from_le_bytes(*b"E\0\0\0"));
    tiff_entry(&mut output, 4, 5, 3, (rational_start + 24) as u32);
    output.extend_from_slice(&0u32.to_le_bytes());
    for number in [1u32, 2, 3, 4, 5, 6] {
        output.extend_from_slice(&number.to_le_bytes());
        output.extend_from_slice(&1u32.to_le_bytes());
    }
    output
}

fn fixed(value: f64) -> [u8; 4] {
    ((value * 65536.0).round() as i32).to_be_bytes()
}

fn xyz(values: [f64; 3]) -> Vec<u8> {
    let mut result = b"XYZ \0\0\0\0".to_vec();
    for value in values {
        result.extend_from_slice(&fixed(value));
    }
    result
}

fn synthetic_icc() -> Vec<u8> {
    let curve = b"curv\0\0\0\0\0\0\0\x01\x02\x33\0\0".to_vec();
    let mut description = b"desc\0\0\0\0\0\0\0\x0eSynthetic RGB\0".to_vec();
    description.extend_from_slice(&[0; 78]);
    let tags = [
        (*b"desc", description),
        (*b"cprt", b"text\0\0\0\0Synthetic fixture\0".to_vec()),
        (*b"wtpt", xyz([0.9642, 1.0, 0.8249])),
        (*b"rXYZ", xyz([0.4361, 0.2225, 0.0139])),
        (*b"gXYZ", xyz([0.3851, 0.7169, 0.0971])),
        (*b"bXYZ", xyz([0.1431, 0.0606, 0.7141])),
        (*b"rTRC", curve.clone()),
        (*b"gTRC", curve.clone()),
        (*b"bTRC", curve),
    ];
    let mut header = vec![0; 128];
    header[8..12].copy_from_slice(&[2, 0x10, 0, 0]);
    header[12..16].copy_from_slice(b"mntr");
    header[16..20].copy_from_slice(b"RGB ");
    header[20..24].copy_from_slice(b"XYZ ");
    for (index, value) in [2000u16, 1, 1, 0, 0, 0].iter().enumerate() {
        header[24 + index * 2..26 + index * 2].copy_from_slice(&value.to_be_bytes());
    }
    header[36..40].copy_from_slice(b"acsp");
    for (index, value) in [0.9642, 1.0, 0.8249].iter().enumerate() {
        header[68 + index * 4..72 + index * 4].copy_from_slice(&fixed(*value));
    }
    let mut payload = Vec::new();
    header.extend_from_slice(&(tags.len() as u32).to_be_bytes());
    let data_start = 128 + 4 + tags.len() * 12;
    for (name, value) in tags {
        header.extend_from_slice(&name);
        header.extend_from_slice(&((data_start + payload.len()) as u32).to_be_bytes());
        header.extend_from_slice(&(value.len() as u32).to_be_bytes());
        payload.extend_from_slice(&value);
        while !payload.len().is_multiple_of(4) {
            payload.push(0);
        }
    }
    header.extend_from_slice(&payload);
    let length = header.len() as u32;
    header[..4].copy_from_slice(&length.to_be_bytes());
    header
}

fn archive(parts: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::from_date_and_time(2000, 1, 1, 0, 0, 0)?);
    for (name, data) in parts {
        writer.start_file(*name, options)?;
        writer.write_all(data)?;
    }
    Ok(writer.finish()?.into_inner())
}

fn office(kind: &str, png: &[u8], signed: bool) -> Result<Vec<u8>> {
    let core = br#"<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:creator>Synthetic Author</dc:creator><cp:lastModifiedBy>Synthetic Editor</cp:lastModifiedBy><dcterms:created xsi:type="dcterms:W3CDTF">2000-01-01T00:00:00Z</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">2000-01-02T00:00:00Z</dcterms:modified></cp:coreProperties>"#;
    let app = br#"<?xml version="1.0" encoding="UTF-8"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>Synthetic Office</Application><AppVersion>1.0</AppVersion><Company>Synthetic Company</Company></Properties>"#;
    let custom = br#"<?xml version="1.0" encoding="UTF-8"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="Synthetic source"><vt:lpwstr>Synthetic value</vt:lpwstr></property></Properties>"#;
    let (main_name, main_type, main, extra) = match kind {
        "word" => ("word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml", br#"<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><w:body><w:p><w:r><w:t>Synthetic visible document</w:t></w:r></w:p><w:p><w:commentRangeStart w:id="0"/><w:r><w:t>Commented text</w:t></w:r><w:commentRangeEnd w:id="0"/><w:r><w:commentReference w:id="0"/></w:r></w:p><w:p><w:r><w:drawing><wp:inline><wp:extent cx="914400" cy="685800"/><wp:docPr id="1" name="Synthetic image"/><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic><pic:nvPicPr><pic:cNvPr id="1" name="Synthetic image"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:embed="rId2"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="914400" cy="685800"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p><w:sectPr/></w:body></w:document>"#.to_vec(), word_parts(png)),
        "xl" => ("xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml", br#"<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Synthetic sheet" sheetId="1" r:id="rId1"/></sheets></workbook>"#.to_vec(), excel_parts()),
        "ppt" => ("ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml", br#"<?xml version="1.0" encoding="UTF-8"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId2"/></p:sldMasterIdLst><p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst><p:sldSz cx="9144000" cy="6858000"/><p:notesSz cx="6858000" cy="9144000"/></p:presentation>"#.to_vec(), powerpoint_parts(png)),
        _ => return Err("unknown fixture format".into()),
    };
    let mut types = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/><Override PartName="/{main_name}" ContentType="{main_type}"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/><Override PartName="/docProps/custom.xml" ContentType="application/vnd.openxmlformats-officedocument.custom-properties+xml"/>"#
    );
    for (name, _) in &extra {
        let content_type = match name.as_str() {
            "word/comments.xml" => {
                Some("application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml")
            }
            "xl/worksheets/sheet1.xml" => {
                Some("application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml")
            }
            "xl/charts/chart1.xml" => {
                Some("application/vnd.openxmlformats-officedocument.drawingml.chart+xml")
            }
            "xl/drawings/drawing1.xml" => {
                Some("application/vnd.openxmlformats-officedocument.drawing+xml")
            }
            "ppt/slides/slide1.xml" => {
                Some("application/vnd.openxmlformats-officedocument.presentationml.slide+xml")
            }
            "ppt/slideMasters/slideMaster1.xml" => {
                Some("application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml")
            }
            "ppt/slideLayouts/slideLayout1.xml" => {
                Some("application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml")
            }
            "ppt/theme/theme1.xml" => {
                Some("application/vnd.openxmlformats-officedocument.theme+xml")
            }
            _ => None,
        };
        if let Some(content_type) = content_type {
            types.push_str(&format!(
                r#"<Override PartName="/{name}" ContentType="{content_type}"/>"#
            ));
        }
    }
    let mut root_rels = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="{main_name}"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/><Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties" Target="docProps/custom.xml"/>"#
    );
    let mut parts = vec![
        ("docProps/core.xml".to_string(), core.to_vec()),
        ("docProps/app.xml".to_string(), app.to_vec()),
        ("docProps/custom.xml".to_string(), custom.to_vec()),
        (main_name.to_string(), main),
    ];
    parts.extend(extra);
    if signed {
        types.push_str(r#"<Default Extension="sigs" ContentType="application/vnd.openxmlformats-package.digital-signature-origin"/><Override PartName="/_xmlsignatures/sig1.xml" ContentType="application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml"/>"#);
        root_rels.push_str(r#"<Relationship Id="rIdSignature" Type="http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin" Target="_xmlsignatures/origin.sigs"/>"#);
        parts.push(("_xmlsignatures/origin.sigs".into(), Vec::new()));
        parts.push(("_xmlsignatures/_rels/origin.sigs.rels".into(), br#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature" Target="sig1.xml"/></Relationships>"#.to_vec()));
        parts.push(("_xmlsignatures/sig1.xml".into(), br#"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo/><SignatureValue>U3ludGhldGlj</SignatureValue></Signature>"#.to_vec()));
    }
    types.push_str("</Types>");
    root_rels.push_str("</Relationships>");
    parts.push(("[Content_Types].xml".into(), types.into_bytes()));
    parts.push(("_rels/.rels".into(), root_rels.into_bytes()));
    let borrowed: Vec<_> = parts
        .iter()
        .map(|(name, data)| (name.as_str(), data.as_slice()))
        .collect();
    archive(&borrowed)
}

fn relationships(entries: &[(&str, &str, &str)]) -> Vec<u8> {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"#,
    );
    for (id, kind, target) in entries {
        xml.push_str(&format!(r#"<Relationship Id="{id}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/{kind}" Target="{target}"/>"#));
    }
    xml.push_str("</Relationships>");
    xml.into_bytes()
}

fn word_parts(png: &[u8]) -> Vec<(String, Vec<u8>)> {
    vec![
        ("word/comments.xml".into(), br#"<?xml version="1.0" encoding="UTF-8"?><w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:comment w:id="0" w:author="Synthetic Reviewer" w:date="2000-01-01T00:00:00Z"><w:p><w:r><w:t>Synthetic retained comment</w:t></w:r></w:p></w:comment></w:comments>"#.to_vec()),
        ("word/media/image1.png".into(), png.to_vec()),
        ("word/_rels/document.xml.rels".into(), relationships(&[("rId1", "comments", "comments.xml"), ("rId2", "image", "media/image1.png")])),
    ]
}

fn excel_parts() -> Vec<(String, Vec<u8>)> {
    vec![
        ("xl/_rels/workbook.xml.rels".into(), relationships(&[("rId1", "worksheet", "worksheets/sheet1.xml")])),
        ("xl/worksheets/sheet1.xml".into(), br#"<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheetData><row r="1"><c r="A1"><v>2</v></c><c r="B1"><v>3</v></c><c r="C1"><f>SUM(A1:B1)</f><v>5</v></c></row></sheetData><drawing r:id="rId1"/></worksheet>"#.to_vec()),
        ("xl/worksheets/_rels/sheet1.xml.rels".into(), relationships(&[("rId1", "drawing", "../drawings/drawing1.xml")])),
        ("xl/drawings/drawing1.xml".into(), br#"<?xml version="1.0" encoding="UTF-8"?><xdr:wsDr xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><xdr:twoCellAnchor><xdr:from><xdr:col>0</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>3</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:from><xdr:to><xdr:col>6</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>15</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:to><xdr:graphicFrame macro=""><xdr:nvGraphicFramePr><xdr:cNvPr id="2" name="Synthetic chart"/><xdr:cNvGraphicFramePr/></xdr:nvGraphicFramePr><xdr:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/></xdr:xfrm><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/chart"><c:chart xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" r:id="rId1"/></a:graphicData></a:graphic></xdr:graphicFrame><xdr:clientData/></xdr:twoCellAnchor></xdr:wsDr>"#.to_vec()),
        ("xl/drawings/_rels/drawing1.xml.rels".into(), relationships(&[("rId1", "chart", "../charts/chart1.xml")])),
        ("xl/charts/chart1.xml".into(), br#"<?xml version="1.0" encoding="UTF-8"?><c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><c:chart><c:plotArea><c:layout/><c:pieChart><c:varyColors val="1"/><c:ser><c:idx val="0"/><c:order val="0"/><c:tx><c:v>Synthetic values</c:v></c:tx><c:cat><c:strLit><c:ptCount val="2"/><c:pt idx="0"><c:v>A</c:v></c:pt><c:pt idx="1"><c:v>B</c:v></c:pt></c:strLit></c:cat><c:val><c:numRef><c:f>'Synthetic sheet'!$A$1:$B$1</c:f><c:numCache><c:formatCode>General</c:formatCode><c:ptCount val="2"/><c:pt idx="0"><c:v>2</c:v></c:pt><c:pt idx="1"><c:v>3</c:v></c:pt></c:numCache></c:numRef></c:val></c:ser></c:pieChart></c:plotArea><c:plotVisOnly val="1"/></c:chart></c:chartSpace>"#.to_vec()),
    ]
}

fn powerpoint_parts(png: &[u8]) -> Vec<(String, Vec<u8>)> {
    let group = r#"<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>"#;
    let slide = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><p:cSld><p:spTree>{group}<p:pic><p:nvPicPr><p:cNvPr id="2" name="Synthetic image"/><p:cNvPicPr/><p:nvPr/></p:nvPicPr><p:blipFill><a:blip r:embed="rId2"/><a:stretch><a:fillRect/></a:stretch></p:blipFill><p:spPr><a:xfrm><a:off x="100000" y="100000"/><a:ext cx="2000000" cy="1500000"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr></p:pic></p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>"#
    );
    let master = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><p:sldMaster xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><p:cSld><p:spTree>{group}</p:spTree></p:cSld><p:clrMap accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" bg1="lt1" bg2="lt2" folHlink="folHlink" hlink="hlink" tx1="dk1" tx2="dk2"/><p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst><p:txStyles/></p:sldMaster>"#
    );
    let layout = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><p:sldLayout xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" type="blank"><p:cSld name="Blank"><p:spTree>{group}</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>"#
    );
    let theme = br#"<?xml version="1.0" encoding="UTF-8"?><a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="Synthetic"><a:themeElements><a:clrScheme name="Synthetic"><a:dk1><a:srgbClr val="000000"/></a:dk1><a:lt1><a:srgbClr val="FFFFFF"/></a:lt1><a:dk2><a:srgbClr val="202020"/></a:dk2><a:lt2><a:srgbClr val="EEEEEE"/></a:lt2><a:accent1><a:srgbClr val="336699"/></a:accent1><a:accent2><a:srgbClr val="993333"/></a:accent2><a:accent3><a:srgbClr val="339966"/></a:accent3><a:accent4><a:srgbClr val="663399"/></a:accent4><a:accent5><a:srgbClr val="339999"/></a:accent5><a:accent6><a:srgbClr val="CC6633"/></a:accent6><a:hlink><a:srgbClr val="0000FF"/></a:hlink><a:folHlink><a:srgbClr val="800080"/></a:folHlink></a:clrScheme><a:fontScheme name="Synthetic"><a:majorFont><a:latin typeface="Arial"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont><a:minorFont><a:latin typeface="Arial"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont></a:fontScheme><a:fmtScheme name="Synthetic"><a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst><a:lnStyleLst><a:ln w="9525"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:prstDash val="solid"/></a:ln><a:ln w="9525"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:prstDash val="solid"/></a:ln><a:ln w="9525"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:prstDash val="solid"/></a:ln></a:lnStyleLst><a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst><a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst></a:fmtScheme></a:themeElements></a:theme>"#;
    vec![
        (
            "ppt/_rels/presentation.xml.rels".into(),
            relationships(&[
                ("rId1", "slide", "slides/slide1.xml"),
                ("rId2", "slideMaster", "slideMasters/slideMaster1.xml"),
            ]),
        ),
        ("ppt/slides/slide1.xml".into(), slide.into_bytes()),
        (
            "ppt/slides/_rels/slide1.xml.rels".into(),
            relationships(&[
                ("rId1", "slideLayout", "../slideLayouts/slideLayout1.xml"),
                ("rId2", "image", "../media/image1.png"),
            ]),
        ),
        (
            "ppt/slideMasters/slideMaster1.xml".into(),
            master.into_bytes(),
        ),
        (
            "ppt/slideMasters/_rels/slideMaster1.xml.rels".into(),
            relationships(&[
                ("rId1", "slideLayout", "../slideLayouts/slideLayout1.xml"),
                ("rId2", "theme", "../theme/theme1.xml"),
            ]),
        ),
        (
            "ppt/slideLayouts/slideLayout1.xml".into(),
            layout.into_bytes(),
        ),
        (
            "ppt/slideLayouts/_rels/slideLayout1.xml.rels".into(),
            relationships(&[("rId1", "slideMaster", "../slideMasters/slideMaster1.xml")]),
        ),
        ("ppt/theme/theme1.xml".into(), theme.to_vec()),
        ("ppt/media/image1.png".into(), png.to_vec()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_are_deterministic_and_images_decode() {
        let first = fixtures().unwrap();
        assert_eq!(first, fixtures().unwrap());
        for (name, bytes) in &first {
            if matches!(
                *name,
                "jpeg_exif_gps_author.jpg"
                    | "jpeg_clean.jpg"
                    | "jpeg_app_unknown.jpg"
                    | "png_itxt_exif_icc.png"
                    | "png_clean.png"
            ) {
                let decoded = image::load_from_memory(bytes).unwrap();
                assert_eq!((decoded.width(), decoded.height()), (8, 6));
            }
        }
    }

    #[test]
    fn office_fixtures_have_real_content_and_signatures_are_synthetic() {
        for kind in ["word", "xl", "ppt"] {
            let data = office(kind, b"synthetic media", false).unwrap();
            let mut package = zip::ZipArchive::new(Cursor::new(data)).unwrap();
            assert!(package.by_name("[Content_Types].xml").is_ok());
            assert!(package.by_name("_rels/.rels").is_ok());
            assert!(package.by_name("docProps/core.xml").is_ok());
            assert!(package.by_name("_xmlsignatures/sig1.xml").is_err());
        }
        let data = office("word", b"synthetic media", true).unwrap();
        let mut package = zip::ZipArchive::new(Cursor::new(data)).unwrap();
        assert!(package.by_name("_xmlsignatures/sig1.xml").is_ok());
    }

    #[test]
    fn output_creation_does_not_overwrite() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sample.bin");
        write_new(&path, b"first").unwrap();
        assert!(write_new(&path, b"second").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"first");
    }
}

// FVPROV1 30138 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJhYzA1YmMxMDEyNjIyOGNkMzliNGM5YjgzZmMxYjNlY2NkMDhkOWY1Y2E2ZjYyOGI4OTRhMWMzYzMyODc4ZmMzIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL2ZpeHR1cmUtZ2VuZXJhdG9yL3NyYy9tYWluLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiY2Q2NjMwZGU5ZDczMWFmNzg1NGIzYjJkNDk5ZTM4OTI4NDZkMjk0ZThjNmJhOWZlY2M4ZmEyMjVkOGI5YzU2ODQ0ZTU5YTFlZjZlNDE2ZWVjZDU1ZWI3NzgyMDg1YThhNzU5M2Y4OGEzYjNkZmEwMjE1ZjRhMTcxNmMzMjIyMGEifV19XQ== FVPROV1-END
