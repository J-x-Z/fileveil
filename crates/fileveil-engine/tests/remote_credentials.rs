// SPDX-License-Identifier: MPL-2.0
//! Standard provenance properties protect bindings even when the URI contains no scheme keyword.
use fileveil_core::{Error, Format, Limits, Outcome, Policy, SanitizeOptions};
use fileveil_engine::{advanced, provenance, scan};
use image::{DynamicImage, ImageFormat};
use std::{fs, io::Cursor};

const XMP: &[u8] = br#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description rdf:about="" xmlns:dcterms="http://purl.org/dc/terms/" dcterms:provenance="https://example.invalid/credentials/PRIVATE_SOURCE"/></rdf:RDF></x:xmpmeta>"#;

fn png_chunk(kind: &[u8; 4], content: &[u8]) -> Vec<u8> {
    let mut chunk = (content.len() as u32).to_be_bytes().to_vec();
    chunk.extend_from_slice(kind);
    chunk.extend_from_slice(content);
    let mut crc = u32::MAX;
    for byte in &chunk[4..] {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    chunk.extend_from_slice(&(!crc).to_be_bytes());
    chunk
}

fn image_with_remote_reference(format: Format) -> Vec<u8> {
    let image =
        DynamicImage::ImageRgb8(image::RgbImage::from_pixel(4, 4, image::Rgb([40, 80, 160])));
    let mut encoded = Cursor::new(Vec::new());
    image
        .write_to(
            &mut encoded,
            if format == Format::Jpeg {
                ImageFormat::Jpeg
            } else {
                ImageFormat::Png
            },
        )
        .unwrap();
    let original = encoded.into_inner();
    if format == Format::Jpeg {
        let mut payload = b"http://ns.adobe.com/xap/1.0/\0".to_vec();
        payload.extend_from_slice(XMP);
        let mut source = original[..2].to_vec();
        source.extend_from_slice(&[0xff, 0xe1]);
        source.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        source.extend_from_slice(&payload);
        source.extend_from_slice(&original[2..]);
        source
    } else {
        let mut payload = b"XML:com.adobe.xmp\0\0\0\0\0".to_vec();
        payload.extend_from_slice(XMP);
        let end = original.len() - 12;
        let mut source = original[..end].to_vec();
        source.extend(png_chunk(b"iTXt", &payload));
        source.extend_from_slice(&original[end..]);
        source
    }
}

fn pdf_stream(dictionary: &str, content: &[u8]) -> Vec<u8> {
    let mut stream = format!("<< {dictionary} /Length {} >>\nstream\n", content.len()).into_bytes();
    stream.extend_from_slice(content);
    stream.extend_from_slice(b"\nendstream");
    stream
}

fn pdf_with_remote_reference() -> Vec<u8> {
    let objects = [
        b"<< /Type /Catalog /Pages 2 0 R /Metadata 6 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>".to_vec(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
        pdf_stream("", b"BT /F1 12 Tf 20 200 Td (Visible source text) Tj ET"),
        pdf_stream("/Type /Metadata /Subtype /XML", XMP),
        b"<< /Author (PRIVATE_AUTHOR) >>".to_vec(),
    ];
    let mut source = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (index, object) in objects.iter().enumerate() {
        offsets.push(source.len());
        source.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
        source.extend_from_slice(object);
        source.extend_from_slice(b"\nendobj\n");
    }
    let xref = source.len();
    source.extend_from_slice(b"xref\n0 8\n0000000000 65535 f \n");
    for offset in offsets {
        source.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    source.extend_from_slice(
        format!("trailer\n<< /Size 8 /Root 1 0 R /Info 7 0 R >>\nstartxref\n{xref}\n%%EOF\n")
            .as_bytes(),
    );
    source
}

#[test]
fn standard_remote_references_protect_safe_and_allow_explicit_deep_removal() {
    let limits = Limits::default();
    let options = SanitizeOptions {
        policy: Policy::Deep,
        remove_provenance: true,
        ..Default::default()
    };
    for (name, format, source) in [
        (
            "remote.jpg",
            Format::Jpeg,
            image_with_remote_reference(Format::Jpeg),
        ),
        (
            "remote.png",
            Format::Png,
            image_with_remote_reference(Format::Png),
        ),
        ("remote.pdf", Format::Pdf, pdf_with_remote_reference()),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join(name);
        let output = directory.path().join(format!("clean-{name}"));
        fs::write(&input, &source).unwrap();
        let evidence = provenance::inspect(&source, format, &limits)
            .unwrap()
            .unwrap();
        assert_eq!(
            evidence.presence,
            provenance::ManifestPresence::RemoteReference,
            "{name}"
        );
        assert!(evidence.offline);
        let report = scan(&input, &limits).unwrap();
        if format == Format::Pdf {
            assert_eq!(report.result, Outcome::PartiallyVerified, "{name}");
            assert_eq!(report.pdf.as_ref().unwrap()["safe_rewrite_allowed"], false);
        } else {
            assert_eq!(report.result, Outcome::Blocked, "{name}");
        }
        assert_eq!(
            report.provenance.as_ref().unwrap()["presence"],
            "remote_reference"
        );
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("example.invalid")
        );
        assert!(
            matches!(
                fileveil_engine::sanitize(&input, Some(&output), &limits),
                Err(Error::Blocked(_))
            ),
            "{name}"
        );
        assert!(
            matches!(
                advanced::sanitize_with_options(
                    &input,
                    Some(&output),
                    &limits,
                    &SanitizeOptions::default()
                ),
                Err(Error::Blocked(_))
            ),
            "{name}"
        );
        assert!(!output.exists());
        if format == Format::Pdf {
            assert!(matches!(
                fileveil_engine::pdf::sanitize(&source, &limits),
                Err(Error::Blocked(_))
            ));
        }
        let report =
            advanced::sanitize_with_options(&input, Some(&output), &limits, &options).unwrap();
        assert_eq!(report.result, Outcome::PartiallyVerified, "{name}");
        assert_eq!(report.integrity.original_unchanged, Some(true));
        let clean = fs::read(&output).unwrap();
        assert!(
            provenance::inspect(&clean, format, &limits)
                .unwrap()
                .is_none()
        );
        if format.is_image() {
            let before = image::load_from_memory(&source).unwrap();
            let after = image::load_from_memory(&clean).unwrap();
            assert_eq!(before.color(), after.color());
            assert_eq!(before.as_bytes(), after.as_bytes());
        }
        advanced::verify_with_options(&input, &output, &limits, &options).unwrap();
        assert_eq!(fs::read(&input).unwrap(), source);
    }
}

// FVPROV1 7327 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIwNmQ5ODM4Y2RjYjdiMTNlM2FiNzU3ZjU2NWM4NTZlMWY4YTQxOTAyZjUzOTZkNDM5N2YzOTliODJhMjc5ODU2IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS40IiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuNCIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvdGVzdHMvcmVtb3RlX2NyZWRlbnRpYWxzLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiYjc5YjQxZWQzNGU3ZDQyYmI1Zjc3YmRkNTUyMmViZDMxZDEwM2I3NDIwZmJiY2Q5ODFhMTlhYjRjY2JkNzc1MTI0MjEyZmE5MzEwMDRiMzk3YmIyODE4MTM0ZjQ0NWUzZTI1ZjlhYjg1YjBkMjZiZjg0YzY0ZjE3YjMzZjM1MGUifV19XQ== FVPROV1-END
