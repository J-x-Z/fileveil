// SPDX-License-Identifier: MPL-2.0
use std::{
    fs,
    io::Cursor,
    path::Path,
    time::{Duration, SystemTime},
};

use fileveil_core::{
    FilesystemOptions, Format, Limits, Policy, Report, SanitizeOptions, TextOptions, digest,
};
use fileveil_engine::advanced::{
    publish_advanced_staged, sanitize_with_options, verify_with_options,
};
use image::{DynamicImage, ImageFormat, RgbImage};

fn image_file(path: &Path, format: ImageFormat) -> Vec<u8> {
    let image = DynamicImage::ImageRgb8(RgbImage::from_pixel(8, 8, image::Rgb([32, 64, 128])));
    let mut output = Cursor::new(Vec::new());
    image.write_to(&mut output, format).unwrap();
    let bytes = output.into_inner();
    fs::write(path, &bytes).unwrap();
    bytes
}

fn normalized_options() -> SanitizeOptions {
    SanitizeOptions {
        filesystem: FilesystemOptions {
            normalize_output_timestamps: true,
            ..FilesystemOptions::default()
        },
        ..SanitizeOptions::default()
    }
}

#[test]
fn png_and_jpeg_options_preserve_pixels_and_verify_modification_time_only() {
    let directory = tempfile::tempdir().unwrap();
    for (extension, format) in [("png", ImageFormat::Png), ("jpg", ImageFormat::Jpeg)] {
        let original = directory.path().join(format!("original.{extension}"));
        let output = directory.path().join(format!("clean.{extension}"));
        let bytes = image_file(&original, format);
        let options = normalized_options();
        let report =
            sanitize_with_options(&original, Some(&output), &Limits::default(), &options).unwrap();
        assert_eq!(report.integrity.pixel_equal, Some(true));
        assert_eq!(report.integrity.security_markers_preserved, Some(true));
        assert_eq!(report.integrity.original_unchanged, Some(true));
        assert_eq!(
            report.advanced.as_ref().unwrap()["timestamp_scope"],
            "output_modification_only_verified"
        );
        assert_eq!(
            fs::metadata(&output).unwrap().modified().unwrap(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(946_684_800)
        );
        let verified =
            verify_with_options(&original, &output, &Limits::default(), &options).unwrap();
        assert_eq!(verified.integrity.pixel_equal, Some(true));
        assert_eq!(fs::read(&original).unwrap(), bytes);
    }
}

#[test]
fn text_scope_removes_bom_preserves_language_and_rejects_option_mismatch() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original.txt");
    let output = directory.path().join("clean.txt");
    let text = "\u{feff}中文 हिन्दी\u{200d} العربية\u{200c}\n";
    fs::write(&original, text).unwrap();
    let options = SanitizeOptions {
        text: TextOptions {
            remove_bom: true,
            ..TextOptions::default()
        },
        ..SanitizeOptions::default()
    };
    let report =
        sanitize_with_options(&original, Some(&output), &Limits::default(), &options).unwrap();
    assert_eq!(
        fs::read_to_string(&output).unwrap(),
        text.trim_start_matches('\u{feff}')
    );
    assert_eq!(
        report.input_sha256.as_deref(),
        Some(digest(text.as_bytes()).as_str())
    );
    verify_with_options(&original, &output, &Limits::default(), &options).unwrap();
    assert!(
        verify_with_options(
            &original,
            &output,
            &Limits::default(),
            &SanitizeOptions::default()
        )
        .is_err()
    );
    assert_eq!(fs::read_to_string(&original).unwrap(), text);
}

#[test]
fn unsupported_content_choices_fail_before_creating_an_output() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original.png");
    let output = directory.path().join("clean.png");
    let bytes = image_file(&original, ImageFormat::Png);
    let mut options = SanitizeOptions {
        policy: Policy::Deep,
        ..SanitizeOptions::default()
    };
    options.deep.remove_comments = true;
    assert!(sanitize_with_options(&original, Some(&output), &Limits::default(), &options).is_err());
    assert!(!output.exists());
    options.deep.remove_comments = false;
    options.text.remove_bom = true;
    assert!(sanitize_with_options(&original, Some(&output), &Limits::default(), &options).is_err());
    assert!(!output.exists());
    options.text.remove_bom = false;
    options.pdf.remove_attachments = true;
    assert!(sanitize_with_options(&original, Some(&output), &Limits::default(), &options).is_err());
    assert!(!output.exists());
    options.policy = Policy::Safe;
    assert!(sanitize_with_options(&original, Some(&output), &Limits::default(), &options).is_err());
    assert_eq!(fs::read(&original).unwrap(), bytes);
}

#[test]
fn image_scoped_verification_keeps_the_existing_content_protection() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original.png");
    let output = directory.path().join("clean.png");
    image_file(&original, ImageFormat::Png);
    let options = SanitizeOptions::default();
    sanitize_with_options(&original, Some(&output), &Limits::default(), &options).unwrap();
    let mut changed = image::load_from_memory(&fs::read(&output).unwrap())
        .unwrap()
        .into_rgb8();
    changed.get_pixel_mut(0, 0)[0] ^= 1;
    let mut bytes = Cursor::new(Vec::new());
    DynamicImage::ImageRgb8(changed)
        .write_to(&mut bytes, ImageFormat::Png)
        .unwrap();
    fs::write(&output, bytes.into_inner()).unwrap();
    assert!(verify_with_options(&original, &output, &Limits::default(), &options).is_err());
}

#[test]
fn staged_publication_binds_the_report_options_and_parse_result() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original.png");
    let staged = directory.path().join("staged.png");
    let output = directory.path().join("published.png");
    let original_bytes = image_file(&original, ImageFormat::Png);
    let options = SanitizeOptions::default();
    let report =
        sanitize_with_options(&original, Some(&staged), &Limits::default(), &options).unwrap();
    let mut forged = report.clone();
    forged.integrity.parseable = false;
    assert!(
        publish_advanced_staged(
            &original,
            &staged,
            Some(&output),
            &mut forged,
            &Limits::default(),
            &options
        )
        .is_err()
    );
    let mut wrong_options = options.clone();
    wrong_options.filesystem.remove_download_origin = true;
    assert!(
        publish_advanced_staged(
            &original,
            &staged,
            Some(&output),
            &mut report.clone(),
            &Limits::default(),
            &wrong_options
        )
        .is_err()
    );
    assert!(!output.exists());
    let mut report = report;
    publish_advanced_staged(
        &original,
        &staged,
        Some(&output),
        &mut report,
        &Limits::default(),
        &options,
    )
    .unwrap();
    assert!(output.is_file());
    assert!(!staged.exists());
    assert_eq!(fs::read(&original).unwrap(), original_bytes);
}

#[test]
fn staged_publication_uses_bound_file_identity_for_virtual_input_aliases() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original.png");
    let staged = directory.path().join("staged.png");
    let output = directory.path().join("published.png");
    let bytes = image_file(&original, ImageFormat::Png);
    let options = SanitizeOptions::default();
    let mut report =
        sanitize_with_options(&original, Some(&staged), &Limits::default(), &options).unwrap();
    let alias = directory.path().join("virtual-input-alias.png");
    assert!(!alias.exists());
    fileveil_engine::access_guard::with_bound_files(
        vec![(alias.clone(), fs::File::open(&original).unwrap())],
        || {
            publish_advanced_staged(
                &alias,
                &staged,
                Some(&output),
                &mut report,
                &Limits::default(),
                &options,
            )
        },
    )
    .unwrap();
    assert!(output.is_file());
    assert_eq!(fs::read(&original).unwrap(), bytes);
}

#[test]
fn every_publisher_rejects_the_original_as_an_artifact() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original.png");
    let staged = directory.path().join("staged.png");
    let output = directory.path().join("published.png");
    let bytes = image_file(&original, ImageFormat::Png);
    let mut safe = fileveil_engine::sanitize(&original, Some(&staged), &Limits::default()).unwrap();
    safe.output_sha256 = safe.input_sha256.clone();
    assert!(
        fileveil_engine::publish_staged(
            &original,
            &original,
            Some(&output),
            &mut safe,
            &Limits::default()
        )
        .is_err()
    );
    let processed = directory.path().join("processed.png");
    let mut research = fileveil_engine::process_image_in(
        &original,
        Some(&processed),
        &fileveil_core::ImageProcessOptions::default(),
        &Limits::default(),
        None,
    )
    .unwrap();
    research.output_sha256 = research.input_sha256.clone();
    assert!(
        fileveil_engine::publish_processed_staged(
            &original,
            &original,
            Some(&output),
            &mut research,
            &Limits::default()
        )
        .is_err()
    );
    assert!(!output.exists());
    assert_eq!(fs::read(&original).unwrap(), bytes);
}

#[test]
fn staged_publication_cannot_take_ownership_of_the_original_or_hardlinks() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original.png");
    let staged = directory.path().join("staged.png");
    let linked = directory.path().join("linked.png");
    let output = directory.path().join("published.png");
    let bytes = image_file(&original, ImageFormat::Png);
    let options = SanitizeOptions::default();
    let report =
        sanitize_with_options(&original, Some(&staged), &Limits::default(), &options).unwrap();
    let mut forged = report.clone();
    forged.output_sha256 = forged.input_sha256.clone();
    assert!(
        publish_advanced_staged(
            &original,
            &original,
            Some(&output),
            &mut forged,
            &Limits::default(),
            &options
        )
        .is_err()
    );
    fs::hard_link(&staged, &linked).unwrap();
    assert!(
        publish_advanced_staged(
            &original,
            &linked,
            Some(&output),
            &mut report.clone(),
            &Limits::default(),
            &options
        )
        .is_err()
    );
    assert!(linked.exists());
    assert!(staged.exists());
    assert!(!output.exists());
    assert_eq!(fs::read(&original).unwrap(), bytes);
}

#[test]
fn staged_timestamp_changes_invalidate_publication_even_with_unchanged_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original.png");
    let staged = directory.path().join("staged.png");
    let output = directory.path().join("published.png");
    image_file(&original, ImageFormat::Png);
    let options = normalized_options();
    let mut report =
        sanitize_with_options(&original, Some(&staged), &Limits::default(), &options).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&staged)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(SystemTime::now()))
        .unwrap();
    assert!(
        publish_advanced_staged(
            &original,
            &staged,
            Some(&output),
            &mut report,
            &Limits::default(),
            &options
        )
        .is_err()
    );
    assert!(!output.exists());
}

#[test]
fn version_02_reports_deserialize_with_new_fields_absent() {
    let mut value = serde_json::to_value(Report::new("scan", Format::Png)).unwrap();
    let object = value.as_object_mut().unwrap();
    object.insert("schema_version".into(), "0.2".into());
    for field in ["pdf", "provenance", "advanced"] {
        object.remove(field);
    }
    let legacy: Report = serde_json::from_value(value).unwrap();
    assert_eq!(legacy.schema_version, "0.2");
    assert!(legacy.pdf.is_none());
    assert!(legacy.provenance.is_none());
    assert!(legacy.advanced.is_none());
    let legacy_options: SanitizeOptions = serde_json::from_str(r#"{"policy":"safe"}"#).unwrap();
    assert!(!legacy_options.remove_provenance);
    assert!(!legacy_options.any());
}

#[test]
fn explicit_credential_removal_preserves_original_validity_and_verifies_the_output() {
    let directory = tempfile::tempdir().unwrap();
    for extension in ["png", "jpg"] {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("tests/fixtures/provenance/signed.{extension}"));
        let original = directory.path().join(format!("original.{extension}"));
        let output = directory.path().join(format!("clean.{extension}"));
        let bytes = fs::read(fixture).unwrap();
        fs::write(&original, &bytes).unwrap();
        let mut options = SanitizeOptions::default();
        assert!(
            sanitize_with_options(&original, Some(&output), &Limits::default(), &options).is_err()
        );
        options.remove_provenance = true;
        assert!(
            sanitize_with_options(&original, Some(&output), &Limits::default(), &options).is_err()
        );
        assert!(!output.exists());
        options.policy = Policy::Deep;
        let report =
            sanitize_with_options(&original, Some(&output), &Limits::default(), &options).unwrap();
        let removal = &report.advanced.as_ref().unwrap()["provenance_removal"];
        assert_eq!(removal["before"]["signature"], "valid");
        assert_eq!(removal["before"]["asset_binding"], "valid");
        assert!(removal["after"].is_null());
        assert_eq!(report.integrity.pixel_equal, Some(true));
        assert_eq!(report.result, fileveil_core::Outcome::PartiallyVerified);
        verify_with_options(&original, &output, &Limits::default(), &options).unwrap();
        assert_eq!(fs::read(&original).unwrap(), bytes);
    }
}

#[test]
fn pdf_content_choices_require_deep_and_report_partial_verification() {
    assert_eq!(fileveil_engine::pdf::capabilities()["available"], true);
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << >> /Contents 4 0 R /Annots [6 0 R] >>",
        "<< /Length 0 >>\nstream\n\nendstream",
        "<< /S /JavaScript /JS (PRIVATE_SCRIPT) >>",
        "<< /Type /Annot /Subtype /Text /Rect [20 20 40 40] /Contents (PRIVATE_COMMENT) >>",
    ];
    let mut bytes = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (index, object) in objects.iter().enumerate() {
        offsets.push(bytes.len());
        bytes.extend_from_slice(format!("{} 0 obj\n{object}\nendobj\n", index + 1).as_bytes());
    }
    let xref = bytes.len();
    bytes.extend_from_slice(b"xref\n0 7\n0000000000 65535 f \n");
    for offset in offsets {
        bytes.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    bytes.extend_from_slice(
        format!("trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
    );
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original.pdf");
    let output = directory.path().join("clean.pdf");
    fs::write(&original, &bytes).unwrap();
    let mut options = SanitizeOptions::default();
    options.pdf.remove_javascript = true;
    options.pdf.remove_annotations = true;
    assert!(sanitize_with_options(&original, Some(&output), &Limits::default(), &options).is_err());
    assert!(!output.exists());
    options.policy = Policy::Deep;
    let report =
        sanitize_with_options(&original, Some(&output), &Limits::default(), &options).unwrap();
    assert_eq!(report.result, fileveil_core::Outcome::PartiallyVerified);
    assert_eq!(report.integrity.content_equal, None);
    assert_eq!(report.pdf.as_ref().unwrap()["javascript_actions"], 0);
    assert_eq!(report.pdf.as_ref().unwrap()["annotation_structures"], 0);
    assert_eq!(report.integrity.original_unchanged, Some(true));
    verify_with_options(&original, &output, &Limits::default(), &options).unwrap();
    assert_eq!(fs::read(&original).unwrap(), bytes);
}

#[cfg(target_os = "macos")]
#[test]
fn macos_selected_attributes_are_removed_and_quarantine_remains() {
    use xattr::FileExt;
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original.png");
    let output = directory.path().join("clean.png");
    let bytes = image_file(&original, ImageFormat::Png);
    let file = fs::OpenOptions::new().write(true).open(&original).unwrap();
    for (name, value) in [
        ("com.apple.metadata:kMDItemWhereFroms", "PRIVATE_ORIGIN"),
        (
            "com.apple.metadata:kMDItemDownloadedDate",
            "PRIVATE_DOWNLOAD_DATE",
        ),
        ("com.apple.lastuseddate#PS", "PRIVATE_LAST_USE"),
        ("com.apple.metadata:_kMDItemUserTags", "PRIVATE_TAG"),
        ("com.apple.quarantine", "0081;0;FileVeil;"),
        ("user.fileveil-test", "PRIVATE_USER_ATTRIBUTE"),
    ] {
        file.set_xattr(name, value.as_bytes()).unwrap();
    }
    let options = SanitizeOptions {
        filesystem: FilesystemOptions {
            remove_download_origin: true,
            remove_finder_tags: true,
            remove_user_attributes: true,
            remove_usage_metadata: true,
            ..FilesystemOptions::default()
        },
        ..SanitizeOptions::default()
    };
    let report =
        sanitize_with_options(&original, Some(&output), &Limits::default(), &options).unwrap();
    let result = fs::File::open(&output).unwrap();
    for name in [
        "com.apple.metadata:kMDItemWhereFroms",
        "com.apple.metadata:kMDItemDownloadedDate",
        "com.apple.lastuseddate#PS",
        "com.apple.metadata:_kMDItemUserTags",
        "user.fileveil-test",
    ] {
        assert!(result.get_xattr(name).unwrap().is_none());
        assert!(file.get_xattr(name).unwrap().is_some());
    }
    assert_eq!(
        result.get_xattr("com.apple.quarantine").unwrap(),
        file.get_xattr("com.apple.quarantine").unwrap()
    );
    assert_eq!(report.integrity.security_markers_preserved, Some(true));
    assert!(!serde_json::to_string(&report).unwrap().contains("PRIVATE_"));
    verify_with_options(&original, &output, &Limits::default(), &options).unwrap();
    assert_eq!(fs::read(&original).unwrap(), bytes);
}

#[cfg(windows)]
#[test]
fn ntfs_mark_of_the_web_case_variants_survive_private_stream_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original.png");
    let output = directory.path().join("clean.png");
    image_file(&original, ImageFormat::Png);
    let stream = |path: &Path, name: &str| {
        let mut stream = path.as_os_str().to_os_string();
        stream.push(name);
        std::path::PathBuf::from(stream)
    };
    fs::write(
        stream(&original, ":zOnE.IdEnTiFiEr:$DATA"),
        b"[ZoneTransfer]\r\nZoneId=3\r\n",
    )
    .unwrap();
    fs::write(
        stream(&original, ":FileVeilPrivate:$DATA"),
        b"PRIVATE_STREAM",
    )
    .unwrap();
    let options = SanitizeOptions {
        filesystem: FilesystemOptions {
            remove_ntfs_private_streams: true,
            ..FilesystemOptions::default()
        },
        ..SanitizeOptions::default()
    };
    sanitize_with_options(&original, Some(&output), &Limits::default(), &options).unwrap();
    assert_eq!(
        fs::read(stream(&output, ":Zone.Identifier:$DATA")).unwrap(),
        b"[ZoneTransfer]\r\nZoneId=3\r\n"
    );
    assert!(!stream(&output, ":FileVeilPrivate:$DATA").exists());
    assert!(stream(&original, ":FileVeilPrivate:$DATA").exists());
}

#[test]
fn explicit_utf8_text_control_cleanup_accepts_nul_without_relaxing_binary_detection() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.TXT");
    let output = directory.path().join("clean.txt");
    let bytes = "Visible\0 text\u{200d} joining\u{202e} bidi".as_bytes();
    fs::write(&input, bytes).unwrap();
    let options = SanitizeOptions {
        text: TextOptions {
            remove_control_characters: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let report =
        sanitize_with_options(&input, Some(&output), &Limits::default(), &options).unwrap();
    assert_eq!(report.input_format, "text/plain");
    assert_eq!(fs::read(&input).unwrap(), bytes);
    assert_eq!(
        fs::read(&output).unwrap(),
        "Visible text\u{200d} joining\u{202e} bidi".as_bytes()
    );
    verify_with_options(&input, &output, &Limits::default(), &options).unwrap();
    for (index, name, bytes) in [
        (0, "unknown.bin", b"UTF8\0binary".as_slice()),
        (1, "invalid.txt", b"\xff\xfe\0binary".as_slice()),
        (2, "pdf.txt", b"%PDF-1.7\ntext\0PDF".as_slice()),
        (3, "zip.txt", b"PK\x03\x04\0zip".as_slice()),
    ] {
        let input = directory.path().join(name);
        let output = directory.path().join(format!("rejected-{index}"));
        fs::write(&input, bytes).unwrap();
        assert!(
            sanitize_with_options(&input, Some(&output), &Limits::default(), &options).is_err()
        );
        assert!(!output.exists());
        assert_eq!(fs::read(&input).unwrap(), bytes);
    }
}

#[test]
fn creation_time_choice_is_verified_or_fails_without_publication() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.png");
    let output = directory.path().join("output.png");
    let bytes = image_file(&input, ImageFormat::Png);
    let original_created = fs::metadata(&input).unwrap().created().ok();
    let options = SanitizeOptions {
        filesystem: FilesystemOptions {
            normalize_creation_time: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let result = sanitize_with_options(&input, Some(&output), &Limits::default(), &options);
    if cfg!(any(target_os = "macos", windows)) {
        let report = result.unwrap();
        assert_eq!(
            report.advanced.as_ref().unwrap()["creation_time_scope"],
            "output_creation_time_verified"
        );
        let expected = SystemTime::UNIX_EPOCH + Duration::from_secs(946_684_800);
        assert_eq!(fs::metadata(&output).unwrap().created().unwrap(), expected);
        verify_with_options(&input, &output, &Limits::default(), &options).unwrap();
        let mut staged_report = report.clone();
        staged_report.output_name = None;
        #[cfg(target_os = "macos")]
        use std::os::darwin::fs::FileTimesExt;
        #[cfg(windows)]
        use std::os::windows::fs::FileTimesExt;
        #[cfg(any(target_os = "macos", windows))]
        fs::OpenOptions::new()
            .write(true)
            .open(&output)
            .unwrap()
            .set_times(fs::FileTimes::new().set_created(SystemTime::now()))
            .unwrap();
        assert!(verify_with_options(&input, &output, &Limits::default(), &options).is_err());
        assert!(
            publish_advanced_staged(
                &input,
                &output,
                Some(&directory.path().join("published.png")),
                &mut staged_report,
                &Limits::default(),
                &options
            )
            .is_err()
        );
        assert!(!directory.path().join("published.png").exists());
    } else {
        assert!(matches!(result, Err(fileveil_core::Error::Unsupported(_))));
        assert!(!output.exists());
    }
    assert_eq!(
        fs::metadata(&input).unwrap().created().ok(),
        original_created
    );
    assert_eq!(fs::read(&input).unwrap(), bytes);
}
