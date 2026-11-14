// SPDX-License-Identifier: MPL-2.0
use fileveil_core::{Error, FindingState, Limits, Outcome, digest};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}
fn copy_fixture(name: &str, directory: &Path) -> PathBuf {
    let destination = directory.join(name);
    fs::copy(fixtures().join(name), &destination).unwrap();
    destination
}
#[test]
fn supported_fixtures_complete_scan_sanitize_verify_without_changing_original() {
    for name in [
        "jpeg_exif_gps_author.jpg",
        "png_itxt_exif_icc.png",
        "docx_author_comments_rels.docx",
        "xlsx_author_custom_formula.xlsx",
        "pptx_author_media.pptx",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let input = copy_fixture(name, directory.path());
        let original_hash = digest(&fs::read(&input).unwrap());
        let scan = fileveil_engine::scan(&input, &Limits::default()).unwrap();
        assert!(
            scan.findings
                .iter()
                .any(|f| f.action == fileveil_core::Action::Remove),
            "{name}"
        );
        let output = directory.path().join(format!("净化 副本 {name}"));
        let report = fileveil_engine::sanitize(&input, Some(&output), &Limits::default()).unwrap();
        assert!(
            matches!(
                report.result,
                Outcome::VerifiedWithinScope | Outcome::PartiallyVerified
            ),
            "{name} {report:?}"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.state == FindingState::RemovedVerified),
            "{name}"
        );
        assert_eq!(report.integrity.original_unchanged, Some(true));
        assert_eq!(digest(&fs::read(&input).unwrap()), original_hash);
        let verified = fileveil_engine::verify(&input, &output, &Limits::default()).unwrap();
        assert_eq!(verified.result, report.result);
        assert_eq!(verified.integrity.content_equal, Some(true));
        if name.ends_with("jpg") || name.ends_with("png") {
            assert_eq!(verified.integrity.pixel_equal, Some(true));
        }
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains(directory.path().to_str().unwrap()));
        assert!(!serialized.contains("Fictional Author"));
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.state == FindingState::NotAssessed)
        );
    }
}
#[test]
fn existing_output_and_input_are_protected() {
    let directory = tempfile::tempdir().unwrap();
    let input = copy_fixture("png_itxt_exif_icc.png", directory.path());
    let original = fs::read(&input).unwrap();
    assert!(matches!(
        fileveil_engine::sanitize(&input, Some(&input), &Limits::default()),
        Err(Error::Input(_))
    ));
    assert_eq!(fs::read(&input).unwrap(), original);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}
#[test]
fn default_name_conflicts_publish_separate_copies() {
    let directory = tempfile::tempdir().unwrap();
    let input = copy_fixture("png_itxt_exif_icc.png", directory.path());
    let first = fileveil_engine::sanitize(&input, None, &Limits::default()).unwrap();
    let second = fileveil_engine::sanitize(&input, None, &Limits::default()).unwrap();
    assert_ne!(first.output_name, second.output_name);
    assert!(directory.path().join(first.output_name.unwrap()).is_file());
    assert!(directory.path().join(second.output_name.unwrap()).is_file());
}
#[test]
fn signatures_malformed_and_unsupported_never_publish_output() {
    for name in [
        "docx_signed.docx",
        "png_bad_crc.png",
        "zip_slip.zip",
        "zip_bomb.zip",
        "pdf_corrupt.pdf",
        "unicode_invisible.txt",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let input = copy_fixture(name, directory.path());
        let output = directory.path().join("must_not_exist");
        assert!(
            fileveil_engine::sanitize(&input, Some(&output), &Limits::default()).is_err(),
            "{name}"
        );
        assert!(!output.exists());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1, "{name}");
    }
}
#[test]
fn verification_rejects_changed_content_and_uncleaned_fields() {
    let directory = tempfile::tempdir().unwrap();
    let input = copy_fixture("png_itxt_exif_icc.png", directory.path());
    let report = fileveil_engine::verify(&input, &input, &Limits::default()).unwrap();
    assert_eq!(report.result, Outcome::Failed);
    let output = copy_fixture("png_clean.png", directory.path());
    // A bare clean file is missing retained ICC structures from the original.
    assert!(fileveil_engine::verify(&input, &output, &Limits::default()).is_err());
}
#[test]
fn input_byte_limit_is_enforced_before_reading() {
    let limits = Limits {
        max_file_bytes: 1,
        ..Limits::default()
    };
    assert!(matches!(
        fileveil_engine::scan(&fixtures().join("png_clean.png"), &limits),
        Err(Error::Blocked(_))
    ));
}
#[test]
fn simultaneous_default_outputs_do_not_clobber_each_other() {
    let directory = tempfile::tempdir().unwrap();
    let input = copy_fixture("jpeg_exif_gps_author.jpg", directory.path());
    let tasks: Vec<_> = (0..3)
        .map(|_| {
            let input = input.clone();
            std::thread::spawn(move || {
                fileveil_engine::sanitize(&input, None, &Limits::default())
                    .unwrap()
                    .output_name
                    .unwrap()
            })
        })
        .collect();
    let names: std::collections::HashSet<_> =
        tasks.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(names.len(), 3);
}
#[cfg(unix)]
#[test]
fn symbolic_link_input_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let link = directory.path().join("link.png");
    std::os::unix::fs::symlink(fixtures().join("png_clean.png"), &link).unwrap();
    assert!(matches!(
        fileveil_engine::scan(&link, &Limits::default()),
        Err(Error::Input(_))
    ));
}
#[cfg(target_os = "macos")]
#[test]
fn quarantine_and_download_origin_are_preserved_without_reporting_values() {
    let directory = tempfile::tempdir().unwrap();
    let input = copy_fixture("png_itxt_exif_icc.png", directory.path());
    xattr::set(
        &input,
        "com.apple.quarantine",
        b"0081;00000000;FileVeilTest;synthetic",
    )
    .unwrap();
    xattr::set(
        &input,
        "com.apple.metadata:kMDItemWhereFroms",
        b"https://fictional.invalid/private-account",
    )
    .unwrap();
    let output = directory.path().join("safe.png");
    let report = fileveil_engine::sanitize(&input, Some(&output), &Limits::default()).unwrap();
    assert_eq!(report.result, Outcome::PartiallyVerified);
    assert_eq!(
        xattr::get(&input, "com.apple.quarantine").unwrap(),
        xattr::get(&output, "com.apple.quarantine").unwrap()
    );
    assert_eq!(
        xattr::get(&input, "com.apple.metadata:kMDItemWhereFroms").unwrap(),
        xattr::get(&output, "com.apple.metadata:kMDItemWhereFroms").unwrap()
    );
    let serialized = serde_json::to_string(&report).unwrap();
    assert!(!serialized.contains("fictional.invalid"));
    assert!(!serialized.contains("0081"));
}
#[cfg(target_os = "macos")]
#[test]
fn resource_fork_can_be_audited_and_blocks_copy_rewrite() {
    let directory = tempfile::tempdir().unwrap();
    let input = copy_fixture("png_clean.png", directory.path());
    xattr::set(&input, "com.apple.ResourceFork", b"synthetic resource").unwrap();
    let report = fileveil_engine::scan(&input, &Limits::default()).unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.code == "filesystem.resource_fork")
    );
    assert!(matches!(
        fileveil_engine::sanitize(&input, None, &Limits::default()),
        Err(Error::Blocked(_))
    ));
}

#[test]
fn extension_conflict_uses_magic_and_is_reported() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("misnamed.jpg");
    fs::copy(fixtures().join("png_clean.png"), &input).unwrap();
    let report = fileveil_engine::scan(&input, &Limits::default()).unwrap();
    assert_eq!(report.input_format, "image/png");
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("extension disagrees"))
    );
}

// FVPROV1 8586 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI3MDRjZjJhNjliODg2NWQzY2RlN2JhOThiNTFiNTZjNDQ5MjE4MTRhMzZjZjkyNTk3ODM5NTE2N2Y4YThkOTk1IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS40IiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuNCIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvdGVzdHMvcGlwZWxpbmUucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI2YzZiZDY0MTZmMTg2ZWQyZGIwOTBjNmNjN2QwMDViN2UxMmUwMGM0ODQ2YWY2NzAzYjNlOTA4ZDBmNjI4Y2JiNGM0NjAyOTllYWJmZjE0ZDgwMGY0ZjdlNjIxODI5NmI5MTI2ZGU5ZjkzMTg2ODJiOTc3YzRlZTY5NTc4ZmEwOCJ9XX1d FVPROV1-END
