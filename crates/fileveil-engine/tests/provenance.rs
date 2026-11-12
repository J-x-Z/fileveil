// SPDX-License-Identifier: MPL-2.0
use std::{fs, io::Cursor, path::PathBuf};

use fileveil_core::{Format, Limits, digest};
use fileveil_engine::provenance::{self, CheckStatus, ManifestPresence, TrustStatus};
use image::{DynamicImage, ImageFormat};

fn fixture(name: &str) -> Vec<u8> {
    fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/provenance")
            .join(name),
    )
    .expect("committed public synthetic C2PA fixture")
}

#[test]
fn provider_availability_matches_configured_backends() {
    let capabilities = provenance::capabilities();
    assert_eq!(
        capabilities
            .iter()
            .filter(|item| item.status == "available")
            .count(),
        1
    );
    assert!(capabilities.iter().all(|item| !item.network_enabled));
    assert!(
        capabilities
            .iter()
            .filter(|item| item.provider_id != "c2pa")
            .all(|item| item.verified_formats.is_empty() && item.status == "unavailable")
    );
}

#[test]
fn official_private_copy_removal_clears_signed_and_remote_credentials_without_pixel_changes() {
    for (name, format) in [
        ("signed.png", Format::Png),
        ("signed.jpg", Format::Jpeg),
        ("remote.png", Format::Png),
    ] {
        let source = fixture(name);
        let original_hash = digest(&source);
        let before = image::load_from_memory(&source).unwrap();
        let output = provenance::remove(&source, format, &Limits::default()).unwrap();
        assert!(
            provenance::inspect(&output, format, &Limits::default())
                .unwrap()
                .is_none()
        );
        let after = image::load_from_memory(&output).unwrap();
        assert_eq!(before.color(), after.color());
        assert_eq!(before.as_bytes(), after.as_bytes());
        assert_eq!(digest(&source), original_hash);
    }
}

fn png(value: u8) -> Vec<u8> {
    let image = DynamicImage::ImageRgb8(image::RgbImage::from_pixel(
        4,
        4,
        image::Rgb([value, 64, 128]),
    ));
    let mut output = Cursor::new(Vec::new());
    image.write_to(&mut output, ImageFormat::Png).unwrap();
    output.into_inner()
}

#[test]
fn signed_png_checks_crypto_and_binding_without_assuming_trust() {
    let data = fixture("signed.png");
    let before = digest(&data);
    let report = provenance::inspect(&data, Format::Png, &Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(report.presence, ManifestPresence::Embedded);
    assert_eq!(report.manifest_count, 1);
    assert_eq!(report.signature, CheckStatus::Valid);
    assert_eq!(report.asset_binding, CheckStatus::Valid);
    assert_eq!(report.manifest_validation, CheckStatus::Valid);
    assert_eq!(report.trust, TrustStatus::NotAssessed);
    assert_eq!(report.revocation, CheckStatus::NotAssessed);
    assert_eq!(report.timestamp, CheckStatus::NotAssessed);
    assert!(report.offline);
    assert_eq!(digest(&data), before);
    let json = serde_json::to_string(&report).unwrap();
    for private_value in [
        "PRIVATE_SYNTHETIC_TITLE",
        "Synthetic Signer",
        "https://example.invalid",
        "PRIVATE_GENERATOR",
    ] {
        assert!(!json.contains(private_value));
    }
    assert_eq!(
        serde_json::from_str::<provenance::ProvenanceReport>(&json).unwrap(),
        report
    );
}

#[test]
fn local_root_trust_is_explicit_and_jpeg_is_supported() {
    let root = String::from_utf8(fixture("root.pem")).unwrap();
    let report = provenance::inspect_with_trust(
        &fixture("signed.jpg"),
        Format::Jpeg,
        &Limits::default(),
        Some(&root),
    )
    .unwrap()
    .unwrap();
    assert_eq!(report.signature, CheckStatus::Valid);
    assert_eq!(report.asset_binding, CheckStatus::Valid);
    assert_eq!(report.trust, TrustStatus::Trusted);
    assert_eq!(
        report.trust_anchor_sha256.as_deref(),
        Some(digest(root.as_bytes()).as_str())
    );
    assert_eq!(report.signature_algorithm.as_deref(), Some("es256"));
}

#[test]
fn unrelated_root_preserves_valid_signature_and_reports_untrusted() {
    let root = String::from_utf8(fixture("unrelated-root.pem")).unwrap();
    let report = provenance::inspect_with_trust(
        &fixture("signed.png"),
        Format::Png,
        &Limits::default(),
        Some(&root),
    )
    .unwrap()
    .unwrap();
    assert_eq!(report.signature, CheckStatus::Valid);
    assert_eq!(report.asset_binding, CheckStatus::Valid);
    assert_eq!(report.trust, TrustStatus::Untrusted);
}

#[test]
fn tampering_claim_breaks_signature_and_tampering_pixels_breaks_binding() {
    let data = fixture("signed.png");
    let manifest = c2pa::jumbf_io::load_jumbf_from_memory("image/png", &data).unwrap();
    let mut changed_claim = manifest.clone();
    let marker = b"PRIVATE_GENERATOR";
    let offset = changed_claim
        .windows(marker.len())
        .position(|bytes| bytes == marker)
        .unwrap();
    changed_claim[offset] ^= 1;
    let changed = c2pa::jumbf_io::save_jumbf_to_memory("image/png", &data, &changed_claim).unwrap();
    let report = provenance::inspect(&changed, Format::Png, &Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(report.signature, CheckStatus::Invalid);
    assert_eq!(report.manifest_validation, CheckStatus::Invalid);

    let changed = c2pa::jumbf_io::save_jumbf_to_memory("image/png", &png(251), &manifest).unwrap();
    let report = provenance::inspect(&changed, Format::Png, &Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(report.signature, CheckStatus::Valid);
    assert_eq!(report.asset_binding, CheckStatus::Invalid);
    assert_eq!(report.manifest_validation, CheckStatus::Invalid);
}

#[test]
fn remote_manifest_is_blocked_offline_and_url_stays_private() {
    let report = provenance::inspect(&fixture("remote.png"), Format::Png, &Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(report.presence, ManifestPresence::RemoteReference);
    assert_eq!(report.signature, CheckStatus::Unverifiable);
    assert!(report.offline);
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("example.invalid")
    );
}

#[test]
fn clean_unknown_and_malformed_inputs_do_not_claim_valid_credentials() {
    assert!(
        provenance::inspect(&png(16), Format::Png, &Limits::default())
            .unwrap()
            .is_none()
    );
    assert!(
        provenance::inspect(
            b"c2pa jumb PRIVATE_GENERATOR",
            Format::Text,
            &Limits::default()
        )
        .unwrap()
        .is_none()
    );
    let malformed =
        c2pa::jumbf_io::save_jumbf_to_memory("image/png", &png(16), b"malformed").unwrap();
    let report = provenance::inspect(&malformed, Format::Png, &Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(report.signature, CheckStatus::Unverifiable);
    assert_eq!(report.manifest_validation, CheckStatus::Unverifiable);
}

#[test]
fn file_manifest_and_trust_limits_are_enforced() {
    let data = fixture("signed.png");
    let limits = Limits {
        max_file_bytes: 1,
        ..Limits::default()
    };
    assert!(provenance::inspect(&data, Format::Png, &limits).is_err());
    let limits = Limits {
        max_metadata_bytes: 8,
        ..Limits::default()
    };
    assert!(provenance::inspect(&data, Format::Png, &limits).is_err());
    assert!(
        provenance::inspect_with_trust(
            &png(16),
            Format::Png,
            &limits,
            Some("invalid trust bundle larger than limit")
        )
        .is_err()
    );
    assert!(
        provenance::inspect_with_trust(&data, Format::Png, &Limits::default(), Some("invalid PEM"))
            .is_err()
    );
}

/// Reproducible local fixture creation. Only public signed images and root
/// certificates are retained. TempDir removes every generated private key.
#[test]
#[ignore = "manual public fixture regeneration requires a local OpenSSL executable"]
fn regenerate_public_fixtures() {
    use c2pa::{Builder, Context, SigningAlg, create_signer};
    use serde_json::json;
    use std::{path::Path, process::Command};

    fn openssl(dir: &Path, args: &[&str]) {
        let output = Command::new("openssl")
            .current_dir(dir)
            .args(args)
            .output()
            .expect("local OpenSSL for fixture generation");
        assert!(output.status.success(), "OpenSSL fixture command failed");
    }

    let temporary = tempfile::tempdir().unwrap();
    let dir = temporary.path();
    for (key, certificate, subject) in [
        ("root.key", "root.pem", "/CN=FileVeil Synthetic Root"),
        (
            "unrelated.key",
            "unrelated-root.pem",
            "/CN=FileVeil Unrelated Root",
        ),
    ] {
        openssl(
            dir,
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                key,
            ],
        );
        openssl(
            dir,
            &[
                "req",
                "-x509",
                "-new",
                "-key",
                key,
                "-sha256",
                "-days",
                "36500",
                "-subj",
                subject,
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-out",
                certificate,
            ],
        );
    }
    openssl(
        dir,
        &[
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            "signer.key",
        ],
    );
    openssl(
        dir,
        &[
            "req",
            "-new",
            "-key",
            "signer.key",
            "-subj",
            "/CN=FileVeil Synthetic Signer",
            "-out",
            "signer.csr",
        ],
    );
    fs::write(dir.join("signer.ext"), "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=emailProtection\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n").unwrap();
    openssl(
        dir,
        &[
            "x509",
            "-req",
            "-in",
            "signer.csr",
            "-CA",
            "root.pem",
            "-CAkey",
            "root.key",
            "-set_serial",
            "2",
            "-days",
            "36500",
            "-sha256",
            "-extfile",
            "signer.ext",
            "-out",
            "signer.pem",
        ],
    );
    let signer = create_signer::from_keys(
        &fs::read(dir.join("signer.pem")).unwrap(),
        &fs::read(dir.join("signer.key")).unwrap(),
        SigningAlg::Es256,
        None,
    )
    .unwrap();
    let context = Context::new().with_settings(json!({
        "verify": {"verify_after_sign": false, "remote_manifest_fetch": false, "ocsp_fetch": false},
        "core": {"allowed_network_hosts": [], "allow_redirects": false}
    })).unwrap().into_shared();
    let output_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/provenance");
    fs::create_dir_all(&output_dir).unwrap();
    for (extension, mime, image_format) in [
        ("png", "image/png", ImageFormat::Png),
        ("jpg", "image/jpeg", ImageFormat::Jpeg),
    ] {
        let image =
            DynamicImage::ImageRgb8(image::RgbImage::from_pixel(4, 4, image::Rgb([16, 64, 128])));
        let mut source = Cursor::new(Vec::new());
        image.write_to(&mut source, image_format).unwrap();
        let definition = json!({
            "claim_version": 2,
            "title": "PRIVATE_SYNTHETIC_TITLE",
            "format": mime,
            "claim_generator_info": [{"name": "PRIVATE_GENERATOR", "version": "0.3"}],
            "assertions": [{"label": "c2pa.actions", "data": {"actions": [{"action": "c2pa.created", "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/algorithmicMedia"}]}}]
        });
        let mut builder = Builder::from_shared_context(&context)
            .with_definition(definition.to_string())
            .unwrap();
        let mut output = Cursor::new(Vec::new());
        builder
            .sign(signer.as_ref(), mime, &mut source, &mut output)
            .unwrap();
        fs::write(
            output_dir.join(format!("signed.{extension}")),
            output.into_inner(),
        )
        .unwrap();
        if extension == "png" {
            let mut builder = Builder::from_shared_context(&context)
                .with_definition(definition.to_string())
                .unwrap();
            builder
                .set_remote_url("https://example.invalid/PRIVATE_SYNTHETIC_TITLE.c2pa")
                .set_no_embed(true);
            let mut output = Cursor::new(Vec::new());
            builder
                .sign(signer.as_ref(), mime, &mut source, &mut output)
                .unwrap();
            fs::write(output_dir.join("remote.png"), output.into_inner()).unwrap();
        }
    }
    for name in ["root.pem", "unrelated-root.pem"] {
        fs::copy(dir.join(name), output_dir.join(name)).unwrap();
    }
}
