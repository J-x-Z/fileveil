// SPDX-License-Identifier: MPL-2.0
//! Offline C2PA creation using a user-selected ES256 certificate and private key.
//! The SDK writes bounded in-memory streams. Only the caller publishes a new copy.
//! Certificate trust, author assertions and trusted time remain separate from a
//! valid claim signature and asset binding.

use super::signing::read_private_key_bytes;
use crate::provenance::{self, CheckStatus, ProvenanceReport};
use c2pa::{Builder, BuilderIntent, Context, SigningAlg, create_signer};
use fileveil_core::{Error, Format, Limits, Result, digest};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    path::Path,
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct C2paMarkClaims {
    pub title: String,
    pub author: String,
    pub work_id: String,
    pub edition: String,
    pub version: String,
    pub asserted_time: String,
}

pub struct C2paMarkedAsset {
    pub bytes: Vec<u8>,
    pub manifest_sha256: String,
    pub provenance: ProvenanceReport,
}

pub fn sign_bytes_with_key_path(
    input: &[u8],
    format: Format,
    certificate_pem: &[u8],
    private_key_path: &Path,
    claims: &C2paMarkClaims,
    limits: &Limits,
) -> Result<C2paMarkedAsset> {
    let key = read_private_key_bytes(private_key_path)?;
    sign_bytes(input, format, certificate_pem, &key, claims, limits)
}

/// Signs an already-bounded snapshot. Prefer `sign_bytes_with_key_path` when
/// reading files, to retain private-file permissions and MCP descriptor checks.
/// The caller owns the supplied secret buffer. This module zeroizes its copy.
pub fn sign_bytes(
    input: &[u8],
    format: Format,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    claims: &C2paMarkClaims,
    limits: &Limits,
) -> Result<C2paMarkedAsset> {
    if input.len() as u64 > limits.max_file_bytes {
        return Err(Error::Blocked(
            "C2PA marking input exceeds the file byte limit".into(),
        ));
    }
    if !matches!(
        format,
        Format::Jpeg
            | Format::Png
            | Format::Pdf
            | Format::Text
            | Format::Wav
            | Format::Heic
            | Format::Avif
            | Format::Mp4
            | Format::Mov
    ) {
        return Err(Error::Unsupported(
            "This format cannot receive C2PA credentials in this build".into(),
        ));
    }
    if private_key_pem.is_empty()
        || private_key_pem.len() > 16 * 1024
        || certificate_pem.is_empty()
        || certificate_pem.len() > 256 * 1024
        || certificate_pem.len() > limits.max_metadata_bytes
    {
        return Err(Error::Blocked(
            "C2PA certificate or private-key byte limit exceeded".into(),
        ));
    }
    for text in [
        &claims.title,
        &claims.author,
        &claims.work_id,
        &claims.edition,
        &claims.version,
        &claims.asserted_time,
    ] {
        if text.len() > 4096 {
            return Err(Error::Blocked(
                "C2PA author statement exceeds its text limit".into(),
            ));
        }
    }
    if claims.title.is_empty() || claims.work_id.is_empty() || claims.version.is_empty() {
        return Err(Error::Input(
            "C2PA title, work ID and version must be present".into(),
        ));
    }
    let key = Zeroizing::new(private_key_pem.to_vec());
    // An absent TSA URL and disabled host access prevent content or timestamps
    // from being submitted to an external service by this signing operation.
    let signer =
        create_signer::from_keys(certificate_pem, &key, SigningAlg::Es256, None).map_err(|_| {
            Error::Input("C2PA requires a compatible local ES256 certificate and PEM key".into())
        })?;
    let context = Context::new().with_settings(json!({
        "verify": {
            "verify_after_sign": true,
            "verify_trust": false,
            "remote_manifest_fetch": false,
            "ocsp_fetch": false,
            "ocsp_fetch_should_override": false
        },
        "core": {
            "allowed_network_hosts": [],
            "allow_redirects": false,
            "decode_identity_assertions": false,
            "max_decompressed_manifest_size_in_mb": limits.max_metadata_bytes.div_ceil(1024 * 1024).clamp(1, 32)
        }
    })).map_err(|_| Error::Input("Could not configure offline C2PA signing".into()))?;
    let definition = json!({
        "title": claims.title,
        "claim_generator_info": [{"name":"FileVeil", "version":env!("CARGO_PKG_VERSION")}],
        "assertions": [{
            "label":"org.fileveil.heritage",
            "data": {
                "schema":"fileveil.c2pa.author_claim.v1",
                "work_id":claims.work_id,
                "author":claims.author,
                "edition":claims.edition,
                "version":claims.version,
                "asserted_time":claims.asserted_time,
                "identity_scope":"user_asserted_author_claim",
                "timestamp_scope":"user_asserted_time"
            }
        }]
    });
    let mut builder = Builder::from_context(context)
        .with_definition(definition)
        .map_err(|_| Error::Input("Could not construct C2PA author statements".into()))?;
    // Preserve an existing credential as a parent ingredient. Adding a claim
    // describes opening an existing asset, rather than inventing its creation.
    builder.set_intent(BuilderIntent::Edit);
    let mut source = Cursor::new(input);
    let mut destination = BoundedCursor {
        inner: Cursor::new(Vec::new()),
        maximum: limits.max_file_bytes,
    };
    let manifest = builder
        .sign(
            signer.as_ref(),
            format.mime(),
            &mut source,
            &mut destination,
        )
        .map_err(|_| {
            Error::Verification(
                "C2PA signing failed certificate, structure or output-budget validation".into(),
            )
        })?;
    let output = destination.inner.into_inner();
    let verified = provenance::inspect(&output, format, limits)?.ok_or_else(|| {
        Error::Verification("C2PA output contains no readable embedded credential".into())
    })?;
    if verified.signature != CheckStatus::Valid || verified.asset_binding != CheckStatus::Valid {
        return Err(Error::Verification(
            "C2PA output failed post-signing claim-signature or asset-binding verification".into(),
        ));
    }
    Ok(C2paMarkedAsset {
        bytes: output,
        manifest_sha256: digest(&manifest),
        provenance: verified,
    })
}

struct BoundedCursor {
    inner: Cursor<Vec<u8>>,
    maximum: u64,
}

impl Write for BoundedCursor {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .inner
            .position()
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > self.maximum)
        {
            return Err(io::Error::other("C2PA output byte limit exceeded"));
        }
        self.inner.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Read for BoundedCursor {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.inner.read(bytes)
    }
}

impl Seek for BoundedCursor {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let previous = self.inner.position();
        let actual = self.inner.seek(position)?;
        if actual > self.maximum {
            self.inner.set_position(previous);
            return Err(io::Error::other("C2PA output seek exceeds its byte limit"));
        }
        Ok(actual)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, process::Command};

    fn claims() -> C2paMarkClaims {
        C2paMarkClaims {
            title: "Synthetic image".into(),
            author: "Synthetic Author".into(),
            work_id: "fixture-1".into(),
            edition: "1".into(),
            version: "1".into(),
            asserted_time: "2026-11-12T00:00:00Z".into(),
        }
    }

    #[test]
    fn output_writer_enforces_growth_and_seek_limits() {
        let mut output = BoundedCursor {
            inner: Cursor::new(Vec::new()),
            maximum: 8,
        };
        output.write_all(&[1; 8]).unwrap();
        assert!(output.write_all(&[2]).is_err());
        assert!(output.seek(SeekFrom::Start(u64::MAX)).is_err());
        assert_eq!(output.inner.position(), 8);
        assert_eq!(output.inner.get_ref().len(), 8);
        output.seek(SeekFrom::Start(0)).unwrap();
        output.write_all(&[2; 8]).unwrap();
        assert_eq!(output.inner.get_ref(), &[2; 8]);
    }

    #[test]
    fn signing_rejects_unsupported_and_unbounded_inputs() {
        assert!(
            sign_bytes(
                b"x",
                Format::Docx,
                b"cert",
                b"key",
                &claims(),
                &Limits::default()
            )
            .is_err()
        );
        let limits = Limits {
            max_file_bytes: 0,
            ..Limits::default()
        };
        assert!(sign_bytes(b"x", Format::Png, b"cert", b"key", &claims(), &limits).is_err());
        assert!(
            sign_bytes(
                b"x",
                Format::Png,
                b"cert",
                &vec![0; 16 * 1024 + 1],
                &claims(),
                &Limits::default()
            )
            .is_err()
        );
        assert!(
            sign_bytes(
                b"x",
                Format::Png,
                b"invalid",
                b"invalid",
                &claims(),
                &Limits::default()
            )
            .is_err()
        );
    }

    fn openssl(directory: &Path, arguments: &[&str]) {
        let output = Command::new("openssl")
            .current_dir(directory)
            .args(arguments)
            .output()
            .expect("OpenSSL is required for this explicit interoperability test");
        assert!(
            output.status.success(),
            "OpenSSL certificate generation failed"
        );
    }

    fn protect_test_pem(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        #[cfg(windows)]
        {
            // Replace inherited and explicit ACEs. Updating an existing grant
            // with icacls can leave other explicit OpenSSL-created entries.
            let script = r#"
$ErrorActionPreference = 'Stop'
$owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = [System.Security.AccessControl.FileSecurity]::new()
$acl.SetOwner($owner)
$acl.SetAccessRuleProtection($true, $false)
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new($owner, 'FullControl', 'Allow')
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $env:FILEVEIL_TEST_PEM -AclObject $acl
"#;
            let output = Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", script])
                .env("FILEVEIL_TEST_PEM", path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "Could not protect ephemeral test PEM"
            );
        }
    }

    fn check_pdf_display(display: &serde_json::Value) {
        let fields = [
            "independent_page_count_equal",
            "independent_text_equal",
            "independent_render_equal",
        ];
        for field in fields {
            assert_ne!(display[field], false);
        }
        let complete = fields.iter().all(|field| display[field] == true);
        assert_eq!(
            display["result"],
            if complete {
                "verified_within_scope"
            } else {
                "partially_verified"
            }
        );
        assert!(
            display["scope"]
                .as_str()
                .unwrap()
                .contains("Credential trust")
        );
        if crate::pdf::capabilities()["independent_validation_available"] == true {
            assert!(complete, "Available Poppler checks must all run");
        } else {
            assert!(!complete);
            assert!(!display["warnings"].as_array().unwrap().is_empty());
        }
    }

    #[test]
    #[ignore = "Generates an ephemeral local ES256 certificate with OpenSSL"]
    fn creates_c2pa_with_local_certificate_and_rechecks_pixels_signature_and_binding() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        openssl(
            path,
            &[
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-keyout",
                "root.key",
                "-out",
                "root.pem",
                "-days",
                "3650",
                "-subj",
                "/CN=FileVeil Ephemeral Test Root",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        );
        openssl(
            path,
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
            path,
            &[
                "req",
                "-new",
                "-key",
                "signer.key",
                "-subj",
                "/CN=FileVeil Ephemeral Test Signer",
                "-out",
                "signer.csr",
            ],
        );
        fs::write(path.join("signer.ext"), "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=emailProtection\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n").unwrap();
        openssl(
            path,
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
                "3650",
                "-sha256",
                "-extfile",
                "signer.ext",
                "-out",
                "signer.pem",
            ],
        );
        let certificate = fs::read(path.join("signer.pem")).unwrap();
        let key_path = path.join("signer.key");
        protect_test_pem(&key_path);
        let secret = read_private_key_bytes(&key_path).unwrap();
        let trust_root = fs::read_to_string(path.join("root.pem")).unwrap();
        let unrelated_root = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/provenance/unrelated-root.pem"),
        )
        .unwrap();
        let image = image::RgbImage::from_fn(48, 48, |x, y| image::Rgb([x as u8, y as u8, 90]));
        for format in [Format::Png, Format::Jpeg] {
            let mut source = Cursor::new(Vec::new());
            let encoding = if format == Format::Png {
                image::ImageFormat::Png
            } else {
                image::ImageFormat::Jpeg
            };
            image::DynamicImage::ImageRgb8(image.clone())
                .write_to(&mut source, encoding)
                .unwrap();
            let source = source.into_inner();
            let original_hash = digest(&source);
            let marked = sign_bytes(
                &source,
                format,
                &certificate,
                &secret,
                &claims(),
                &Limits::default(),
            )
            .unwrap();
            assert_eq!(digest(&source), original_hash);
            assert_eq!(marked.provenance.signature, CheckStatus::Valid);
            assert_eq!(marked.provenance.asset_binding, CheckStatus::Valid);
            assert_eq!(
                marked.provenance.trust,
                provenance::TrustStatus::NotAssessed
            );
            assert_eq!(
                image::load_from_memory(&source).unwrap().to_rgb8(),
                image::load_from_memory(&marked.bytes).unwrap().to_rgb8()
            );
            let trusted = provenance::inspect_with_trust(
                &marked.bytes,
                format,
                &Limits::default(),
                Some(&trust_root),
            )
            .unwrap()
            .unwrap();
            assert_eq!(trusted.trust, provenance::TrustStatus::Trusted);
            let untrusted = provenance::inspect_with_trust(
                &marked.bytes,
                format,
                &Limits::default(),
                Some(&unrelated_root),
            )
            .unwrap()
            .unwrap();
            assert_eq!(untrusted.trust, provenance::TrustStatus::Untrusted);
            let mut altered = marked.bytes.clone();
            let offset = altered.windows(4).position(|part| part == b"IDAT");
            if let Some(offset) = offset {
                altered[offset + 8] ^= 1;
                assert!(
                    !matches!(provenance::inspect(&altered, format, &Limits::default()), Ok(Some(report)) if report.asset_binding == CheckStatus::Valid)
                );
            }
        }

        // Use the committed, independently readable PDF fixture, removing its
        // old credential in an operation-owned copy before creating a new one.
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/provenance/signed.pdf");
        let fixture_bytes = fs::read(&fixture).unwrap();
        let fixture_hash = digest(&fixture_bytes);
        let limits = Limits::default();
        let source = provenance::remove_store(&fixture_bytes, Format::Pdf.mime(), &limits).unwrap();
        assert!(
            provenance::inspect(&source, Format::Pdf, &limits)
                .unwrap()
                .is_none()
        );
        let marked = sign_bytes(
            &source,
            Format::Pdf,
            &certificate,
            &secret,
            &claims(),
            &limits,
        )
        .unwrap();
        assert_eq!(marked.provenance.signature, CheckStatus::Valid);
        assert_eq!(marked.provenance.asset_binding, CheckStatus::Valid);
        assert_eq!(
            marked.provenance.trust,
            provenance::TrustStatus::NotAssessed
        );
        assert!(marked.provenance.offline);
        let trusted =
            provenance::inspect_with_trust(&marked.bytes, Format::Pdf, &limits, Some(&trust_root))
                .unwrap()
                .unwrap();
        assert_eq!(trusted.trust, provenance::TrustStatus::Trusted);
        let untrusted = provenance::inspect_with_trust(
            &marked.bytes,
            Format::Pdf,
            &limits,
            Some(&unrelated_root),
        )
        .unwrap()
        .unwrap();
        assert_eq!(untrusted.trust, provenance::TrustStatus::Untrusted);
        check_pdf_display(
            &crate::pdf::verify_heritage_display(&source, &marked.bytes, &limits).unwrap(),
        );

        // Exercise the normal Core operation with file-based credentials and a
        // fresh destination, including its own output reparse and Poppler scope.
        let input_path = path.join("source.pdf");
        let output_path = path.join("marked.pdf");
        fs::write(&input_path, &source).unwrap();
        let source_hash = digest(&source);
        let key_hash = digest(&fs::read(&key_path).unwrap());
        let statement = claims();
        let request = crate::heritage::HeritageRequest {
            action: crate::heritage::HeritageAction::C2paMark,
            mark: crate::heritage::MarkSettings {
                work_id: statement.work_id,
                author: statement.author,
                edition: statement.edition,
                version: statement.version,
                created_at: statement.asserted_time,
                ..Default::default()
            },
            certificate: Some(path.join("signer.pem")),
            private_key: Some(key_path.clone()),
            ..Default::default()
        };
        let report =
            crate::heritage::run(&input_path, Some(&output_path), &request, &limits).unwrap();
        let credential = report.provenance.as_ref().unwrap();
        assert_eq!(credential["signature"], "valid");
        assert_eq!(credential["asset_binding"], "valid");
        assert_eq!(credential["trust"], "not_assessed");
        assert_eq!(report.integrity.original_unchanged, Some(true));
        assert_eq!(report.integrity.content_equal, None);
        assert_eq!(report.input_sha256.as_deref(), Some(source_hash.as_str()));
        let output = fs::read(&output_path).unwrap();
        assert_eq!(
            report.output_sha256.as_deref(),
            Some(digest(&output).as_str())
        );
        check_pdf_display(&report.advanced.as_ref().unwrap()["heritage"]["pdf_display"]);
        let verified =
            provenance::inspect_with_trust(&output, Format::Pdf, &limits, Some(&trust_root))
                .unwrap()
                .unwrap();
        assert_eq!(verified.signature, CheckStatus::Valid);
        assert_eq!(verified.asset_binding, CheckStatus::Valid);
        assert_eq!(verified.trust, provenance::TrustStatus::Trusted);
        assert_eq!(digest(&fs::read(&input_path).unwrap()), source_hash);
        assert_eq!(digest(&fs::read(&key_path).unwrap()), key_hash);
        assert_eq!(digest(&fs::read(&fixture).unwrap()), fixture_hash);
    }
}
