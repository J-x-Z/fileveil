// SPDX-License-Identifier: MPL-2.0
//! RFC 3161 request/response handling through a bounded offline OpenSSL backend.
use super::signing::VerificationState;
use fileveil_core::{Error, Result, digest};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const MAX_TIMESTAMP_BYTES: usize = 1024 * 1024;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampVerification {
    pub verification: VerificationState,
    pub expected_imprint_sha256: String,
    pub response_sha256: String,
    pub asserted_tsa_time: Option<String>,
    pub certificate_validation_time: Option<i64>,
    pub nonce_checked: bool,
    pub offline: bool,
    pub scope: String,
    pub reason: Option<String>,
}

pub fn capabilities() -> serde_json::Value {
    serde_json::json!({"rfc3161_query":openssl_program().is_some(),"offline_verification":openssl_program().is_some(),
        "backend":"openssl_ts","network_default":false,"max_response_bytes":MAX_TIMESTAMP_BYTES,
        "revocation":"not_assessed","trust":"explicit_pem_roots_only"})
}

pub fn create_query(imprint_sha256: &str) -> Result<Vec<u8>> {
    query_with_nonce(imprint_sha256, true)
}

fn query_with_nonce(imprint_sha256: &str, nonce: bool) -> Result<Vec<u8>> {
    validate_digest(imprint_sha256)?;
    let program = openssl_program()
        .ok_or_else(|| Error::Unsupported("OpenSSL timestamp backend is unavailable".into()))?;
    let directory = tempfile::tempdir()
        .map_err(|_| Error::Io("Could not create private timestamp job".into()))?;
    let mut args = vec![
        "ts",
        "-query",
        "-digest",
        imprint_sha256,
        "-sha256",
        "-cert",
        "-out",
        "query.der",
    ];
    if !nonce {
        args.push("-no_nonce");
    }
    let result = bounded_command(&program, &args, directory.path(), None)?;
    if !result.success {
        return Err(Error::Verification(
            "OpenSSL could not create an RFC3161 request".into(),
        ));
    }
    let query = bounded_file(&directory.path().join("query.der"), 16 * 1024)?;
    if query_imprint(&query)? != imprint_sha256 {
        return Err(Error::Verification(
            "Timestamp query imprint mismatch".into(),
        ));
    }
    Ok(query)
}

pub fn verify_timestamp(
    response_der: &[u8],
    expected_sha256: &str,
    roots_pem: Option<&[u8]>,
    original_query_der: Option<&[u8]>,
) -> Result<TimestampVerification> {
    validate_digest(expected_sha256)?;
    if response_der.is_empty()
        || response_der.len() > MAX_TIMESTAMP_BYTES
        || original_query_der.is_some_and(|b| b.len() > 16 * 1024)
        || roots_pem.is_some_and(|b| b.len() > 256 * 1024)
    {
        return Err(Error::Blocked(
            "RFC3161 input exceeds its byte budget".into(),
        ));
    }
    if let Some(query) = original_query_der
        && query_imprint(query)? != expected_sha256
    {
        return Err(Error::Verification(
            "Original timestamp query has a different imprint".into(),
        ));
    }
    let mut report=TimestampVerification {verification:VerificationState::NotAssessed,
        expected_imprint_sha256:expected_sha256.into(),response_sha256:digest(response_der),asserted_tsa_time:None,
        certificate_validation_time:None,nonce_checked:false,offline:true,
        scope:"RFC3161 SHA-256 message imprint, original query nonce when supplied, CMS/TSA signature and explicit certificate trust at the signed generation time. Online revocation and identity assertions require separate evidence.".into(),reason:None};
    let Some(program) = openssl_program() else {
        report.reason = Some("OpenSSL timestamp backend unavailable".into());
        return Ok(report);
    };
    let directory = tempfile::tempdir()
        .map_err(|_| Error::Io("Could not create timestamp verification job".into()))?;
    fs::write(directory.path().join("response.der"), response_der)
        .map_err(|_| Error::Io("Could not stage timestamp response".into()))?;
    let token = bounded_command(
        &program,
        &[
            "ts",
            "-reply",
            "-in",
            "response.der",
            "-token_out",
            "-out",
            "token.der",
        ],
        directory.path(),
        None,
    )?;
    let content = if token.success {
        bounded_command(
            &program,
            &[
                "cms",
                "-verify",
                "-inform",
                "DER",
                "-in",
                "token.der",
                "-noverify",
                "-binary",
                "-nosigs",
                "-out",
                "tstinfo.der",
            ],
            directory.path(),
            None,
        )?
    } else {
        report.verification = VerificationState::Invalid;
        report.reason = Some("Malformed or rejected RFC3161 response".into());
        return Ok(report);
    };
    if !content.success {
        report.verification = VerificationState::Invalid;
        report.reason = Some("Timestamp signed content could not be extracted".into());
        return Ok(report);
    }
    // Read generation time from CMS encapsulated TSTInfo. Unsigned status text
    // and display strings never determine the certificate verification time.
    let tstinfo = bounded_file(&directory.path().join("tstinfo.der"), 64 * 1024)?;
    let mut outer = tstinfo.as_slice();
    let mut body = tlv(&mut outer, 0x30)?;
    if !outer.is_empty() || tlv(&mut body, 0x02)? != [1] {
        return Err(Error::Unsupported(
            "Unsupported timestamp TSTInfo encoding".into(),
        ));
    }
    tlv(&mut body, 0x06)?;
    tlv(&mut body, 0x30)?;
    tlv(&mut body, 0x02)?;
    let encoded_time = tlv(&mut body, 0x18)?;
    let encoded_time = std::str::from_utf8(encoded_time)
        .map_err(|_| Error::Input("Invalid timestamp generation time".into()))?;
    report.asserted_tsa_time = Some(encoded_time.into());
    report.certificate_validation_time = Some(parse_generalized_time(encoded_time)?);
    let Some(roots) = roots_pem.filter(|b| !b.is_empty()) else {
        report.reason =
            Some("Explicit TSA trust roots required for cryptographic verification".into());
        return Ok(report);
    };
    fs::write(directory.path().join("roots.pem"), roots)
        .map_err(|_| Error::Io("Could not stage TSA trust roots".into()))?;
    let attime = report.certificate_validation_time.unwrap().to_string();
    let mut arguments = vec![
        "ts",
        "-verify",
        "-in",
        "response.der",
        "-CAfile",
        "roots.pem",
        "-attime",
        attime.as_str(),
    ];
    let generated;
    let query = if let Some(original) = original_query_der {
        original
    } else {
        generated = query_with_nonce(expected_sha256, false)?;
        &generated
    };
    fs::write(directory.path().join("query.der"), query)
        .map_err(|_| Error::Io("Could not stage timestamp query".into()))?;
    arguments.extend(["-queryfile", "query.der"]);
    let checked = bounded_command(&program, &arguments, directory.path(), None)?;
    report.verification = if checked.success {
        VerificationState::Valid
    } else {
        VerificationState::Invalid
    };
    report.nonce_checked = checked.success && original_query_der.is_some();
    if !checked.success {
        report.reason = Some(
            "RFC3161 signature, imprint, nonce or explicit trust-chain verification failed".into(),
        );
    }
    Ok(report)
}

pub(crate) struct ProcessOutput {
    pub success: bool,
    pub stdout: Zeroizing<Vec<u8>>,
}
pub(crate) fn bounded_command(
    program: &Path,
    arguments: &[&str],
    directory: &Path,
    input: Option<&[u8]>,
) -> Result<ProcessOutput> {
    if input.is_some_and(|b| b.len() > 4096) {
        return Err(Error::Blocked(
            "Secret backend input exceeds its budget".into(),
        ));
    }
    let mut command = Command::new(program);
    command
        .args(arguments)
        .current_dir(directory)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("OPENSSL_CONF")
        .env_remove("OPENSSL_ENGINES")
        .env_remove("OPENSSL_MODULES");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn().map_err(|_| {
        Error::Unsupported("Required local cryptographic backend could not start".into())
    })?;
    let out = child.stdout.take().unwrap();
    let err = child.stderr.take().unwrap();
    let read = |stream: Box<dyn Read + Send>| {
        let mut bytes = Zeroizing::new(Vec::new());
        stream
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    };
    let output_thread = thread::spawn(move || read(Box::new(out)));
    let error_thread = thread::spawn(move || read(Box::new(err)));
    if let Some(input) = input
        && child.stdin.take().unwrap().write_all(input).is_err()
    {
        let _ = child.kill();
        let _ = child.wait();
        let _ = output_thread.join();
        let _ = error_thread.join();
        return Err(Error::Io(
            "Could not send bounded private backend input".into(),
        ));
    }
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = output_thread.join();
                let _ = error_thread.join();
                return Err(Error::Io("Could not inspect cryptographic backend".into()));
            }
        }
        if start.elapsed() > Duration::from_secs(15) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = output_thread.join();
            let _ = error_thread.join();
            return Err(Error::Blocked(
                "Local cryptographic backend timed out".into(),
            ));
        }
        thread::sleep(Duration::from_millis(20));
    };
    let stdout = output_thread
        .join()
        .map_err(|_| Error::Io("Backend output reader failed".into()))?
        .map_err(|_| Error::Io("Could not read bounded backend output".into()))?;
    let stderr = error_thread
        .join()
        .map_err(|_| Error::Io("Backend diagnostic reader failed".into()))?
        .map_err(|_| Error::Io("Could not read bounded backend diagnostics".into()))?;
    if stdout.len() > 64 * 1024 || stderr.len() > 64 * 1024 {
        return Err(Error::Blocked(
            "Cryptographic backend output exceeds its budget".into(),
        ));
    }
    Ok(ProcessOutput {
        success: status.success(),
        stdout,
    })
}

fn openssl_program() -> Option<PathBuf> {
    let supported = |path: PathBuf| {
        let path = path.canonicalize().ok().filter(|p| p.is_file())?;
        let version = bounded_command(&path, &["version"], &std::env::temp_dir(), None).ok()?;
        let text = std::str::from_utf8(&version.stdout).ok()?;
        (version.success && text.starts_with("OpenSSL ")).then_some(path)
    };
    if let Some(path) = std::env::var_os("FILEVEIL_OPENSSL") {
        let path = PathBuf::from(path);
        return path.is_absolute().then(|| supported(path)).flatten();
    }
    [
        "/opt/homebrew/opt/openssl@3/bin/openssl",
        "/usr/local/opt/openssl@3/bin/openssl",
        "/usr/bin/openssl",
        "C:/Program Files/Git/usr/bin/openssl.exe",
    ]
    .into_iter()
    .find_map(|path| supported(PathBuf::from(path)))
}
fn bounded_file(path: &Path, cap: usize) -> Result<Vec<u8>> {
    let file =
        fs::File::open(path).map_err(|_| Error::Io("Timestamp backend output is absent".into()))?;
    if file
        .metadata()
        .map_err(|_| Error::Io("Could not inspect timestamp output".into()))?
        .len()
        > cap as u64
    {
        return Err(Error::Blocked(
            "Timestamp output exceeds its byte budget".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Io("Could not read timestamp output".into()))?;
    if bytes.len() > cap {
        return Err(Error::Blocked(
            "Timestamp output exceeds its byte budget".into(),
        ));
    }
    Ok(bytes)
}
fn validate_digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Input(
            "Timestamp imprint must be a lower-case SHA-256 digest".into(),
        ));
    }
    Ok(())
}
fn parse_generalized_time(text: &str) -> Result<i64> {
    let without_zone = text
        .strip_suffix('Z')
        .ok_or_else(|| Error::Input("TSA generation time must use UTC".into()))?;
    let (main, fraction) = without_zone
        .split_once('.')
        .map_or((without_zone, None), |(a, b)| (a, Some(b)));
    if main.len() != 14
        || !main.bytes().all(|b| b.is_ascii_digit())
        || fraction
            .is_some_and(|f| f.is_empty() || f.len() > 32 || !f.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(Error::Input("Invalid RFC3161 GeneralizedTime".into()));
    }
    let part = |start: usize, end: usize| {
        main[start..end]
            .parse::<u8>()
            .map_err(|_| Error::Input("Invalid TSA time component".into()))
    };
    let year = main[..4]
        .parse::<i32>()
        .map_err(|_| Error::Input("Invalid TSA year".into()))?;
    let month =
        time::Month::try_from(part(4, 6)?).map_err(|_| Error::Input("Invalid TSA month".into()))?;
    let date = time::Date::from_calendar_date(year, month, part(6, 8)?)
        .map_err(|_| Error::Input("Invalid TSA date".into()))?;
    let clock = time::Time::from_hms(part(8, 10)?, part(10, 12)?, part(12, 14)?)
        .map_err(|_| Error::Input("Invalid TSA clock".into()))?;
    Ok(time::PrimitiveDateTime::new(date, clock)
        .assume_utc()
        .unix_timestamp())
}
// Strict bounded DER walk for the request's SHA-256 messageImprint. OpenSSL
// performs response, signature, nonce and certificate processing independently.
fn query_imprint(bytes: &[u8]) -> Result<String> {
    let mut outer = bytes;
    let mut body = tlv(&mut outer, 0x30)?;
    if !outer.is_empty() || tlv(&mut body, 0x02)? != [1] {
        return Err(Error::Input("Invalid RFC3161 query version".into()));
    }
    let mut imprint = tlv(&mut body, 0x30)?;
    let mut algorithm = tlv(&mut imprint, 0x30)?;
    if tlv(&mut algorithm, 0x06)? != [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] {
        return Err(Error::Input("Timestamp query must use SHA-256".into()));
    }
    if !algorithm.is_empty() && (!tlv(&mut algorithm, 0x05)?.is_empty() || !algorithm.is_empty()) {
        return Err(Error::Input("Invalid timestamp digest parameters".into()));
    }
    let hash = tlv(&mut imprint, 0x04)?;
    if hash.len() != 32 || !imprint.is_empty() {
        return Err(Error::Input("Invalid timestamp query imprint".into()));
    }
    // Remaining policy, nonce and certReq fields are parsed and checked by OpenSSL.
    Ok(hash.iter().map(|b| format!("{b:02x}")).collect())
}
fn tlv<'a>(bytes: &mut &'a [u8], tag: u8) -> Result<&'a [u8]> {
    let fail = || Error::Input("Malformed bounded timestamp DER".into());
    if bytes.len() < 2 || bytes[0] != tag {
        return Err(fail());
    }
    let first = bytes[1];
    let (length, header) = if first < 128 {
        (first as usize, 2)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 2 || bytes.len() < 2 + count || bytes[2] == 0 {
            return Err(fail());
        }
        let mut len = 0;
        for b in &bytes[2..2 + count] {
            len = (len << 8) | *b as usize;
        }
        if len < 128 {
            return Err(fail());
        }
        (len, 2 + count)
    };
    if length > bytes.len() - header {
        return Err(fail());
    }
    let value = &bytes[header..header + length];
    *bytes = &bytes[header + length..];
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timestamp_budget_digest_and_calendar_validation_fail_before_backend() {
        assert!(create_query("../bad").is_err());
        assert!(verify_timestamp(&[], &"0".repeat(64), None, None).is_err());
        assert!(
            verify_timestamp(
                &vec![0; MAX_TIMESTAMP_BYTES + 1],
                &"0".repeat(64),
                None,
                None
            )
            .is_err()
        );
        assert!(parse_generalized_time("20260230120000Z").is_err());
        assert_eq!(
            parse_generalized_time("20000101000000.123Z").unwrap(),
            946684800
        );
        assert!(query_imprint(b"\x30\x80\x00\x00").is_err());
    }
    #[test]
    #[ignore = "Independent OpenSSL temporary RFC3161 TSA and certificate-chain interoperability"]
    fn local_tsa_token_checks_signature_trust_imprint_and_original_nonce() {
        let Some(program) = openssl_program() else {
            panic!("OpenSSL prerequisite required");
        };
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        let run = |arguments: &[&str]| {
            let output = Command::new(&program)
                .args(arguments)
                .current_dir(path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        run(&[
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
            "30",
            "-subj",
            "/CN=FileVeil Ephemeral TSA Root",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]);
        run(&[
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "tsa.key",
            "-out",
            "tsa.csr",
            "-subj",
            "/CN=FileVeil Ephemeral TSA",
        ]);
        fs::write(path.join("tsa.ext"),"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n").unwrap();
        run(&[
            "x509",
            "-req",
            "-in",
            "tsa.csr",
            "-CA",
            "root.pem",
            "-CAkey",
            "root.key",
            "-set_serial",
            "2",
            "-days",
            "30",
            "-sha256",
            "-extfile",
            "tsa.ext",
            "-out",
            "tsa.pem",
        ]);
        fs::write(path.join("serial"), "01\n").unwrap();
        fs::write(path.join("tsa.cnf"),"[tsa]\ndefault_tsa=local\n[local]\nserial=serial\ncrypto_device=builtin\nsigner_cert=tsa.pem\nsigner_key=tsa.key\ncerts=root.pem\nsigner_digest=sha256\ndefault_policy=1.3.6.1.4.1.55555.1\nother_policies=1.3.6.1.4.1.55555.2\ndigests=sha256\naccuracy=secs:1\nordering=yes\ntsa_name=yes\ness_cert_id_chain=no\ness_cert_id_alg=sha256\n").unwrap();
        let owner = crate::heritage::signing::SigningKey::generate().unwrap();
        let asset = b"independently verified copyright evidence asset";
        let mut declaration = crate::heritage::signing::RecordBody::new(
            digest(asset),
            "timestamped-work".into(),
            "Synthetic timestamp author".into(),
            "1".into(),
            "2026-11-13T00:00:00Z".into(),
            owner.public_key().key_id,
        );
        declaration.schema = crate::heritage::signing::SCHEMA_V2.into();
        declaration.copy_id = Some("copy-tsa-1".into());
        let history =
            vec![crate::heritage::signing::append_record(&[], declaration, &[&owner]).unwrap()];
        let hash = crate::heritage::signing::record_hash(&history[0]).unwrap();
        let query = create_query(&hash).unwrap();
        fs::write(path.join("query.der"), &query).unwrap();
        run(&[
            "ts",
            "-reply",
            "-config",
            "tsa.cnf",
            "-queryfile",
            "query.der",
            "-out",
            "response.der",
        ]);
        let response = fs::read(path.join("response.der")).unwrap();
        let roots = fs::read(path.join("root.pem")).unwrap();
        let verified = verify_timestamp(&response, &hash, Some(&roots), Some(&query)).unwrap();
        assert_eq!(verified.verification, VerificationState::Valid);
        assert!(verified.nonce_checked);
        assert!(verified.certificate_validation_time.is_some());
        {
            use crate::heritage::custody::{
                self, AttachedTimestamp, EvidenceAsset, TimestampSubject,
            };
            use base64::{Engine, engine::general_purpose::STANDARD};
            let evidence = custody::create_evidence(
                &history,
                vec![EvidenceAsset {
                    version: "1".into(),
                    sha256: digest(asset),
                    size_bytes: asset.len() as u64,
                    media_type: "application/octet-stream".into(),
                }],
                vec![],
                vec![AttachedTimestamp {
                    subject: TimestampSubject::Record,
                    subject_sha256: hash.clone(),
                    response_der_base64: STANDARD.encode(&response),
                }],
                &owner,
            )
            .unwrap();
            let checked = custody::verify_evidence(
                &evidence,
                &crate::heritage::signing::TrustStore::default(),
                &[],
                Some(&roots),
            )
            .unwrap();
            assert_eq!(checked.timestamps[0].verification, VerificationState::Valid);
            fs::write(
                path.join("evidence.json"),
                custody::canonical_evidence(&evidence).unwrap(),
            )
            .unwrap();
            fs::write(path.join("asset.bin"), asset).unwrap();
            let script =
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/verify-evidence.py");
            let python = if cfg!(windows) { "python" } else { "python3" };
            let independent = Command::new(python)
                .arg(script)
                .arg(path.join("evidence.json"))
                .arg("--asset")
                .arg(path.join("asset.bin"))
                .arg("--tsa-roots")
                .arg(path.join("root.pem"))
                .arg("--openssl")
                .arg(&program)
                .output()
                .unwrap();
            assert!(
                independent.status.success(),
                "{}",
                String::from_utf8_lossy(&independent.stderr)
            );
            let report: serde_json::Value = serde_json::from_slice(&independent.stdout).unwrap();
            assert_eq!(report["trusted_timestamps"], 1);
            assert_eq!(report["provided_assets_verified"], 1);
        }
        let no_root = verify_timestamp(&response, &hash, None, Some(&query)).unwrap();
        assert_eq!(no_root.verification, VerificationState::NotAssessed);
        assert_eq!(
            verify_timestamp(&response, &digest(b"wrong"), Some(&roots), None)
                .unwrap()
                .verification,
            VerificationState::Invalid
        );
        let wrong_nonce = create_query(&hash).unwrap();
        assert_ne!(wrong_nonce, query);
        assert_eq!(
            verify_timestamp(&response, &hash, Some(&roots), Some(&wrong_nonce))
                .unwrap()
                .verification,
            VerificationState::Invalid
        );
        let unrelated = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/provenance/unrelated-root.pem");
        assert_eq!(
            verify_timestamp(
                &response,
                &hash,
                Some(&fs::read(unrelated).unwrap()),
                Some(&query)
            )
            .unwrap()
            .verification,
            VerificationState::Invalid
        );
        let mut changed = response;
        let index = changed.len() - 8;
        changed[index] ^= 1;
        assert_ne!(
            verify_timestamp(&changed, &hash, Some(&roots), Some(&query))
                .unwrap()
                .verification,
            VerificationState::Valid
        );
    }
}

// FVPROV1 25293 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIxZTA1MzU5Njk2NmRmNTk3YzI1ZWVlZmQ4MGE0NDIzMWUyNjIzNjVlMDg1ZGI0OTg4NTBkZTgwNjViYmJjMmIwIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvc3JjL2hlcml0YWdlL3RpbWVzdGFtcC5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6ImRlMTdhM2VhNmFjODA0MDNhYjE5MmNhOTMyMWIwZjAwMWExMDFhZjg1NGU2Nzk3MDc5ODcxNDEzMDljMjIxNTczYTc2N2Y5OTlmZGRmOGZlZjlkZDkxNDVlYWYxNzQ0ZmZhZTllYjdlN2Q5OTA2NDNmZTUwNTA1NzFlMWNmNTBiIn1dfV0= FVPROV1-END
