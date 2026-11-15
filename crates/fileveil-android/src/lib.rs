// SPDX-License-Identifier: MPL-2.0
//! Bounded, offline Android bridge. The UI grants URI access and stages private
//! copies; this module never receives provider URIs or executes a worker process.
use fileveil_core::{Error, Limits, Result};
use fileveil_engine::heritage::{HeritageAction, HeritageRequest};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    ffi::{CStr, CString, c_char},
    fs,
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;

const MAX_REQUEST: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub action: String,
    pub input: String,
    #[serde(default)]
    pub work_id: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub copy_id: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub robust: bool,
    #[serde(default)]
    pub clean_signal: bool,
    #[serde(default)]
    pub watermark_version: Option<u8>,
}

fn input_path(root: &Path, name: &str) -> Result<PathBuf> {
    if name.is_empty()
        || name.len() > 240
        || name.contains(['/', '\\', '\0'])
        || Path::new(name)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(Error::Input("Input must be a staged file basename".into()));
    }
    let path = root.join(name);
    let meta =
        fs::symlink_metadata(&path).map_err(|_| Error::Input("Missing staged input".into()))?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(Error::Blocked("Staged input must be a regular file".into()));
    }
    Ok(path)
}

struct PrivateKey(PathBuf);
impl Drop for PrivateKey {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub fn execute(root: &Path, encoded: &[u8], seed: Option<&[u8]>) -> Result<Value> {
    if encoded.len() > MAX_REQUEST {
        return Err(Error::Blocked("Request limit exceeded".into()));
    }
    let request: Request = serde_json::from_slice(encoded)
        .map_err(|_| Error::Input("Invalid Android request".into()))?;
    let meta = fs::symlink_metadata(root)
        .map_err(|_| Error::Input("Missing private task directory".into()))?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(Error::Blocked("Unsafe task directory".into()));
    }
    let root = root
        .canonicalize()
        .map_err(|_| Error::Input("Invalid task directory".into()))?;
    let input = input_path(&root, &request.input)?;
    let limits = Limits {
        max_file_bytes: 64 * 1024 * 1024,
        max_uncompressed_bytes: 128 * 1024 * 1024,
        max_pixels: 12_000_000,
        ..Limits::default()
    };
    let mut key = None;
    if let Some(seed) = seed {
        if seed.len() != 32 {
            return Err(Error::Input("Invalid Ed25519 seed length".into()));
        }
        let path = root.join(".signing-key");
        let seed: &[u8; 32] = seed.try_into().expect("seed length checked");
        fileveil_engine::heritage::signing::SigningKey::from_secret_seed(seed).save_new(&path)?;
        key = Some(PrivateKey(path));
    }
    let output = root.join("output");
    fs::create_dir(&output)
        .map_err(|_| Error::Blocked("Output already exists; start a fresh task".into()))?;
    let destination = output.join(if request.action == "evidence_export" {
        "evidence.json"
    } else {
        &request.input
    });
    let report = match request.action.as_str() {
        "scan" => fileveil_engine::scan(&input, &limits)?,
        "sanitize" => fileveil_engine::sanitize(&input, Some(&destination), &limits)?,
        "mark" | "verify" | "clean" | "trace" | "evidence_export" | "evidence_verify" => {
            let mut operation = HeritageRequest {
                action: match request.action.as_str() {
                    "mark" => HeritageAction::Mark,
                    "clean" => HeritageAction::Clean,
                    "trace" => HeritageAction::Trace,
                    "evidence_export" => HeritageAction::EvidenceExport,
                    "evidence_verify" => HeritageAction::EvidenceVerify,
                    _ => HeritageAction::Verify,
                },
                ..HeritageRequest::default()
            };
            if request.action == "mark" && key.is_none() {
                return Err(Error::Blocked(
                    "Mark requires the protected local identity".into(),
                ));
            }
            if let Some(key) = &key {
                if matches!(request.action.as_str(), "mark" | "evidence_export") {
                    operation.key_paths.push(key.0.clone());
                }
                operation.watermark_key = Some(key.0.clone());
            }
            operation.mark.work_id = request.work_id;
            operation.mark.author = request.author;
            operation.mark.copy_id = request.copy_id;
            operation.mark.created_at = request.created_at;
            operation.mark.signature_v2 = true;
            operation.mark.watermark_version = request.watermark_version.unwrap_or(2);
            operation.mark.robust = request.robust;
            operation.clean_signal = request.clean_signal;
            operation.clean_metadata = request.action == "clean";
            let destination = operation.writes_file().then_some(destination.as_path());
            fileveil_engine::heritage::run(&input, destination, &operation, &limits)?
        }
        _ => return Err(Error::Unsupported("Unsupported Android operation".into())),
    };
    let mut outputs = Vec::new();
    for item in fs::read_dir(&output).map_err(|_| Error::Io("Could not list results".into()))? {
        let item = item.map_err(|_| Error::Io("Could not inspect result".into()))?;
        if item
            .file_type()
            .map_err(|_| Error::Io("Could not inspect result".into()))?
            .is_file()
        {
            outputs.push(item.file_name().to_string_lossy().into_owned());
        }
    }
    outputs.sort();
    Ok(
        json!({"ok":true,"schema":"fileveil.android.v1","offline":true,"source_scope":"private_snapshot_of_user_granted_document","provider_input_write_requested":false,"report":report,"outputs":outputs}),
    )
}

/// JSON buffers are UTF-8, never JNI modified UTF-8. Key bytes are optional and
/// never serialized into a response. The C JNI shim bounds all copied lengths.
///
/// # Safety
/// `root` and `request` must point to readable NUL-terminated UTF-8 buffers.
/// A nonempty `key` must point to `key_len` readable bytes for this call.
/// Release the returned pointer exactly once with `fileveil_android_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fileveil_android_call(
    root: *const c_char,
    request: *const c_char,
    key: *const u8,
    key_len: usize,
) -> *mut c_char {
    let result = std::panic::catch_unwind(|| {
        if root.is_null() || request.is_null() || key_len > 32 || (key_len != 0 && key.is_null()) {
            return json!({"ok":false,"error":"Invalid native arguments"});
        }
        let root = unsafe { CStr::from_ptr(root) }.to_str();
        let request = unsafe { CStr::from_ptr(request) }.to_bytes();
        let secret = if key_len == 0 {
            None
        } else {
            Some(Zeroizing::new(
                unsafe { std::slice::from_raw_parts(key, key_len) }.to_vec(),
            ))
        };
        match root
            .map_err(|_| Error::Input("Invalid task path".into()))
            .and_then(|root| {
                execute(
                    Path::new(root),
                    request,
                    secret.as_deref().map(Vec::as_slice),
                )
            }) {
            Ok(value) => value,
            Err(error) => json!({"ok":false,"error":error.to_string(),"code":error.exit_code()}),
        }
    })
    .unwrap_or_else(|_| json!({"ok":false,"error":"Native processing failed safely"}));
    CString::new(result.to_string())
        .expect("JSON escapes NUL")
        .into_raw()
}

#[unsafe(no_mangle)]
/// Releases a response returned by `fileveil_android_call`.
///
/// # Safety
/// `value` must be null or a still-owned response from that function. It must
/// never be freed twice or supplied from a different allocator.
pub unsafe extern "C" fn fileveil_android_free(value: *mut c_char) {
    if !value.is_null() {
        drop(unsafe { CString::from_raw(value) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_escape_and_oversized_request() {
        let root = std::env::temp_dir().join(format!("fileveil-android-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        assert!(execute(&root, br#"{"action":"scan","input":"../secret"}"#, None).is_err());
        assert!(execute(&root, &vec![0; MAX_REQUEST + 1], None).is_err());
        let _ = fs::remove_dir_all(root);
    }
    #[test]
    fn desktop_protocol_mark_clean_round_trip() {
        let root =
            std::env::temp_dir().join(format!("fileveil-android-protocol-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let fixture = include_bytes!("../../../tests/fixtures/png_clean.png");
        fs::write(root.join("sample.png"), fixture).unwrap();
        let request = br#"{"action":"mark","input":"sample.png","work_id":"urn:fileveil:test:android","author":"Test","copy_id":"arm64","created_at":"2026-11-15"}"#;
        let seed = [7u8; 32];
        let marked = execute(&root, request, Some(&seed)).unwrap();
        assert_eq!(marked["ok"], true);
        assert_eq!(fs::read(root.join("sample.png")).unwrap(), fixture);
        assert!(!root.join(".signing-key").exists());
        let verify_root = root.join("verify");
        fs::create_dir(&verify_root).unwrap();
        fs::copy(
            root.join("output/sample.png"),
            verify_root.join("sample.png"),
        )
        .unwrap();
        let verified = execute(
            &verify_root,
            br#"{"action":"verify","input":"sample.png"}"#,
            Some(&seed),
        )
        .unwrap();
        assert_eq!(verified["ok"], true);
        let evidence_root = root.join("evidence");
        fs::create_dir(&evidence_root).unwrap();
        fs::copy(
            root.join("output/sample.png"),
            evidence_root.join("sample.png"),
        )
        .unwrap();
        let evidence = execute(
            &evidence_root,
            br#"{"action":"evidence_export","input":"sample.png"}"#,
            Some(&seed),
        )
        .unwrap();
        assert_eq!(evidence["ok"], true);
        let evidence_verify_root = root.join("evidence-verify");
        fs::create_dir(&evidence_verify_root).unwrap();
        fs::copy(
            evidence_root.join("output/evidence.json"),
            evidence_verify_root.join("evidence.json"),
        )
        .unwrap();
        let evidence_verified = execute(
            &evidence_verify_root,
            br#"{"action":"evidence_verify","input":"evidence.json"}"#,
            None,
        )
        .unwrap();
        assert_eq!(evidence_verified["ok"], true);
        assert_eq!(evidence_verified["outputs"], json!([]));
        let clean_root = root.join("clean");
        fs::create_dir(&clean_root).unwrap();
        fs::copy(
            root.join("output/sample.png"),
            clean_root.join("sample.png"),
        )
        .unwrap();
        let cleaned = execute(
            &clean_root,
            br#"{"action":"clean","input":"sample.png"}"#,
            Some(&seed),
        )
        .unwrap();
        assert_eq!(cleaned["ok"], true);
        assert_eq!(
            fs::read(clean_root.join("output/sample.png")).unwrap(),
            fixture
        );
        fs::remove_dir_all(root).unwrap();
    }
}

// FVPROV1 11810 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJhOGE1ZTA5ZGZjMjFjYmYwNDgwNWVkNTQyYmQ2OTZmYWVkMzc2OGM4OTljMDg2ZDM0NDIxNTBhMzllMzEwMjNkIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1hbmRyb2lkL3NyYy9saWIucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiJiZDUzYjI5NTcxZGFmMmY0YjViYzQzNDg4YWE3NjA2YjQzMjNjZDI2ZjAwZDJlZWFmOTA2NTI2MDkyY2M4N2Q5ZDVkM2UzM2JjODBkMGJkZDA0ZWYzNzBmOWM2MDMwMDg1MzViYjk3OTlmMTAzZjQ1YTdhMGZiYzAwMWFlNGUwOCJ9XX1d FVPROV1-END
