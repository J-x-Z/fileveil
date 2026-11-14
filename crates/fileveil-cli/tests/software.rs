// SPDX-License-Identifier: MPL-2.0
//! Software byte inspection through the actual confined CLI worker.
use serde_json::Value;
use std::{fs, process::Command};
#[test]
fn software_cli_inspects_a_real_binary_without_changing_or_executing_it() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("sample.bin");
    fs::copy(control_binary(), &input).unwrap();
    let before = fs::read(&input).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_fileveil"))
        .args(["--json", "--max-file-mib", "512", "software", "inspect"])
        .arg(&input)
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&result.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&result.stderr)));
    assert!(matches!(result.status.code(), Some(0 | 4)), "{report}");
    assert_eq!(report["operation"], "software");
    assert_eq!(report["advanced"]["software"]["action"], "inspect");
    assert_eq!(fs::read(&input).unwrap(), before);
}

fn control_binary() -> std::path::PathBuf {
    #[cfg(unix)]
    let candidate = std::path::PathBuf::from("/usr/bin/true");
    #[cfg(windows)]
    let candidate = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_default())
        .join("System32/where.exe");
    if candidate.is_file() {
        candidate
    } else {
        std::env::current_exe().unwrap()
    }
}

// FVPROV1 1401 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIyZjcwNjQwYmEyZDI1ZTk3MWFiZTI4NGU1M2VjMzhmODNiNWM0OTA0ODA3NGE1ZjFmNjJlZmQ0NzNkOGI3MWNjIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1jbGkvdGVzdHMvc29mdHdhcmUucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiJlMWI4Yjg3MTYyMWZlZmUwYjYzNzBiYmIxMjE3ZWUwYTlkMjBjOWJmNzg1ZGE5MWM2ZDZiMGExNDBiMjE0YWU0NjUzNDE0ZDIyMGYxYjRhOTg3N2I2ZjA5M2JhNDhiMmU2ZmYxYWFjMzY2MWRjNTE5NzdhMTBiN2M0MjIyNzQwZiJ9XX1d FVPROV1-END
