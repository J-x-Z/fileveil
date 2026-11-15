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

// FVPROV1 1401 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIyZjcwNjQwYmEyZDI1ZTk3MWFiZTI4NGU1M2VjMzhmODNiNWM0OTA0ODA3NGE1ZjFmNjJlZmQ0NzNkOGI3MWNjIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1jbGkvdGVzdHMvc29mdHdhcmUucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiJhZTE3NTllOWMzMmMwMzJhMmIxZDkxMDU5YzlmZjg5NjA4MDgxODEyMWIwZTNjZjVhYzc4YWU5MzJkYzNmMGQzNDkzZGJkOWIxNzZkMzc1YzA0NWY1ODkzMzgxYWZhMzZhYmY2NDQ4MGZiNTZhYzBjNzEyNjNkODllNTlmZWUwYiJ9XX1d FVPROV1-END
