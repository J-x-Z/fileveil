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
