// SPDX-License-Identifier: MPL-2.0
use std::{fs, process::Command};

#[test]
fn comma_delimited_compute_arguments_reach_confined_parser() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("weights.safetensors");
    fs::write(&input, u64::MAX.to_le_bytes()).unwrap();
    let before = fs::read(&input).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fileveil"))
        .args(["--json", "compute"])
        .arg(&input)
        .args([
            "--tensor",
            "embedding",
            "--rows",
            "2000,2500,3000",
            "--seeds",
            "7",
            "--sm-counts",
            "108,132,148,152",
        ])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
    assert_eq!(report["operation"], "compute_fingerprint");
    assert_eq!(report["result"], "blocked");
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(fs::read(input).unwrap(), before);
}
