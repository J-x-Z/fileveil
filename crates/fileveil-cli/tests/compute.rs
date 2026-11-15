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

// FVPROV1 1099 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI3NWQ0MjE2YTJlZGUyNDQ0M2RmOWNmM2RjYzJlZTk3NGFiYzc5NzBjZmUyOTk0YWQ4MTU0ODUwYmYzM2ZkYTA3IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1jbGkvdGVzdHMvY29tcHV0ZS5ycyJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6ImZhMTQ3Y2NlZDM1OGY4OGM4ODA0Y2JiZmRhYmVkNjI5NGUxZGViMzMwNmM5NzRhNWI0NmE1MTg1NWY5MjhiMTNlOTQ1MGZjMjM1MjM2ODRkOWRhY2I2ZjAxMGZmZTYxNzcxNmNkYTg3OWUxYjNiZmI1ZjRlN2RjOTI1ZTJhZDA0In1dfV0= FVPROV1-END
