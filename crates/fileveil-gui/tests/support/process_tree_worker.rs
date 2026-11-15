// SPDX-License-Identifier: MPL-2.0
//! Native Windows cancellation fixture. Business starts after the request pipe closes.
use std::{
    fs,
    io::Read,
    process::{Command, Stdio},
    time::Duration,
};

fn main() {
    let mut request = Vec::new();
    std::io::stdin().read_to_end(&mut request).unwrap();
    let executable = std::env::current_exe().unwrap();
    let root = executable.parent().unwrap();
    let descendant = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Sleep -Seconds 60",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    fs::write(root.join("grandchild.pid"), descendant.id().to_string()).unwrap();
    let scratch = std::env::var_os("FILEVEIL_PDF_STAGING").unwrap();
    fs::write(
        std::path::Path::new(&scratch).join("snapshot.pdf"),
        b"private backend input",
    )
    .unwrap();
    fs::write(
        root.join("scratch.path"),
        scratch.to_string_lossy().as_bytes(),
    )
    .unwrap();
    fs::write(root.join("worker.pid"), std::process::id().to_string()).unwrap();
    if executable
        .file_name()
        .is_some_and(|name| name == "normal-exit-worker.exe")
    {
        return;
    }
    std::thread::sleep(Duration::from_secs(60));
}

// FVPROV1 1402 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJjODQ1ZDJjMmMzNTU3YzM3M2UxYmE1YTA1YTgyMGE4NDhmOTA2MGYxYzRiNzlkMzRlM2IwZjNhMmI4MjE4MjkwIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvdGVzdHMvc3VwcG9ydC9wcm9jZXNzX3RyZWVfd29ya2VyLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiZTI2MDQ3YzExNDY2MzRmN2ZkYzk4ZjJmNGVkNWY2NTE1YTAwMjJmMDFjNmFmODkwZjFmNzhmN2Q1OWE4NDE1NDJkMjBkZDkxYzI2ZThkNjI3MTA1Mjc0NTdlNGU5M2VlMDE1YTQ4NmVlYjk2MjBlYjI0Y2E5MzdmOTgxOTdjMGMifV19XQ== FVPROV1-END
