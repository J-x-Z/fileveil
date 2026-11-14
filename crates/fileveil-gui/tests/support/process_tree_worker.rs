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

// FVPROV1 1402 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJjODQ1ZDJjMmMzNTU3YzM3M2UxYmE1YTA1YTgyMGE4NDhmOTA2MGYxYzRiNzlkMzRlM2IwZjNhMmI4MjE4MjkwIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4yIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMiIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvdGVzdHMvc3VwcG9ydC9wcm9jZXNzX3RyZWVfd29ya2VyLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiMjkyMmRiZmM5MGI5N2RiODk3OWFlZTZhOTk5MjdiMTJlMDljNDZjYjgxMWUzNTQ1MjE2YmUzYWExOTgwODZiYzQ0MWI1ZGMzNmFhOThhYmFjNGZjMmQwMTQxNjllNjM3ZWI2ODViM2RmNjhmZjkwZmQxOTAwODFlYWMwZDQ5MDIifV19XQ== FVPROV1-END
