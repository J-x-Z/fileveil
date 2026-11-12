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
    std::thread::sleep(Duration::from_secs(60));
}
