// SPDX-License-Identifier: MPL-2.0
#[cfg(unix)]
#[test]
fn normal_exit_stops_descendants_before_reaping_and_preserves_exit_status() {
    use fileveil_engine::worker::{WorkerGuard, configure_command};
    use std::{
        io::{BufRead, BufReader, Read},
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "/bin/sleep 30 & printf '%s\\n' \"$!\"; exit 0"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    configure_command(&mut command);
    let mut guard = WorkerGuard::new(command.spawn().unwrap()).unwrap();
    let mut output = BufReader::new(guard.child.stdout.take().unwrap());
    let mut descendant = String::new();
    output.read_line(&mut descendant).unwrap();
    let descendant = descendant.trim();
    assert!(descendant.parse::<u32>().is_ok_and(|pid| pid > 0));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = guard.try_wait().unwrap() {
            break status;
        }
        assert!(started.elapsed() < Duration::from_secs(5));
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(0));
    assert_eq!(guard.try_wait().unwrap().unwrap().code(), Some(0));
    let mut remaining = String::new();
    output.read_to_string(&mut remaining).unwrap();
    assert!(remaining.is_empty(), "Descendant retained the report pipe");
    loop {
        let state = Command::new("/bin/ps")
            .args(["-o", "stat=", "-p", descendant])
            .output()
            .unwrap();
        let state_text = String::from_utf8_lossy(&state.stdout);
        if !state.status.success()
            || state_text.trim().is_empty()
            || state_text.trim().starts_with('Z')
        {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "Descendant survived normal worker completion"
        );
        thread::sleep(Duration::from_millis(10));
    }
    guard.terminate();
    drop(guard);
}
