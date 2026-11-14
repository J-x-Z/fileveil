// SPDX-License-Identifier: MPL-2.0
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
use fileveil_gui::{app::FileVeilApp, jobs, mcp, mcp_access::McpAccessConfig};
use std::{ffi::OsStr, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    let mut arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let smoke_report = if arguments
        .first()
        .is_some_and(|arg| arg == OsStr::new("--smoke-test-report"))
    {
        if arguments.len() < 2 {
            return ExitCode::from(2);
        }
        let report = PathBuf::from(arguments.remove(1));
        arguments.remove(0);
        if report.exists() || report.with_extension("png").exists() {
            return ExitCode::from(2);
        }
        Some(report)
    } else {
        None
    };
    if arguments
        .first()
        .is_some_and(|argument| argument == OsStr::new("--mcp"))
    {
        return match mcp_configuration(&arguments[1..]) {
            Ok(configuration) => ExitCode::from(mcp::run_with_config(configuration) as u8),
            Err(message) => {
                eprintln!("{message}");
                ExitCode::from(2)
            }
        };
    }
    if arguments.len() == 1 && arguments[0] == OsStr::new("--fileveil-worker") {
        return ExitCode::from(jobs::worker_main() as u8);
    }
    if arguments.len() == 1 && arguments[0] == OsStr::new("--version") {
        println!("FileVeil {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if arguments
        .iter()
        .take_while(|arg| *arg != OsStr::new("--"))
        .any(|arg| arg == OsStr::new("--help"))
    {
        println!(
            "FileVeil {}\n\nUsage\n  fileveil-gui [FILES...]\n  fileveil-gui --mcp [--mcp-read-root DIR] [--mcp-write-root DIR] [--mcp-signing-key FILE] [--mcp-signing-key-ref ID] [--mcp-max-operations 64]\n\nNative offline privacy workbench. Selected files are added to the read-only scan queue.\nMCP file access requires explicit authorized roots. Repeat root options to grant multiple directories.\nUse -- before filenames beginning with a dash.",
            env!("CARGO_PKG_VERSION")
        );
        return ExitCode::SUCCESS;
    }
    let mut paths = Vec::new();
    let mut terminated = false;
    for argument in arguments {
        if !terminated && argument == OsStr::new("--") {
            terminated = true;
            continue;
        }
        if !terminated && argument.to_string_lossy().starts_with('-') {
            eprintln!("Unknown GUI option. Use --help for usage.");
            return ExitCode::from(2);
        }
        paths.push(PathBuf::from(argument));
    }
    let image = image::load_from_memory(include_bytes!("../../../assets/icon.png"))
        .expect("bundled application icon")
        .into_rgba8();
    let icon = eframe::egui::IconData {
        width: image.width(),
        height: image.height(),
        rgba: image.into_raw(),
    };
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("FileVeil")
            .with_inner_size([1360.0, 850.0])
            .with_min_inner_size([1060.0, 700.0])
            .with_transparent(cfg!(target_os = "macos"))
            .with_fullsize_content_view(cfg!(target_os = "macos"))
            .with_title_shown(!cfg!(target_os = "macos"))
            .with_titlebar_shown(!cfg!(target_os = "macos"))
            .with_icon(icon),
        renderer: eframe::Renderer::Glow,
        centered: true,
        ..Default::default()
    };
    let expected_smoke_report = smoke_report.clone();
    match eframe::run_native(
        "FileVeil",
        options,
        Box::new(move |context| {
            Ok(Box::new(
                FileVeilApp::new(context, paths).with_smoke_report(smoke_report),
            ))
        }),
    ) {
        Ok(()) => {
            if expected_smoke_report.is_none_or(|path| path.is_file()) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(5)
            }
        }
        Err(error) => {
            eprintln!("Could not start FileVeil GUI. {error}");
            ExitCode::from(5)
        }
    }
}

fn mcp_configuration(arguments: &[std::ffi::OsString]) -> Result<McpAccessConfig, String> {
    let mut configuration = McpAccessConfig::default();
    let mut arguments = arguments.iter();
    while let Some(option) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| "MCP options require a directory or numeric value".to_string())?;
        match option.to_str() {
            Some("--mcp-read-root") => configuration.read_roots.push(PathBuf::from(value)),
            Some("--mcp-write-root") => configuration.write_roots.push(PathBuf::from(value)),
            Some("--mcp-signing-key") => configuration.signing_keys.push(PathBuf::from(value)),
            Some("--mcp-signing-key-ref") => configuration.signing_key_refs.push(
                value
                    .to_str()
                    .ok_or("System key references must be Unicode")?
                    .into(),
            ),
            Some("--mcp-max-operations") => {
                configuration.max_operations = value
                    .to_str()
                    .and_then(|value| value.parse::<u32>().ok())
                    .filter(|value| (1..=10_000).contains(value))
                    .ok_or_else(|| "MCP operation limit must be between 1 and 10000".to_string())?;
            }
            _ => return Err("Unknown MCP option. Use --help for supported options".into()),
        }
    }
    Ok(configuration)
}

// FVPROV1 5649 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIxMTdhMjBkOWM2MTY1OGI1ZDM4NzkzYTE4MDJmNmMwODFhZGUzYzFmZmQ5NmIwNGRjNzMyODQ5MmUwMDRhNjNhIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS40IiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuNCIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1ndWkvc3JjL21haW4ucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiJmNTVkODBlYjY2MzdjZTdiNWYxNjFhNmIzNDA3YTg5YTI4NTY4Yzk2MjUyZWNlZTczYWIyZGViYjc4OWQ3NGUwNWNkNzZkNTZlMDEyMTcxNGQxZGI5YTUyZGYzMWJmNmI0YTRhMWZmZDI2MDM0ZDA1MGRlNjVmOTZmMjY5MjAwNiJ9XX1d FVPROV1-END
