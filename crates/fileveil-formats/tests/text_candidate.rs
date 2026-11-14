// SPDX-License-Identifier: MPL-2.0
use std::path::Path;

use fileveil_core::{Action, Error, Format, Limits, SanitizeOptions, TextOptions};
use fileveil_formats::{identify, inspect, inspect_with_options, sanitize};

#[test]
fn nul_utf8_text_is_audited_read_only_and_explicit_options_reuse_the_same_scope() {
    let source = "Visible\0 text\u{200d} joining\u{202e} bidi".as_bytes();
    let limits = Limits::default();
    let options = SanitizeOptions {
        text: TextOptions {
            remove_control_characters: true,
            ..Default::default()
        },
        ..Default::default()
    };
    for extension in ["TXT", "md", "markdown"] {
        let name = format!("control.{extension}");
        let path = Path::new(&name);
        assert_eq!(identify(source, path), Format::Unknown);
        let audit = inspect(source, path, &limits).unwrap();
        assert_eq!(audit.format, Format::Text);
        assert!(!audit.rewrite_supported);
        assert!(audit.findings.iter().any(|finding| {
            finding.code == "text.control_character" && finding.action == Action::Preserve
        }));
        assert!(matches!(
            sanitize(source, audit.format, &limits),
            Err(Error::Unsupported(_))
        ));
        let selected = inspect_with_options(source, path, &limits, &options).unwrap();
        assert!(selected.rewrite_supported);
        assert!(selected.findings.iter().any(|finding| {
            finding.code == "text.control_character" && finding.action == Action::Remove
        }));
    }
}

#[test]
fn text_candidate_audit_preserves_binary_and_container_boundaries() {
    let limits = Limits::default();
    let options = SanitizeOptions {
        text: TextOptions {
            remove_control_characters: true,
            ..Default::default()
        },
        ..Default::default()
    };
    for (name, source) in [
        ("unknown.bin", b"Visible\0 binary".as_slice()),
        ("invalid.txt", b"\xff\xfe\0binary".as_slice()),
        ("document.txt", b"%PDF-1.7\ntext\0PDF".as_slice()),
        ("package.md", b"PK\x03\x04\0zip".as_slice()),
    ] {
        let hint = Path::new(name);
        assert_ne!(identify(source, hint), Format::Text);
        for inspection in [
            inspect(source, hint, &limits),
            inspect_with_options(source, hint, &limits, &options),
        ]
        .into_iter()
        .flatten()
        {
            assert_ne!(inspection.format, Format::Text, "{name}");
            assert!(!inspection.rewrite_supported, "{name}");
        }
    }
}

// FVPROV1 2555 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIzODNlZmRkZmViNGNkZmIwYjgxZTc2YzhmODg3NDY2ZjFmNjU5MGNhNWExNWFkN2QxMjRhZWVkYjQ2Y2QzNzg3IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4zIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMyIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1mb3JtYXRzL3Rlc3RzL3RleHRfY2FuZGlkYXRlLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiYzc1ZmYzNTIxZDY3NDJlOTA4ZGIyMDBiODllOTE0YmFlODY4YjRhNzYzNDJkNTMzZGRkMzE0Mjk5NGViMmU3ZTY5ZjI2ZjgzODdhZDFlZTBlZDIxZmIzZTlkNTcyNjNkZjk4ZmE1Zjc3M2JmNDk3MDQyODJlMmFlODA5NzJiMGUifV19XQ== FVPROV1-END
