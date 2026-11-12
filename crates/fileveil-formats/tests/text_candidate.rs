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
