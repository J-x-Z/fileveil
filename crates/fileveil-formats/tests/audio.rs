// SPDX-License-Identifier: MPL-2.0
use fileveil_core::{Action, Error, Format, Limits};
use fileveil_formats::{audio, inspect, sanitize};
use std::path::Path;
fn chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut result = kind.to_vec();
    result.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    result.extend_from_slice(payload);
    if payload.len() % 2 == 1 {
        result.push(0);
    }
    result
}
fn wav(extra: &[Vec<u8>]) -> Vec<u8> {
    let mut result = b"RIFF\0\0\0\0WAVE".to_vec();
    let mut fmt = 1u16.to_le_bytes().to_vec();
    fmt.extend_from_slice(&1u16.to_le_bytes());
    fmt.extend_from_slice(&8000u32.to_le_bytes());
    fmt.extend_from_slice(&16000u32.to_le_bytes());
    fmt.extend_from_slice(&2u16.to_le_bytes());
    fmt.extend_from_slice(&16u16.to_le_bytes());
    result.extend(chunk(b"fmt ", &fmt));
    for bytes in extra {
        result.extend_from_slice(bytes);
    }
    result.extend(chunk(b"data", &[0, 0, 1, 0, 255, 255, 2, 0]));
    let length = (result.len() - 8) as u32;
    result[4..8].copy_from_slice(&length.to_le_bytes());
    result
}
fn flac_block(kind: u8, last: bool, payload: &[u8]) -> Vec<u8> {
    let mut result = vec![kind | if last { 128 } else { 0 }];
    result.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    result.extend_from_slice(payload);
    result
}
fn vorbis(fields: &[&str]) -> Vec<u8> {
    let vendor = b"PRIVATE_ENCODER";
    let mut result = (vendor.len() as u32).to_le_bytes().to_vec();
    result.extend_from_slice(vendor);
    result.extend_from_slice(&(fields.len() as u32).to_le_bytes());
    for field in fields {
        result.extend_from_slice(&(field.len() as u32).to_le_bytes());
        result.extend_from_slice(field.as_bytes());
    }
    result
}
fn flac(comment: &[u8], extra: &[Vec<u8>]) -> Vec<u8> {
    let mut info = vec![0; 34];
    info[..4].copy_from_slice(&[0, 16, 0, 16]);
    let bits = (8000u64 << 44) | (15u64 << 36) | 4;
    info[10..18].copy_from_slice(&bits.to_be_bytes());
    let mut result = b"fLaC".to_vec();
    result.extend(flac_block(0, false, &info));
    for bytes in extra {
        result.extend_from_slice(bytes);
    }
    result.extend(flac_block(4, true, comment));
    result.extend_from_slice(&[0xff, 0xf8, 0x60, 0x08, 0, 0, 0, 0]);
    result
}
#[test]
fn wav_removes_known_metadata_and_retains_sample_payload() {
    let mut info = b"INFO".to_vec();
    info.extend(chunk(b"IART", b"PRIVATE_AUTHOR\0"));
    let original = wav(&[
        chunk(b"LIST", &info),
        chunk(b"bext", b"PRIVATE_ORIGIN"),
        chunk(b"iXML", b"<author>PRIVATE_AUTHOR</author>"),
    ]);
    let before = inspect(&original, Path::new("audio.wav"), &Limits::default()).unwrap();
    assert_eq!(before.format, Format::Wav);
    assert!(before.rewrite_supported);
    let output = sanitize(&original, Format::Wav, &Limits::default()).unwrap();
    assert!(!String::from_utf8_lossy(&output).contains("PRIVATE_"));
    let after = inspect(&output, Path::new("audio.wav"), &Limits::default()).unwrap();
    assert_eq!(before.content_digest, after.content_digest);
    assert!(
        !after
            .findings
            .iter()
            .any(|finding| finding.action == Action::Remove)
    );
    assert_eq!(&original[original.len() - 8..], &output[output.len() - 8..]);
    assert!(after.limited_support);
}
#[test]
fn wav_private_chunks_are_retained_and_reported() {
    let original = wav(&[chunk(b"priv", b"PRIVATE_PAYLOAD")]);
    let output = sanitize(&original, Format::Wav, &Limits::default()).unwrap();
    assert_eq!(original, output);
    let inspected = audio::inspect(&output, Format::Wav, &Limits::default()).unwrap();
    assert!(
        inspected.findings.iter().any(
            |finding| finding.code == "wav.retained_chunk" && finding.action == Action::AskUser
        )
    );
    assert!(!format!("{:?}", inspected.findings).contains("PRIVATE_PAYLOAD"));
}

#[test]
fn typed_audio_provenance_is_protected_without_treating_private_text_as_a_signature() {
    let limits = Limits::default();
    let original = wav(&[
        chunk(b"bext", b"PRIVATE_AUTHOR"),
        chunk(b"C2PA", b"not a valid signature"),
    ]);
    let before = original.clone();
    let inspection = audio::inspect(&original, Format::Wav, &limits).unwrap();
    assert!(!inspection.rewrite_supported);
    assert!(
        inspection
            .findings
            .iter()
            .any(|finding| finding.code == "wav.provenance"
                && finding.state == fileveil_core::FindingState::Blocked)
    );
    assert!(matches!(
        audio::sanitize(&original, Format::Wav, &limits),
        Err(Error::Blocked(_))
    ));
    assert_eq!(original, before);
    let unrelated = wav(&[chunk(b"priv", b"The word C2PA in ordinary private bytes")]);
    assert!(
        audio::inspect(&unrelated, Format::Wav, &limits)
            .unwrap()
            .blockers
            .is_empty()
    );
    for id in [b"c2pa", b"C2PA"] {
        let original = flac(
            &vorbis(&["ARTIST=PRIVATE_AUTHOR"]),
            &[flac_block(
                2,
                false,
                &[id.as_slice(), b"private candidate"].concat(),
            )],
        );
        let inspection = audio::inspect(&original, Format::Flac, &limits).unwrap();
        assert!(!inspection.rewrite_supported);
        assert!(
            inspection
                .findings
                .iter()
                .any(|finding| finding.code == "flac.provenance_candidate"
                    && finding.state == fileveil_core::FindingState::Blocked)
        );
        assert!(matches!(
            audio::sanitize(&original, Format::Flac, &limits),
            Err(Error::Blocked(_))
        ));
    }
}
#[test]
fn flac_removes_human_tags_and_keeps_frames() {
    let original = flac(
        &vorbis(&["ARTIST=PRIVATE_AUTHOR", "DATE=PRIVATE_DATE"]),
        &[],
    );
    let before = inspect(&original, Path::new("audio.flac"), &Limits::default()).unwrap();
    let output = sanitize(&original, Format::Flac, &Limits::default()).unwrap();
    let after = inspect(&output, Path::new("audio.flac"), &Limits::default()).unwrap();
    assert_eq!(before.content_digest, after.content_digest);
    assert!(!String::from_utf8_lossy(&output).contains("PRIVATE_"));
    assert_eq!(&original[original.len() - 8..], &output[output.len() - 8..]);
    assert_eq!(output[4] & 0x80, 0x80);
}
#[test]
fn flac_channel_mapping_and_replaygain_are_preserved() {
    let original = flac(
        &vorbis(&[
            "ARTIST=PRIVATE_AUTHOR",
            "WAVEFORMATEXTENSIBLE_CHANNEL_MASK=0x4",
            "REPLAYGAIN_TRACK_GAIN=-3.0 dB",
        ]),
        &[],
    );
    let output = sanitize(&original, Format::Flac, &Limits::default()).unwrap();
    let text = String::from_utf8_lossy(&output);
    assert!(text.contains("WAVEFORMATEXTENSIBLE_CHANNEL_MASK=0x4"));
    assert!(text.contains("REPLAYGAIN_TRACK_GAIN=-3.0 dB"));
    assert!(!text.contains("PRIVATE_"));
    let after = audio::inspect(&output, Format::Flac, &Limits::default()).unwrap();
    assert!(
        !after
            .findings
            .iter()
            .any(|finding| finding.action == Action::Remove)
    );
    assert!(
        after
            .findings
            .iter()
            .any(|finding| finding.code == "flac.playback_fields")
    );
    assert_eq!(
        output,
        sanitize(&output, Format::Flac, &Limits::default()).unwrap()
    );
}
#[test]
fn flac_application_and_picture_metadata_remain_visible_risks() {
    let original = flac(
        &vorbis(&["ARTIST=PRIVATE_AUTHOR"]),
        &[
            flac_block(2, false, b"TESTPRIVATE_APPLICATION"),
            flac_block(6, false, b"PRIVATE_PICTURE"),
        ],
    );
    let output = sanitize(&original, Format::Flac, &Limits::default()).unwrap();
    let after = audio::inspect(&output, Format::Flac, &Limits::default()).unwrap();
    assert_eq!(
        after
            .findings
            .iter()
            .filter(|finding| finding.action == Action::AskUser)
            .count(),
        2
    );
    assert!(String::from_utf8_lossy(&output).contains("PRIVATE_APPLICATION"));
}
#[test]
fn mp3_is_metadata_audit_only() {
    let mut bytes = b"ID3\x04\0\0\0\0\0\x05abcde".to_vec();
    bytes.extend_from_slice(&[0xff, 0xfb, 0x90, 0x64, 0, 0]);
    let result = inspect(&bytes, Path::new("audio.mp3"), &Limits::default()).unwrap();
    assert_eq!(result.format, Format::Mp3);
    assert!(!result.rewrite_supported);
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.code == "mp3.id3v2")
    );
    assert!(matches!(
        sanitize(&bytes, Format::Mp3, &Limits::default()),
        Err(Error::Unsupported(_))
    ));
    assert!(!audio::mp3_signature(b"ID3 is a normal text label"));
}
#[test]
fn corrupt_audio_lengths_duplicates_and_budgets_fail_safely() {
    let original = wav(&[]);
    for end in 0..original.len() {
        assert!(audio::inspect(&original[..end], Format::Wav, &Limits::default()).is_err());
    }
    let mut bad = flac(&vorbis(&["ARTIST=A"]), &[]);
    bad[7] = 0xff;
    assert!(audio::inspect(&bad, Format::Flac, &Limits::default()).is_err());
    let duplicate = flac(&vorbis(&[]), &[flac_block(4, false, &vorbis(&[]))]);
    assert!(audio::inspect(&duplicate, Format::Flac, &Limits::default()).is_err());
    let limits = Limits {
        max_members: 1,
        ..Default::default()
    };
    assert!(audio::inspect(&original, Format::Wav, &limits).is_err());
    let limits = Limits {
        max_metadata_bytes: 2,
        ..Default::default()
    };
    assert!(audio::inspect(&flac(&vorbis(&[]), &[]), Format::Flac, &limits).is_err());
}

// FVPROV1 9746 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJkMjFjYTUxMjRmMjVhN2E0NGQ0YjI3MjZhMWI4NDVjNmIyNGFlYzMzNzQ5NzRjYjNiZjI1YmZiMjRhMWUwZmMyIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1mb3JtYXRzL3Rlc3RzL2F1ZGlvLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiOTExMDgzZDI1NzJhMjMzNzRmNTVjZTc0OWE1NmY5ZWJjOGEyYjAyYmQwMGZlOWM3Mjk1MDZkMjZkNGM2YmM2ZWZlNjVhYTg3Mzk1MjRiMmI2NDUyNWZjMTFkNThlMGZiMzQxNGI3NDU1ZWUxZDAwM2RjOGE0YjM1NjRjZWQ1MDIifV19XQ== FVPROV1-END
