// SPDX-License-Identifier: MPL-2.0
use fileveil_core::{Format, Limits, Outcome, digest};
use fileveil_engine::{sanitize, scan, verify};
use std::fs;
#[cfg(target_os = "macos")]
use std::{io::Write, path::Path, process::Command};
fn chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut bytes = kind.to_vec();
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    if payload.len() % 2 == 1 {
        bytes.push(0);
    }
    bytes
}
fn waveform() -> Vec<u8> {
    let mut bytes = b"RIFF\0\0\0\0WAVE".to_vec();
    let mut fmt = 1u16.to_le_bytes().to_vec();
    fmt.extend_from_slice(&1u16.to_le_bytes());
    fmt.extend_from_slice(&8000u32.to_le_bytes());
    fmt.extend_from_slice(&16000u32.to_le_bytes());
    fmt.extend_from_slice(&2u16.to_le_bytes());
    fmt.extend_from_slice(&16u16.to_le_bytes());
    bytes.extend(chunk(b"fmt ", &fmt));
    let mut info = b"INFO".to_vec();
    info.extend(chunk(b"IART", b"PRIVATE_AUTHOR\0"));
    bytes.extend(chunk(b"LIST", &info));
    let samples: Vec<u8> = (0..9216)
        .flat_map(|index| (((index % 20) - 10) as i16 * 1000).to_le_bytes())
        .collect();
    bytes.extend(chunk(b"data", &samples));
    let size = (bytes.len() - 8) as u32;
    bytes[4..8].copy_from_slice(&size.to_le_bytes());
    bytes
}
#[test]
fn wav_normal_entry_points_preserve_source_and_validate_new_copy() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("original.wav");
    let output = directory.path().join("clean.wav");
    let original = waveform();
    fs::write(&input, &original).unwrap();
    let before = scan(&input, &Limits::default()).unwrap();
    assert_eq!(before.input_format, Format::Wav.mime());
    let report = sanitize(&input, Some(&output), &Limits::default()).unwrap();
    assert_eq!(report.result, Outcome::PartiallyVerified);
    assert_eq!(report.integrity.original_unchanged, Some(true));
    assert_eq!(digest(&fs::read(&input).unwrap()), digest(&original));
    assert!(!String::from_utf8_lossy(&fs::read(&output).unwrap()).contains("PRIVATE_AUTHOR"));
    verify(&input, &output, &Limits::default()).unwrap();
    assert!(sanitize(&input, Some(&output), &Limits::default()).is_err());
}

#[cfg(target_os = "macos")]
fn tag_flac(original: &[u8]) -> Vec<u8> {
    let mut offset = 4;
    let mut blocks = Vec::new();
    loop {
        let header = &original[offset..offset + 4];
        let kind = header[0] & 127;
        let size = u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize;
        let end = offset + 4 + size;
        if kind != 4 {
            blocks.push((kind, original[offset + 4..end].to_vec()));
        }
        offset = end;
        if header[0] & 128 != 0 {
            break;
        }
    }
    let vendor = b"PRIVATE_NATIVE_ENCODER";
    let field = b"ARTIST=PRIVATE_NATIVE_AUTHOR";
    let mut comment = (vendor.len() as u32).to_le_bytes().to_vec();
    comment.extend_from_slice(vendor);
    comment.extend_from_slice(&1u32.to_le_bytes());
    comment.extend_from_slice(&(field.len() as u32).to_le_bytes());
    comment.extend_from_slice(field);
    blocks.push((4, comment));
    let count = blocks.len();
    let mut output = b"fLaC".to_vec();
    for (index, (kind, bytes)) in blocks.into_iter().enumerate() {
        output.push(kind | if index + 1 == count { 128 } else { 0 });
        output.extend_from_slice(&(bytes.len() as u32).to_be_bytes()[1..]);
        output.extend_from_slice(&bytes);
    }
    output.extend_from_slice(&original[offset..]);
    output
}
#[cfg(target_os = "macos")]
fn convert(input: &Path, output: &Path, format: &str, data: &str) {
    let result = Command::new("/usr/bin/afconvert")
        .args(["-f", format, "-d", data])
        .arg(input)
        .arg(output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "Native CoreAudio conversion failed"
    );
}
#[cfg(target_os = "macos")]
#[test]
#[ignore = "uses native CoreAudio afconvert and Python wave for independent decoding"]
fn coreaudio_independently_decodes_wav_and_flac_before_and_after_cleaning() {
    let directory = tempfile::tempdir().unwrap();
    let wav = directory.path().join("source.wav");
    let native_flac = directory.path().join("native.flac");
    fs::write(&wav, waveform()).unwrap();
    convert(&wav, &native_flac, "flac", "flac");
    let tagged_flac = directory.path().join("tagged.flac");
    fs::write(&tagged_flac, tag_flac(&fs::read(&native_flac).unwrap())).unwrap();
    for (index, input) in [wav, tagged_flac].iter().enumerate() {
        let original_hash = digest(&fs::read(input).unwrap());
        let output = directory.path().join(format!(
            "clean-{index}.{}",
            if index == 0 { "wav" } else { "flac" }
        ));
        let report = sanitize(input, Some(&output), &Limits::default()).unwrap();
        assert_eq!(report.integrity.content_equal, Some(true));
        assert_eq!(report.result, Outcome::PartiallyVerified);
        assert_eq!(digest(&fs::read(input).unwrap()), original_hash);
        let decoded_before = directory.path().join(format!("before-{index}.wav"));
        let decoded_after = directory.path().join(format!("after-{index}.wav"));
        convert(input, &decoded_before, "WAVE", "LEI16");
        convert(&output, &decoded_after, "WAVE", "LEI16");
        let script = "import sys,wave\na=wave.open(sys.argv[1],'rb'); b=wave.open(sys.argv[2],'rb')\nassert a.getparams()[:4]==b.getparams()[:4]\nassert a.readframes(a.getnframes())==b.readframes(b.getnframes())\nprint(a.getnframes())\n";
        let result = Command::new("python3")
            .args(["-I", "-c", script])
            .arg(decoded_before)
            .arg(decoded_after)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "Independent wave decoder rejected or changed PCM samples"
        );
        assert_eq!(result.stdout, b"9216\n");
    }
    std::io::stdout()
        .write_all(b"CoreAudio FLAC/WAV decode and Python PCM equality passed\n")
        .unwrap();
}

#[test]
fn remote_wav_provenance_prevents_metadata_rewriting_without_fetching_content() {
    use fileveil_core::{Error, SanitizeOptions};
    use fileveil_engine::{advanced, provenance};
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("remote.wav");
    let output = directory.path().join("clean.wav");
    let xmp=br#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description rdf:about="" xmlns:dcterms="http://purl.org/dc/terms/" dcterms:provenance="https://example.invalid/PRIVATE_SOURCE.c2pa"/></rdf:RDF></x:xmpmeta>"#;
    let mut source = waveform();
    let mut broadcast = vec![0; 602];
    let author = b"PRIVATE_BROADCAST_AUTHOR";
    broadcast[..author.len()].copy_from_slice(author);
    source.extend(chunk(b"bext", &broadcast));
    source.extend(chunk(b"XMP ", xmp));
    let size = (source.len() - 8) as u32;
    source[4..8].copy_from_slice(&size.to_le_bytes());
    fs::write(&input, &source).unwrap();
    let evidence = provenance::inspect(&source, Format::Wav, &Limits::default())
        .unwrap()
        .unwrap();
    assert_eq!(
        evidence.presence,
        provenance::ManifestPresence::RemoteReference
    );
    assert!(evidence.offline);
    let report = scan(&input, &Limits::default()).unwrap();
    assert_eq!(report.result, Outcome::Blocked);
    assert_eq!(
        report.provenance.as_ref().unwrap()["presence"],
        "remote_reference"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "wav.provenance")
    );
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("PRIVATE_SOURCE")
    );
    assert!(matches!(
        sanitize(&input, Some(&output), &Limits::default()),
        Err(Error::Blocked(_))
    ));
    assert!(!output.exists());
    assert!(matches!(
        advanced::sanitize_with_options(
            &input,
            Some(&output),
            &Limits::default(),
            &SanitizeOptions::default()
        ),
        Err(Error::Blocked(_))
    ));
    assert!(!output.exists());
    assert_eq!(fs::read(&input).unwrap(), source);
}

// FVPROV1 8351 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJkM2IyOGI1M2ZkNWJhYzBkYmY0N2Y3OWY3ZjZlNDA4ZjlkNTgxMTdkMmRmN2M3NWRjZjU2MWVjNmYyNjVkNjUyIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvdGVzdHMvYXVkaW8ucnMifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI2OTQ2ZGYzZGU3YWRlY2U1NjY3MGQzZWFkZDhiNjhlMjhiYzRmNmZhMDkzMmI4ZjZjMmM1OGEwYmZjMjQ4ZTAxMTZmODgzMzQzNDUwNGEzZDg3NDkxYTUwNTBjZTA3YjQ1ZWFhMjQ0MTNmMmQ5YzZmMDA1MGIyMDg0MGVlNjcwYSJ9XX1d FVPROV1-END
