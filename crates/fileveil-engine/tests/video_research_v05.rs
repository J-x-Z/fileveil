// SPDX-License-Identifier: MPL-2.0
use fileveil_core::Limits;
use fileveil_engine::heritage::{
    self, HeritageAction, HeritageRequest, robust_v2, signing::SigningKey,
};
use std::{path::Path, process::Command};

#[test]
#[ignore = "Requires an explicitly configured local FFmpeg with H.264 encoding"]
fn selected_video_frames_recover_keyed_marks_without_changing_original() {
    let program = std::env::var_os("FILEVEIL_FFMPEG").expect("Set FILEVEIL_FFMPEG explicitly");
    let directory = tempfile::tempdir().unwrap();
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/watermark/astronaut.png");
    let image = image::open(source).unwrap();
    let key = SigningKey::generate().unwrap();
    let key_path = directory.path().join("owner.key");
    key.save_new(&key_path).unwrap();
    let watermark_key = key.derive_watermark_key();
    let (marked, _) = robust_v2::embed(
        &image,
        "video-work",
        "video-copy",
        &watermark_key,
        20,
        &Limits::default(),
    )
    .unwrap();
    let frame = directory.path().join("frame.png");
    marked.save(&frame).unwrap();
    let video = directory.path().join("marked.mp4");
    let result = Command::new(program)
        .args(["-nostdin", "-v", "error", "-loop", "1", "-i"])
        .arg(&frame)
        .args([
            "-t", "2.2", "-c:v", "libx264", "-threads", "1", "-pix_fmt", "yuv420p", "-crf", "18",
        ])
        .arg(&video)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let original = std::fs::read(&video).unwrap();
    let report = heritage::run(
        &video,
        None,
        &HeritageRequest {
            action: HeritageAction::Lab,
            watermark_key: Some(key_path),
            ..Default::default()
        },
        &Limits::default(),
    )
    .unwrap();
    let lab = &report.advanced.unwrap()["heritage"]["lab"];
    assert_eq!(lab["pixel_protocol"], "selected_video_frames");
    let frames = lab["frames"].as_array().unwrap();
    assert_eq!(frames.len(), 3);
    for frame in frames {
        assert_eq!(
            frame["watermarks"]["primary"]["frame_valid"], true,
            "{frame}"
        );
        assert_eq!(
            frame["watermarks"]["primary"]["copy_id_digest"],
            robust_v2::copy_id_digest("video-copy").unwrap()
        );
    }
    assert_eq!(lab["video_cleaning"], "not_assessed");
    assert_eq!(std::fs::read(video).unwrap(), original);
}

// FVPROV1 2564 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIzZGYzODc1MzNiNTFjMWYxYWNjNDNlOTVkZDUwMzZkYTMzY2I5OTllMTc4N2IyYzhlZWMwNGNhMTBiODExMGI0IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS40IiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuNCIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvdGVzdHMvdmlkZW9fcmVzZWFyY2hfdjA1LnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiMTAwNzg5MGYxNzkwMGZhNzQxOTU0NjczYjY2ZGI4ZGNjMzU1MjFiM2I2NDBmMjA4ZmQwODBmM2M4OWFiODE4NjBmNWYzYjEyNzdhNmM4YWVkMjRmYTY4NDY5NTc1OWMxM2Q0MTRkOWMxMGRlN2VjYjQxOWQzOWMyMTQ4NTZjMDIifV19XQ== FVPROV1-END
