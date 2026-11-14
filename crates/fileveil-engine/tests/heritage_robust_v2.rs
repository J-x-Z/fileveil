// SPDX-License-Identifier: MPL-2.0
use fileveil_core::Limits;
use fileveil_engine::heritage::robust_v2::{self, DEFAULT_STRENGTH};
use image::{DynamicImage, GenericImageView, imageops::FilterType};

const PHOTO: &[u8] = include_bytes!("fixtures/watermark/astronaut.png");
const KEY: [u8; 32] = [0x39; 32];
fn photo() -> DynamicImage {
    image::load_from_memory(PHOTO).unwrap().to_rgb8().into()
}
fn jpeg(image: &DynamicImage, quality: u8) -> DynamicImage {
    let mut data = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut data, quality)
        .encode_image(image)
        .unwrap();
    image::load_from_memory(&data).unwrap()
}
#[test]
fn keyed_work_and_copy_recovery_survives_quarter_turns() {
    let limits = Limits::default();
    let mut rgba = photo().to_rgba8();
    for (i, p) in rgba.pixels_mut().enumerate() {
        p[3] = (i % 256) as u8;
    }
    let original = DynamicImage::ImageRgba8(rgba);
    let (marked, report) = robust_v2::embed(
        &original,
        "v2-work",
        "edition-1",
        &KEY,
        DEFAULT_STRENGTH,
        &limits,
    )
    .unwrap();
    assert!(report.authenticated && report.frame_valid);
    assert_eq!(marked.dimensions(), original.dimensions());
    for (a, b) in original.to_rgba8().pixels().zip(marked.to_rgba8().pixels()) {
        assert_eq!(a[3], b[3]);
    }
    for attacked in [
        marked.clone(),
        marked.rotate90(),
        marked.rotate180(),
        marked.rotate270(),
    ] {
        let r = robust_v2::detect(&attacked, &KEY, &limits).unwrap();
        assert!(r.frame_valid, "{}", serde_json::to_string(&r).unwrap());
        assert_eq!(r.work_id_digest, report.work_id_digest);
        assert_eq!(r.copy_id_digest, report.copy_id_digest);
    }
}
#[test]
fn measured_compression_crop_resize_and_cleanup_matrix() {
    let limits = Limits::default();
    let (marked, report) = robust_v2::embed(
        &photo(),
        "v2-work",
        "copy-A",
        &KEY,
        DEFAULT_STRENGTH,
        &limits,
    )
    .unwrap();
    for (name, image) in [
        ("jpeg_90", jpeg(&marked, 90)),
        ("jpeg_70", jpeg(&marked, 70)),
        ("jpeg_30", jpeg(&marked, 30)),
        ("jpeg_10", jpeg(&marked, 10)),
        ("crop_unaligned", marked.crop_imm(35, 49, 384, 384)),
        (
            "resize_384",
            marked.resize_exact(384, 384, FilterType::Triangle),
        ),
    ] {
        let r = robust_v2::detect(&image, &KEY, &limits).unwrap();
        println!("{name} {}", serde_json::to_string(&r).unwrap());
        if r.frame_valid {
            assert_eq!(r.work_id_digest, report.work_id_digest);
            assert_eq!(r.copy_id_digest, report.copy_id_digest);
        }
    }
    let (clean, r) = robust_v2::clean(&marked, &KEY, &limits).unwrap();
    assert!(!r.frame_valid);
    assert_eq!(clean.dimensions(), marked.dimensions());
}
#[test]
fn wrong_keys_clean_controls_and_budget_failures_never_authenticate() {
    let limits = Limits::default();
    let original = photo();
    let (marked, _) = robust_v2::embed(
        &original,
        "v2-work",
        "copy-A",
        &KEY,
        DEFAULT_STRENGTH,
        &limits,
    )
    .unwrap();
    assert!(
        !robust_v2::detect(&marked, &[0x40; 32], &limits)
            .unwrap()
            .frame_valid
    );
    assert!(
        !robust_v2::detect(&original, &KEY, &limits)
            .unwrap()
            .frame_valid
    );
    assert!(robust_v2::clean(&marked, &[0x40; 32], &limits).is_err());
    assert!(robust_v2::embed(&original, "", "copy-A", &KEY, 24, &limits).is_err());
    assert!(robust_v2::embed(&original, "work", "", &KEY, 24, &limits).is_err());
    let mut bounded = limits;
    bounded.max_pixels = 100;
    assert!(robust_v2::detect(&original, &KEY, &bounded).is_err());
}

#[test]
#[ignore = "Uses explicitly generated independent Pillow geometric fixtures"]
fn independent_pillow_rotation_sync_and_cleaning() {
    let root = std::env::var_os("FILEVEIL_ROTATION_FIXTURES")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../work/v05-research")
        });
    let limits = Limits::default();
    let key = std::array::from_fn(|i| i as u8);
    for angle in [3, 5, 15, 27, 43] {
        let image = image::open(root.join(format!("angle-{angle}.png")))
            .unwrap()
            .to_rgb8()
            .into();
        let r = robust_v2::detect(&image, &key, &limits).unwrap();
        println!("rotation_{angle} {}", serde_json::to_string(&r).unwrap());
        assert!(r.frame_valid, "rotation {angle}");
        assert_eq!(
            r.work_id_digest,
            Some(robust_v2::work_id_digest("v2-work").unwrap())
        );
        assert!((r.deskew_degrees.unwrap() + angle as f32).abs() <= 0.3);
        if angle == 5 {
            let (cleaned, recheck) = robust_v2::clean(&image, &key, &limits).unwrap();
            assert!(!recheck.frame_valid);
            assert_eq!(cleaned.dimensions(), image.dimensions());
        }
    }
}

// FVPROV1 5086 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI5NTBjYzU2ZWE5NGNkZWEyMjM4MWUzNzU0NTE1OGUwM2JhYWM2ZjlkOGE4ZTA0OGE3MmJiZjBlYTZjMDM5ZmJjIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS40IiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuNCIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvdGVzdHMvaGVyaXRhZ2Vfcm9idXN0X3YyLnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiMjA4ZGRkNzVlOGM3NDQyOTgwZDZiY2Q0M2RmMzUxNThkMTg4Mzc4ZjY2YmNhYjg3ZjJhNmQxZDQxOWQ0YzMwMzg1NmFiYTA0MDA3YmNkNWViNWEzYWUzZDY1ZTM5Y2ZhMjk4OWI3NDkwNDUxZjNkYmIyNGQzZTZlNDBlZDQ5MGYifV19XQ== FVPROV1-END
