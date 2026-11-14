// SPDX-License-Identifier: MPL-2.0
use fileveil_core::Limits;
use fileveil_engine::heritage::robust::{DEFAULT_STRENGTH, clean, detect, embed, work_id_digest};
use fileveil_engine::watermark::DetectionStatus;
use image::{DynamicImage, GenericImageView, ImageFormat, Rgb, RgbImage, imageops::FilterType};
use std::io::Cursor;

const PHOTO: &[u8] = include_bytes!("fixtures/watermark/astronaut.png");
const WORK: &str = "FileVeil offline public work reference α-2026";

fn photo() -> DynamicImage {
    image::load_from_memory(PHOTO).unwrap().to_rgb8().into()
}

fn jpeg(image: &DynamicImage, quality: u8) -> DynamicImage {
    let mut encoded = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut encoded, quality)
        .encode_image(image)
        .unwrap();
    image::load_from_memory(&encoded).unwrap()
}

#[test]
fn natural_photo_roundtrip_recovers_only_public_work_digest_and_preserves_alpha() {
    let limits = Limits::default();
    let mut rgba = photo().to_rgba8();
    for (index, pixel) in rgba.pixels_mut().enumerate() {
        pixel[3] = (index % 256) as u8;
    }
    let original = DynamicImage::ImageRgba8(rgba);
    let (marked, evidence) = embed(&original, WORK, DEFAULT_STRENGTH, &limits).unwrap();
    assert_eq!(evidence.status, DetectionStatus::Detected);
    assert_eq!(evidence.work_id_digest, Some(work_id_digest(WORK).unwrap()));
    assert!(!evidence.authenticated);
    assert!(evidence.frame_valid);
    assert!(evidence.minimum_repetitions >= 3);
    assert!(evidence.bit_vote_agreement > 0.9);
    assert_eq!(original.dimensions(), marked.dimensions());
    for (before, after) in original.to_rgba8().pixels().zip(marked.to_rgba8().pixels()) {
        assert_eq!(before[3], after[3]);
    }
    let mut png = Cursor::new(Vec::new());
    marked.write_to(&mut png, ImageFormat::Png).unwrap();
    let decoded = image::load_from_memory(png.get_ref()).unwrap();
    assert_eq!(
        detect(&decoded, &limits).unwrap().work_id_digest,
        evidence.work_id_digest
    );
}

#[test]
fn natural_photo_survival_matrix_is_measured_for_jpeg_resize_and_crops() {
    let limits = Limits::default();
    let (marked, _) = embed(&photo(), WORK, DEFAULT_STRENGTH, &limits).unwrap();
    let expected = work_id_digest(WORK).unwrap();
    let candidates = [
        ("jpeg_90", jpeg(&marked, 90)),
        ("jpeg_70", jpeg(&marked, 70)),
        (
            "resize_768",
            marked.resize_exact(768, 768, FilterType::Triangle),
        ),
        (
            "resize_384",
            marked.resize_exact(384, 384, FilterType::Triangle),
        ),
        ("crop_384_aligned", marked.crop_imm(32, 48, 384, 384)),
        ("crop_384_unaligned", marked.crop_imm(35, 49, 384, 384)),
        (
            "crop_then_resize",
            marked
                .crop_imm(32, 48, 384, 384)
                .resize_exact(768, 768, FilterType::Triangle),
        ),
    ];
    for (name, attacked) in candidates {
        let evidence = detect(&attacked, &limits).unwrap();
        println!("{name} {}", serde_json::to_string(&evidence).unwrap());
        assert_eq!(evidence.status, DetectionStatus::Detected, "{name}");
        assert_eq!(evidence.work_id_digest.as_ref(), Some(&expected), "{name}");
        assert!(evidence.tested_grids <= 6);
        assert!(evidence.tested_phases <= 69 * 256);
    }
}

#[test]
fn destructive_attacks_report_recovery_scope_without_inventing_other_identities() {
    let limits = Limits::default();
    let (marked, _) = embed(&photo(), WORK, DEFAULT_STRENGTH, &limits).unwrap();
    let expected = work_id_digest(WORK).unwrap();
    for (name, attacked) in [
        ("jpeg_10", jpeg(&marked, 10)),
        ("rotate_90", marked.rotate90()),
        ("blur_2", marked.blur(2.0)),
        ("crop_256", marked.crop_imm(101, 71, 256, 256)),
    ] {
        let report = detect(&attacked, &limits).unwrap();
        println!("attack_{name} {}", serde_json::to_string(&report).unwrap());
        if report.status == DetectionStatus::Detected {
            assert_eq!(report.work_id_digest.as_ref(), Some(&expected), "{name}");
        } else {
            assert!(report.work_id_digest.is_none(), "{name}");
        }
        if name == "rotate_90" {
            assert_ne!(report.status, DetectionStatus::Detected);
        }
    }
}

#[test]
fn clean_photo_public_sd_marks_and_synthetic_controls_do_not_decode_work_references() {
    let limits = Limits::default();
    for bytes in [
        PHOTO,
        include_bytes!("fixtures/watermark/astronaut-sd1.png").as_slice(),
        include_bytes!("fixtures/watermark/astronaut-sdxl.png").as_slice(),
    ] {
        let image = image::load_from_memory(bytes).unwrap().to_rgb8().into();
        let report = detect(&image, &limits).unwrap();
        assert_ne!(report.status, DetectionStatus::Detected);
        assert!(report.work_id_digest.is_none());
        assert!(!report.frame_valid);
    }
    for seed in 0..4 {
        let mut state = 0x3141_5926_u32 ^ seed;
        let noise = RgbImage::from_fn(512, 512, |x, y| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            if seed == 0 {
                Rgb([((x + y) % 256) as u8; 3])
            } else {
                Rgb(state.to_le_bytes()[..3].try_into().unwrap())
            }
        });
        let report = detect(&noise.into(), &limits).unwrap();
        assert_ne!(report.status, DetectionStatus::Detected);
        assert!(report.work_id_digest.is_none());
    }
}

#[test]
fn work_references_sample_models_and_budgets_are_validated_before_processing() {
    let limits = Limits::default();
    let original = photo();
    assert!(work_id_digest("").is_err());
    assert!(work_id_digest("  \n").is_err());
    assert!(work_id_digest(&"x".repeat(4097)).is_err());
    assert!(embed(&original, WORK, 15, &limits).is_err());
    assert!(embed(&original, WORK, 65, &limits).is_err());
    assert!(
        embed(
            &original.resize_exact(511, 512, FilterType::Nearest),
            WORK,
            32,
            &limits
        )
        .is_err()
    );
    assert!(detect(&original.to_luma8().into(), &limits).is_err());
    assert!(
        detect(
            &original,
            &Limits {
                max_pixels: 100_000,
                ..limits.clone()
            }
        )
        .is_err()
    );
    assert!(
        detect(
            &original.resize_exact(255, 512, FilterType::Nearest),
            &limits
        )
        .is_err()
    );
}

#[test]
fn marked_nonsquare_large_image_recovers_on_reference_grid() {
    let limits = Limits::default();
    let large = photo().resize_exact(1024, 768, FilterType::Triangle);
    let (marked, evidence) = embed(&large, WORK, 40, &limits).unwrap();
    assert_eq!(marked.dimensions(), large.dimensions());
    assert_eq!(evidence.work_id_digest, Some(work_id_digest(WORK).unwrap()));
    assert_eq!(
        detect(&jpeg(&marked, 85), &limits).unwrap().status,
        DetectionStatus::Detected
    );
}

#[test]
fn targeted_cleaning_retests_png_jpeg_and_unaligned_crop_and_preserves_alpha() {
    let limits = Limits::default();
    let mut rgba = photo().to_rgba8();
    for (index, pixel) in rgba.pixels_mut().enumerate() {
        pixel[3] = (index % 256) as u8;
    }
    let (marked, _) = embed(&rgba.into(), WORK, DEFAULT_STRENGTH, &limits).unwrap();
    for (name, image) in [
        ("png", marked.clone()),
        ("jpeg70", jpeg(&marked.to_rgb8().into(), 70)),
        ("unaligned_crop", marked.crop_imm(35, 49, 384, 384)),
    ] {
        let (cleaned, report) = clean(&image, &limits).unwrap();
        assert_ne!(report.status, DetectionStatus::Detected, "{name}");
        assert!(report.work_id_digest.is_none());
        let before = image.to_rgba8();
        let after = cleaned.to_rgba8();
        let mut squared_error = 0_u64;
        for (original, output) in before.pixels().zip(after.pixels()) {
            assert_eq!(original[3], output[3], "{name}");
            for channel in 0..3 {
                squared_error += (original[channel] as i32 - output[channel] as i32).pow(2) as u64;
            }
        }
        let mse = squared_error as f64 / (image.width() * image.height() * 3) as f64;
        println!(
            "clean_{name} MSE={mse:.6} {}",
            serde_json::to_string(&report).unwrap()
        );
        assert!(mse < 50.0);
    }
    assert!(clean(&photo(), &limits).is_err());
}

#[test]
#[ignore = "explicit local CPU/RSS observation with fixed input"]
fn fixed_input_detection_performance_observation() {
    let input = std::env::var_os("FILEVEIL_ROBUST_BENCH_INPUT")
        .map(|path| image::open(path).unwrap())
        .unwrap_or_else(photo);
    let started = std::time::Instant::now();
    let report = detect(&input, &Limits::default()).unwrap();
    println!(
        "detection_seconds={:.6} {}",
        started.elapsed().as_secs_f64(),
        serde_json::to_string(&report).unwrap()
    );
}

#[test]
#[ignore = "requires developer-only Python OpenCV, NumPy and Pillow"]
fn independent_python_encoder_and_decoder_interoperate_with_rust() {
    let limits = Limits::default();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let evidence = root.join("work/v04-research/robust-oracle");
    std::fs::create_dir_all(&evidence).unwrap();
    let rust_marked = evidence.join("rust-marked.png");
    let (marked, _) = embed(&photo(), WORK, DEFAULT_STRENGTH, &limits).unwrap();
    marked.save(&rust_marked).unwrap();
    let (cleaned, _) = clean(&marked, &limits).unwrap();
    cleaned.save(evidence.join("rust-cleaned.png")).unwrap();
    jpeg(&cleaned, 70)
        .save(evidence.join("rust-cleaned-reencoded70.png"))
        .unwrap();
    let (cleaned_jpeg, _) = clean(&jpeg(&marked, 70), &limits).unwrap();
    cleaned_jpeg
        .save(evidence.join("rust-cleaned-jpeg70.png"))
        .unwrap();
    let status = std::process::Command::new("python3")
        .arg(root.join("tests/support/heritage_robust_oracle.py"))
        .arg("--image")
        .arg(root.join("crates/fileveil-engine/tests/fixtures/watermark/astronaut.png"))
        .arg("--work")
        .arg(WORK)
        .arg("--output")
        .arg(&evidence)
        .arg("--rust-marked")
        .arg(&rust_marked)
        .status()
        .unwrap();
    assert!(status.success());
    let python_marked = image::open(evidence.join("python-marked.png")).unwrap();
    let report = detect(&python_marked, &limits).unwrap();
    assert_eq!(report.status, DetectionStatus::Detected);
    assert_eq!(report.work_id_digest, Some(work_id_digest(WORK).unwrap()));
}

// FVPROV1 10687 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJlYmNiMDkyMGRkZTk2Yjc2YjQ3ZjVjYzNiZGRhNzM1N2JlMWY4NWFmOGZmNmIyODhjZTA2OTg1NTIxNzI2NWQ5IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvdGVzdHMvaGVyaXRhZ2Vfcm9idXN0LnJzIn0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiZjA4YmI5Y2UwNjVlZTI2NzYxNTNmZjcwOGFjZThiMjgzODNhNDliMWM5MzYyN2FkY2ZhNmE2ODI4ODE5MzViOWEyY2FjNDE5MjZiNjhmMmZkZDJjMjU2YjdhMzI4NzExZGYzMzlkZGRjMTdhNzliYzQ1N2Q0MmM1OWE0MGU0MDMifV19XQ== FVPROV1-END
