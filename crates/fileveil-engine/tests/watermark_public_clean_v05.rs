// SPDX-License-Identifier: MPL-2.0
use fileveil_core::Limits;
use fileveil_engine::watermark::{self, DetectionStatus};
use image::{DynamicImage, RgbaImage};

#[test]
fn recognized_sd_payloads_are_targeted_rechecked_and_quality_measured() {
    for (name, bytes, method) in [
        (
            "sd1",
            include_bytes!("fixtures/watermark/astronaut-sd1.png").as_slice(),
            "stable_diffusion_dwt_dct_v1",
        ),
        (
            "sdxl",
            include_bytes!("fixtures/watermark/astronaut-sdxl.png").as_slice(),
            "stable_diffusion_xl_dwt_dct",
        ),
        (
            "sd1-jpeg",
            include_bytes!("fixtures/watermark/astronaut-sd1-444.jpg").as_slice(),
            "stable_diffusion_dwt_dct_v1",
        ),
        (
            "sdxl-jpeg",
            include_bytes!("fixtures/watermark/astronaut-sdxl-444.jpg").as_slice(),
            "stable_diffusion_xl_dwt_dct",
        ),
    ] {
        let image = image::load_from_memory(bytes).unwrap();
        let original = image.as_bytes().to_vec();
        let (output, report) = watermark::clean_known_public(&image, &Limits::default()).unwrap();
        assert!(
            report
                .processed_methods
                .iter()
                .any(|processed| processed == method)
        );
        assert!(
            report
                .after
                .iter()
                .all(|report| report.status != DetectionStatus::Detected)
        );
        assert_eq!(
            report
                .after
                .iter()
                .find(|report| report.method_id == method)
                .unwrap()
                .status,
            DetectionStatus::NotDetected
        );
        assert_eq!(image.as_bytes(), original);
        let before = image.to_rgb8();
        let after = output.to_rgb8();
        let mse = before
            .as_raw()
            .iter()
            .zip(after.as_raw())
            .map(|(a, b)| (f64::from(*a) - f64::from(*b)).powi(2))
            .sum::<f64>()
            / before.as_raw().len() as f64;
        let psnr = 10.0 * (255.0f64.powi(2) / mse).log10();
        assert!(psnr > 30.0, "{name} PSNR {psnr}");
        eprintln!(
            "{name} targeted public quantization PSNR {psnr:.4} dB, MSE {mse:.4}; recheck {:?}",
            report.after
        );
        if let Some(directory) = std::env::var_os("FILEVEIL_PUBLIC_CLEAN_EVIDENCE") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            output.save(directory.join(format!("{name}.png"))).unwrap();
        }
    }
}

#[test]
fn clean_controls_are_exactly_unchanged_and_rgba_alpha_is_preserved() {
    let clean =
        image::load_from_memory(include_bytes!("fixtures/watermark/astronaut.png")).unwrap();
    let (output, report) = watermark::clean_known_public(&clean, &Limits::default()).unwrap();
    assert_eq!(output.as_bytes(), clean.as_bytes());
    assert!(report.processed_methods.is_empty());
    let other =
        image::load_from_memory(include_bytes!("fixtures/watermark/astronaut-other.png")).unwrap();
    let (output, report) = watermark::clean_known_public(&other, &Limits::default()).unwrap();
    assert_eq!(output.as_bytes(), other.as_bytes());
    assert!(report.processed_methods.is_empty());
    let marked = image::load_from_memory(include_bytes!("fixtures/watermark/astronaut-sdxl.png"))
        .unwrap()
        .to_rgb8();
    let rgba = RgbaImage::from_fn(marked.width(), marked.height(), |x, y| {
        let pixel = marked.get_pixel(x, y);
        image::Rgba([pixel[0], pixel[1], pixel[2], ((x + y) % 256) as u8])
    });
    let (output, report) =
        watermark::clean_known_public(&DynamicImage::ImageRgba8(rgba.clone()), &Limits::default())
            .unwrap();
    assert_eq!(report.processed_methods, ["stable_diffusion_xl_dwt_dct"]);
    assert!(
        rgba.pixels()
            .zip(output.to_rgba8().pixels())
            .all(|(a, b)| a[3] == b[3])
    );
    let limits = Limits {
        max_pixels: 16,
        ..Default::default()
    };
    assert!(watermark::clean_known_public(&clean, &limits).is_err());
}

#[test]
fn synthetic_packet_removal_only_touches_its_declared_rgb_lsb_extent() {
    let payload = b"public test packet";
    let mut packet = watermark::SYNTHETIC_MAGIC.to_vec();
    packet.push(watermark::SYNTHETIC_VERSION);
    packet.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    let hash = fileveil_core::digest(payload);
    for pair in hash.as_bytes().as_chunks::<2>().0 {
        packet.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
    }
    packet.extend_from_slice(payload);
    let mut image = image::RgbImage::from_pixel(32, 32, image::Rgb([101, 103, 105]));
    for (index, bit) in packet
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |shift| (byte >> shift) & 1))
        .enumerate()
    {
        image.as_mut()[index] = (image.as_raw()[index] & !1) | bit;
    }
    let original = image.clone();
    let (output, report) =
        watermark::clean_known_public(&image.into(), &Limits::default()).unwrap();
    assert_eq!(report.processed_methods, ["synthetic_lsb_v1"]);
    assert_eq!(report.after[0].status, DetectionStatus::NotDetected);
    assert_eq!(
        &output.as_bytes()[packet.len() * 8..],
        &original.as_raw()[packet.len() * 8..]
    );
    assert!(
        original
            .as_raw()
            .iter()
            .zip(output.as_bytes())
            .all(|(a, b)| a.abs_diff(*b) <= 1)
    );
}
