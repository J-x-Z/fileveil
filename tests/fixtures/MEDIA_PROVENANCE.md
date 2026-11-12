# Synthetic native media fixtures

`heic_exif_gps.heic` and `avif_exif_gps.avif` were encoded from the existing synthetic `jpeg_exif_gps_author.jpg` fixture with macOS ImageIO through `sips`. They contain fictitious EXIF/GPS and XMP fields. Each file was independently decoded to PNG with ImageIO.

`mp4_container_times.mp4` and `mov_model_metadata.mov` were generated with AVFoundation from two 64 × 64 constant-color H.264 frames. The model field is the fictitious text `FileVeil Synthetic Device`. Both containers were independently decoded into BGRA pixel buffers with AVAssetReader.

`mp4_av_source.mp4` combines the same synthetic video with a 220 Hz artificial tone, exported to H.264/AAC by `crates/fileveil-engine/tests/support/generate_av_fixture.swift`. It contains fictional QuickTime device metadata.

The original four files total under 6 KiB. The BMFF integration test reads these codec-produced files through the normal format entry point. The engine tests exercise Scan → Sanitize → Verify. The opt-in macOS interoperability test independently compares decoded RGBA pixels, audio PCM, video frames, track transforms and sample timing with ImageIO and AVAssetReader. Runtime verification compares retained encoded content and structure without invoking those platform decoders.
