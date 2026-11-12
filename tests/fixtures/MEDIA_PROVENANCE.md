# Synthetic native media fixtures

`heic_exif_gps.heic` and `avif_exif_gps.avif` were encoded from the existing synthetic `jpeg_exif_gps_author.jpg` fixture with macOS ImageIO through `sips`. They contain fictitious EXIF/GPS and XMP fields. Each file was independently decoded to PNG with ImageIO.

`mp4_container_times.mp4` and `mov_model_metadata.mov` were generated with AVFoundation from two 64 × 64 constant-color H.264 frames. The model field is the fictitious text `FileVeil Synthetic Device`. Both containers were independently decoded into BGRA pixel buffers with AVAssetReader.

These four files total under 6 KiB. The BMFF integration test reads these codec-produced files through the normal format entry point. HEIF, AVIF, MP4 and MOV rewriting remains unsupported.
