# SPDX-License-Identifier: MPL-2.0
"""Regenerate photo fixtures using the independent upstream implementation.

Developer-only dependencies: numpy, opencv-python and PyWavelets. Exact runtime
versions are recorded in the evidence. Cargo tests use checked-in fixtures offline.
Invoke with --oracle-dir work/watermark-oracle. --processed-dir optionally
checks FileVeil's processed sd1.png/sdxl.png through the upstream decoder.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

import cv2
import numpy as np
import pywt

ROOT = Path(__file__).resolve().parents[4]
FIXTURES = ROOT / "crates/fileveil-engine/tests/fixtures/watermark"
COMMIT = "68d0376d94a4701ed240af0841ec12e00676e325"
SOURCE_HASH = "b7f024cd525b793116f6b7ae461ddcb12be0c6004e2ada8a32c7f8fdae398cc3"
PHOTO_HASH = "88431cd9653ccd539741b555fb0a46b61558b301d4110412b5bc28b5e3ea6cb5"
PAYLOADS = {
    "sd1": b"StableDiffusionV1",
    "sdxl": bytes.fromhex("b3ec907bb19e"),
    "other": b"OtherWatermarkV1",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle-dir", type=Path, required=True)
    parser.add_argument("--processed-dir", type=Path)
    args = parser.parse_args()
    args.oracle_dir.mkdir(parents=True, exist_ok=True)
    source = args.oracle_dir / "maxDct.py"
    if not source.exists():
        subprocess.run([
            "curl", "--fail", "--silent", "--show-error", "--location",
            f"https://raw.githubusercontent.com/ShieldMnt/invisible-watermark/{COMMIT}/imwatermark/maxDct.py",
            "--output", str(source),
        ], check=True)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == SOURCE_HASH
    photo = FIXTURES / "astronaut.png"
    assert hashlib.sha256(photo.read_bytes()).hexdigest() == PHOTO_HASH
    module_spec = importlib.util.spec_from_file_location("upstream_max_dct", source)
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    image = cv2.imread(str(photo))
    results = []
    for name, payload in PAYLOADS.items():
        bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
        codec = module.EmbedMaxDct(watermarks=bits, wmLen=len(bits))
        encoded = codec.encode(image)
        path = FIXTURES / f"astronaut-{name}.png"
        assert cv2.imwrite(str(path), encoded)
        results.append({
            "file": path.name,
            "bits": len(bits),
            "matched_bits_upstream": int(np.count_nonzero(codec.decode(cv2.imread(str(path))) == bits)),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        })
        if name == "other":
            continue
        jpeg = FIXTURES / f"astronaut-{name}.jpg"
        assert cv2.imwrite(str(jpeg), encoded, [cv2.IMWRITE_JPEG_QUALITY, 95])
        results.append({
            "file": jpeg.name,
            "bits": len(bits),
            "matched_bits_upstream": int(np.count_nonzero(codec.decode(cv2.imread(str(jpeg))) == bits)),
            "sha256": hashlib.sha256(jpeg.read_bytes()).hexdigest(),
            "role": "ordinary_lossy_reencoding_control",
        })
        jpeg444 = FIXTURES / f"astronaut-{name}-444.jpg"
        assert cv2.imwrite(str(jpeg444), encoded, [
            cv2.IMWRITE_JPEG_QUALITY, 95,
            cv2.IMWRITE_JPEG_SAMPLING_FACTOR, cv2.IMWRITE_JPEG_SAMPLING_FACTOR_444,
        ])
        results.append({
            "file": jpeg444.name,
            "bits": len(bits),
            "matched_bits_upstream": int(np.count_nonzero(codec.decode(cv2.imread(str(jpeg444))) == bits)),
            "sha256": hashlib.sha256(jpeg444.read_bytes()).hexdigest(),
            "role": "positive_jpeg_444_quality_95",
        })
    clean = {}
    processed = {}
    for name in ["sd1", "sdxl"]:
        bits = np.unpackbits(np.frombuffer(PAYLOADS[name], dtype=np.uint8))
        codec = module.EmbedMaxDct(wmLen=len(bits))
        clean[name] = int(np.count_nonzero(codec.decode(image) == bits))
        if args.processed_dir:
            for variant in [name, f"{name}-jpeg"]:
                path = args.processed_dir / f"{variant}.png"
                if variant.endswith("-jpeg") and not path.exists():
                    continue
                output = cv2.imread(str(path))
                assert output is not None, f"Missing processed output {path}"
                processed[variant] = {
                    "matched_bits_upstream": int(np.count_nonzero(codec.decode(output) == bits)),
                    "bits": len(bits),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
    evidence = {
        "upstream_commit": COMMIT, "upstream_source_sha256": SOURCE_HASH,
        "numpy": np.__version__, "opencv": cv2.__version__, "pywavelets": pywt.__version__,
        "clean_photo_matches": clean, "results": results,
    }
    if processed:
        evidence["fileveil_signal_recipe_upstream_retest"] = processed
    (FIXTURES / "upstream-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()

# FVPROV1 5159 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJjOTI4NDFlODQ1M2NjODdiMTM1ZDQ0MDBmMjM1NTAwZjFiZjRhODJjMWZkNzg3ZDRhYmViZGFkZDg3OGY5NTU0IiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2NyYXRlcy9maWxldmVpbC1lbmdpbmUvdGVzdHMvc3VwcG9ydC9nZW5lcmF0ZV93YXRlcm1hcmtfZml4dHVyZXMucHkifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI2YThjMjFjMmY2ZTdiNzNkZmRjMGJiYjFiNDFlMzRlN2YwMTZhMGU2ZWEyM2NiN2QwZjM2NGJiZDc1MGE0ZjBkZTI5Y2RkYzY5ZWIyNDY2NzRiNDhkMTQzZDc4Nzc3OWYxZTJmMjNiYjhkMGYzN2ViODA2MmU4ZDhmYzM4ZWQwYyJ9XX1d FVPROV1-END
