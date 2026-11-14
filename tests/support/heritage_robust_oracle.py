#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Independent OpenCV implementation of the public FVHDCT1 frame protocol.

Developer-only oracle. No network or model weights. Python dependencies are
NumPy, OpenCV and Pillow. Generated fixtures stay in the requested work folder.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import zlib

import cv2
import numpy as np
from PIL import Image


MAGIC = b"FVHDCT1\n"
VERSION = bytes([1, 0, 0, 0])


def frame(work):
    header = MAGIC + hashlib.sha256(work.encode()).digest()[:16]
    return header + struct.pack(">I", zlib.crc32(header)) + VERSION


def embed(rgb, work, strength):
    """Reference encoder on the native 512-square grid using cv2 DCT/IDCT."""
    assert rgb.shape == (512, 512, 3)
    result = rgb.astype(np.float32)
    bits = np.unpackbits(np.frombuffer(frame(work), dtype=np.uint8))
    for by in range(64):
        for bx in range(64):
            tile = result[by * 8:by * 8 + 8, bx * 8:bx * 8 + 8]
            gray = tile @ np.array([0.299, 0.587, 0.114], dtype=np.float32)
            transformed = cv2.dct(gray)
            difference = transformed[3, 2] - transformed[2, 3]
            target = strength if bits[(by % 16) * 16 + bx % 16] else -strength
            change = max(0, target - difference) if target > 0 else min(0, target - difference)
            residual = np.zeros((8, 8), np.float32)
            residual[3, 2] = change / 2
            residual[2, 3] = -change / 2
            tile += cv2.idct(residual)[:, :, None]
    return np.clip(np.round(result), 0, 255).astype(np.uint8)


def recover(rgb):
    """Blind recovery using independent full cv2 transforms and hard evidence."""
    native_height, native_width = rgb.shape[:2]
    grids = [(512, 512, False)]
    if 256 <= min(native_width, native_height) and max(native_width, native_height) <= 768:
        grids.append((native_width, native_height, True))
    grids.extend((edge, edge, False) for edge in [448, 384, 320, 256])
    candidates = 0
    for width, height, search in grids:
        resized = cv2.resize(rgb, (width, height), interpolation=cv2.INTER_LINEAR)
        gray = resized.astype(np.float32) @ np.array([0.299, 0.587, 0.114], dtype=np.float32)
        for py in range(8 if search else 1):
            for px in range(8 if search else 1):
                votes = np.zeros((16, 16), np.float64)
                counts = np.zeros((16, 16), np.uint32)
                for by in range((height - py) // 8):
                    for bx in range((width - px) // 8):
                        transformed = cv2.dct(gray[py + by * 8:py + by * 8 + 8, px + bx * 8:px + bx * 8 + 8])
                        difference = transformed[3, 2] - transformed[2, 3]
                        votes[by % 16, bx % 16] += np.clip(difference, -64, 64)
                        counts[by % 16, bx % 16] += 1
                if counts.min() < 3:
                    continue
                for ty in range(16):
                    for tx in range(16):
                        candidates += 1
                        bits = np.roll(votes >= 0, (-ty, -tx), (0, 1)).reshape(-1)
                        data = np.packbits(bits).tobytes()
                        if data[:8] != MAGIC or data[-4:] != VERSION:
                            continue
                        if struct.unpack(">I", data[24:28])[0] != zlib.crc32(data[:24]):
                            continue
                        return {"status": "detected", "work_id_digest": data[8:24].hex(), "dimensions": [width, height], "pixel_phase": [px, py], "tile_phase": [tx, ty], "minimum_repetitions": int(counts.min()), "candidate_count": candidates}
    return {"status": "not_detected", "candidate_count": candidates}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rust-marked", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    rgb = np.asarray(Image.open(args.image).convert("RGB"))
    marked = embed(rgb, args.work, 32)
    python_path = args.output / "python-marked.png"
    Image.fromarray(marked).save(python_path)
    expected = hashlib.sha256(args.work.encode()).hexdigest()[:32]
    reports = {"python_marked": recover(marked)}
    if args.rust_marked:
        rust = np.asarray(Image.open(args.rust_marked).convert("RGB"))
        reports["rust_marked"] = recover(rust)
        encoded = cv2.imencode(".jpg", cv2.cvtColor(rust, cv2.COLOR_RGB2BGR), [cv2.IMWRITE_JPEG_QUALITY, 70])[1]
        jpeg = cv2.cvtColor(cv2.imdecode(encoded, cv2.IMREAD_COLOR), cv2.COLOR_BGR2RGB)
        reports["rust_jpeg70"] = recover(jpeg)
        reports["rust_crop_unaligned"] = recover(rust[49:49 + 384, 35:35 + 384])
    for name, report in reports.items():
        assert report["status"] == "detected", (name, report)
        assert report["work_id_digest"] == expected, (name, report)
    for name in ["rust-cleaned.png", "rust-cleaned-jpeg70.png", "rust-cleaned-reencoded70.png"]:
        path = args.output / name
        if path.is_file():
            cleaned = np.asarray(Image.open(path).convert("RGB"))
            reports[name] = recover(cleaned)
            assert reports[name]["status"] == "not_detected", (name, reports[name])
    receipt = {"protocol": "fileveil_heritage_dct_v1", "opencv": cv2.__version__, "numpy": np.__version__, "input_sha256": hashlib.sha256(args.image.read_bytes()).hexdigest(), "expected_digest": expected, "reports": reports}
    (args.output / "oracle.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()

# FVPROV1 5809 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI2ZmFjMWI2M2RhOTEwYTQ3MjdiNTNmN2U2OWZmM2Q1OTkzMWU4OTMzN2E4MmY3NmQ5YjQ4Yjc4YmVjNDZjMGU0IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4zIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMyIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rlc3RzL3N1cHBvcnQvaGVyaXRhZ2Vfcm9idXN0X29yYWNsZS5weSJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjI3OTM1ZWYwNTdkOWJiZjZlYmU4OGQ4ODdkMGEzM2I2OWM2MDdhMWIzY2QyOTUwMWE2NTJkY2FhY2Q2NmZjZjc3M2VjYjk5NjE2ZmYwM2RiMWY2ZWQ2OTJkMjEwYmE1ODBiYmE3MzkxOGRjNjE2ZGQzMzhjNjIzYTU3MDgzZDA3In1dfV0= FVPROV1-END
