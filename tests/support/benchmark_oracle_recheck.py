#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Independently decode and recheck a small, pinned real-image benchmark subset."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import time

import cv2
import numpy as np
from PIL import Image, ImageOps

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest", type=Path, default=ROOT / "work/v05-benchmark/manifest.json"
    )
    parser.add_argument(
        "--executable",
        type=Path,
        default=ROOT / "work/v05-benchmark/bin/benchmark-engine-frozen",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "work/v05-benchmark/independent-recheck.json",
    )
    parser.add_argument("--samples-per-stratum", type=int, default=2)
    args = parser.parse_args()
    benchmark = module("benchmark", ROOT / "tools/benchmark-watermarks.py")
    v1 = module("v1_oracle", ROOT / "tests/support/heritage_robust_oracle.py")
    v2 = module("v2_oracle", ROOT / "tests/support/watermark_v2_oracle.py")
    cv2.setNumThreads(1)
    bch = v2.BCH()
    manifest = json.loads(args.manifest.read_text())
    selected = []
    groups = sorted({item["stratum"] for item in manifest["images"]})
    for group in groups:
        selected.extend(
            [item for item in manifest["images"] if item["stratum"] == group][
                : args.samples_per_stratum
            ]
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    receipt = {
        "schema": "fileveil.watermark.independent_recheck.v1",
        "scope": "Real source files center-cropped to a 512-square interoperability subset. OpenCV full DCT, independent CRC or complete BCH t<=3 syndrome table and standard HMAC. V2 searches native dimensions, quarter turns and pixel/tile phases. FFT deskew and resized-grid searches are outside this oracle's scope.",
        "manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
        "runner_sha256": hashlib.sha256(args.executable.read_bytes()).hexdigest(),
        "oracle_source_sha256": {
            name: hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
            for name, path in {
                "v1": "tests/support/heritage_robust_oracle.py",
                "v2": "tests/support/watermark_v2_oracle.py",
            }.items()
        },
        "opencv": cv2.__version__,
        "samples_per_stratum": args.samples_per_stratum,
        "cases": [],
    }
    runner = benchmark.Runner(args.executable)
    started = time.time()
    try:
        with tempfile.TemporaryDirectory(
            prefix=".oracle-recheck-", dir=args.output.parent
        ) as folder:
            folder = Path(folder)
            for item in selected:
                source_bytes = (args.manifest.parent / item["path"]).read_bytes()
                if hashlib.sha256(source_bytes).hexdigest() != item["sha256"]:
                    raise ValueError("Pinned source SHA mismatch")
                original = ImageOps.fit(
                    Image.open(io.BytesIO(source_bytes)).convert("RGB"),
                    (512, 512),
                    Image.Resampling.LANCZOS,
                )
                source = folder / "source.png"
                original.save(source)
                work = f"FileVeil-public-benchmark-work-{item['page_id']}"
                copy = f"edition-{item['page_id']}"
                for protocol, strength in (("v1", 32), ("v2", 12)):
                    marked_path = folder / "marked.png"
                    clean_path = folder / "clean.png"
                    marked_path.unlink(missing_ok=True)
                    clean_path.unlink(missing_ok=True)
                    embedded = runner.call(
                        "embed", source, protocol, work, copy, strength, marked_path
                    )
                    if not embedded.get("ok"):
                        raise RuntimeError(embedded)
                    marked = Image.open(marked_path).convert("RGB")
                    compressed = io.BytesIO()
                    marked.save(compressed, "JPEG", quality=70)
                    jpeg = Image.open(io.BytesIO(compressed.getvalue())).convert("RGB")
                    cleaned = runner.call(
                        "clean", marked_path, protocol, work, copy, strength, clean_path
                    )
                    if not cleaned.get("ok"):
                        raise RuntimeError(cleaned)
                    clean = Image.open(clean_path).convert("RGB")

                    def decode(image):
                        if protocol == "v1":
                            return v1.recover(np.asarray(image))
                        return v2.detect(image, bch=bch)

                    reports = {
                        "marked": decode(marked),
                        "jpeg70": decode(jpeg),
                        "cleaned": decode(clean),
                    }
                    expected_work = hashlib.sha256(work.encode()).hexdigest()[
                        : 32 if protocol == "v1" else 24
                    ]
                    expected_copy = hashlib.sha256(copy.encode()).hexdigest()[:16]
                    for report in reports.values():
                        report["expected_payload_matches"] = (
                            report.get("status") == "detected"
                            and report.get("work_id_digest") == expected_work
                            and (
                                protocol == "v1"
                                or report.get("copy_id_digest") == expected_copy
                            )
                        )
                    receipt["cases"].append(
                        {
                            "source_id": item["page_id"],
                            "stratum": item["stratum"],
                            "source_sha256": item["sha256"],
                            "protocol": protocol,
                            "strength": strength,
                            "marked_sha256": hashlib.sha256(
                                marked_path.read_bytes()
                            ).hexdigest(),
                            "cleaned_sha256": hashlib.sha256(
                                clean_path.read_bytes()
                            ).hexdigest(),
                            "reports": reports,
                            "clean_quality": benchmark.metrics(original, clean),
                        }
                    )
                    args.output.write_text(json.dumps(receipt, indent=2) + "\n")
                    print(
                        json.dumps(
                            {
                                "source": item["page_id"],
                                "protocol": protocol,
                                "reports": reports,
                                "elapsed_seconds": round(time.time() - started, 1),
                            }
                        ),
                        flush=True,
                    )
    finally:
        runner.close()
    receipt["elapsed_wall_seconds"] = time.time() - started
    args.output.write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()

# FVPROV1 7594 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIxYzc4NmY4MjUwY2IxMTg2YWE1OTUxOTQ2ZmE4ODEyYjk5ZWQ1ZmFkMzBjNGY3OWU5ZTg2NmIwNTU4NDU1MDliIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4yIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMiIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rlc3RzL3N1cHBvcnQvYmVuY2htYXJrX29yYWNsZV9yZWNoZWNrLnB5In0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiOWRjMmQ0ZGU3NGZkNGEwYjc4OWNmNmI2YzZmM2JmOWFiMjI2ZGFhNzQ5YTA4M2QwYmMyZGJmNTU4OGUxZWEwNTE3MzNhNGViNTk0ZjA0MGUwMGRmYzlmZTAyNjg3MTZiM2JkOTkwYzUzMDM1ZjYxZmJkMDE5ZGYwYjFhZDI2MGQifV19XQ== FVPROV1-END
