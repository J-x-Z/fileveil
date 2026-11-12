#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Replay a pinned public-image corpus through real Rust watermark algorithms.

Images are processed one at a time. Attack intermediates live in a TemporaryDirectory.
JSONL records are resumable and retain source/binary/algorithm hashes and metric scope.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
from pathlib import Path
import platform
import struct
import subprocess
import tempfile
import time
import zlib

import cv2
import numpy as np
from PIL import Image, ImageEnhance, ImageFilter, features

cv2.setNumThreads(1)

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_KEY = bytes(range(32)).hex()
WRONG_KEY = bytes(reversed(range(32))).hex()
QUICK = [
    "original",
    "jpeg_10",
    "jpeg_30",
    "jpeg_70",
    "jpeg_95",
    "scale_75",
    "crop_offset_75",
    "crop_center_50",
    "rotate_90",
    "rotate_5",
    "blur_1",
    "noise_6",
    "color_contrast",
    "combo",
    "metadata_strip",
]
FULL = (
    ["original", "png"]
    + [f"jpeg_{quality}" for quality in [10, 20, 30, 40, 50, 60, 70, 80, 90, 95]]
    + [
        "webp_30",
        "webp_70",
        "webp_lossless",
        "avif_35",
        "avif_70",
        "scale_50",
        "scale_75",
        "scale_150",
        "crop_center_75",
        "crop_offset_75",
        "crop_center_50",
        "rotate_90",
        "rotate_180",
        "rotate_270",
        "rotate_5",
        "rotate_15",
        "screen_resample",
        "blur_0.5",
        "blur_1",
        "blur_2",
        "noise_3",
        "noise_6",
        "color_brightness",
        "color_contrast",
        "color_saturation",
        "multi_edit",
        "combo",
        "metadata_strip",
    ]
)


class Runner:
    def __init__(self, executable):
        self.executable = executable
        self.process = subprocess.Popen(
            [str(executable)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def call(
        self,
        action,
        source,
        protocol,
        work,
        copy,
        strength=32,
        output=None,
        wrong_key=False,
    ):
        request = dict(
            action=action, input=str(source), work_id=work, strength=strength
        )
        if protocol != "v1":
            request.update(
                protocol=protocol,
                copy_id=copy,
                key_hex=WRONG_KEY if wrong_key else PUBLIC_KEY,
            )
        if output is not None:
            request["output"] = str(output)
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError(f"Benchmark runner exited with {self.process.poll()}")
        return json.loads(line)

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=20)


def metrics(reference, output):
    a, b = (
        np.asarray(reference.convert("RGB"), dtype=np.float32),
        np.asarray(output.convert("RGB"), dtype=np.float32),
    )
    if a.shape != b.shape:
        return {
            "mse": None,
            "psnr_db": None,
            "ssim": None,
            "quality_scope": "geometry_not_aligned",
        }
    mse = float(np.mean((a - b) ** 2))
    psnr = None if mse == 0 else 10 * math.log10(255**2 / mse)
    mu_a = cv2.GaussianBlur(a, (11, 11), 1.5)
    mu_b = cv2.GaussianBlur(b, (11, 11), 1.5)
    sigma_a = cv2.GaussianBlur(a * a, (11, 11), 1.5) - mu_a * mu_a
    sigma_b = cv2.GaussianBlur(b * b, (11, 11), 1.5) - mu_b * mu_b
    covariance = cv2.GaussianBlur(a * b, (11, 11), 1.5) - mu_a * mu_b
    numerator = (2 * mu_a * mu_b + 6.5025) * (2 * covariance + 58.5225)
    denominator = (mu_a * mu_a + mu_b * mu_b + 6.5025) * (sigma_a + sigma_b + 58.5225)
    ssim = float(np.mean((numerator / denominator)[5:-5, 5:-5]))
    return {
        "mse": mse,
        "psnr_db": psnr,
        "psnr_infinite": mse == 0,
        "ssim": ssim,
        "quality_scope": "RGB8_Wang_Gaussian11_sigma1.5_valid_interior",
    }


def encode_roundtrip(image, codec, **options):
    buffer = io.BytesIO()
    image.save(buffer, format=codec, **options)
    buffer.seek(0)
    result = Image.open(buffer)
    result.load()
    return result.convert("RGB")


def transform(image, name, seed):
    """Return attacked pixels and the known geometric reference transform."""
    if name in ("original", "metadata_strip"):
        return image.copy(), image
    if name == "png":
        return encode_roundtrip(image, "PNG"), image
    if name.startswith("jpeg_"):
        return encode_roundtrip(
            image, "JPEG", quality=int(name.split("_")[1]), subsampling=2
        ), image
    if name.startswith("webp_"):
        value = name.split("_")[1]
        return encode_roundtrip(
            image,
            "WEBP",
            quality=70 if value == "lossless" else int(value),
            lossless=value == "lossless",
            method=4,
        ), image
    if name.startswith("avif_"):
        return encode_roundtrip(
            image, "AVIF", quality=int(name.split("_")[1]), speed=8, max_threads=2
        ), image
    if name.startswith("scale_"):
        factor = int(name.split("_")[1]) / 100
        size = tuple(max(1, round(edge * factor)) for edge in image.size)
        result = image.resize(size, Image.Resampling.LANCZOS)
        return result, result
    if name.startswith("crop_"):
        factor = int(name.split("_")[-1]) / 100
        width, height = (round(edge * factor) for edge in image.size)
        x = round((image.width - width) * (0.37 if "offset" in name else 0.5))
        y = round((image.height - height) * (0.61 if "offset" in name else 0.5))
        result = image.crop((x, y, x + width, y + height))
        return result, result
    if name.startswith("rotate_"):
        degrees = int(name.split("_")[1])
        result = image.rotate(
            degrees,
            resample=Image.Resampling.BICUBIC,
            expand=degrees % 90 == 0,
            fillcolor=(127, 127, 127),
        )
        return result, result
    if name == "screen_resample":
        # Explicit screenshot-style resampling simulation. No OS screenshot claim.
        small = image.resize(
            (round(image.width * 0.9), round(image.height * 0.9)),
            Image.Resampling.BILINEAR,
        )
        result = small.resize(image.size, Image.Resampling.BILINEAR)
        return result, result
    if name.startswith("blur_"):
        return image.filter(ImageFilter.GaussianBlur(float(name.split("_")[1]))), image
    if name.startswith("noise_"):
        sigma = float(name.split("_")[1])
        noise = np.random.default_rng(seed).normal(0, sigma, np.asarray(image).shape)
        return Image.fromarray(
            np.clip(
                np.rint(np.asarray(image, dtype=np.float32) + noise), 0, 255
            ).astype(np.uint8)
        ), image
    if name.startswith("color_"):
        operation = name.split("_")[1]
        enhancer, factor = {
            "brightness": (ImageEnhance.Brightness, 1.15),
            "contrast": (ImageEnhance.Contrast, 1.15),
            "saturation": (ImageEnhance.Color, 0.5),
        }[operation]
        return enhancer(image).enhance(factor), image
    if name == "multi_edit":
        stage = encode_roundtrip(image, "JPEG", quality=85, subsampling=2)
        stage = stage.resize(
            (round(image.width * 0.75), round(image.height * 0.75)),
            Image.Resampling.LANCZOS,
        )
        stage = encode_roundtrip(stage, "JPEG", quality=70, subsampling=2)
        return stage.resize(image.size, Image.Resampling.LANCZOS), image
    if name == "combo":
        stage = image.rotate(
            5, resample=Image.Resampling.BICUBIC, fillcolor=(127, 127, 127)
        )
        stage = stage.resize(
            (round(image.width * 0.75), round(image.height * 0.75)),
            Image.Resampling.LANCZOS,
        )
        return encode_roundtrip(stage, "JPEG", quality=70, subsampling=2), stage
    raise ValueError(name)


def baseline_ber(image, work, report):
    """Independent coefficient observation, without changing the Rust decision."""
    reference = report.get("reference_dimensions") or [512, 512]
    phase = report.get("pixel_phase") or [0, 0]
    tile_phase = report.get("tile_phase") or [0, 0]
    gray = np.asarray(
        image.resize(tuple(reference), Image.Resampling.BILINEAR), dtype=np.float32
    ) @ np.array([0.299, 0.587, 0.114], np.float32)
    px, py = phase
    h, w = ((gray.shape[0] - py) // 8) * 8, ((gray.shape[1] - px) // 8) * 8
    blocks = (
        gray[py : py + h, px : px + w]
        .reshape(h // 8, 8, w // 8, 8)
        .transpose(0, 2, 1, 3)
    )
    p = np.arange(8, dtype=np.float32)
    c2 = np.cos((2 * p + 1) * 2 * np.pi / 16) * 0.5
    c3 = np.cos((2 * p + 1) * 3 * np.pi / 16) * 0.5
    basis = np.outer(c3, c2) - np.outer(c2, c3)
    differences = np.einsum("abij,ij->ab", blocks, basis).clip(-64, 64)
    votes = np.zeros((16, 16), np.float32)
    ys, xs = np.indices(differences.shape)
    np.add.at(votes, (ys % 16, xs % 16), differences)
    observed = np.roll(votes, (-tile_phase[1], -tile_phase[0]), (0, 1)).reshape(-1) >= 0
    frame = b"FVHDCT1\n" + hashlib.sha256(work.encode()).digest()[:16]
    frame += struct.pack(">I", zlib.crc32(frame)) + bytes([1, 0, 0, 0])
    expected = np.unpackbits(np.frombuffer(frame, np.uint8))
    return {
        "bit_errors": int(np.count_nonzero(observed != expected)),
        "bits": 256,
        "ber": float(np.mean(observed != expected)),
        "scope": "independent_detector_selected_geometry"
        if report.get("frame_valid")
        else "independent_nominal_512_grid_phase0_without_geometric_synchronization",
    }


def compact(response):
    report = response.get("report", {})
    selected = {
        key: report.get(key)
        for key in (
            "method_id",
            "detector_version",
            "status",
            "frame_valid",
            "work_id_digest",
            "copy_id_digest",
            "corrected_codeword_bits",
            "decoded_codeword_disagreement_rate",
            "rotation_degrees",
            "reference_dimensions",
            "tested_grids",
            "tested_phases",
            "tested_candidates",
        )
        if key in report
    }
    return {
        "ok": response.get("ok", False),
        "error": response.get("error"),
        "detector": selected,
        "algorithm_wall_seconds": response.get("wall_seconds"),
        "algorithm_cpu_seconds": response.get("cpu_seconds"),
        "process_peak_rss_bytes": response.get("process_peak_rss_bytes"),
        "memory_scope": response.get("memory_scope"),
    }


def choose(items, limit):
    groups = {
        group: [item for item in items if item["stratum"] == group]
        for group in sorted({i["stratum"] for i in items})
    }
    selected = []
    while len(selected) < min(limit, len(items)):
        for group in groups.values():
            if group and len(selected) < limit:
                selected.append(group.pop(0))
    return selected


def summarize(records, metadata):
    attacks = {}
    for row in records:
        name = row["attack"]
        group = attacks.setdefault(
            name,
            dict(
                cases=0,
                assessed=0,
                detected=0,
                correct_payload=0,
                errors=0,
                not_applicable=0,
                indeterminate=0,
                different_work_reference_matches=0,
                different_copy_reference_matches=0,
                cpu_seconds=0.0,
                wall_seconds=0.0,
                peak_rss_bytes=0,
                psnr=[],
                psnr_infinite_count=0,
                ssim=[],
                ber=[],
            ),
        )
        group["cases"] += 1
        if row.get("ok"):
            group["assessed"] += 1
            group["detected"] += row["detector"].get("status") == "detected"
            group["correct_payload"] += bool(row.get("payload_matches"))
            group["indeterminate"] += row["detector"].get("status") == "indeterminate"
        elif row.get("capability_status") == "not_applicable":
            group["not_applicable"] += 1
        else:
            group["errors"] += 1
        group["different_work_reference_matches"] += bool(
            row.get("different_work_reference_matches")
        )
        group["different_copy_reference_matches"] += bool(
            row.get("different_copy_reference_matches")
        )
        group["psnr_infinite_count"] += bool(
            row.get("quality", {}).get("psnr_infinite")
        )
        group["cpu_seconds"] += row.get("algorithm_cpu_seconds") or 0
        group["wall_seconds"] += row.get("algorithm_wall_seconds") or 0
        group["peak_rss_bytes"] = max(
            group["peak_rss_bytes"], row.get("process_peak_rss_bytes") or 0
        )
        if row.get("quality", {}).get("psnr_db") is not None:
            group["psnr"].append(row["quality"]["psnr_db"])
        if row.get("quality", {}).get("ssim") is not None:
            group["ssim"].append(row["quality"]["ssim"])
        if row.get("raw_ber", {}).get("ber") is not None:
            group["ber"].append(row["raw_ber"]["ber"])
    for name, group in attacks.items():
        group["detection_rate"] = (
            group["detected"] / group["assessed"] if group["assessed"] else None
        )
        group["correct_payload_rate"] = (
            group["correct_payload"] / group["assessed"] if group["assessed"] else None
        )
        group["end_to_end_correct_payload_rate"] = (
            group["correct_payload"] / group["cases"]
            if name not in ("negative", "wrong_key", "clean")
            else None
        )
        group["false_positive_rate"] = (
            group["detection_rate"] if name in ("negative", "wrong_key") else None
        )
        for metric in ("psnr", "ssim", "ber"):
            values = group.pop(metric)
            group[metric + "_mean"] = float(np.mean(values)) if values else None
            group[metric + "_n"] = len(values)
    return {
        **metadata,
        "attacks": attacks,
        "records": len(records),
        "failure_ranking": sorted(
            [
                dict(attack=name, **g)
                for name, g in attacks.items()
                if name not in ("negative", "wrong_key", "embedding", "clean")
            ],
            key=lambda g: (
                g["correct_payload_rate"]
                if g["correct_payload_rate"] is not None
                else -1,
                g["attack"],
            ),
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest", type=Path, default=ROOT / "work/v05-benchmark/manifest.json"
    )
    parser.add_argument(
        "--executable",
        type=Path,
        default=ROOT / "target/release/examples/benchmark_engine",
    )
    parser.add_argument(
        "--output", type=Path, default=ROOT / "work/v05-benchmark/results"
    )
    parser.add_argument("--protocol", choices=["v1"], default="v1")
    parser.add_argument("--profile", choices=["quick", "full"], default="full")
    parser.add_argument("--strength", type=int, default=32)
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(args.manifest.read_text())
    sources = choose(manifest["images"], args.limit)
    prefix = f"{args.protocol}-s{args.strength}-{args.profile}-{len(sources)}"
    journal = args.output / (prefix + ".jsonl")
    if journal.exists() and not args.resume:
        raise RuntimeError(
            "Existing results require explicit --resume or a fresh output directory"
        )
    records = (
        [json.loads(line) for line in journal.read_text().splitlines()]
        if journal.exists()
        else []
    )
    done = {(r["source_id"], r["attack"]) for r in records}
    metadata = {
        "schema": "fileveil.watermark.benchmark.results.v1",
        "protocol": args.protocol,
        "profile": args.profile,
        "strength": args.strength,
        "images": len(sources),
        "strata_counts": {
            group: sum(item["stratum"] == group for item in sources)
            for group in sorted({item["stratum"] for item in sources})
        },
        "manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
        "runner_sha256": hashlib.sha256(args.executable.read_bytes()).hexdigest(),
        "algorithm_source_sha256": hashlib.sha256(
            (
                ROOT
                / "crates/fileveil-engine/src/heritage"
                / ("robust_v2.rs" if args.protocol == "v2" else "robust.rs")
            ).read_bytes()
        ).hexdigest(),
        "harness_source_sha256": hashlib.sha256(
            Path(__file__).read_bytes()
        ).hexdigest(),
        "baseline_source_sha256": hashlib.sha256(
            (ROOT / "crates/fileveil-engine/src/heritage/robust.rs").read_bytes()
        ).hexdigest(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "pillow": Image.__version__,
        "numpy": np.__version__,
        "opencv": cv2.__version__,
        "codecs": {"webp": features.check("webp"), "avif": features.check("avif")},
        "metric_scope": {
            "memory": "persistent worker process-lifetime high-water mark, reported separately per protocol run",
            "cpu": "Rust worker CPU delta includes decode/algorithm and output PNG encode for write operations",
            "ssim": "RGB8 Gaussian11 sigma1.5 valid image interior; geometric attacks use the known geometric reference transform",
            "ber": "v1 independent 256-bit observation with explicit synchronization scope; v2 records its known-payload coded-bit scope separately",
            "screenshot": "screen_resample is a screenshot-style resampling simulation; source screenshot stratum contains real software screenshots",
        },
    }
    runner = Runner(args.executable)
    started = time.time()
    try:
        with (
            journal.open("a", encoding="utf-8") as log,
            tempfile.TemporaryDirectory(
                prefix=".benchmark-", dir=args.output
            ) as temporary,
        ):
            temporary = Path(temporary)

            def record(row):
                records.append(row)
                done.add((row["source_id"], row["attack"]))
                log.write(json.dumps(row, ensure_ascii=False) + "\n")
                log.flush()

            for index, item in enumerate(sources):
                source_path = args.manifest.parent / item["path"]
                data = source_path.read_bytes()
                if hashlib.sha256(data).hexdigest() != item["sha256"]:
                    raise RuntimeError("Source SHA mismatch")
                original = Image.open(io.BytesIO(data)).convert("RGB")
                original.thumbnail((1024, 1024), Image.Resampling.LANCZOS)
                if min(original.size) < 512:
                    raise RuntimeError(
                        "Prepared baseline input is below 512 pixels; corpus entry requires review"
                    )
                source = temporary / "source.png"
                original.save(source)
                marked_path = temporary / "marked.png"
                if marked_path.exists():
                    marked_path.unlink()
                work = f"FileVeil-public-benchmark-work-{item['page_id']}"
                copy = f"edition-{item['page_id']}"
                common = {
                    "source_id": item["page_id"],
                    "stratum": item["stratum"],
                    "source_sha256": item["sha256"],
                    "source_dimensions": item["downloaded_dimensions"],
                    "prepared_dimensions": list(original.size),
                    "work_sha256": hashlib.sha256(work.encode()).hexdigest(),
                    "copy_sha256": hashlib.sha256(copy.encode()).hexdigest(),
                }
                if (item["page_id"], "negative") not in done:
                    negative = runner.call(
                        "detect", source, args.protocol, work, copy, args.strength
                    )
                    record(
                        {
                            **common,
                            "attack": "negative",
                            **compact(negative),
                            "payload_matches": False,
                        }
                    )
                if args.protocol == "v1" and (item["page_id"], "wrong_key") not in done:
                    record(
                        {
                            **common,
                            "attack": "wrong_key",
                            "ok": False,
                            "capability_status": "not_applicable",
                            "error": "The public v1 protocol has no watermark key",
                            "payload_matches": False,
                        }
                    )
                embedded = runner.call(
                    "embed",
                    source,
                    args.protocol,
                    work,
                    copy,
                    args.strength,
                    marked_path,
                )
                if not embedded.get("ok"):
                    if (item["page_id"], "embedding") not in done:
                        record({**common, "attack": "embedding", **compact(embedded)})
                    for failed_attack in (
                        QUICK if args.profile == "quick" else FULL
                    ) + (["clean"] if args.profile == "full" else []):
                        if (item["page_id"], failed_attack) not in done:
                            record(
                                {
                                    **common,
                                    "attack": failed_attack,
                                    "ok": False,
                                    "error": "embedding_failed: "
                                    + str(embedded.get("error")),
                                    "payload_matches": False,
                                }
                            )
                    print(
                        json.dumps(
                            {
                                "image": index + 1,
                                "total": len(sources),
                                "embed_error": embedded.get("error"),
                            }
                        ),
                        flush=True,
                    )
                    continue
                marked = Image.open(marked_path).convert("RGB")
                if (item["page_id"], "embedding") not in done:
                    record(
                        {
                            **common,
                            "attack": "embedding",
                            **compact(embedded),
                            "quality": metrics(original, marked),
                            "payload_matches": True,
                        }
                    )
                for control, path, wrong_key in (
                    [("wrong_key", marked_path, True)] if args.protocol == "v2" else []
                ):
                    if (item["page_id"], control) in done:
                        continue
                    result = runner.call(
                        "detect",
                        path,
                        args.protocol,
                        work,
                        copy,
                        args.strength,
                        wrong_key=wrong_key,
                    )
                    record(
                        {
                            **common,
                            "attack": control,
                            **compact(result),
                            "payload_matches": False,
                        }
                    )
                for attack in QUICK if args.profile == "quick" else FULL:
                    if (item["page_id"], attack) in done:
                        continue
                    case = dict(common, attack=attack)
                    cpu = time.process_time()
                    wall = time.perf_counter()
                    try:
                        attacked, _ = transform(marked, attack, item["page_id"])
                        _, reference = (
                            transform(original, attack, item["page_id"])
                            if attack.startswith(("scale_", "crop_", "rotate_"))
                            or attack in ("screen_resample", "combo")
                            else (original, original)
                        )
                        path = temporary / "attack.png"
                        attacked.save(path)
                        after = time.process_time()
                        transform_wall = time.perf_counter() - wall
                        result = runner.call(
                            "analyze", path, args.protocol, work, copy, args.strength
                        )
                        case.update(
                            compact(result),
                            transform_wall_seconds=transform_wall,
                            transform_cpu_seconds=after - cpu,
                            quality=metrics(reference, attacked),
                        )
                        report = result.get("report", {})
                        actual = report.get("work_id_digest")
                        expected = (
                            hashlib.sha256(work.encode()).hexdigest()[: len(actual)]
                            if actual
                            else None
                        )
                        case["payload_matches"] = bool(
                            report.get("frame_valid") and actual and actual == expected
                        )
                        case["different_work_reference_matches"] = bool(
                            actual
                            and actual
                            == hashlib.sha256((work + "-wrong").encode()).hexdigest()[
                                : len(actual)
                            ]
                        )
                        if args.protocol == "v1":
                            case["raw_ber"] = baseline_ber(attacked, work, report)
                        elif result.get("known_payload"):
                            measurement = result["known_payload"]
                            case["raw_ber"] = {
                                "ber": measurement["coded_ber"],
                                "bit_errors": measurement["coded_bit_errors"],
                                "bits": measurement["coded_bits"],
                                "scope": measurement["selection"],
                            }
                            case["known_payload_measurement"] = measurement
                        copy_digest = report.get("copy_id_digest")
                        if args.protocol == "v2":
                            case["copy_matches"] = bool(
                                copy_digest
                                and copy_digest
                                == hashlib.sha256(copy.encode()).hexdigest()[
                                    : len(copy_digest)
                                ]
                            )
                            case["different_copy_reference_matches"] = bool(
                                copy_digest
                                and copy_digest
                                == hashlib.sha256(
                                    (copy + "-wrong").encode()
                                ).hexdigest()[: len(copy_digest)]
                            )
                            case["payload_matches"] = (
                                case["payload_matches"] and case["copy_matches"]
                            )
                    except Exception as error:
                        case.update(
                            ok=False, error=type(error).__name__ + ": " + str(error)
                        )
                    record(case)
                if args.profile == "full" and (item["page_id"], "clean") not in done:
                    clean_path = temporary / "cleaned.png"
                    if clean_path.exists():
                        clean_path.unlink()
                    cleaned = runner.call(
                        "clean",
                        marked_path,
                        args.protocol,
                        work,
                        copy,
                        args.strength,
                        clean_path,
                    )
                    if cleaned.get("ok"):
                        cleaned_image = Image.open(clean_path).convert("RGB")
                        cleaned.update(
                            report=runner.call(
                                "detect",
                                clean_path,
                                args.protocol,
                                work,
                                copy,
                                args.strength,
                            ).get("report", {})
                        )
                        record(
                            {
                                **common,
                                "attack": "clean",
                                **compact(cleaned),
                                "quality": metrics(original, cleaned_image),
                                "payload_matches": False,
                            }
                        )
                    else:
                        record({**common, "attack": "clean", **compact(cleaned)})
                summary = summarize(
                    records, {**metadata, "elapsed_wall_seconds": time.time() - started}
                )
                (args.output / (prefix + "-summary.json")).write_text(
                    json.dumps(summary, indent=2) + "\n"
                )
                print(
                    json.dumps(
                        {
                            "image": index + 1,
                            "total": len(sources),
                            "protocol": args.protocol,
                            "records": len(records),
                            "elapsed": round(time.time() - started, 1),
                        }
                    ),
                    flush=True,
                )
    finally:
        runner.close()
    summary = summarize(
        records, {**metadata, "elapsed_wall_seconds": time.time() - started}
    )
    (args.output / (prefix + "-summary.json")).write_text(
        json.dumps(summary, indent=2) + "\n"
    )
    with (args.output / (prefix + "-summary.csv")).open("w", newline="") as stream:
        fields = [
            "attack",
            "cases",
            "assessed",
            "detected",
            "correct_payload",
            "errors",
            "indeterminate",
            "not_applicable",
            "different_work_reference_matches",
            "different_copy_reference_matches",
            "detection_rate",
            "correct_payload_rate",
            "end_to_end_correct_payload_rate",
            "false_positive_rate",
            "psnr_infinite_count",
            "psnr_mean",
            "psnr_n",
            "ssim_mean",
            "ssim_n",
            "ber_mean",
            "ber_n",
            "cpu_seconds",
            "wall_seconds",
            "peak_rss_bytes",
        ]
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for attack, values in summary["attacks"].items():
            writer.writerow({"attack": attack, **values})
    print(
        json.dumps(
            {
                "summary": str(args.output / (prefix + "-summary.json")),
                "records": len(records),
            }
        )
    )


if __name__ == "__main__":
    main()
