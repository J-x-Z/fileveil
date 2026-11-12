#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Benchmark actual native egui framebuffer screenshots of the pinned corpus.

One native window is reused. Each image is really uploaded, rendered and cropped
from the returned framebuffer. This does not capture the OS desktop compositor.
Only journals and optional first-image evidence are retained.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import platform
import queue
import shutil
import subprocess
import tempfile
import threading
import time

import cv2
import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
PROFILES = {"v1-s32": ("v1", 32), "v2-s12": ("v2", 12), "v2-s20": ("v2", 20)}


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runner_identity(runner, executable, snapshot_path):
    """Require an inline fingerprint or the exact preserved legacy executable."""
    fingerprint = runner.call("fingerprint", Path("."), "v1", "", "")
    fields = ["baseline_source_sha256", "v2_source_sha256", "geometry_source_sha256", "runner_source_sha256"]
    if fingerprint.get("ok"):
        if not all(isinstance(fingerprint.get(field), str) and len(fingerprint[field]) == 64 and set(fingerprint[field]) <= set("0123456789abcdef") for field in fields):
            raise RuntimeError("Runner returned an incomplete compiled-source fingerprint")
        return fingerprint, {"status": "verified", "scope": "runner_emitted_compiled_source_fingerprint"}
    snapshot = json.loads(snapshot_path.read_text())
    entries = [entry for entry in snapshot["files"] if entry["path"] == "target/release/examples/benchmark_engine"]
    if len(entries) != 1 or entries[0]["sha256"] != sha256(executable) or entries[0]["bytes"] != executable.stat().st_size:
        raise RuntimeError("Runner fingerprint failed and its executable does not match the pinned algorithm snapshot")
    return fingerprint, {
        "status": "not_supported",
        "scope": "executable_sha256_matches_preserved_build_snapshot; source hashes are snapshot evidence without an inline compiled-source fingerprint",
        "query_evidence_field": "algorithm_fingerprint",
        "pinned_snapshot": {
            "path": str(snapshot_path.relative_to(ROOT)) if snapshot_path.is_relative_to(ROOT) else str(snapshot_path),
            "sha256": sha256(snapshot_path),
            "scope": snapshot["scope"],
            "files": snapshot["files"],
        },
    }


class Capture:
    def __init__(self, executable, stderr):
        self.process = subprocess.Popen(
            [str(executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=stderr, text=True, bufsize=1,
        )
        self.responses = queue.Queue()
        self.reader = threading.Thread(target=self.read_responses, daemon=True)
        self.reader.start()

    def read_responses(self):
        for line in self.process.stdout:
            self.responses.put(line)
        self.responses.put(None)

    def call(self, request):
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        try:
            line = self.responses.get(timeout=30)
        except queue.Empty as error:
            raise TimeoutError("Native framebuffer capture exceeded 30 seconds") from error
        if not line:
            raise RuntimeError(f"Capture window exited with {self.process.poll()}")
        response = json.loads(line)
        if response.get("id") != request["id"] or not response.get("ok"):
            raise RuntimeError(f"Native capture failed. {response}")
        if response.get("os_desktop_capture") is not False:
            raise RuntimeError("Capture provenance did not declare its scope")
        if sha256(Path(request["output"])) != response["capture_sha256"]:
            raise RuntimeError("Native capture SHA mismatch")
        if sha256(Path(request["input"])) != response["input_sha256"]:
            raise RuntimeError("Native capture input SHA mismatch")
        if response.get("compiled_capture_source_sha256") != sha256(ROOT / "crates/fileveil-gui/examples/native_watermark_screen.rs"):
            raise RuntimeError("Native capture executable differs from its recorded source")
        return response

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)
        self.reader.join(timeout=1)


def payload_matches(response, work, copy, protocol):
    report = response.get("report", {})
    return bool(
        report.get("frame_valid")
        and report.get("work_id_digest") == hashlib.sha256(work.encode()).hexdigest()[:32 if protocol == "v1" else 24]
        and (protocol == "v1" or report.get("copy_id_digest") == hashlib.sha256(copy.encode()).hexdigest()[:16])
    )


def summary(records, metadata):
    groups = {}
    for row in records:
        group = groups.setdefault(row["profile"], {})
        values = group.setdefault(row["attack"], {"cases": 0, "detected": 0, "correct_payload": 0, "errors": 0, "algorithm_cpu_seconds": 0.0, "capture_wall_seconds": 0.0})
        values["cases"] += 1
        values["detected"] += row.get("detector", {}).get("status") == "detected"
        values["correct_payload"] += bool(row.get("payload_matches"))
        values["errors"] += not row.get("ok", False)
        values["algorithm_cpu_seconds"] += row.get("algorithm_cpu_seconds") or 0
        values["capture_wall_seconds"] += row.get("capture", {}).get("capture_wall_seconds") or 0
    for group in groups.values():
        for attack, values in group.items():
            values["detection_rate"] = values["detected"] / values["cases"]
            values["correct_payload_rate"] = values["correct_payload"] / values["cases"] if attack == "native_framebuffer_screenshot" else None
    for profile, group in groups.items():
        for attack, values in group.items():
            matching = [row for row in records if row["profile"] == profile and row["attack"] == attack]
            oracle = [row["independent_recheck"] for row in matching if "independent_recheck" in row]
            values["independently_assessed"] = len(oracle)
            values["independently_correct_payload"] = sum(bool(row.get("expected_payload_matches")) for row in oracle)
            for metric in ["psnr_db", "ssim"]:
                samples = [row.get("quality", {}).get(metric) for row in matching]
                samples = [sample for sample in samples if sample is not None]
                values[metric + "_mean"] = float(np.mean(samples)) if samples else None
    return {**metadata, "profiles": groups, "records": len(records)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "work/v05-benchmark/manifest.json")
    parser.add_argument("--executable", type=Path, default=ROOT / "work/v05-benchmark/bin/benchmark-engine-frozen")
    parser.add_argument("--capture-executable", type=Path, default=ROOT / "target/release/examples/native_watermark_screen")
    parser.add_argument("--pinned-snapshot", type=Path, default=ROOT / "work/v05-benchmark/final-algorithm-snapshot.json")
    parser.add_argument("--output", type=Path, default=ROOT / "work/v05-benchmark/native-screen")
    parser.add_argument("--profiles", nargs="+", choices=PROFILES, default=list(PROFILES))
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--max-side-points", type=float, default=384.0)
    parser.add_argument("--zoom-factor", type=float, default=1.0)
    parser.add_argument("--independent-per-stratum", type=int, default=1)
    parser.add_argument("--controls-per-stratum", type=int, default=2)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--keep-first", action="store_true")
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.executable = args.executable.resolve()
    args.capture_executable = args.capture_executable.resolve()
    args.manifest = args.manifest.resolve()
    args.pinned_snapshot = args.pinned_snapshot.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    cv2.setNumThreads(1)
    benchmark = module("native_screen_benchmark_helpers", ROOT / "tools/benchmark-watermarks.py")
    sources = benchmark.choose(json.loads(args.manifest.read_text())["images"], args.limit)
    journal = args.output / "records.jsonl"
    if journal.exists() and not args.resume:
        raise RuntimeError("Existing screenshot results require --resume or a fresh output directory")
    records = [json.loads(line) for line in journal.read_text().splitlines()] if journal.exists() else []
    done = {(row["source_id"], row["profile"], row["attack"]) for row in records}
    runner = benchmark.Runner(args.executable)
    try:
        fingerprint, identity = runner_identity(runner, args.executable, args.pinned_snapshot)
    except Exception:
        runner.close()
        raise
    metadata = {
        "schema": "fileveil.watermark.native_framebuffer_benchmark.v1",
        "capture_scope": "actual native egui Glow framebuffer image crop, not OS desktop compositor capture",
        "os_desktop_capture": False, "images": len(sources), "profiles_requested": args.profiles,
        "max_side_points": args.max_side_points, "zoom_factor": args.zoom_factor,
        "manifest_sha256": sha256(args.manifest), "runner_sha256": sha256(args.executable),
        "capture_executable_sha256": sha256(args.capture_executable),
        "capture_source_sha256": sha256(ROOT / "crates/fileveil-gui/examples/native_watermark_screen.rs"),
        "script_sha256": sha256(Path(__file__)), "algorithm_fingerprint": fingerprint,
        "algorithm_identity": identity,
        "helper_source_sha256": sha256(ROOT / "tools/benchmark-watermarks.py"),
        "independent_source_sha256": {name: sha256(ROOT / f"tests/support/{path}") for name, path in [("v1", "heritage_robust_oracle.py"), ("v2", "watermark_v2_oracle.py")]},
        "platform": platform.platform(), "pillow": Image.__version__, "opencv": cv2.__version__,
        "independent_per_stratum": args.independent_per_stratum, "controls_per_stratum": args.controls_per_stratum,
        "independent_scope": "OpenCV v1 multi-grid CRC decoder; v2 canonical512 linear normalization then independent BCH syndrome-table/HMAC native and quarter-turn pixel/tile search. FFT and bounded Chase search are outside the oracle scope.",
        "quality_scope": "Captured unmarked image compared with captured marked image at identical native display geometry",
        "memory_scope": "Algorithm runner reports its process lifetime high-water mark shared across requested profiles; capture timings include event-loop waiting",
    }
    benchmark.bind_run(args.output / "run.json", metadata, bool(records))
    independent = None
    if args.independent_per_stratum:
        v1 = module("native_v1_oracle", ROOT / "tests/support/heritage_robust_oracle.py")
        v2 = module("native_v2_oracle", ROOT / "tests/support/watermark_v2_oracle.py")
        independent = (v1, v2, v2.BCH())
    counts = {}
    started = time.time()
    try:
        with (journal.open("a") as log, (args.output / "native-window.stderr").open("a") as stderr,
              tempfile.TemporaryDirectory(prefix=".native-screen-", dir=args.output) as folder):
            folder = Path(folder)
            capture = Capture(args.capture_executable, stderr)
            try:
                def record(row):
                    records.append(row)
                    done.add((row["source_id"], row["profile"], row["attack"]))
                    log.write(json.dumps(row) + "\n")
                    log.flush()
                    (args.output / "summary.json").write_text(json.dumps(summary(records, metadata), indent=2) + "\n")

                def screenshot(source, output, identity):
                    output.unlink(missing_ok=True)
                    return capture.call({"id": identity, "input": str(source), "output": str(output), "max_side_points": args.max_side_points, "zoom_factor": args.zoom_factor})

                for index, item in enumerate(sources):
                    ordinal = counts.get(item["stratum"], 0)
                    counts[item["stratum"]] = ordinal + 1
                    if all((item["page_id"], profile, "native_framebuffer_screenshot") in done for profile in args.profiles):
                        continue
                    source_path = args.manifest.parent / item["path"]
                    data = source_path.read_bytes()
                    if hashlib.sha256(data).hexdigest() != item["sha256"]:
                        raise RuntimeError("Pinned source SHA mismatch")
                    original = Image.open(io.BytesIO(data)).convert("RGB")
                    original.thumbnail((1024, 1024), Image.Resampling.LANCZOS)
                    if min(original.size) < 512:
                        raise RuntimeError("Prepared screenshot benchmark input is below 512 pixels")
                    source = folder / "source.png"
                    original.save(source)
                    clean_capture = folder / "unmarked-capture.png"
                    clean_metadata = screenshot(source, clean_capture, f"{item['page_id']}-negative")
                    with Image.open(clean_capture) as image:
                        reference = image.convert("RGB")
                    work = f"FileVeil-public-benchmark-work-{item['page_id']}"
                    copy = f"edition-{item['page_id']}"
                    for profile in args.profiles:
                        protocol, strength = PROFILES[profile]
                        common = {"source_id": item["page_id"], "stratum": item["stratum"], "source_sha256": item["sha256"], "prepared_dimensions": list(original.size), "profile": profile}
                        if ordinal < args.controls_per_stratum and (item["page_id"], profile, "negative") not in done:
                            negative = runner.call("detect", clean_capture, protocol, work, copy, strength)
                            record({**common, "attack": "negative", **benchmark.compact(negative), "payload_matches": False, "capture": clean_metadata})
                        if (item["page_id"], profile, "native_framebuffer_screenshot") in done:
                            continue
                        marked = folder / "marked.png"
                        marked.unlink(missing_ok=True)
                        embedded = runner.call("embed", source, protocol, work, copy, strength, marked)
                        if not embedded.get("ok"):
                            record({**common, "attack": "native_framebuffer_screenshot", **benchmark.compact(embedded), "payload_matches": False})
                            continue
                        captured = folder / "marked-capture.png"
                        capture_metadata = screenshot(marked, captured, f"{item['page_id']}-{profile}")
                        result = runner.call("analyze", captured, protocol, work, copy, strength)
                        with Image.open(captured) as image:
                            actual = image.convert("RGB")
                        row = {**common, "attack": "native_framebuffer_screenshot", **benchmark.compact(result), "payload_matches": payload_matches(result, work, copy, protocol), "capture": capture_metadata, "quality": benchmark.metrics(reference, actual)}
                        if independent and ordinal < args.independent_per_stratum:
                            v1, v2, bch = independent
                            if protocol == "v1":
                                row["independent_recheck"] = v1.recover(np.asarray(actual))
                            else:
                                normalized = Image.fromarray(cv2.resize(np.asarray(actual), (512, 512), interpolation=cv2.INTER_LINEAR))
                                row["independent_recheck"] = v2.detect(normalized, bch=bch)
                            row["independent_recheck"]["expected_payload_matches"] = payload_matches({"report": {**row["independent_recheck"], "frame_valid": row["independent_recheck"].get("status") == "detected"}}, work, copy, protocol)
                        record(row)
                        if args.keep_first and index == 0:
                            shutil.copyfile(captured, args.output / f"first-{profile}.png")
                        print(json.dumps({"image": index + 1, "total": len(sources), "profile": profile, "detected": row["payload_matches"], "capture_dimensions": capture_metadata["capture_dimensions"], "pixels_per_point": capture_metadata["pixels_per_point"], "elapsed_seconds": round(time.time() - started, 1)}), flush=True)
                    if sha256(source_path) != item["sha256"]:
                        raise RuntimeError("Original source changed during native screenshot testing")
            finally:
                capture.close()
    finally:
        runner.close()
    print(json.dumps(summary(records, metadata), indent=2))


if __name__ == "__main__":
    main()
