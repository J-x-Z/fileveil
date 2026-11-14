#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Validate real CLI reports and legacy envelopes against the shipped schemas."""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
import subprocess

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path)
    arguments = parser.parse_args()
    executable = arguments.executable or ROOT / "target" / "debug" / ("fileveil.exe" if os.name == "nt" else "fileveil")
    executable = executable.resolve()
    single = json.loads((ROOT / "docs/report.schema.json").read_text())
    batch = json.loads((ROOT / "docs/batch-report.schema.json").read_text())
    Draft202012Validator.check_schema(single)
    Draft202012Validator.check_schema(batch)
    validator = Draft202012Validator(single)
    commands = [
        ["heritage", "detect", "tests/fixtures/png_clean.png", "--json"],
        ["scan", "tests/fixtures/png_clean.png", "--json"],
        ["provenance", "crates/fileveil-engine/tests/fixtures/provenance/signed.png", "--json"],
        ["provenance", "crates/fileveil-engine/tests/fixtures/provenance/signed.pdf", "--json"],
        ["provenance", "crates/fileveil-engine/tests/fixtures/provenance/signed.txt", "--json"],
        ["provenance", "crates/fileveil-engine/tests/fixtures/provenance/signed.md", "--json"],
        ["provenance", "crates/fileveil-engine/tests/fixtures/provenance/signed.wav", "--json"],
        ["lab", "tests/fixtures/png_clean.png", "tests/fixtures/png_itxt_exif_icc.png", "--json"],
        ["scan", "tests/fixtures/pdf_corrupt.pdf", "--json"],
        ["scan", "tests/fixtures/mp4_av_source.mp4", "--json"],
        ["detect-watermark", "crates/fileveil-engine/tests/fixtures/watermark/astronaut-sdxl.png", "--json"],
        ["lab", "--groups-json", '[{"label":"reference","sample_indices":[0,1]}]',
         "crates/fileveil-engine/tests/fixtures/watermark/astronaut.png",
         "crates/fileveil-engine/tests/fixtures/watermark/astronaut-sdxl.png", "--json"],
    ]
    scratch = ROOT / "work" / "schema-tmp"
    scratch.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ, TMPDIR=str(scratch))
    reports = []
    for command in commands:
        result = subprocess.run([str(executable), *command], cwd=ROOT, env=environment,
                                capture_output=True, text=True, encoding="utf-8", timeout=60)
        assert result.returncode in (0, 3, 4, 5), (command, result.stderr, result.stdout)
        report = json.loads(result.stdout)
        validator.validate(report)
        reports.append(report)
    with tempfile.TemporaryDirectory(prefix="heritage-schema-", dir=scratch) as directory:
        directory = Path(directory)
        key = directory / "owner.key"
        marked = directory / "marked.png"
        cleaned = directory / "cleaned.png"
        options = json.dumps({"key_paths":[str(key)], "mark":{"work_id":"schema-synthetic-work", "author":"Synthetic author"}})
        workflow = [
            ["heritage-keygen", "-o", str(key), "--json"],
            ["heritage", "mark", "tests/fixtures/png_clean.png", "-o", str(marked), "--options-json", options, "--json"],
            ["heritage", "verify", str(marked), "--json"],
            ["heritage", "clean", str(marked), "-o", str(cleaned), "--json"],
        ]
        for command in workflow:
            result = subprocess.run([str(executable), *command], cwd=ROOT, env=environment,
                                    capture_output=True, text=True, encoding="utf-8", timeout=60)
            assert result.returncode in (0, 4), (command[0:2], result.stderr, result.stdout)
            report = json.loads(result.stdout)
            validator.validate(report)
            reports.append(report)
        assert cleaned.read_bytes() == (ROOT / "tests/fixtures/png_clean.png").read_bytes()
    legacy_source = next(report for report in reports if report["operation"] == "scan" and report["input_format"] == "image/png")
    legacy = {key: value for key, value in legacy_source.items()
              if key not in ("pdf", "provenance", "advanced", "image_processing")}
    for version in ("0.1", "0.2", "0.3"):
        legacy["schema_version"] = version
        validator.validate(legacy)
    envelope = {"schema_version": reports[0]["schema_version"], "tool": "FileVeil", "version": reports[0]["version"],
                "operation": "batch_export", "reports": reports}
    Draft202012Validator(batch).validate(envelope)
    print(json.dumps({"real_reports": len(reports), "legacy_reports": 3,
                      "batch_validated": True, "draft": "2020-12"}))


if __name__ == "__main__":
    main()

# FVPROV1 4840 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJmMWYwODgzMDFlOWQxYzVhMmY0MjUwY2IyODczZjIxYTcxZWJhNmRkM2MyY2I4NDQwZjBkYjhjOWRiMjI3OTk3IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4yIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMiIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL2NoZWNrLXJlcG9ydC1zY2hlbWFzLnB5In0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiNzM4OTAyNjJiODliNDE4YTE5M2JkMzJkMGVlNzdkMTZhMjA2Mjg1NzdlYWU1MTRlYzcwZGZjODNiZTI5MjIzMGI4MDc0NTc3YzcyZjUyMzViOThlN2JhOWJkYTA5Y2E5YmM2ZGY1NjM1OTA4Y2JmZTc3YzBmYWVkMWFhODVjMGMifV19XQ== FVPROV1-END
