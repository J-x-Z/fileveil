#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Validate real CLI reports and legacy envelopes against the shipped schemas."""
from __future__ import annotations

import argparse
import json
import os
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
    legacy = {key: value for key, value in reports[0].items()
              if key not in ("pdf", "provenance", "advanced", "image_processing")}
    for version in ("0.1", "0.2"):
        legacy["schema_version"] = version
        validator.validate(legacy)
    envelope = {"schema_version": "0.3", "tool": "FileVeil", "version": "0.3.0",
                "operation": "batch_export", "reports": reports}
    Draft202012Validator(batch).validate(envelope)
    print(json.dumps({"real_reports": len(reports), "legacy_reports": 2,
                      "batch_validated": True, "draft": "2020-12"}))


if __name__ == "__main__":
    main()
