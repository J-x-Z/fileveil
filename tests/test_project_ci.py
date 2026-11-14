#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Focused generator and local post-build boundary regressions."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("project_postprocess", ROOT / "tools/project-postprocess.py")
PROCESSOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROCESSOR)
STAGE_SPEC = importlib.util.spec_from_file_location("project_ci_stage", ROOT / "tools/project-ci-stage.py")
STAGE = importlib.util.module_from_spec(STAGE_SPEC)
STAGE_SPEC.loader.exec_module(STAGE)


class ProjectCiTests(unittest.TestCase):
    def test_history_retains_metadata_and_omits_asset_copies(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            history = root / "history"
            generation = history / "project-id" / "000000000001-generation"
            (generation / "files").mkdir(parents=True)
            (generation / "files/image.png").write_bytes(b"private asset copy")
            (generation / "derived").mkdir()
            (generation / "derived/program.bin").write_bytes(b"compiler output copy")
            for filename in ("manifest.json", "evidence.json", "COMMITTED"):
                (generation / filename).write_bytes(b"signed public metadata")
            bundle = root / "history.zip"
            STAGE.history_bundle(history, bundle)
            STAGE.receive(bundle, root / "restored", history=True)
            self.assertEqual(len(list((root / "restored").rglob("*.*"))), 2)
            self.assertFalse(list((root / "restored").rglob("*.png")))
            self.assertFalse(list((root / "restored").rglob("*.bin")))
            (generation / "unexpected.key").write_bytes(b"private")
            with self.assertRaises(ValueError):
                STAGE.history_bundle(history, root / "bad.zip")

    def test_portable_verification_omits_private_filesystem_paths(self):
        source = {"version": "0.6", "result": "verified_within_scope", "advanced": {"project": {
            "config": {"source_root": "/private/user/source", "output_directory": "/private/output"},
            "manifest_sha256": "ab" * 32, "integrity": "valid"}}}
        portable = PROCESSOR.public_report(source)
        self.assertNotIn("/private", json.dumps(portable))
        self.assertEqual(portable["project"]["manifest_sha256"], "ab" * 32)

    def test_build_transfer_preserves_bytes_and_never_executes_received_files(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "dist").mkdir()
            original = b"unexecuted executable bytes"
            (root / "dist/program.bin").write_bytes(original)
            config = root / "ci.json"
            config.write_text(json.dumps({"work_id": "w", "author": "a", "copy_id": "c", "artifact_directory": "dist"}))
            bundle = root / "build.zip"
            STAGE.prepare(config, bundle)
            STAGE.receive(bundle, root / "received")
            self.assertEqual((root / "received/artifacts/program.bin").read_bytes(), original)
            received = json.loads((root / "received/ci-config.json").read_text())
            self.assertEqual(received["build_argv"], [])
            self.assertEqual(received["artifact_directory"], "artifacts")
            with self.assertRaises(ValueError):
                STAGE.receive(bundle, root / "received")

    def test_transfer_traversal_symlinks_and_case_aliases_fail_atomically(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for index, entries in enumerate(([("../escape", b"x")], [("A", b"x"), ("a", b"y")])):
                bundle = root / f"bad-{index}.zip"
                with zipfile.ZipFile(bundle, "w") as archive:
                    for path, content in entries:
                        archive.writestr(path, content)
                with self.assertRaises(ValueError):
                    STAGE.receive(bundle, root / f"out-{index}")
                self.assertFalse((root / f"out-{index}").exists())
            bundle = root / "symlink.zip"
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            with zipfile.ZipFile(bundle, "w") as archive:
                archive.writestr(info, "outside")
            with self.assertRaises(ValueError):
                STAGE.receive(bundle, root / "symlink-out")

    def test_windows_device_and_alias_paths_are_rejected_on_every_platform(self):
        for name in ("NUL", "path/CON.txt", "AUX", "COM1.exe", "dir/file. ", "dir//file", "a?b"):
            with self.subTest(name=name):
                self.assertFalse(STAGE.portable(name))
        self.assertTrue(STAGE.portable("assets/console.png"))

    def test_zip_directory_budget_is_checked_before_zipinfo_allocation(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bundle = root / "empty.zip"
            with zipfile.ZipFile(bundle, "w"):
                pass
            data = bytearray(bundle.read_bytes())
            data[12:16] = (33 * 1024 * 1024).to_bytes(4, "little")
            bundle.write_bytes(data)
            with patch.object(STAGE.zipfile, "ZipFile", side_effect=AssertionError("parser allocated")):
                with self.assertRaises(ValueError):
                    STAGE.receive(bundle, root / "out")
            self.assertFalse((root / "out").exists())

    def test_zip64_override_is_checked_even_without_legacy_sentinels(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bundle = root / "zip64.zip"
            record = struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, 20003, 20003, 64 * 1024**2, 0)
            locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, 0, 1)
            legacy = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 0, 0, 0, 0, 0)
            bundle.write_bytes(record + locator + legacy)
            with patch.object(STAGE.zipfile, "ZipFile", side_effect=AssertionError("parser allocated")):
                with self.assertRaises(ValueError):
                    STAGE.receive(bundle, root / "out")
            self.assertFalse((root / "out").exists())

    def test_valid_zip64_transfer_remains_supported(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bundle = root / "valid.zip"
            with patch.object(zipfile, "ZIP64_LIMIT", 1):
                with zipfile.ZipFile(bundle, "w", allowZip64=True) as archive:
                    archive.writestr("program.txt", b"valid ZIP64 content")
            STAGE.receive(bundle, root / "out")
            self.assertEqual((root / "out/program.txt").read_bytes(), b"valid ZIP64 content")

    def test_changed_transfer_input_is_rejected_before_publication(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = root / "input.bin"
            path.write_bytes(b"initial")
            expected = path.stat()
            path.write_bytes(b"concurrent modification")
            destination = root / "transfer.zip"
            with self.assertRaises(ValueError):
                with STAGE.archive_new(destination) as archive:
                    STAGE.write_member(archive, path, "input.bin", expected)
            self.assertFalse(destination.exists())

    def test_unknown_private_key_fields_and_path_traversal_are_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            config = root / "config.json"
            config.write_text(json.dumps({"work_id": "w", "author": "a", "copy_id": "c", "private_key": "forbidden"}))
            with self.assertRaises(ValueError):
                PROCESSOR.read_config(config)
            for path in ("../outside", "..\\outside", "/absolute", "C:/Windows"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    PROCESSOR.relative_directory(root, path)

    def test_build_failure_preserves_original_artifacts_and_has_no_evidence(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "dist").mkdir()
            original = root / "dist/program.bin"
            original.write_bytes(b"original executable bytes")
            config = {"work_id": "w", "author": "a", "copy_id": "c", "artifact_directory": "dist",
                      "output_directory": "release", "build_argv": [sys.executable, "-c", "raise SystemExit(7)"]}
            (root / "fileveil-ci.json").write_text(json.dumps(config))
            result = subprocess.run([sys.executable, str(ROOT / "tools/project-postprocess.py"),
                "--fileveil", sys.executable, "--config", str(root / "fileveil-ci.json"),
                "--evidence-directory", str(root / "evidence")], capture_output=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(original.read_bytes(), b"original executable bytes")
            self.assertFalse((root / "evidence").exists())
            self.assertFalse((root / "release").exists())

    def test_signing_secret_is_removed_from_build_and_cli_environments(self):
        previous = os.environ.get("FILEVEIL_SIGNING_KEY_BASE64")
        os.environ["FILEVEIL_SIGNING_KEY_BASE64"] = "test-only-secret"
        try:
            self.assertNotIn("FILEVEIL_SIGNING_KEY_BASE64", PROCESSOR.clean_environment())
        finally:
            if previous is None:
                os.environ.pop("FILEVEIL_SIGNING_KEY_BASE64", None)
            else:
                os.environ["FILEVEIL_SIGNING_KEY_BASE64"] = previous


if __name__ == "__main__":
    unittest.main()
