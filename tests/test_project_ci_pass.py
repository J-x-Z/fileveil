#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Built LLVM pass discovery and secret-free preflight contracts."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("project_ci_pass", ROOT / "tools/project-ci-compiler.py")
COMPILER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPILER)


def metadata(directory, name, kind=None, compiled=True):
    directory.mkdir(parents=True, exist_ok=True)
    value = {"schema": "fileveil.software.llvm-plugin.v1", "plugin": name}
    if kind is not None:
        value["execution_kind"] = kind
    (directory / "fileveil-plugin.json").write_text(json.dumps(value))
    if compiled:
        (directory / name).write_bytes(b"synthetic artifact, never executed")


class BuiltPassTests(unittest.TestCase):
    def test_selects_completed_release_and_ignores_unbuilt_configurations(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            metadata(root / "Debug", "FileVeilWatermarkDriver.exe", "standalone_driver", compiled=False)
            metadata(root / "Release", "FileVeilWatermarkDriver.exe", "standalone_driver")
            path, kind = COMPILER.built_pass(root)
            self.assertEqual(path, (root / "Release/FileVeilWatermarkDriver.exe").resolve())
            self.assertEqual(kind, "standalone_driver")

    def test_legacy_plugin_metadata_and_duplicate_completed_builds(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            metadata(root / "Release", "FileVeilWatermark.so")
            self.assertEqual(COMPILER.built_pass(root)[1], "plugin")
            metadata(root / "Debug", "FileVeilWatermark.so")
            with self.assertRaises(ValueError):
                COMPILER.built_pass(root)

    def test_metadata_cannot_redirect_to_another_path_or_execution_kind(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for filename, kind in (("../other.exe", "standalone_driver"), ("pass.exe", "shell")):
                metadata(root, filename, kind, compiled=False)
                with self.assertRaises(ValueError):
                    COMPILER.built_pass(root)

    def test_preflight_uses_fixed_backend_arguments_and_removes_signing_secret(self):
        for kind in ("plugin", "standalone_driver"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                build = root / "build"
                metadata(build, "pass.bin", kind)
                sdk = root / "sdk"
                binary = sdk / "bin"
                binary.mkdir(parents=True)
                extension = ".exe" if os.name == "nt" else ""
                for program in ("clang", "clang++", "opt"):
                    (binary / (program + extension)).write_bytes(b"not executed")
                with patch.dict(os.environ, {"FILEVEIL_SIGNING_KEY_BASE64": "synthetic-secret"}), \
                        patch.object(COMPILER.subprocess, "run") as run:
                    selected = COMPILER.probe_built_pass(build, sdk)
                self.assertEqual(run.call_count, 4)
                for call in run.call_args_list:
                    self.assertNotIn("FILEVEIL_SIGNING_KEY_BASE64", call.kwargs["env"])
                arguments = run.call_args_list[0].args[0]
                self.assertIn("FILEVEIL_SOFTWARE_PACKET", run.call_args_list[0].kwargs["env"])
                if kind == "standalone_driver":
                    self.assertEqual(arguments[:4], [str(selected), "--operation", "mark", "--input"])
                else:
                    self.assertEqual(arguments[0], str((binary / ("opt" + extension)).resolve()))
                    self.assertIn("--load-pass-plugin=" + str(selected), arguments)
                    self.assertIn("-passes=fileveil-mark", arguments)


if __name__ == "__main__":
    unittest.main()

# FVPROV1 4087 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIyNDUwYTdjZmQzYTZiYjQwZTAyNWMwNGEyYTA3OTVhNGJlZTU0ODAzYzM4MGI1OGU5OWExNDFlNjJjNzNmMzAwIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rlc3RzL3Rlc3RfcHJvamVjdF9jaV9wYXNzLnB5In0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiMmQ1ZGQ0Y2I0MDM1YzlhNmJiMmQ0NGMzYWQwZjUxMTFiMGM0NGE4MmE4NzgzMTQ3NzA3YjViMjAwN2M2ZTcwNDI4NDg2OTFiYWUxM2U5MTE4OWFlYmY4M2JmNmU2OWU4NjY1NzY0N2E5MDUyOGFmZDY2OWNmMjdmZDc1M2I2MDYifV19XQ== FVPROV1-END
