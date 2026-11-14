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

# FVPROV1 4087 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIyNDUwYTdjZmQzYTZiYjQwZTAyNWMwNGEyYTA3OTVhNGJlZTU0ODAzYzM4MGI1OGU5OWExNDFlNjJjNzNmMzAwIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rlc3RzL3Rlc3RfcHJvamVjdF9jaV9wYXNzLnB5In0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiNDVhY2ViNjc3ZjM5N2NlNzNlZDVmMDY3ZTE5NTBjOTY4OTJjMzM2NmQ5MjRiMjZjYjA4MjMwYzUwMjY2MGEyNWZjYTI5YWIwN2UwZDljNjZlYWMyYWJlNzZhZTlkNDliMWQwNDI0ZGU0MGVmM2ExOTQwYWY5NDQ0ODQ0ZTFhMGEifV19XQ== FVPROV1-END
