#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Signing command regressions without distribution credentials."""
import argparse
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("desktop_signing", Path(__file__).resolve().parents[1] / "tools/sign-desktop.py")
SIGNING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SIGNING)


class DesktopSigningTests(unittest.TestCase):
    def test_certificate_fingerprint_validation(self):
        self.assertEqual(SIGNING.fingerprint("a" * 40), "A" * 40)
        with self.assertRaises(argparse.ArgumentTypeError):
            SIGNING.fingerprint("Developer ID Application: Somebody")

    def test_macos_audit_does_not_sign_or_submit(self):
        with mock.patch.object(SIGNING, "run", return_value=subprocess.CompletedProcess([], 1)) as run:
            report = SIGNING.macos(Path("FileVeil.app"), None, None)
        self.assertFalse(report["signed_this_run"])
        self.assertFalse(report["gatekeeper_accepted"])
        for call in run.call_args_list:
            self.assertNotIn("--sign", call.args[0])
            self.assertNotIn("submit", call.args[0])

    def test_development_identity_cannot_be_used_for_distribution(self):
        listing = f'1) {"A" * 40} "Apple Development: Example"'
        with mock.patch.object(SIGNING, "run", return_value=subprocess.CompletedProcess([], 0, listing)):
            with self.assertRaisesRegex(ValueError, "Developer ID"):
                SIGNING.macos(Path("FileVeil.app"), "A" * 40, None)

    def test_notarization_requires_distribution_signature(self):
        with mock.patch.object(SIGNING, "run", return_value=subprocess.CompletedProcess([], 1)) as run:
            with self.assertRaisesRegex(ValueError, "Developer ID"):
                SIGNING.macos(Path("FileVeil.app"), None, "local-profile")
        self.assertFalse(any("submit" in call.args[0] for call in run.call_args_list))

    def test_notarization_staging_uses_private_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            app = Path(temporary) / "FileVeil.app"
            app.mkdir()
            with mock.patch.object(SIGNING, "run", return_value=subprocess.CompletedProcess([], 0, '{"status":"Accepted"}')) as run:
                SIGNING.macos(app, None, "local-profile")
            submission = next(call.args[0] for call in run.call_args_list if "submit" in call.args[0])
            archive = Path(submission[3])
            self.assertEqual(archive.name, "upload.zip")
            self.assertEqual(archive.parent.parent, app.parent)
            self.assertNotEqual(archive.parent, app.parent)
            self.assertFalse(archive.parent.exists())

    def test_windows_audit_reports_real_unsigned_state(self):
        with mock.patch.object(SIGNING, "powershell", return_value=subprocess.CompletedProcess([], 0, '{"status":"NotSigned","timestamped":false}')):
            report = SIGNING.windows(Path("FileVeil.exe"), None)
        self.assertEqual(report["authenticode_status"], "NotSigned")
        self.assertFalse(report["signed_this_run"])

    def test_windows_requires_valid_timestamped_signature(self):
        with mock.patch.object(SIGNING.shutil, "which", return_value="signtool"), mock.patch.object(SIGNING, "run"), mock.patch.object(SIGNING, "powershell", return_value=subprocess.CompletedProcess([], 0, '{"status":"Valid","timestamped":false}')):
            with self.assertRaisesRegex(ValueError, "timestamp"):
                SIGNING.windows(Path("FileVeil.exe"), "A" * 40)


if __name__ == "__main__":
    unittest.main()

# FVPROV1 3703 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJjYjBkYjViYjgyYzAzMWNhMzBkOWE3ZGFkYWI2ZDgyZjgwYmU4YzFlNzQ2MjY5OTVkYjVkN2VlNzQ4ZmZhM2NlIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rlc3RzL3Rlc3RfZGVza3RvcF9zaWduaW5nLnB5In0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiNjhkYmJhZjEyZDA0ZGNmNWY2NGEzMGFhNDY1NjQxMTM0MWNhM2MyYTUyMjY0MWM2Mzc2ZThkZWU0ZGM3OWI3MzU2MWJhMDg5ZDY5MTY0YzdhM2E5MTdjOTljZjJlYjBmYTAwZWRlMjIwMmVjMWZkMGQ0ZjdjNTI2Y2Y3YTU3MDkifV19XQ== FVPROV1-END
