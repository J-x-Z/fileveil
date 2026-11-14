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
