#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Snapshot binding across Windows path stat and descriptor stat views."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile


ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


STAGE = module("snapshot_transfer", "project-ci-stage.py")
COMPILER = module("snapshot_compiler", "project-ci-compiler.py")


def metadata(info, **changes):
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")
    result = {field: getattr(info, field) for field in fields}
    result["st_birthtime_ns"] = getattr(info, "st_birthtime_ns", None)
    result["st_file_attributes"] = getattr(info, "st_file_attributes", 0)
    result.update(changes)
    return SimpleNamespace(**result)


class ProjectCiSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.path = self.root / "program.bin"
        self.content = b"bounded compiler artifact\x00\xff"
        self.path.write_bytes(self.content)
        self.real_fstat = os.fstat

    def windows_descriptor(self, descriptor):
        actual = self.real_fstat(descriptor)
        return metadata(actual, st_ctime_ns=actual.st_ctime_ns + 100)

    def test_native_snapshot_export_and_hash_preserve_bytes(self):
        output = self.root / "transfer.zip"
        with STAGE.archive_new(output) as archive:
            STAGE.write_member(archive, self.path, "artifacts/program.bin", self.path.lstat())
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(archive.read("artifacts/program.bin"), self.content)
        self.assertEqual(COMPILER.sha(self.path), hashlib.sha256(self.content).hexdigest())

    def test_windows_distinct_ctime_views_allow_unchanged_transfer(self):
        archive_bytes = io.BytesIO()
        with patch.object(STAGE.VERIFIER, "WINDOWS", True), patch.object(
            STAGE.os, "fstat", side_effect=self.windows_descriptor
        ):
            with zipfile.ZipFile(archive_bytes, "w") as archive:
                STAGE.write_member(archive, self.path, "program.bin", self.path.lstat())
        with zipfile.ZipFile(archive_bytes) as archive:
            self.assertEqual(archive.read("program.bin"), self.content)

    def test_windows_distinct_ctime_views_allow_unchanged_compiler_hash(self):
        with patch.object(COMPILER.STAGE.VERIFIER, "WINDOWS", True), patch.object(
            COMPILER.os, "fstat", side_effect=self.windows_descriptor
        ):
            self.assertEqual(COMPILER.sha(self.path), hashlib.sha256(self.content).hexdigest())

    def test_descriptor_ctime_change_prevents_transfer_publication(self):
        observations = 0

        def changing_descriptor(descriptor):
            nonlocal observations
            observations += 1
            actual = self.real_fstat(descriptor)
            return metadata(actual, st_ctime_ns=actual.st_ctime_ns + 100 * observations)

        output = self.root / "changed.zip"
        with patch.object(STAGE.VERIFIER, "WINDOWS", True), patch.object(
            STAGE.os, "fstat", side_effect=changing_descriptor
        ):
            with self.assertRaisesRegex(ValueError, "changed during snapshot"):
                with STAGE.archive_new(output) as archive:
                    STAGE.write_member(archive, self.path, "program.bin", self.path.lstat())
        self.assertFalse(output.exists())
        self.assertFalse(list(self.root.glob(".fileveil-zip-*")))

    def test_path_ctime_change_is_rejected_with_stable_descriptor(self):
        actual_lstat = Path.lstat
        observations = 0

        def changing_path(path):
            nonlocal observations
            actual = actual_lstat(path)
            if path == self.path:
                observations += 1
                if observations > 1:
                    return metadata(actual, st_ctime_ns=actual.st_ctime_ns + 100)
            return actual

        with patch.object(STAGE.VERIFIER, "WINDOWS", True), patch.object(
            STAGE.os, "fstat", side_effect=self.windows_descriptor
        ), patch.object(Path, "lstat", changing_path):
            with self.assertRaisesRegex(ValueError, "changed during snapshot"):
                with STAGE.open_snapshot(self.path) as (source, _):
                    self.assertEqual(source.read(), self.content)

    def test_expected_path_ctime_is_checked_before_opening(self):
        actual = self.path.lstat()
        previous = metadata(actual, st_ctime_ns=actual.st_ctime_ns - 100)
        with patch.object(STAGE.VERIFIER, "WINDOWS", True), patch.object(
            STAGE.os, "open", side_effect=AssertionError("changed input was opened")
        ):
            with self.assertRaisesRegex(ValueError, "changed before"):
                with STAGE.open_snapshot(self.path, previous):
                    self.fail("A changed expected path was accepted")

    def test_windows_cross_api_file_identity_fields_remain_mandatory(self):
        for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_birthtime_ns"):
            with self.subTest(field=field):
                def different_descriptor(descriptor):
                    info = self.windows_descriptor(descriptor)
                    value = getattr(info, field)
                    return metadata(info, **{field: 1 if value is None else value + 1})

                with patch.object(STAGE.VERIFIER, "WINDOWS", True), patch.object(
                    STAGE.os, "fstat", side_effect=different_descriptor
                ):
                    with self.assertRaisesRegex(ValueError, "replaced before"):
                        with STAGE.open_snapshot(self.path):
                            self.fail("A different file identity was accepted")

    def test_reparse_or_nonregular_descriptor_is_rejected(self):
        for changes in ({"st_file_attributes": 0x400}, {"st_mode": stat.S_IFIFO}):
            with self.subTest(changes=changes):
                def unsafe_descriptor(descriptor):
                    return metadata(self.windows_descriptor(descriptor), **changes)

                with patch.object(STAGE.VERIFIER, "WINDOWS", True), patch.object(
                    STAGE.os, "fstat", side_effect=unsafe_descriptor
                ):
                    with self.assertRaisesRegex(ValueError, "replaced before"):
                        with STAGE.open_snapshot(self.path):
                            self.fail("An unsafe descriptor was accepted")

    def test_symbolic_input_is_rejected(self):
        symbolic = self.root / "symbolic.bin"
        try:
            symbolic.symlink_to(self.path)
        except OSError as error:
            self.skipTest(f"Symbolic links unavailable in this environment: {error}")
        with self.assertRaisesRegex(ValueError, "regular non-reparse"):
            COMPILER.sha(symbolic)

    def test_compiler_hash_still_enforces_its_file_budget(self):
        with self.assertRaisesRegex(ValueError, "regular-file budget"):
            COMPILER.sha(self.path, len(self.content) - 1)


if __name__ == "__main__":
    unittest.main()

# FVPROV1 7549 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI3MzgyMWExOGViMzFjNTRhOGZmZTM0ZjU4MDg4NTE4ZmUyNzdiYWMyOTk5YjM2YWUxYTI4MDdhMWZiOGQ0MzU4IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rlc3RzL3Rlc3RfcHJvamVjdF9jaV9zbmFwc2hvdC5weSJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6ImE2Y2Y1OTUzYjg4MGI3ZjNjMzA2MDFhYWQ4MThlMzFjZTA2MzcyMWJkY2ZjNmVjYjFkOTliYjVjOWIxOTkyYjc0ZDdhYzMzZmNiNGVlMDMyNDY3MzgzZjc0NTBhNjUwNDc0ZjQzNmVjN2RhNGFlNmQwOGI1NGY3NTFkYTc3YzA1In1dfV0= FVPROV1-END
