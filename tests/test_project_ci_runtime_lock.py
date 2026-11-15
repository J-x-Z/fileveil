#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Runtime namespace locks stay outside portable signed history."""
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("runtime_lock_stage", ROOT / "tools/project-ci-stage.py")
STAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STAGE)


class RuntimeHistoryLockTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.history = self.root / "history"
        self.namespace = self.history / ("a" * 32)
        generation = self.namespace / "000000000001-generation"
        generation.mkdir(parents=True)
        for name in ("manifest.json", "evidence.json", "COMMITTED"):
            (generation / name).write_bytes(b"signed public history fixture")
        self.lock = self.namespace / ".lock"
        self.lock.touch()

    def test_regular_empty_runtime_lock_is_omitted_and_history_restores(self):
        bundle = self.root / "history.zip"
        STAGE.history_bundle(self.history, bundle)
        with zipfile.ZipFile(bundle) as archive:
            self.assertEqual(len(archive.namelist()), 3)
            self.assertFalse(any(name.endswith(".lock") for name in archive.namelist()))
        restored = self.root / "restored"
        STAGE.receive(bundle, restored, history=True)
        self.assertEqual(len(list(restored.rglob("COMMITTED"))), 1)
        self.assertFalse(list(restored.rglob(".lock")))
        self.assertEqual(self.lock.read_bytes(), b"")

    def test_nonempty_or_misplaced_lock_cannot_be_hidden_from_history(self):
        for path in (self.lock, self.history / ".lock", self.namespace / "000000000001-generation/.lock"):
            with self.subTest(path=path):
                path.write_bytes(b"unexpected data")
                with self.assertRaises(ValueError):
                    STAGE.history_bundle(self.history, self.root / "bad.zip")
                self.assertFalse((self.root / "bad.zip").exists())
                path.unlink()
                self.lock.touch()

    def test_reparse_runtime_lock_is_rejected_without_publication(self):
        original = Path.lstat

        def metadata(path):
            value = original(path)
            if path == self.lock:
                return SimpleNamespace(st_mode=value.st_mode, st_size=0, st_nlink=1,
                                       st_file_attributes=0x400)
            return value

        with patch.object(Path, "lstat", metadata):
            with self.assertRaises(ValueError):
                STAGE.history_bundle(self.history, self.root / "bad.zip")
        self.assertFalse((self.root / "bad.zip").exists())

    def test_symbolic_or_hardlinked_runtime_locks_are_rejected(self):
        target = self.root / "other-file"
        target.touch()
        for symbolic in [True, False]:
            with self.subTest(symbolic=symbolic):
                self.lock.unlink(missing_ok=True)
                try:
                    if symbolic:
                        self.lock.symlink_to(target)
                    else:
                        os.link(target, self.lock)
                except OSError as error:
                    self.skipTest(f"Filesystem link creation unavailable: {error}")
                with self.assertRaises(ValueError):
                    STAGE.history_bundle(self.history, self.root / "bad.zip")
                self.assertFalse((self.root / "bad.zip").exists())


if __name__ == "__main__":
    unittest.main()

# FVPROV1 3785 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJlOTM5ZGE3MGUzNjQ1MmE5NzNlZjBlZjQ2NTc5MTVjNTMyYjEyOTVkODU1MjI2MDNiYzBlMjI2NWFjYTc4ZjZhIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rlc3RzL3Rlc3RfcHJvamVjdF9jaV9ydW50aW1lX2xvY2sucHkifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI4YmI5ZjU0MmE4ZmZjZDI3MDVhM2U1ZTU3MGI0NmYxYTBkOGMwZTI0MWQ5MzllZGEyYjg0NmNlZjhmZjU4YjRmNzYxNWUwMGNjMzNkNTc0NDU5ZjdmN2IyY2FmNzU2Mzc4ZGQ1NzVlNDc5OGNmYWE1MDIyYzVhZTJjMTk1NzkwOSJ9XX1d FVPROV1-END
