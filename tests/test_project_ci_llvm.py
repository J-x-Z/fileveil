#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Offline regressions for the pinned CI LLVM installer boundary."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("project_ci_llvm", ROOT / "tools/project-ci-llvm.py")
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


def sdk_archive():
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:xz") as archive:
        for name, data in (
            ("sdk/lib/cmake/llvm/LLVMConfig.cmake", b"# synthetic LLVM package\n"),
            ("sdk/bin/clang", b"synthetic compiler bytes, never executed\n"),
        ):
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(data))
    return stream.getvalue()


class ProjectCiLlvmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = sdk_archive()
        cls.checksum = hashlib.sha256(cls.payload).hexdigest()

    def test_fixed_platform_assets_and_download_urls_match(self):
        expected = {
            ("linux", "x86_64"): "LLVM-23.1.5-Linux-X64.tar.xz",
            ("darwin", "arm64"): "LLVM-23.1.5-macOS-ARM64.tar.xz",
            ("win32", "amd64"): "clang+llvm-23.1.5-x86_64-pc-windows-msvc.tar.xz",
        }
        self.assertEqual(INSTALLER.VERSION, "23.1.5")
        self.assertEqual(set(INSTALLER.ASSETS), set(expected))
        for platform_id, asset in expected.items():
            with self.subTest(platform=platform_id), tempfile.TemporaryDirectory() as name:
                original_asset, original_checksum = INSTALLER.ASSETS[platform_id]
                self.assertEqual(original_asset, asset)
                self.assertRegex(original_checksum, r"^[a-f0-9]{64}$")
                destination = Path(name) / "llvm"
                with patch.object(INSTALLER, "sys", SimpleNamespace(platform=platform_id[0])), \
                        patch.object(INSTALLER.platform, "machine", return_value=platform_id[1].upper()), \
                        patch.dict(INSTALLER.ASSETS, {platform_id: (asset, self.checksum)}), \
                        patch.object(INSTALLER.urllib.request, "urlopen", return_value=io.BytesIO(self.payload)) as download:
                    self.assertEqual(INSTALLER.install(destination), destination)
                download.assert_called_once_with(
                    "https://github.com/llvm/llvm-project/releases/download/llvmorg-23.1.5/" + asset,
                    timeout=120,
                )
                self.assertEqual((destination / "bin/clang").read_bytes(), b"synthetic compiler bytes, never executed\n")
                self.assertTrue((destination / "lib/cmake/llvm/LLVMConfig.cmake").is_file())
                self.assertEqual(list(Path(name).iterdir()), [destination])

    def test_checksum_failure_leaves_no_destination_or_scratch_directory(self):
        with tempfile.TemporaryDirectory() as name:
            destination = Path(name) / "llvm"
            asset = INSTALLER.ASSETS[("linux", "x86_64")][0]
            with patch.object(INSTALLER, "sys", SimpleNamespace(platform="linux")), \
                    patch.object(INSTALLER.platform, "machine", return_value="x86_64"), \
                    patch.dict(INSTALLER.ASSETS, {("linux", "x86_64"): (asset, "0" * 64)}), \
                    patch.object(INSTALLER.urllib.request, "urlopen", return_value=io.BytesIO(self.payload)):
                with self.assertRaisesRegex(ValueError, "checksum"):
                    INSTALLER.install(destination)
            self.assertFalse(destination.exists())
            self.assertEqual(list(Path(name).iterdir()), [])

    def test_unsupported_platform_fails_before_download(self):
        with tempfile.TemporaryDirectory() as name:
            destination = Path(name) / "llvm"
            with patch.object(INSTALLER, "sys", SimpleNamespace(platform="freebsd13")), \
                    patch.object(INSTALLER.platform, "machine", return_value="AARCH64"), \
                    patch.object(INSTALLER.urllib.request, "urlopen") as download:
                with self.assertRaisesRegex(ValueError, "does not support freebsd13/aarch64"):
                    INSTALLER.install(destination)
            download.assert_not_called()
            self.assertFalse(destination.exists())
            self.assertEqual(list(Path(name).iterdir()), [])

    def test_existing_directory_and_file_are_preserved_without_download(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            directory = root / "existing-directory"
            directory.mkdir()
            marker = directory / "preserved.txt"
            marker.write_bytes(b"preserved")
            existing_file = root / "existing-file"
            existing_file.write_bytes(b"preserved")
            for destination in (directory, existing_file):
                with self.subTest(destination=destination.name), patch.object(INSTALLER.urllib.request, "urlopen") as download:
                    with self.assertRaisesRegex(ValueError, "requires a new directory"):
                        INSTALLER.install(destination)
                    download.assert_not_called()
            self.assertEqual(marker.read_bytes(), b"preserved")
            self.assertEqual(existing_file.read_bytes(), b"preserved")

    def test_dangling_symbolic_destination_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            destination = Path(name) / "llvm"
            try:
                destination.symlink_to(Path(name) / "missing", target_is_directory=True)
            except OSError as error:
                self.skipTest("Symbolic-link creation is unavailable: " + str(error))
            with patch.object(INSTALLER.urllib.request, "urlopen") as download:
                with self.assertRaisesRegex(ValueError, "requires a new directory"):
                    INSTALLER.install(destination)
            download.assert_not_called()
            self.assertTrue(destination.is_symlink())

    def test_destination_created_during_download_is_preserved(self):
        with tempfile.TemporaryDirectory() as name:
            destination = Path(name) / "llvm"
            asset = INSTALLER.ASSETS[("linux", "x86_64")][0]
            created_identity = []

            def download(*_arguments, **_keywords):
                destination.mkdir()
                created_identity.append((destination.stat().st_dev, destination.stat().st_ino))
                return io.BytesIO(self.payload)

            with patch.object(INSTALLER, "sys", SimpleNamespace(platform="linux")), \
                    patch.object(INSTALLER.platform, "machine", return_value="x86_64"), \
                    patch.dict(INSTALLER.ASSETS, {("linux", "x86_64"): (asset, self.checksum)}), \
                    patch.object(INSTALLER.urllib.request, "urlopen", side_effect=download):
                with self.assertRaises((OSError, ValueError)):
                    INSTALLER.install(destination)
            self.assertEqual((destination.stat().st_dev, destination.stat().st_ino), created_identity[0])
            self.assertEqual(list(destination.iterdir()), [])


if __name__ == "__main__":
    unittest.main()

# FVPROV1 7499 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI0ZTMyZWU3YjU3ZGQ1MGRhMTM3Yzk5Y2I3ZjJhMGJlMTFmNTc3N2RkZmIyZmIwMWJhOTU1ZmUyZmU1MTI5OGIwIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rlc3RzL3Rlc3RfcHJvamVjdF9jaV9sbHZtLnB5In0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiZTU1MjM0MjU1OGYwMmFmOWM1ZTE3NzdlOGE2NjcxZDdmMGI4ODBkZGQ3NDc4MjVlMWUxMDBkYTllYTFmMGI5YjIyYzU3NjVhMjAzNWUyYzk0MTYzZWRlZjhjZWM1MDU3MjNiOTM0NTBmMDY2MTY0ZjFkNGM0ZGYzZTM0MzYyMGQifV19XQ== FVPROV1-END
