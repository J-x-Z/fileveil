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
    def test_windows_pass_dependencies_are_static_and_keep_secrets_out(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            (root / "vcpkg.exe").touch()
            (root / "scripts/buildsystems").mkdir(parents=True)
            (root / "scripts/buildsystems/vcpkg.cmake").touch()
            prefix = root / "installed/x64-windows-static-md"
            (prefix / "include").mkdir(parents=True)
            (prefix / "lib").mkdir()
            (prefix / "include/zlib.h").touch()
            (prefix / "lib/libzs.lib").touch()
            (prefix / "share/zstd").mkdir(parents=True)
            (prefix / "share/zstd/zstdConfig.cmake").touch()
            environment = root / "environment"
            with patch.dict(INSTALLER.os.environ, {"VCPKG_INSTALLATION_ROOT": str(root),
                    "GITHUB_ENV": str(environment), "CMAKE_PREFIX_PATH": "existing-prefix",
                    "FILEVEIL_SIGNING_KEY_BASE64": "test-secret"}), \
                    patch.object(INSTALLER.subprocess, "run") as run:
                INSTALLER.windows_pass_dependencies()
                self.assertEqual(run.call_args.args[0], [str(root / "vcpkg.exe"), "install",
                    "zlib:x64-windows-static-md", "zstd:x64-windows-static-md"])
                self.assertNotIn("FILEVEIL_SIGNING_KEY_BASE64", run.call_args.kwargs["env"])
                self.assertEqual(INSTALLER.os.environ["CMAKE_PREFIX_PATH"],
                                 str(prefix) + INSTALLER.os.pathsep + "existing-prefix")
            self.assertIn("CMAKE_PREFIX_PATH=" + str(prefix) + INSTALLER.os.pathsep + "existing-prefix\n",
                          environment.read_text())
            self.assertIn("FILEVEIL_CI_VCPKG_ROOT=" + str(root) + "\n", environment.read_text())

    def test_missing_windows_support_files_fail_before_environment_export(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "vcpkg.exe").touch()
            (root / "scripts/buildsystems").mkdir(parents=True)
            (root / "scripts/buildsystems/vcpkg.cmake").touch()
            environment = root / "environment"
            with patch.dict(INSTALLER.os.environ, {"VCPKG_INSTALLATION_ROOT": str(root),
                    "GITHUB_ENV": str(environment)}), patch.object(INSTALLER.subprocess, "run"):
                with self.assertRaisesRegex(ValueError, "development files"):
                    INSTALLER.windows_pass_dependencies()
            self.assertFalse(environment.exists())

    def test_macos_does_not_override_system_cpp_runtime_search(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            environment_file = root / "environment"
            with patch.object(INSTALLER.sys, "argv", ["project-ci-llvm.py", str(root / "llvm")]), \
                    patch.object(INSTALLER.sys, "platform", "darwin"), \
                    patch.dict(INSTALLER.os.environ, {"GITHUB_ENV": str(environment_file),
                        "GITHUB_PATH": str(root / "path"), "DYLD_LIBRARY_PATH": "existing-system-search"}), \
                    patch.object(INSTALLER, "install"), \
                    patch.object(INSTALLER.subprocess, "run"):
                INSTALLER.main()
                self.assertEqual(INSTALLER.os.environ["DYLD_LIBRARY_PATH"], "existing-system-search")
            self.assertNotIn("DYLD_LIBRARY_PATH", environment_file.read_text())

    def test_main_exports_sdk_environment_and_checks_executables(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            destination = root / "llvm"
            environment_file = root / "environment"
            path_file = root / "path"
            windows = INSTALLER.os.name == "nt"
            with patch.object(INSTALLER.sys, "argv", ["project-ci-llvm.py", str(destination)]), \
                    patch.object(INSTALLER.sys, "platform", "win32" if windows else "linux"), \
                    patch.dict(INSTALLER.os.environ, {"GITHUB_ENV": str(environment_file),
                        "GITHUB_PATH": str(path_file), "PATH": "original", "LD_LIBRARY_PATH": "python-library"}), \
                    patch.object(INSTALLER, "install") as install, \
                    patch.object(INSTALLER.subprocess, "run") as run:
                INSTALLER.main()
                install.assert_called_once_with(destination)
                expected_library = "python-library" if windows else str(destination / "lib") + INSTALLER.os.pathsep + "python-library"
                self.assertEqual(INSTALLER.os.environ["LD_LIBRARY_PATH"], expected_library)
            lines = environment_file.read_text().splitlines()
            self.assertIn("LLVM_PATH=" + str(destination), lines)
            self.assertEqual(path_file.read_text(), str(destination / "bin") + "\n")
            commands = [call.args[0] for call in run.call_args_list]
            suffix = ".exe" if windows else ""
            expected_commands = [] if windows else [["ldd", str(destination / "bin/opt")]]
            expected_commands.extend([[str(destination / "bin" / (name + suffix)), "--version"] for name in ("opt", "clang")])
            self.assertEqual(commands, expected_commands)

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

# FVPROV1 12779 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI2YWQyMmRiYjBiZDIzNzJhMTI5MDBhZmJhMjUyNTMyMGM5YmI1YjIyZWY1NzdkNzNkNzU4NWUzNDE4OWMwZDFlIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rlc3RzL3Rlc3RfcHJvamVjdF9jaV9sbHZtLnB5In0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiZDEzYTM5YjU5MTJjMjJhY2IzYTljNDZjMGUzZTYzNTMzZjhlYjhlZWFiZTQwYTBiZTI3MmJmNWVjZWU1Zjg2ZjY1ZDk0OWQ1NzQzMDlhY2RiZTVhMDQwZDAxYTkzY2Q5N2ZjMTUwZGE1YWMxMTk4YjYzNjQzMDdjOTMzOGEzMDcifV19XQ== FVPROV1-END
