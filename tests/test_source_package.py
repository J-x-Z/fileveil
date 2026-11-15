# SPDX-License-Identifier: MPL-2.0
"""Source ZIP verification with the existing synthetic signed-tree fixture."""
import binascii
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PACKAGE = load("fileveil_source_package", ROOT / "tools/verify-source-package.py")
FIXTURES = load("fileveil_source_package_fixtures", ROOT / "tests/test_source_tree_verifier.py")


class SourcePackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FIXTURES.SourceTreeTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        FIXTURES.SourceTreeTests.tearDownClass()

    def setUp(self):
        self.fixture = FIXTURES.SourceTreeTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.directory = Path(self.fixture.directory.name)
        self.work = self.directory / "work"
        patcher = mock.patch.object(PACKAGE, "WORK", self.work)
        patcher.start()
        self.addCleanup(patcher.stop)

    def archive(self, name="source.zip", extras=(), replacements=None):
        path = self.directory / name
        replacements = replacements or {}
        with warnings.catch_warnings(), zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            warnings.simplefilter("ignore", UserWarning)
            for source in sorted(self.fixture.root.rglob("*")):
                if source.is_file():
                    relative = source.relative_to(self.fixture.root).as_posix()
                    archive.writestr(relative, replacements.get(relative, source.read_bytes()))
            for member, data in extras:
                archive.writestr(member, data)
        return path

    def verify(self, archive):
        return PACKAGE.verify(archive, self.fixture.key["key_id"], self.fixture.openssl)

    def test_valid_signed_archive_pin_and_new_report(self):
        archive = self.archive()
        result = self.verify(archive)
        self.assertEqual(result["archive_sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())
        self.assertEqual(result["independent_verifier"]["catalog_signature"], "valid")
        self.assertEqual(result["independent_verifier"]["release_key_trust"], "externally_pinned")
        self.assertEqual(list(self.work.iterdir()), [])
        report = self.directory / "report.json"
        with mock.patch("builtins.print"):
            self.assertEqual(PACKAGE.main([str(archive), "--key-id", self.fixture.key["key_id"],
                "--openssl", self.fixture.openssl, "--report", str(report)]), 0)
        original = report.read_bytes()
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            PACKAGE.main([str(archive), "--report", str(report)])
        self.assertEqual(report.read_bytes(), original)

    def test_crlf_rewrite_and_wrong_pin_fail(self):
        name = "src/main.py"
        original = (self.fixture.root / name).read_bytes()
        archive = self.archive(replacements={name: original.replace(b"\n", b"\r\n")})
        with self.assertRaisesRegex(ValueError, "hash or size"):
            self.verify(archive)
        valid = self.archive("valid.zip")
        with self.assertRaisesRegex(ValueError, "external pin"):
            PACKAGE.verify(valid, "0" * 64, self.fixture.openssl)
        self.assertEqual(list(self.work.iterdir()), [])

    def test_archive_python_verifier_is_data(self):
        name = "tools/verify-source-tree.py"
        path = self.fixture.root / name
        path.parent.mkdir()
        data = b"raise RuntimeError('Archive verifier must never execute')\n"
        path.write_bytes(data)
        self.fixture.entries.append({"path": name, "sha256": hashlib.sha256(data).hexdigest(),
                                     "size_bytes": len(data), "marked": False})
        self.fixture.refresh()
        self.assertEqual(self.verify(self.archive())["result"], "verified_within_scope")

    def test_unsafe_duplicate_case_alias_and_nonregular_members_fail(self):
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        cases = ["../outside", "/absolute", "C:/outside", "src\\other.py",
                 "src/main.py", "SRC/MAIN.PY", "SRC/other.py", "folder/", "target/cache", link]
        for index, name in enumerate(cases):
            with self.subTest(member=str(name)):
                archive = self.archive(str(index) + ".zip", [(name, b"untrusted payload")])
                with self.assertRaises(ValueError):
                    self.verify(archive)
        self.assertEqual(list(self.work.iterdir()), [])

    def test_archive_member_count_and_declared_byte_budgets(self):
        archive = self.archive()
        for name, limit in [("MAX_FILES", 1), ("MAX_FILE_BYTES", 32),
                            ("MAX_TOTAL_BYTES", 100), ("MAX_ARCHIVE_BYTES", archive.stat().st_size - 1)]:
            with self.subTest(budget=name), mock.patch.object(PACKAGE, name, limit):
                with self.assertRaisesRegex(ValueError, "budget"):
                    self.verify(archive)

    def test_lying_deflate_expanded_size_is_rejected(self):
        path = self.directory / "understated.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("payload", b"A" * 4000)
        data = bytearray(path.read_bytes())
        central = data.index(b"PK\x01\x02")
        crc = binascii.crc32(b"A")
        for offset, checksum_offset, size_offset in [(0, 14, 22), (central, 16, 24)]:
            struct.pack_into("<I", data, offset + checksum_offset, crc)
            struct.pack_into("<I", data, offset + size_offset, 1)
        path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "expanded beyond its declared"):
            self.verify(path)

    def test_corrupt_deflate_cli_writes_structured_failed_report(self):
        path = self.directory / "corrupt-deflate.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("payload", b"A" * 2000)
        data = bytearray(path.read_bytes())
        filename_length, extra_length = struct.unpack_from("<HH", data, 26)
        data[30 + filename_length + extra_length] = 0x07  # Reserved DEFLATE block type.
        path.write_bytes(data)
        report = self.directory / "corrupt-report.json"
        with mock.patch("sys.stderr"):
            self.assertEqual(PACKAGE.main([str(path), "--report", str(report)]), 1)
        result = json.loads(report.read_text())
        self.assertEqual(result["result"], "failed")
        self.assertIn("decompressing", result["reason"])

    def test_same_fd_snapshot_rejects_archive_mutation(self):
        path = self.archive()
        original_extract = PACKAGE.extract

        def changed(*arguments):
            result = original_extract(*arguments)
            info = path.stat()
            os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 10_000_000))
            return result

        with mock.patch.object(PACKAGE, "extract", side_effect=changed):
            with self.assertRaisesRegex(ValueError, "changed during snapshot"):
                self.verify(path)


class SourceLineEndingTests(unittest.TestCase):
    def test_git_autocrlf_checkout_preserves_required_source_bytes(self):
        git = shutil.which("git")
        if git is None:
            self.skipTest("Git is unavailable")
        with tempfile.TemporaryDirectory(prefix="fileveil-source-lf-") as name:
            root = Path(name)
            repository, checkout = root / "repository", root / "checkout"
            repository.mkdir()
            checkout.mkdir()
            (repository / ".gitattributes").write_bytes((ROOT / ".gitattributes").read_bytes())
            files = {"tools/example.c": b"int example(void) { return 7; }\n",
                     "tools/example.cpp": b"int example() { return 7; }\n",
                     "tools/CMakeLists.txt": b"project(synthetic)\n",
                     "tools/example.sh": b"#!/bin/sh\nprintf 'synthetic\\n'\n",
                     "tools/example.hpp": b"#pragma once\nint example();\n"}
            for path, data in files.items():
                selected = repository / path
                selected.parent.mkdir(exist_ok=True)
                selected.write_bytes(data)
            subprocess.run([git, "init", "-q", str(repository)], check=True, capture_output=True, timeout=15)
            for arguments in [("config", "core.autocrlf", "true"), ("config", "core.safecrlf", "false"),
                              ("add", "--all"), ("checkout-index", "--all", "--prefix=" + checkout.as_posix() + "/")]:
                subprocess.run([git, "-C", str(repository), *arguments], check=True, capture_output=True, timeout=15)
            for path, original in files.items():
                self.assertEqual((checkout / path).read_bytes(), original, path)


if __name__ == "__main__":
    unittest.main()

# FVPROV1 9391 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI3ZTZhNGRlMmFlZDI2ZDRlZWFmNWZmNjM5NWFjMmY1ODk0YjZiNDY1NjczODc1YWUxNWU2OGVjMmU1NzYyZTZhIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rlc3RzL3Rlc3Rfc291cmNlX3BhY2thZ2UucHkifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiIyMTI3OTQ5M2NhYjgyYTBlZWRlMzU4NmY5MWY5OGZlY2VmZTRjOTU1YWU3MGNhYTcxNDdiZTZiYzc0NTkwMGE5Y2U5ZGVjNDlhNDBjMTY2YzkwNGQxMDExMjVlMjc0MWU4ZTFiOWMyNWFiOTM4YzRkYzE0OGFhNGE0NzU1NTYwYSJ9XX1d FVPROV1-END
