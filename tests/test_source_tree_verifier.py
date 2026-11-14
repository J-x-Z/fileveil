#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Small source-inventory regressions with ephemeral OpenSSL signing keys."""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import marshal
import os
from pathlib import Path
import stat
import subprocess
import struct
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace


SCRIPT = Path(__file__).resolve().parents[1] / "tools/verify-source-tree.py"
SPEC = importlib.util.spec_from_file_location("fileveil_source_tree", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class SourceTreeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.openssl = VERIFY.openssl_path(None)
        except ValueError as error:
            raise unittest.SkipTest(str(error)) from None
        cls.key_directory = tempfile.TemporaryDirectory(prefix="fileveil-source-key-test-")
        cls.key_path = Path(cls.key_directory.name) / "private.pem"
        generated = subprocess.run(
            [cls.openssl, "genpkey", "-algorithm", "ED25519", "-out", str(cls.key_path)],
            capture_output=True, timeout=15,
        )
        if generated.returncode:
            cls.key_directory.cleanup()
            raise unittest.SkipTest("OpenSSL Ed25519 support is unavailable")
        public = subprocess.check_output(
            [cls.openssl, "pkey", "-in", str(cls.key_path), "-pubout", "-outform", "DER"],
            timeout=15,
        )[-32:]
        cls.key = {
            "schema": "fileveil.release.signing-key.v1",
            "repository": VERIFY.REPOSITORY,
            "subject": "Synthetic source fixture",
            "algorithm": "Ed25519",
            "key_id": hashlib.sha256(public).hexdigest(),
            "public_key_hex": public.hex(),
        }

    @classmethod
    def tearDownClass(cls):
        cls.key_directory.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="fileveil-source-tree-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "tree"
        (self.root / "provenance").mkdir(parents=True)
        (self.root / "src").mkdir()
        (self.root / VERIFY.RELEASE_KEY).write_text(json.dumps(self.key) + "\n")
        (self.root / "src/main.py").write_bytes(self.mark(b'print("synthetic")\n'))
        (self.root / "third-party.bin").write_bytes(b"\0synthetic third-party integrity control")
        self.entries = []
        for name in (VERIFY.RELEASE_KEY, "src/main.py", "third-party.bin"):
            data = (self.root / name).read_bytes()
            self.entries.append({
                "path": name, "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data), "marked": name == "src/main.py",
            })
        self.refresh()

    def signature(self, domain, body):
        message = Path(self.directory.name) / "message.bin"
        output = Path(self.directory.name) / "signature.bin"
        message.write_bytes(domain + VERIFY.CRYPTO.canonical(body))
        subprocess.run(
            [self.openssl, "pkeyutl", "-sign", "-inkey", str(self.key_path), "-rawin", "-in", str(message), "-out", str(output)],
            check=True, capture_output=True, timeout=15,
        )
        return {
            "key_id": self.key["key_id"], "public_key_hex": self.key["public_key_hex"],
            "signature_hex": output.read_bytes().hex(),
        }

    def record(self, source, author="Synthetic owner"):
        body = {
            "schema": VERIFY.CRYPTO.V2, "algorithm": "Ed25519", "kind": "create",
            "mode": "self_sign", "sequence": 0, "previous_record_sha256": None,
            "content_sha256": hashlib.sha256(source).hexdigest(), "work_id": "synthetic-source-work",
            "author": author, "edition": VERIFY.RELEASE, "version": VERIFY.RELEASE,
            "parent_version": None, "created_at": "2026-11-14T00:00:00Z",
            "actor_key_id": self.key["key_id"], "transfer_to_key_id": None,
            "issuer_policy": None, "copy_id": "synthetic-copy",
        }
        return {"body": body, "signatures": [self.signature(b"FileVeil provenance signature v2\0", body)]}

    def carrier(self, source, records):
        encoded = base64.b64encode(VERIFY.CRYPTO.canonical(records))
        return source + b"\n# FVPROV1 " + str(len(source)).encode() + b" " + encoded + b" FVPROV1-END\n"

    def mark(self, source):
        return self.carrier(source, [self.record(source)])

    def refresh(self):
        lines = [
            f"schema = {json.dumps(VERIFY.SCHEMA)}", f"release = {json.dumps(VERIFY.RELEASE)}",
            f"repository = {json.dumps(VERIFY.REPOSITORY)}",
            'created_at = "2026-11-14T00:00:00Z"',
        ]
        for entry in self.entries:
            lines.extend(["", "[[files]]"])
            for name, value in entry.items():
                lines.append(f"{name} = {json.dumps(value)}")
        self.catalog_base = ("\n".join(lines) + "\n").encode()
        self.catalog_records = [self.record(self.catalog_base)]
        (self.root / VERIFY.CATALOG).write_bytes(self.carrier(self.catalog_base, self.catalog_records))
        body = {
            "schema": "fileveil.provenance.evidence.v1", "work_id": "synthetic-source-work",
            "copy_id": "synthetic-copy", "records": self.catalog_records,
            "assets": [{"version": VERIFY.RELEASE, "sha256": hashlib.sha256(self.catalog_base).hexdigest(), "size_bytes": len(self.catalog_base)}],
            "checkpoints": [], "timestamps": [],
        }
        self.package = {"body": body, "signature": self.signature(b"FileVeil copyright evidence package v1\0", body)}
        (self.root / VERIFY.EVIDENCE).write_text(json.dumps(self.package))

    def verify(self, pin=None):
        return VERIFY.verify(self.root, pin, self.openssl)

    def test_signed_tree_and_external_key_pin(self):
        report = self.verify(self.key["key_id"])
        self.assertEqual(report["result"], "verified_within_scope")
        self.assertEqual(report["files_verified"], 3)
        self.assertEqual(report["marked_source_signatures_verified"], 1)
        self.assertEqual(report["release_key_trust"], "externally_pinned")

    def test_wrong_key_pin_and_envelope_signer_fail(self):
        with self.assertRaisesRegex(ValueError, "external pin"):
            self.verify("0" * 64)
        self.package["signature"]["key_id"] = "0" * 64
        (self.root / VERIFY.EVIDENCE).write_text(json.dumps(self.package))
        with self.assertRaisesRegex(ValueError, "Evidence signer"):
            self.verify()

    def test_tampered_file_and_missing_file_fail(self):
        path = self.root / "src/main.py"
        original = path.read_bytes()
        path.write_bytes(original.replace(b"synthetic", b"changed", 1))
        with self.assertRaisesRegex(ValueError, "hash or size"):
            self.verify()
        path.unlink()
        with self.assertRaises(OSError):
            self.verify()

    def test_invalid_catalog_and_evidence_signatures_fail(self):
        path = self.root / VERIFY.CATALOG
        path.write_bytes(path.read_bytes().replace(b"source-catalog.v1", b"source-catalog.v2", 1))
        with self.assertRaisesRegex(ValueError, "content binding"):
            self.verify()
        self.refresh()
        encoded = self.package["signature"]["signature_hex"]
        self.package["signature"]["signature_hex"] = ("0" if encoded[0] != "0" else "1") + encoded[1:]
        (self.root / VERIFY.EVIDENCE).write_text(json.dumps(self.package))
        with self.assertRaisesRegex(ValueError, "Ed25519 signature"):
            self.verify()

    def test_different_valid_inline_history_fails(self):
        different = [self.record(self.catalog_base, author="Another signed declaration")]
        (self.root / VERIFY.CATALOG).write_bytes(self.carrier(self.catalog_base, different))
        with self.assertRaisesRegex(ValueError, "histories differ"):
            self.verify()

    def test_each_marked_source_signature_is_checked(self):
        path = self.root / "src/main.py"
        base, packet = VERIFY.CRYPTO.extract_source_carrier(path.read_bytes())
        records = json.loads(packet)
        encoded = records[0]["signatures"][0]["signature_hex"]
        records[0]["signatures"][0]["signature_hex"] = ("0" if encoded[0] != "0" else "1") + encoded[1:]
        data = self.carrier(base, records)
        path.write_bytes(data)
        self.entries[1].update(sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data))
        self.refresh()
        with self.assertRaisesRegex(ValueError, "Ed25519 signature"):
            self.verify()

    def test_unmarked_file_cannot_claim_a_source_signature(self):
        self.entries[2]["marked"] = True
        self.refresh()
        with self.assertRaisesRegex(ValueError, "no provenance carrier"):
            self.verify()

    def test_traversal_absolute_and_noncanonical_paths_fail(self):
        original = copy.deepcopy(self.entries)
        for name in (".", "../outside", "/absolute", "src/../main.py", "src//main.py", "C:/drive", "src\\main.py"):
            with self.subTest(path=name):
                self.entries = copy.deepcopy(original)
                self.entries[1]["path"] = name
                self.refresh()
                with self.assertRaisesRegex(ValueError, "relative POSIX path"):
                    self.verify()

    def test_duplicate_case_alias_and_self_references_fail(self):
        original = copy.deepcopy(self.entries)
        for name in ("src/main.py", "SRC/MAIN.PY", VERIFY.CATALOG, VERIFY.EVIDENCE):
            with self.subTest(path=name):
                self.entries = copy.deepcopy(original)
                extra = copy.deepcopy(self.entries[1])
                extra["path"] = name
                self.entries.append(extra)
                self.refresh()
                with self.assertRaisesRegex(ValueError, "Duplicate|fixed exceptions"):
                    self.verify()

    def test_only_documented_locations_are_ignored(self):
        for name in (".git/config", "target/cache", "work/private.key", "dist/package.zip", "src/__pycache__/cache.pyc", "src/.DS_Store"):
            path = self.root / name
            path.parent.mkdir(exist_ok=True, parents=True)
            path.write_bytes(b"synthetic excluded data")
        self.assertEqual(self.verify()["files_verified"], 3)
        path = self.root / "nested/target/unlisted.txt"
        path.parent.mkdir(parents=True)
        path.write_text("unexpected")
        with self.assertRaisesRegex(ValueError, "unlisted files"):
            self.verify()

    def test_file_symlink_and_parent_symlink_are_refused(self):
        path = self.root / "src/main.py"
        outside = Path(self.directory.name) / "outside.py"
        path.rename(outside)
        try:
            path.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is unavailable for this user")
        with self.assertRaisesRegex(ValueError, "Symlink"):
            self.verify()
        path.unlink()
        outside.rename(path)
        directory = self.root / "src"
        relocated = Path(self.directory.name) / "outside-directory"
        directory.rename(relocated)
        directory.symlink_to(relocated, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "Symlink"):
            self.verify()

    def test_inventory_budgets_and_field_types(self):
        with mock.patch.object(VERIFY, "MAX_FILES", 1):
            with self.assertRaisesRegex(ValueError, "file count"):
                self.verify()
        with mock.patch.object(VERIFY, "MAX_TOTAL_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "aggregate byte"):
                self.verify()
        self.entries[1]["size_bytes"] = True
        self.refresh()
        with self.assertRaisesRegex(ValueError, "inventory size"):
            self.verify()

    def test_cli_reports_the_verification_scope(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(self.root), "--key-id", self.key["key_id"], "--openssl", self.openssl],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["catalog_signature"], "valid")
        self.assertEqual(report["copyright_identity"], "not_assessed")
        self.assertIn("Third-party", report["scope"])

    def test_adjacent_bytecode_cannot_replace_crypto_source(self):
        tools = Path(self.directory.name) / "trusted-tools"
        tools.mkdir()
        script = tools / SCRIPT.name
        script.write_bytes(SCRIPT.read_bytes())
        helper = tools / "verify-evidence.py"
        helper.write_bytes(SCRIPT.with_name("verify-evidence.py").read_bytes())
        cache = Path(importlib.util.cache_from_source(str(helper)))
        cache.parent.mkdir()
        info = helper.stat()
        header = importlib.util.MAGIC_NUMBER + struct.pack("<III", 0, int(info.st_mtime), info.st_size)
        payload = compile('raise RuntimeError("synthetic unchecked bytecode executed")', str(helper), "exec")
        cache.write_bytes(header + marshal.dumps(payload))
        result = subprocess.run(
            [sys.executable, str(script), str(self.root), "--key-id", self.key["key_id"], "--openssl", self.openssl],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["catalog_signature"], "valid")

    def test_windows_cross_api_binding_retains_identity_fields(self):
        values = dict(st_dev=7, st_ino=11, st_size=19, st_mtime_ns=23,
                      st_ctime_ns=29, st_birthtime_ns=29, st_mode=stat.S_IFREG,
                      st_file_attributes=0)
        by_path = SimpleNamespace(**values)
        opened_values = dict(values, st_ctime_ns=31)
        opened = SimpleNamespace(**opened_values)
        with mock.patch.object(VERIFY, "WINDOWS", True):
            self.assertTrue(VERIFY.matches_opened_file(opened, by_path))
            for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_birthtime_ns"):
                with self.subTest(field=field):
                    changed = dict(opened_values)
                    changed[field] += 1
                    self.assertFalse(VERIFY.matches_opened_file(SimpleNamespace(**changed), by_path))
            reparse = dict(opened_values, st_file_attributes=0x400)
            self.assertFalse(VERIFY.matches_opened_file(SimpleNamespace(**reparse), by_path))
            pipe = dict(opened_values, st_mode=stat.S_IFIFO)
            self.assertFalse(VERIFY.matches_opened_file(SimpleNamespace(**pipe), by_path))
        with mock.patch.object(VERIFY, "WINDOWS", False):
            self.assertFalse(VERIFY.matches_opened_file(opened, by_path))

    def test_windows_distinct_ctime_semantics_allow_an_unchanged_read(self):
        reader = VERIFY.TreeReader(self.root)
        actual_fstat = os.fstat

        def descriptor_info(descriptor):
            actual = actual_fstat(descriptor)
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")
            result = {field: getattr(actual, field) for field in fields}
            result["st_ctime_ns"] += 100
            result["st_birthtime_ns"] = getattr(actual, "st_birthtime_ns", None)
            result["st_file_attributes"] = getattr(actual, "st_file_attributes", 0)
            return SimpleNamespace(**result)

        with mock.patch.object(VERIFY, "WINDOWS", True), mock.patch.object(VERIFY.os, "fstat", side_effect=descriptor_info):
            self.assertEqual(reader.read("third-party.bin"), (self.root / "third-party.bin").read_bytes())

    def test_open_descriptor_ctime_changes_are_still_refused(self):
        reader = VERIFY.TreeReader(self.root)
        actual_fstat = os.fstat
        observations = 0

        def descriptor_info(descriptor):
            nonlocal observations
            actual = actual_fstat(descriptor)
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")
            result = {field: getattr(actual, field) for field in fields}
            observations += 1
            result["st_ctime_ns"] += observations * 100
            result["st_birthtime_ns"] = getattr(actual, "st_birthtime_ns", None)
            result["st_file_attributes"] = getattr(actual, "st_file_attributes", 0)
            return SimpleNamespace(**result)

        with mock.patch.object(VERIFY, "WINDOWS", True), mock.patch.object(VERIFY.os, "fstat", side_effect=descriptor_info):
            with self.assertRaisesRegex(ValueError, "File changed during verification"):
                reader.read("third-party.bin")

    def test_native_path_and_descriptor_metadata_binding(self):
        path = self.root / "third-party.bin"
        data = path.read_bytes()
        path.write_bytes(data)
        by_path = path.lstat()
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if sys.platform == "win32":
                fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_birthtime_ns")
                print(json.dumps({
                    "windows_stat_binding": {
                        "path": {field: getattr(by_path, field, None) for field in fields},
                        "descriptor": {field: getattr(opened, field, None) for field in fields},
                    }
                }), flush=True)
            self.assertTrue(VERIFY.matches_opened_file(opened, by_path))
            self.assertEqual(VERIFY.identity(os.fstat(stream.fileno())), VERIFY.identity(opened))
        self.assertEqual(VERIFY.TreeReader(self.root).read("third-party.bin"), data)


if __name__ == "__main__":
    unittest.main()

# FVPROV1 18119 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJhNGJlYWU0NGEyNmFlYTFiY2UxYzMxYjM1MDE3YjM0MTRhNDIwZmEwZDg4ZmZiNTZhYzQ4OTAxMDJiMjFlYmNhIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4zIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMyIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rlc3RzL3Rlc3Rfc291cmNlX3RyZWVfdmVyaWZpZXIucHkifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiJiZWVjZmVjMmQ5NzA1ZDU0NTJlNGIzYTI1YWY2MTVlYTE3OTMzMmIzYjNhODY4OGQ2YWY3M2JkNDdlY2YwZTdkYWRjYzAyMjc4NzA1ZTBhZTBiYjUzNDQ5NTBhYzA5MjRhZDczMWQ1M2ZlMzFmMTllMjJmMjdlODE4NzFlNzUwNiJ9XX1d FVPROV1-END
