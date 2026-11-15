#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Bind compiler verification snapshots to the exact signed release bytes."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("project_ci_binding", ROOT / "tools/project-postprocess.py")
PROCESSOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROCESSOR)


def manifest_and_summary(digest="a" * 64):
    return ({"files": [{"path": "app.bin", "mode": "external", "source_sha256": digest}]},
            [{"path": "app.bin", "artifact_sha256": digest}])


class ProjectCiBindingTests(unittest.TestCase):
    def test_matching_authenticated_snapshot_is_accepted(self):
        manifest, summaries = manifest_and_summary()
        PROCESSOR.validate_compiler_manifest(manifest, summaries)

    def test_changed_source_digest_is_rejected(self):
        manifest, summaries = manifest_and_summary()
        manifest["files"][0]["source_sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "authenticated compiler artifact snapshot"):
            PROCESSOR.validate_compiler_manifest(manifest, summaries)

    def test_missing_or_reprocessed_compiler_outputs_are_rejected(self):
        for files in ([], [{"path": "app.bin", "mode": "structure", "source_sha256": "a" * 64}]):
            with self.subTest(files=files), self.assertRaises(ValueError):
                PROCESSOR.validate_compiler_manifest({"files": files}, manifest_and_summary()[1])

    def test_duplicate_manifest_and_verification_paths_are_rejected(self):
        manifest, summaries = manifest_and_summary()
        with self.assertRaises(ValueError):
            PROCESSOR.validate_compiler_manifest(manifest, summaries + summaries)
        for alias in ("app.bin", "APP.BIN"):
            with self.subTest(alias=alias), self.assertRaises(ValueError):
                PROCESSOR.validate_compiler_manifest(
                    {"files": manifest["files"] + [{"path": alias, "mode": "external", "source_sha256": "a" * 64}]},
                    summaries,
                )

    def test_mismatched_snapshot_cannot_publish_an_evidence_directory(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            generation = root / "project" / "000000000001-case"
            generation.mkdir(parents=True)
            manifest, summaries = manifest_and_summary()
            manifest["files"][0]["source_sha256"] = "b" * 64
            encoded = json.dumps(manifest).encode()
            (generation / "manifest.json").write_bytes(encoded)
            report = {"advanced": {"project": {"manifest_sha256": hashlib.sha256(encoded).hexdigest()}}}
            destination = root / "evidence"
            with self.assertRaisesRegex(ValueError, "authenticated compiler artifact snapshot"):
                PROCESSOR.stage_evidence(generation, destination, {"verify": report}, {"compiler_verification": summaries})
            self.assertFalse(destination.exists())
            self.assertFalse(list(root.glob(".fileveil-evidence-*")))

    def test_matching_snapshot_exports_the_manifest_bound_build_bytes(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            payload = b"synthetic container bytes"
            (artifacts / "app.bin").write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            manifest, summaries = manifest_and_summary(digest)
            generation = root / "project" / "000000000001-case"
            generation.mkdir(parents=True)
            encoded = json.dumps(manifest).encode()
            manifest_digest = hashlib.sha256(encoded).hexdigest()
            evidence = b"synthetic verification fixture"
            evidence_digest = hashlib.sha256(evidence).hexdigest()
            (generation / "manifest.json").write_bytes(encoded)
            (generation / "COMMITTED").write_text(manifest_digest)
            (generation / "evidence.json").write_bytes(evidence)
            details = {"manifest_sha256": manifest_digest, "evidence_sha256": evidence_digest,
                       "history_metadata": [{"generation": generation.name, "manifest_sha256": manifest_digest,
                                             "evidence_sha256": evidence_digest}]}
            destination = root / "evidence"
            PROCESSOR.stage_evidence(generation, destination, {"verify": {"advanced": {"project": details}}},
                                     {"compiler_verification": summaries}, artifacts)
            with zipfile.ZipFile(destination / "fileveil-build.zip") as archive:
                self.assertEqual(archive.read("app.bin"), payload)
            with zipfile.ZipFile(destination / "fileveil-evidence.zip") as archive:
                self.assertEqual(archive.read("generation/manifest.json"), encoded)


if __name__ == "__main__":
    unittest.main()

# FVPROV1 5085 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI4OTY1NTZkNjVkM2M3YmVlZmRiYjhiMjE3MTRmYWRmMDc0YTNjZjA5YjJkNTgxZTk1ZWY3NWRmM2UwMTQ2ZTZlIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rlc3RzL3Rlc3RfcHJvamVjdF9jaV9iaW5kaW5nLnB5In0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiNDJmM2NlNTk5ZTUyMTI2MzNhMTk2YTA5MDY3NDlhMzRmMWZhNjdhMzRmMGI2MzRiNDkxMDRjNTlkYzFmOTdiMDllZjRmN2E5NmNkYTVmOWJjZjBkMDUzNzc4Mzg0NDEyZDYyYzk5ZmZmMjhhZDFiNjM1NjRhMjlkZTVhYTBlMDcifV19XQ== FVPROV1-END
