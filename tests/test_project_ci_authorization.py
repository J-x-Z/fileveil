#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Bind secret CI operations to independently checked-out caller configuration."""
import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ci_authorization_postprocess", ROOT / "tools/project-postprocess.py")
POST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POST)
COMPILER_SPEC = importlib.util.spec_from_file_location("ci_authorization_compiler", ROOT / "tools/project-ci-compiler.py")
COMPILER = importlib.util.module_from_spec(COMPILER_SPEC)
COMPILER_SPEC.loader.exec_module(COMPILER)
AUTH_SPEC = importlib.util.spec_from_file_location("ci_authorization_entrypoint", ROOT / "tools/project-ci-authorize.py")
AUTH = importlib.util.module_from_spec(AUTH_SPEC)
AUTH_SPEC.loader.exec_module(AUTH)


class ProjectCiAuthorizationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.caller = self.root / "caller"
        self.caller.mkdir()
        self.original = self.caller / "fileveil-ci.json"
        self.received = self.root / "received.json"
        self.config = {"name": "Selected project", "work_id": "selected-work", "author": "Selected Author",
                       "copy_id": "selected-copy", "policy": "hybrid", "rules": [],
                       "artifact_directory": "dist", "output_directory": "signed-release",
                       "build_argv": [], "test_argv": [],
                       "compiler": {"targets": [{"input": "source.c", "output": "program", "backend": "clang_source"}],
                                    "optimization": "O2", "allow_execution": False, "test_arguments": []}}
        self.write_configuration()

    def write_configuration(self):
        self.original.write_text(json.dumps(self.config), encoding="utf-8")
        normalized = POST.read_config(self.original)
        normalized.update(artifact_directory="artifacts", output_directory="copyright", build_argv=[], test_argv=[])
        self.received.write_text(json.dumps(normalized), encoding="utf-8")
        return normalized

    def authorize(self, policy=None):
        return POST.authorize_transfer(self.caller, "fileveil-ci.json", self.received,
                                       policy or self.config["policy"])

    def test_all_four_policies_accept_the_exact_preparation_conversion(self):
        for policy in POST.POLICIES:
            with self.subTest(policy=policy):
                self.config["policy"] = policy
                self.write_configuration()
                self.assertEqual(self.authorize()["policy"], policy)

    def test_producer_cannot_replace_identity_or_downgrade_policy(self):
        for field, value in (("work_id", "replacement-work"), ("author", "Replacement Author"),
                             ("copy_id", "replacement-copy"), ("policy", "manifest_only")):
            with self.subTest(field=field):
                transferred = self.write_configuration()
                transferred[field] = value
                self.received.write_text(json.dumps(transferred), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "authorized caller commit"):
                    self.authorize()

    def test_original_policy_must_match_the_selected_workflow(self):
        with self.assertRaisesRegex(ValueError, "selected workflow policy"):
            self.authorize("manifest_only")

    def test_rules_compiler_flags_targets_and_tests_remain_authorized(self):
        changes = [
            ("rules", [{"pattern": "**/*.png", "mode": "invisible", "strength": 20}]),
            ("compiler", {**self.config["compiler"], "compiler_arguments": ["-DREPLACED=1"]}),
            ("compiler", {**self.config["compiler"], "allow_execution": True, "test_arguments": [["changed"]]}),
            ("compiler", {**self.config["compiler"], "targets": [{"input": "other.c", "output": "program", "backend": "clang_source"}]}),
            ("artifact_directory", "other-artifacts"), ("output_directory", "other-output"),
            ("build_argv", ["unexpected-build"]), ("test_argv", ["unexpected-test"]),
        ]
        for field, value in changes:
            with self.subTest(field=field, value=value):
                transferred = self.write_configuration()
                transferred[field] = value
                self.received.write_text(json.dumps(transferred), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "authorized caller commit"):
                    self.authorize()

    def test_authorization_only_reads_json_without_executing_caller_programs(self):
        self.config["build_argv"] = [sys.executable, "untrusted.py"]
        self.config["test_argv"] = [sys.executable, "other-untrusted.py"]
        self.write_configuration()
        with patch.object(POST.subprocess, "run", side_effect=AssertionError("Unexpected caller execution")), \
                patch.object(POST, "signing_identity", side_effect=AssertionError("Unexpected key import")):
            authorized = self.authorize()
        self.assertEqual(authorized["build_argv"], [])
        self.assertEqual(authorized["test_argv"], [])

    def test_caller_configuration_traversal_and_symlink_are_rejected(self):
        for relative in ("../received.json", "/received.json", "a/../../received.json", "a\\config.json"):
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                POST.authorize_transfer(self.caller, relative, self.received, "hybrid")
        linked = self.caller / "linked"
        try:
            linked.symlink_to(self.root, target_is_directory=True)
        except OSError:
            return  # Windows hosted accounts can lack symbolic-link creation rights.
        with self.assertRaises(ValueError):
            POST.authorize_transfer(self.caller, "linked/received.json", self.received, "hybrid")

    def test_final_signing_rejects_downgrade_before_key_import_or_publication(self):
        transferred = self.write_configuration()
        transferred["policy"] = "manifest_only"
        self.received.write_text(json.dumps(transferred), encoding="utf-8")
        arguments = ["project-postprocess.py", "--fileveil", str(self.root / "unused-cli"), "--config", str(self.received),
                     "--authorized-root", str(self.caller), "--authorized-config", "fileveil-ci.json", "--authorized-policy", "hybrid"]
        with patch.object(sys, "argv", arguments), \
                patch.object(POST, "signing_identity", side_effect=AssertionError("Unexpected key import")), \
                patch.object(POST, "run_cli", side_effect=AssertionError("Unexpected signing operation")):
            with self.assertRaisesRegex(ValueError, "authorized caller commit"):
                POST.main()
        self.assertFalse(list(self.root.rglob("COMMITTED")))

    def test_partial_authorization_arguments_are_rejected(self):
        arguments = ["project-postprocess.py", "--fileveil", "unused-cli", "--config", str(self.received),
                     "--authorized-root", str(self.caller)]
        with patch.object(sys, "argv", arguments), self.assertRaisesRegex(ValueError, "requires the caller root"):
            POST.main()

    def test_producer_platform_cannot_change_the_signed_project_namespace(self):
        self.config["policy"] = "manifest_only"
        self.write_configuration()
        context = self.root / "build-context.json"
        context.write_text(json.dumps({"schema": "fileveil.ci.build-context.v1",
                                       "platform": "producer-selected-platform"}), encoding="utf-8")
        arguments = ["project-postprocess.py", "--fileveil", sys.executable, "--config", str(self.received),
                     "--after-build", "--build-context", str(context),
                     "--evidence-directory", str(self.root / "evidence")]
        with patch.object(sys, "argv", arguments), \
                patch.object(POST, "signing_identity", side_effect=AssertionError("Unexpected key import")):
            with self.assertRaisesRegex(ValueError, "differs from the signing platform"):
                POST.main()
        self.assertFalse(list(self.root.rglob("COMMITTED")))

    def test_ir_signing_binds_the_actual_received_config_before_importing_a_key(self):
        stage = self.root / "prepared"
        stage.mkdir()
        substituted = self.write_configuration()
        substituted["policy"] = "manifest_only"
        (stage / "ci-config.json").write_text(json.dumps(substituted), encoding="utf-8")
        arguments = SimpleNamespace(authorized_root=self.caller, authorized_config="fileveil-ci.json",
                                    authorized_policy="hybrid", input=stage, config=self.received)
        with patch.object(COMPILER, "load_stage", side_effect=AssertionError("Unexpected stage processing")), \
                patch.object(COMPILER.POST, "signing_identity", side_effect=AssertionError("Unexpected key import")):
            with self.assertRaisesRegex(ValueError, "authorized caller commit"):
                COMPILER.mark(arguments)

    def test_authorized_ci_binds_commit_ref_and_build_number_before_key_import(self):
        self.config["policy"] = "manifest_only"
        self.write_configuration()
        context = self.root / "build-context.json"
        observed = {"schema": "fileveil.ci.build-context.v1", "platform": sys.platform,
                    "github_commit": "a" * 40, "github_ref": "refs/tags/test", "build_number": "42"}
        arguments = ["project-postprocess.py", "--fileveil", sys.executable, "--config", str(self.received),
                     "--after-build", "--build-context", str(context),
                     "--evidence-directory", str(self.root / "evidence"),
                     "--authorized-root", str(self.caller), "--authorized-config", "fileveil-ci.json",
                     "--authorized-policy", "manifest_only"]
        environment = {"GITHUB_SHA": observed["github_commit"], "GITHUB_REF": observed["github_ref"],
                       "GITHUB_RUN_NUMBER": observed["build_number"]}
        for field in ("github_commit", "github_ref", "build_number"):
            with self.subTest(field=field):
                context.write_text(json.dumps({**observed, field: "substituted"}), encoding="utf-8")
                with patch.object(sys, "argv", arguments), patch.dict(POST.os.environ, environment), \
                        patch.object(POST, "signing_identity", side_effect=AssertionError("Unexpected key import")):
                    with self.assertRaisesRegex(ValueError, "authorized workflow run"):
                        POST.main()
        self.assertFalse(list(self.root.rglob("COMMITTED")))

    def test_pure_authorization_entry_point_accepts_data_and_rejects_substitution(self):
        arguments = [sys.executable, str(ROOT / "tools/project-ci-authorize.py"), "--caller-root", str(self.caller),
                     "--config", "fileveil-ci.json", "--received-config", str(self.received), "--policy", "hybrid"]
        result = subprocess.run(arguments, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["configuration_authorized"])
        changed = json.loads(self.received.read_text(encoding="utf-8"))
        changed["author"] = "Substituted Author"
        self.received.write_text(json.dumps(changed), encoding="utf-8")
        result = subprocess.run(arguments, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_secret_jobs_independently_checkout_and_validate_before_secret_steps(self):
        workflow = (ROOT / ".github/workflows/project-release.yml").read_text(encoding="utf-8")
        for job, next_job in (("compiler-mark:", "compiler-build:"), ("copyright:", None)):
            section = workflow.split("\n  " + job, 1)[1]
            if next_job:
                section = section.split("\n  " + next_job, 1)[0]
            self.assertIn("repository: ${{ github.repository }}", section)
            self.assertIn("ref: ${{ github.sha }}", section)
            self.assertIn("path: .fileveil-caller", section)
            self.assertLess(section.index("project-ci-authorize.py"), section.index("FILEVEIL_SIGNING_KEY_BASE64:"))
            for flag in ("--authorized-root", "--authorized-config", "--authorized-policy"):
                self.assertIn(flag, section)

    def history(self, version="ci.42.1"):
        edition = self.config["work_id"] + "\0" + self.config["copy_id"] + "\0" + sys.platform
        project_id = hashlib.sha256(("FileVeil CI edition v1\0" + edition).encode()).hexdigest()[:32]
        directory = self.root / "history"
        generation = directory / project_id / "000000000001-synthetic"
        generation.mkdir(parents=True)
        manifest = {"schema": "fileveil.project.manifest.v1", "project_id": project_id,
                    "work_id": self.config["work_id"], "copy_id": self.config["copy_id"],
                    "revision": 1, "version": version}
        (generation / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        (generation / "evidence.json").write_text("{}", encoding="utf-8")
        (generation / "COMMITTED").write_text("synthetic", encoding="utf-8")
        return directory, generation, manifest

    def test_history_binds_latest_version_to_api_producer_and_defers_cryptography(self):
        directory, _, _ = self.history()
        report = AUTH.authorize_history(self.config, directory, "42")
        self.assertEqual(report["version"], "ci.42.1")
        self.assertEqual(report["cryptographic_verification"], "pending_core_verification")
        self.assertEqual(report["freshness_scope"], "retained_artifact_producer_run_binding")

    def test_reuploaded_old_prefix_does_not_match_a_new_artifact_producer(self):
        directory, _, _ = self.history("ci.41.1")
        with self.assertRaisesRegex(ValueError, "artifact producer run"):
            AUTH.authorize_history(self.config, directory, "42")

    def test_history_requires_the_exact_native_project_namespace(self):
        directory, generation, _ = self.history()
        generation.parent.rename(directory / "another-project")
        with self.assertRaisesRegex(ValueError, "edition namespace"):
            AUTH.authorize_history(self.config, directory, "42")

    def test_each_retained_manifest_must_match_the_selected_work_copy_and_project(self):
        directory, generation, manifest = self.history()
        for field in ("work_id", "copy_id", "project_id"):
            with self.subTest(field=field):
                changed = dict(manifest, **{field: "another-edition"})
                (generation / "manifest.json").write_text(json.dumps(changed), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "different project edition"):
                    AUTH.authorize_history(self.config, directory, "42")

    def test_history_uses_highest_revision_with_a_positive_run_attempt(self):
        directory, generation, manifest = self.history("ci.41.1")
        newer = generation.parent / "000000000002-newer"
        newer.mkdir()
        (newer / "evidence.json").write_text("{}", encoding="utf-8")
        (newer / "COMMITTED").write_text("synthetic", encoding="utf-8")
        for version, accepted in (("ci.42.2", True), ("ci.42.0", False), ("ci.41.9", False)):
            with self.subTest(version=version):
                (newer / "manifest.json").write_text(json.dumps(dict(manifest, revision=2, version=version)), encoding="utf-8")
                if accepted:
                    self.assertEqual(AUTH.authorize_history(self.config, directory, "42")["latest_revision"], 2)
                else:
                    with self.assertRaises(ValueError):
                        AUTH.authorize_history(self.config, directory, "42")

    def test_history_rejects_extra_payload_and_partial_cli_arguments(self):
        directory, generation, _ = self.history()
        (generation / "program.exe").write_bytes(b"unexecuted bytes")
        with self.assertRaisesRegex(ValueError, "public generation metadata"):
            AUTH.authorize_history(self.config, directory, "42")
        arguments = ["project-ci-authorize.py", "--caller-root", str(self.caller), "--config", "fileveil-ci.json",
                     "--received-config", str(self.received), "--policy", "hybrid", "--history-directory", str(directory)]
        with patch.object(sys, "argv", arguments), self.assertRaisesRegex(ValueError, "requires both"):
            AUTH.main()

    def test_workflow_binds_history_api_run_id_before_the_secret_step(self):
        workflow = (ROOT / ".github/workflows/project-release.yml").read_text(encoding="utf-8")
        section = workflow.split("\n  copyright:", 1)[1]
        gate = section.index("Bind retained history to its artifact producer")
        self.assertLess(gate, section.index("FILEVEIL_SIGNING_KEY_BASE64:"))
        self.assertIn("FILEVEIL_HISTORY_PRODUCER_RUN_ID: ${{ steps.history.outputs.run-id }}", section)
        self.assertIn("'--history-directory', 'fileveil-input/copyright'", section)


if __name__ == "__main__":
    unittest.main()

# FVPROV1 17588 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIzNmQ1YTVjNDg0MjRjM2Y0M2FhNjEwNWYzNWQ4NDVkOWMyZTBiNmQ4ZjQxYzc1M2Q0YjZiZTJmNGM2ZDY4ZDNmIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rlc3RzL3Rlc3RfcHJvamVjdF9jaV9hdXRob3JpemF0aW9uLnB5In0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiMjVlZmVjMGJkOWY4MDFkZTBjNWNlZGRmYWIyZGZkMjFkYmRjZTRhYzkyZDFjMGViNGFkZjZhMjUwMjFiMzE3N2FmN2YzNGMzMWVmZTYzZDllMjM1NzcwY2I5Zjg4ODEzMDQxMmEzNmJjZjJmMzg5NjU3ODAwNTBjNjM0M2QxMGQifV19XQ== FVPROV1-END
