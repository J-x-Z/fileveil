# SPDX-License-Identifier: MPL-2.0
"""Regression checks for the local release orchestration contract."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("fileveil_ci_local", ROOT / "tools/project-ci-local.py")
LOCAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LOCAL)


class LocalReleaseTests(unittest.TestCase):
    def fixture(self, directory, policy="manifest_only"):
        root = Path(directory).resolve()
        project = root / "project"
        project.mkdir()
        (project / "dist").mkdir()
        (project / "dist/app").write_bytes(b"original build")
        key = root / "owner.key"
        key.write_bytes(LOCAL.POST.KEY_MAGIC + bytes(32))
        executable = root / "fileveil"
        executable.write_text("fixture executable")
        llvm = root / "llvm"
        llvm.mkdir()
        plugin = root / "FileVeilWatermark.dylib"
        plugin.write_bytes(b"fixture plugin")
        config = {"name": "Test", "work_id": "test-work", "author": "Author", "copy_id": "release",
                  "artifact_directory": "dist", "output_directory": "copyright", "policy": policy,
                  "rules": [], "build_argv": [], "test_argv": []}
        if policy in ("compiler_watermark", "hybrid"):
            config["compiler"] = {"targets": [{"input": "main.c", "output": "app", "backend": "clang_source"}],
                                  "llvm_directory": str(llvm), "plugin_path": str(plugin)}
        path = project / "fileveil-ci.json"
        path.write_text(json.dumps(config))
        return ["--fileveil", str(executable), "--config", str(path), "--key", str(key),
                "--state-directory", str(root / "private/state"),
                "--evidence-directory", str(project / "evidence"), "--version", "v1"]

    def test_manifest_and_asset_delegate_without_compiler_work(self):
        for policy in ("manifest_only", "asset_watermark"):
            with self.subTest(policy=policy), tempfile.TemporaryDirectory() as name:
                arguments = self.fixture(name, policy)
                with (
                    patch.object(LOCAL, "postprocess") as post,
                    patch.object(LOCAL, "verify_current", return_value={"generation": "g1"}) as verify,
                    patch.object(LOCAL.COMPILER, "prepare") as prepare,
                ):
                    receipt = LOCAL.main(arguments)
                self.assertEqual(receipt["post_cleanup_verification"], "valid")
                prepare.assert_not_called()
                self.assertEqual(post.call_count, 1)
                self.assertEqual(verify.call_count, 1)
                self.assertEqual(Path(receipt["persistent_source_directory"]), Path(name).resolve() / "project/dist")

    def test_compiler_flow_retains_final_source_and_checks_after_cleanup(self):
        with tempfile.TemporaryDirectory() as name:
            arguments = self.fixture(name, "hybrid")
            events = []
            temporary_roots = []

            def stage(action):
                def execute(args):
                    events.append(action)
                    temporary_roots.append(args.output.parent)
                    args.output.write_bytes(b"mock bounded transfer")
                return execute

            def receive(bundle, destination):
                events.append("receive")
                destination.mkdir(parents=True)
                (destination / "artifacts").mkdir()
                (destination / "artifacts/app").write_bytes(b"final marked build")
                (destination / "ci-config.json").write_text("{}")

            def post(args, config, output=None, received=None):
                events.append("postprocess")
                self.assertEqual(output, Path(name).resolve() / "project/copyright")
                self.assertEqual(config.parent, received)
                self.assertTrue((received / "artifacts/app").is_file())
                self.assertFalse(received.is_relative_to(temporary_roots[0]))

            def verify(args, project_id):
                events.append("verify_after_cleanup")
                self.assertTrue(all(not directory.exists() for directory in temporary_roots))
                return {"generation": "g1"}

            with (
                patch.object(LOCAL.COMPILER, "prepare", side_effect=stage("prepare")),
                patch.object(LOCAL.COMPILER, "mark", side_effect=stage("mark")),
                patch.object(LOCAL.COMPILER, "build", side_effect=stage("build")),
                patch.object(LOCAL.STAGE, "receive", side_effect=receive),
                patch.object(LOCAL, "postprocess", side_effect=post),
                patch.object(LOCAL, "verify_current", side_effect=verify),
                patch.object(LOCAL, "cache_identity", return_value="fixture-cache"),
            ):
                receipt = LOCAL.main(arguments)
            self.assertEqual(events, ["prepare", "receive", "mark", "receive", "build", "receive", "postprocess", "verify_after_cleanup"])
            self.assertEqual((Path(receipt["persistent_source_directory"]) / "app").read_bytes(), b"final marked build")

    def test_project_local_key_is_rejected_before_build(self):
        with tempfile.TemporaryDirectory() as name:
            arguments = self.fixture(name)
            key = Path(name) / "project/local.key"
            key.write_bytes(LOCAL.POST.KEY_MAGIC + bytes(32))
            arguments[arguments.index("--key") + 1] = str(key)
            with (
                patch.object(LOCAL, "postprocess") as post,
                self.assertRaisesRegex(ValueError, "outside project source"),
            ):
                LOCAL.main(arguments)
            post.assert_not_called()

    def test_missing_compiler_tools_fail_without_downloading(self):
        with tempfile.TemporaryDirectory() as name:
            arguments = self.fixture(name, "compiler_watermark")
            path = Path(arguments[arguments.index("--config") + 1])
            config = json.loads(path.read_text())
            del config["compiler"]["llvm_directory"]
            path.write_text(json.dumps(config))
            with (
                patch.object(LOCAL.COMPILER, "prepare") as prepare,
                self.assertRaisesRegex(ValueError, "explicit LLVM directory"),
            ):
                LOCAL.main(arguments)
            prepare.assert_not_called()

    def test_inherited_secret_is_removed_during_local_build_and_restored(self):
        with tempfile.TemporaryDirectory() as name:
            arguments = self.fixture(name)

            def post(*args):
                self.assertNotIn("FILEVEIL_SIGNING_KEY_BASE64", LOCAL.os.environ)

            with (
                patch.dict(LOCAL.os.environ, {"FILEVEIL_SIGNING_KEY_BASE64": "fixture-secret"}),
                patch.object(LOCAL, "postprocess", side_effect=post),
                patch.object(LOCAL, "verify_current", return_value={}),
            ):
                LOCAL.main(arguments)
                self.assertEqual(LOCAL.os.environ["FILEVEIL_SIGNING_KEY_BASE64"], "fixture-secret")

    def test_failed_post_cleanup_verification_prevents_success(self):
        with tempfile.TemporaryDirectory() as name:
            arguments = self.fixture(name)
            invalid = {"advanced": {"project": {"integrity": "failed", "signature": "valid",
                                               "history": "valid", "trust": "valid"}}}
            with (
                patch.object(LOCAL, "postprocess"),
                patch.object(LOCAL.POST, "run_cli", return_value=invalid),
                self.assertRaisesRegex(ValueError, "after intermediate cleanup"),
            ):
                LOCAL.main(arguments)

    def test_repeated_default_runs_choose_new_evidence_beside_private_state(self):
        with tempfile.TemporaryDirectory() as name:
            arguments = self.fixture(name)
            option = arguments.index("--evidence-directory")
            del arguments[option:option + 2]

            def publish(args, config):
                args.evidence_directory.mkdir()

            with (
                patch.object(LOCAL, "postprocess", side_effect=publish),
                patch.object(LOCAL, "verify_current", return_value={"generation": "g1"}),
            ):
                first = LOCAL.main(arguments)
                second = LOCAL.main(arguments)
            first_path = Path(first["evidence_directory"])
            second_path = Path(second["evidence_directory"])
            self.assertNotEqual(first_path, second_path)
            self.assertTrue(first_path.is_dir())
            self.assertTrue(second_path.is_dir())
            self.assertEqual(first_path.parent, Path(name).resolve() / "private/evidence")
            self.assertEqual(first["output_directory"], second["output_directory"])

    def test_unchanged_compiler_repeat_reuses_verified_release(self):
        with tempfile.TemporaryDirectory() as name:
            arguments = self.fixture(name, "compiler_watermark")
            option = arguments.index("--evidence-directory")
            del arguments[option:option + 2]

            def compile_stage(args):
                args.output.write_bytes(b"mock transfer")

            def receive(bundle, destination):
                destination.mkdir(parents=True)
                (destination / "artifacts").mkdir()
                (destination / "artifacts/app").write_bytes(b"same verified release")
                (destination / "ci-config.json").write_text("{}")

            def publish(args, *unused):
                args.evidence_directory.mkdir()

            with (
                patch.object(LOCAL.COMPILER, "prepare", side_effect=compile_stage) as prepare,
                patch.object(LOCAL.COMPILER, "mark", side_effect=compile_stage) as mark,
                patch.object(LOCAL.COMPILER, "build", side_effect=compile_stage) as build,
                patch.object(LOCAL.STAGE, "receive", side_effect=receive),
                patch.object(LOCAL, "cache_identity", return_value="unchanged-input"),
                patch.object(LOCAL, "postprocess", side_effect=publish),
                patch.object(LOCAL, "verify_current", return_value={"generation": "g1"}),
            ):
                first = LOCAL.main(arguments)
                second = LOCAL.main(arguments)
            self.assertEqual(prepare.call_count, 2)
            self.assertEqual(mark.call_count, 1)
            self.assertEqual(build.call_count, 1)
            self.assertFalse(first["compiler_cache_hit"])
            self.assertTrue(second["compiler_cache_hit"])
            self.assertEqual(first["persistent_source_directory"], second["persistent_source_directory"])
            self.assertNotEqual(first["evidence_directory"], second["evidence_directory"])

    def test_cache_identity_binds_inputs_version_time_and_key(self):
        with tempfile.TemporaryDirectory() as name:
            arguments = self.fixture(name, "compiler_watermark")
            value = lambda option: Path(arguments[arguments.index(option) + 1])
            args = SimpleNamespace(config=value("--config"), key=value("--key"),
                fileveil=value("--fileveil"), state_directory=value("--state-directory"),
                evidence_directory=value("--evidence-directory"), llvm_directory=None,
                plugin=None, version="v1", created_at="")
            LOCAL.configuration(args)
            prepared = Path(name) / "prepared"
            prepared.mkdir()
            (prepared / "artifacts").mkdir()
            artifact = prepared / "artifacts/original"
            artifact.write_bytes(b"baseline bytes")
            (prepared / "ci-config.json").write_bytes(args.config.read_bytes())
            stage = {"targets": [{"input": "main.c", "output": "app", "source_sha256": "a" * 64,
                                   "base_ir_sha256": "b" * 64}]}
            path = prepared / "compiler-stage.json"
            path.write_text(json.dumps(stage))
            initial = LOCAL.cache_identity(args, prepared)
            args.created_at = "unix:1"
            self.assertNotEqual(initial, LOCAL.cache_identity(args, prepared))
            args.created_at = ""
            args.version = "v2"
            self.assertNotEqual(initial, LOCAL.cache_identity(args, prepared))
            args.version = "v1"
            original_key = args.key.read_bytes()
            args.key.write_bytes(LOCAL.POST.KEY_MAGIC + bytes([1]) * 32)
            self.assertNotEqual(initial, LOCAL.cache_identity(args, prepared))
            args.key.write_bytes(original_key)
            artifact.write_bytes(b"changed baseline")
            self.assertNotEqual(initial, LOCAL.cache_identity(args, prepared))
            artifact.write_bytes(b"baseline bytes")
            stage["targets"][0]["base_ir_sha256"] = "c" * 64
            path.write_text(json.dumps(stage))
            self.assertNotEqual(initial, LOCAL.cache_identity(args, prepared))

    def test_changed_cached_release_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            releases = root / "releases"
            release = releases / ("a" * 32)
            release.mkdir(parents=True)
            (release / "app").write_bytes(b"verified")
            cache = root / "cache/entry.json"
            LOCAL.save_cache(cache, release)
            self.assertEqual(LOCAL.cached_release(cache, releases), release)
            (release / "app").write_bytes(b"modified")
            with self.assertRaisesRegex(ValueError, "changed or is missing"):
                LOCAL.cached_release(cache, releases)


if __name__ == "__main__":
    unittest.main()
