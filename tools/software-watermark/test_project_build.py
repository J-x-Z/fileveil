#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("project_build", Path(__file__).with_name("project-build.py"))
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


class ProjectBuildTests(unittest.TestCase):
    def test_targets_are_bounded_and_not_shell_or_cmake(self):
        for value in (["x;evil"], ["../x"], ["${x}"], ["x", "x"], [], ["x"] * 33):
            with self.subTest(value=value), self.assertRaises(ValueError):
                build.targets(value)
        self.assertEqual(build.targets(["my-target", "target_2"]), ["my-target", "target_2"])

    def test_cmake_paths_use_literal_brackets(self):
        result = build.cmake_hook(["example"], Path("/tmp/${NOT_EVALUATED}/a.o"))
        self.assertIn("[[/tmp/${NOT_EVALUATED}/a.o]]", result)
        with self.assertRaises(ValueError):
            build.cmake_hook(["example"], Path("/tmp/]]/a.o"))

    def test_windows_requires_ninja_not_visual_studio(self):
        with patch.object(build.shutil, "which", return_value=None):
            with self.assertRaisesRegex(ValueError, "require Ninja"):
                build.cmake_generator_arguments(windows=True)
        with patch.object(build.shutil, "which", return_value="/tools/ninja"):
            args = build.cmake_generator_arguments(windows=True)
            self.assertEqual(args[:2], ["-G", "Ninja"])
        self.assertEqual(build.cmake_generator_arguments(windows=False), [])

    def test_cmake_rejects_ignored_compiler_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "CMakeFiles/4.0"
            folder.mkdir(parents=True)
            identity = folder / "CMakeCCompiler.cmake"
            identity.write_text('set(CMAKE_C_COMPILER "/wrong/cl.exe")\nset(CMAKE_C_COMPILER_ID "MSVC")\nset(CMAKE_C_COMPILER_VERSION "19.0")\n')
            with self.assertRaisesRegex(ValueError, "other than"):
                build.check_cmake_compilers(root, {"C": Path("/wanted/clang")})
            identity.write_text('set(CMAKE_C_COMPILER "/wanted/clang")\nset(CMAKE_C_COMPILER_ID "Clang")\nset(CMAKE_C_COMPILER_VERSION "23.1.5")\n')
            evidence = build.check_cmake_compilers(root, {"C": Path("/wanted/clang"), "CXX": Path("/wanted/clang++")})
            self.assertEqual(evidence["C"]["id"], "Clang")

    def test_cargo_uses_reported_artifact_not_a_stale_conventional_path(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual = root / "target-triple/release/app"
            row = {"reason": "compiler-artifact", "package_id": "package-id", "target": {"name": "app", "kind": ["bin"]},
                   "profile": {"test": False}, "executable": str(actual)}
            self.assertEqual(build.cargo_executable(json.dumps(row).encode(), "package-id", "app", root), actual)
            row["executable"] = str(root.parent / "outside")
            with self.assertRaises(ValueError):
                build.cargo_executable(json.dumps(row).encode(), "package-id", "app", root)

    def test_other_signed_packet_does_not_satisfy_this_runs_identity(self):
        with self.assertRaisesRegex(ValueError, "exact authenticated"):
            build.require_packet({"packet_sha256": "other-work-packet"}, "this-work-packet")
        build.require_packet({"packet_sha256": "same"}, "same")

    def test_shared_cargo_adapter_lock_prevents_interleaved_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with build.cargo_cache_lock(root, 1):
                with self.assertRaisesRegex(ValueError, "locked by another"):
                    with build.cargo_cache_lock(root, 0.05):
                        self.fail("a competing adapter acquired the live target lock")
            with build.cargo_cache_lock(root, 0.05):
                pass

    def test_snapshot_detects_content_and_rejects_file_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a").write_text("before")
            before = build.snapshot(root)
            (root / "a").write_text("after")
            self.assertNotEqual(before, build.snapshot(root))
            (root / "linked").symlink_to(root / "a")
            with self.assertRaises(ValueError):
                build.snapshot(root)

    def test_a_source_directory_named_build_is_not_silently_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "build").mkdir()
            item = root / "build/settings.cmake"
            item.write_text("before")
            before = build.snapshot(root)
            self.assertIn("build/settings.cmake", before)
            item.write_text("after")
            self.assertNotEqual(before, build.snapshot(root))

    def test_failed_build_is_not_success(self):
        import sys
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "exited 9"):
                build.execute([sys.executable, "-c", "raise SystemExit(9)"], directory)

    def test_bounded_command_timeout(self):
        import sys
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "timeout"):
                build.execute([sys.executable, "-c", "import time; time.sleep(5)"], directory, timeout=0.05)

    def test_output_budget_is_checked_after_a_fast_command(self):
        import sys
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "log budget"):
                build.execute([sys.executable, "-c", "print('x' * (3 * 1024 * 1024))"], directory)

    @unittest.skipUnless(build.os.name == "posix", "POSIX process group contract")
    def test_already_exited_leader_does_not_leave_a_background_writer(self):
        import sys
        import time
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "unwanted"
            child = "import time,pathlib; time.sleep(0.5); pathlib.Path(" + repr(str(marker)) + ").write_text('escaped')"
            parent = "import subprocess,sys; subprocess.Popen([sys.executable,'-c'," + repr(child) + "])"
            build.execute([sys.executable, "-c", parent], directory)
            time.sleep(0.7)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
