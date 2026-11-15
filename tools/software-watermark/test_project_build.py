#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
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

    def test_cmake_lto_selects_sdk_lld_in_the_configure_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for system, linker in (("Linux", "ld.lld"), ("Windows", "lld-link.exe")):
                with self.subTest(system=system):
                    sdk = root / system
                    (sdk / "bin").mkdir(parents=True)
                    (sdk / "bin" / linker).touch()
                    args = SimpleNamespace(build_system="cmake", build_tool="cmake", llvm_directory=sdk,
                                           source=root / "source", optimization="O2", lto=True, timeout=1)
                    with patch.object(build.platform, "system", return_value=system), \
                            patch.object(build, "cmake_generator_arguments", return_value=[]), \
                            patch.object(build, "execute", side_effect=RuntimeError("configure observed")) as command:
                        with self.assertRaisesRegex(RuntimeError, "configure observed"):
                            build.compile_targets(args, "baseline", root / ("case-" + system), None)
                    configure = command.call_args.args[0]
                    self.assertIn("-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON", configure)
                    for kind in ("EXE", "SHARED", "MODULE"):
                        self.assertIn("-DCMAKE_" + kind + "_LINKER_FLAGS=-fuse-ld=lld", configure)

    def test_cmake_lto_rejects_missing_sdk_linker_without_using_the_other_platforms(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for system, missing, other in (("Linux", "ld.lld", "lld-link.exe"),
                                            ("Windows", "lld-link.exe", "ld.lld")):
                with self.subTest(system=system):
                    sdk = root / system
                    (sdk / "bin").mkdir(parents=True)
                    (sdk / "bin" / other).touch()
                    with self.assertRaisesRegex(ValueError, "requires the LLVM SDK linker") as error:
                        build.cmake_lto_arguments(sdk, True, system=system)
                    self.assertIn(missing, str(error.exception))

    def test_cmake_lto_preserves_darwin_and_all_non_lto_linkers(self):
        with tempfile.TemporaryDirectory() as directory:
            missing_sdk = Path(directory) / "absent-sdk"
            self.assertEqual(build.cmake_lto_arguments(missing_sdk, True, system="Darwin"),
                             ["-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON"])
            for system in ("Linux", "Windows", "Darwin"):
                self.assertEqual(build.cmake_lto_arguments(missing_sdk, False, system=system), [])

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

# FVPROV1 9472 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI5ZDNmNGE3MDYyYjM4YTBiMmFkMGMwNDU3ZDMwNDBiZWIxZThiZWNmMzQ0YjdlZTFjOTE2ODU2NmM0YTg3NDI2IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL3NvZnR3YXJlLXdhdGVybWFyay90ZXN0X3Byb2plY3RfYnVpbGQucHkifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiIxN2RhMjc2Zjc0MjM3ODUyYzliMWIyZTBjMDIyNDc0OTZhMmRjNTBkYjI3MGQ0M2I1YzMwMDk1MjAxYmNlZDBmNTYyM2EyZjlkNjc3ODlhNjU3YmU4YThhMzA0MzdkZTUwZGM3NDY1M2U4MDRiMGUyMDRhOTZkZDMzYzdiOGEwMCJ9XX1d FVPROV1-END
