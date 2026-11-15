#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
import importlib.util
from pathlib import Path
import tempfile
import unittest

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
