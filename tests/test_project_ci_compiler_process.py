# SPDX-License-Identifier: MPL-2.0
"""Owned compiler/test children are reaped on timeout and interruption."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("fileveil_ci_process", ROOT / "tools/project-ci-compiler.py")
COMPILER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPILER)


def running(pid):
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        handle = kernel.OpenProcess(0x00100000, False, pid)
        if not handle:
            return False
        try:
            return kernel.WaitForSingleObject(handle, 0) == 258
        finally:
            kernel.CloseHandle(handle)
    result = subprocess.run(["ps", "-p", str(pid), "-o", "stat="], capture_output=True, text=True)
    return result.returncode == 0 and bool(result.stdout.strip()) and not result.stdout.strip().startswith("Z")


class CompilerProcessTests(unittest.TestCase):
    def owned_tree(self, root):
        helper = root / "owned.py"
        helper.write_text(
            "from pathlib import Path\nimport json,os,subprocess,sys,time\n"
            "root=Path(sys.argv[1])\n"
            "if len(sys.argv)>2:\n"
            " (root/'ready').write_text(str(os.getpid()))\n"
            " time.sleep(20)\n"
            "else:\n"
            " child=subprocess.Popen([sys.executable,__file__,str(root),'grandchild'])\n"
            " (root/'pids.json').write_text(json.dumps([os.getpid(),child.pid]))\n"
            " time.sleep(20)\n"
        )
        return [sys.executable, str(helper), str(root)]

    def assert_stopped(self, root):
        pids = json.loads((root / "pids.json").read_text())
        deadline = time.monotonic() + 3
        while any(running(pid) for pid in pids) and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertFalse(any(running(pid) for pid in pids), "Owned compiler process tree survived cleanup")

    def cleanup_owned(self, root):
        path = root / "pids.json"
        if not path.exists():
            return
        pids = json.loads(path.read_text())
        if os.name == "posix":
            if any(running(pid) for pid in pids):
                try:
                    os.killpg(pids[0], signal.SIGKILL)
                except ProcessLookupError:
                    pass
        else:
            taskkill = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/taskkill.exe"
            for pid in pids:
                if running(pid):
                    subprocess.run([str(taskkill), "/PID", str(pid), "/T", "/F"],
                                   capture_output=True, timeout=10)

    def test_keyboard_interrupt_reaps_owned_child_and_grandchild(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            argv = self.owned_tree(root)
            ordinary_sleep = time.sleep
            interrupted = False

            def interrupt_once(seconds):
                nonlocal interrupted
                if interrupted:
                    return ordinary_sleep(seconds)
                deadline = time.monotonic() + 5
                while not (root / "ready").exists() and time.monotonic() < deadline:
                    ordinary_sleep(0.01)
                self.assertTrue((root / "ready").exists())
                interrupted = True
                raise KeyboardInterrupt

            try:
                with patch.object(COMPILER.time, "sleep", side_effect=interrupt_once):
                    with self.assertRaises(KeyboardInterrupt):
                        COMPILER.execute(argv, root, timeout=10)
                self.assert_stopped(root)
            finally:
                self.cleanup_owned(root)

    def test_timeout_reaps_owned_child_and_grandchild(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            try:
                with self.assertRaisesRegex(ValueError, "time or output budget"):
                    COMPILER.execute(self.owned_tree(root), root, timeout=2)
                self.assertTrue((root / "ready").exists())
                self.assert_stopped(root)
            finally:
                self.cleanup_owned(root)


if __name__ == "__main__":
    unittest.main()

# FVPROV1 4845 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI2MmY5NzNmMzNlMmNjYjY4Mzg3NDgzYmU5YmFhM2NmY2FlNjdjZDAxYzYwMjVlMmYyODNmNzQ2ODEwMjJhNGNlIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rlc3RzL3Rlc3RfcHJvamVjdF9jaV9jb21waWxlcl9wcm9jZXNzLnB5In0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiYzExNDg2NDhlYmUwOGQ1YmQyNjFiNDE0MDU3NWQ3OGMwODk5NTI5N2Y0ZjA3ZGYwNTRkMmMxYjIyYzgwNTJhODU3MjA1OThmYjRhNDYzMjBiMDdmMGVjNWFlNDE5MzNiZWUwMjU2NmQ1MDdiMzBiODI1ZmY3ZThhODdiZjQ0MDQifV19XQ== FVPROV1-END
