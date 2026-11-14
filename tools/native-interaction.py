#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Exercise the native GUI using operating-system pointer input on CI desktops."""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time


class WindowsPointer:
    """Only target the window owned by the process launched by this test."""

    name = "user32.SetCursorPos+SendInput"

    def __init__(self, pid):
        from ctypes import wintypes

        self.pid = pid
        self.types = wintypes
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.user32.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
        self.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
        self.callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        self.user32.EnumWindows.argtypes = [self.callback_type, wintypes.LPARAM]
        self.user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        self.user32.IsWindowVisible.argtypes = [wintypes.HWND]
        self.user32.ClientToScreen.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.POINT)]
        self.user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        self.user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
        self.user32.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]

        class MouseInput(ctypes.Structure):
            _fields_ = [
                ("dx", wintypes.LONG), ("dy", wintypes.LONG),
                ("mouseData", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_size_t),
            ]

        class InputUnion(ctypes.Union):
            _fields_ = [("mi", MouseInput)]

        class Input(ctypes.Structure):
            _anonymous_ = ("value",)
            _fields_ = [("type", wintypes.DWORD), ("value", InputUnion)]

        self.input_type = Input
        self.user32.SendInput.argtypes = [ctypes.c_uint, ctypes.POINTER(Input), ctypes.c_int]
        self.user32.SendInput.restype = ctypes.c_uint

    def window(self):
        matches = []

        @self.callback_type
        def visit(window, _parameter):
            owner = self.types.DWORD()
            self.user32.GetWindowThreadProcessId(window, ctypes.byref(owner))
            if owner.value == self.pid and self.user32.IsWindowVisible(window):
                matches.append(window)
            return True

        if not self.user32.EnumWindows(visit, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        if not matches:
            raise RuntimeError("The launched GUI has no visible native window")
        return matches[0]

    def click(self, x, y):
        window = self.window()
        self.user32.ShowWindow(window, 9)  # SW_RESTORE
        self.user32.SetForegroundWindow(window)
        point = self.types.POINT(x, y)
        if not self.user32.ClientToScreen(window, ctypes.byref(point)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not self.user32.SetCursorPos(point.x, point.y):
            raise ctypes.WinError(ctypes.get_last_error())
        time.sleep(0.1)
        for flags in [0x0002, 0x0004]:  # MOUSEEVENTF_LEFTDOWN / LEFTUP
            event = self.input_type()
            event.type = 0  # INPUT_MOUSE
            event.mi.dwFlags = flags
            if self.user32.SendInput(1, ctypes.byref(event), ctypes.sizeof(event)) != 1:
                raise ctypes.WinError(ctypes.get_last_error())
            time.sleep(0.05)
        return {"window": int(window), "screen_position": [point.x, point.y]}


class LinuxPointer:
    name = "X11 XTEST via xdotool"

    def __init__(self, pid):
        self.pid = pid

    def click(self, x, y):
        matches = subprocess.check_output(
            ["xdotool", "search", "--onlyvisible", "--pid", str(self.pid)],
            text=True, timeout=5,
        ).splitlines()
        if not matches:
            raise RuntimeError("The launched GUI has no visible native window")
        window = matches[0]
        subprocess.run(["xdotool", "windowfocus", "--sync", window], check=True, timeout=5)
        subprocess.run(
            ["xdotool", "mousemove", "--sync", "--window", window, str(x), str(y)],
            check=True, timeout=5,
        )
        subprocess.run(["xdotool", "click", "1"], check=True, timeout=5)
        return {"window": window, "client_position": [x, y]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--scenario", choices=["images", "heritage"], default="images")
    parser.add_argument("--fixture", type=Path)
    args = parser.parse_args()
    if sys.platform not in ("win32", "linux"):
        parser.error("This pointer driver supports Windows and X11 Linux")
    executable = args.executable.resolve(strict=True)
    default_fixture = Path("work/v04-research/preview_bottle_firstuser.jpg") if args.scenario == "heritage" else Path(
        "crates/fileveil-engine/tests/fixtures/watermark/astronaut-sdxl.png")
    fixture = (args.fixture or default_fixture).resolve(strict=True)
    report = args.report.resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    for extension in ["json", "png", "state.json", "controller.json", "stdout.log", "stderr.log"]:
        if report.with_suffix("." + extension).exists():
            parser.error(f"Evidence path already exists: {report.with_suffix('.' + extension)}")
    original_hash = hashlib.sha256(fixture.read_bytes()).hexdigest()
    environment = dict(os.environ, FILEVEIL_NATIVE_INTERACTION="1")
    controller = {"platform": sys.platform, "scenario": args.scenario, "steps": [], "fixture_sha256": original_hash}
    stdout = report.with_suffix(".stdout.log")
    stderr = report.with_suffix(".stderr.log")
    with stdout.open("xb") as output, stderr.open("xb") as errors:
        process = subprocess.Popen(
            [str(executable), "--smoke-test-report", str(report), str(fixture)],
            env=environment, stdout=output, stderr=errors,
            start_new_session=(os.name != "nt"),
        )
        try:
            pointer = WindowsPointer(process.pid) if os.name == "nt" else LinuxPointer(process.pid)
            controller["input_api"] = pointer.name
            deadline = time.monotonic() + 90
            state_path = report.with_suffix(".state.json")

            def wait_for(condition, description):
                while time.monotonic() < deadline:
                    if state_path.exists():
                        try:
                            state = json.loads(state_path.read_text(encoding="utf-8"))
                        except (OSError, json.JSONDecodeError):
                            state = None
                        if state is not None and condition(state):
                            return state
                    if process.poll() is not None:
                        raise RuntimeError(f"GUI exited {process.returncode} while waiting for {description}")
                    time.sleep(0.1)
                raise TimeoutError(f"Timed out waiting for {description}")

            def click_target(name, state):
                target = state["observations"]["targets"][name]
                logical = target["center"]
                scale = state["pixels_per_point"]
                x, y = (round(value * scale) for value in logical)
                event = pointer.click(x, y)
                controller["steps"].append({
                    "target": name, "logical_center": logical,
                    "pixels_per_point": scale, "native_pointer": event,
                })

            if args.scenario == "heritage":
                ready = wait_for(
                    lambda state: state["observations"]["targets"].get("heritage_tab", {}).get("enabled"),
                    "Heritage workspace tab",
                )
                click_target("heritage_tab", ready)
                ready = wait_for(
                    lambda state: state["observations"]["workspace"] == "heritage"
                    and state["observations"]["targets"].get("heritage_verify_tab", {}).get("enabled"),
                    "Heritage Verify tab",
                )
                click_target("heritage_verify_tab", ready)
                ready = wait_for(
                    lambda state: state["observations"]["workspace"] == "heritage"
                    and state["observations"]["actions"].get("heritage_verify_tab", 0) >= 1
                    and state["observations"]["targets"].get("heritage_run", {}).get("enabled"),
                    "enabled Heritage Verify action",
                )
                click_target("heritage_run", ready)
            else:
                ready = wait_for(
                    lambda state: state["observations"]["targets"].get("images_tab", {}).get("enabled"),
                    "image-watermark tab",
                )
                click_target("images_tab", ready)
                ready = wait_for(
                    lambda state: state["observations"]["workspace"] == "images"
                    and state["observations"]["targets"].get("run_detector", {}).get("enabled"),
                    "enabled watermark detector",
                )
                click_target("run_detector", ready)
            def expected_result_rendered(state):
                result = state["observations"].get("result") or {}
                if result.get("original_unchanged") is not True:
                    return False
                if args.scenario == "heritage":
                    heritage = (result.get("advanced") or {}).get("heritage") or {}
                    legacy = heritage.get("legacy") or {}
                    return (result.get("operation") == "heritage"
                            and heritage.get("action") == "verify"
                            and legacy.get("status") == "detected"
                            and len(legacy.get("locations", [])) == 1
                            and len(legacy.get("decoded_records", [])) == 1)
                return (result.get("operation") == "detect_watermark"
                        and any(detection.get("method_id") == "stable_diffusion_xl_dwt_dct"
                                and detection.get("status") == "detected"
                                for detection in result.get("detections") or []))

            wait_for(expected_result_rendered, "the rendered real processing result")
            process.wait(timeout=max(1, deadline - time.monotonic()))
            if process.returncode != 0:
                raise RuntimeError(f"GUI exited {process.returncode}")
            evidence = json.loads(report.read_text(encoding="utf-8"))
            interaction = evidence["interaction"]
            observed = interaction["observations"]
            expected_targets = ["heritage_tab", "heritage_verify_tab", "heritage_run"] if args.scenario == "heritage" else ["images_tab", "run_detector"]
            assert observed["workspace"] == args.scenario, evidence
            for name in expected_targets:
                assert observed["actions"].get(name, 0) >= 1, evidence
            if args.scenario == "heritage":
                assert len(interaction["pointer_events"]) == 6, evidence
            else:
                assert len(interaction["pointer_events"]) >= 4, evidence
            for step in controller["steps"]:
                x, y = step["logical_center"]
                assert any(event["pressed"] and abs(event["position"][0] - x) <= 3
                           and abs(event["position"][1] - y) <= 3
                           for event in interaction["pointer_events"]), (step, evidence)
                if args.scenario == "heritage":
                    assert any(not event["pressed"] and abs(event["position"][0] - x) <= 3
                               and abs(event["position"][1] - y) <= 3
                               for event in interaction["pointer_events"]), (step, evidence)
            result = observed["result"]
            assert result["original_unchanged"] is True, result
            if args.scenario == "heritage":
                assert result["operation"] == "heritage", result
                heritage = result["advanced"]["heritage"]
                assert heritage["action"] == "verify", heritage
                legacy = heritage["legacy"]
                assert legacy["status"] == "detected", legacy
                assert len(legacy["locations"]) == 1, legacy
                assert len(legacy["decoded_records"]) == 1, legacy
                assert all("identifier" not in record for record in legacy["decoded_records"]), legacy
                assert heritage["personal_identity_authenticated"] is False, heritage
                controller["real_heritage_verification_result_rendered"] = True
            else:
                assert result["operation"] == "detect_watermark", result
                assert any(detection["method_id"] == "stable_diffusion_xl_dwt_dct"
                           and detection["status"] == "detected"
                           for detection in result["detections"]), result
                controller["real_watermark_detector_result_rendered"] = True
            screenshot = report.with_suffix(".png").read_bytes()
            assert screenshot.startswith(b"\x89PNG\r\n\x1a\n") and len(screenshot) > 1024
            assert struct.unpack(">II", screenshot[16:24]) == (evidence["width"], evidence["height"])
            assert hashlib.sha256(fixture.read_bytes()).hexdigest() == original_hash
            controller.update({
                "passed": True, "native_pointer_events_observed": True,
                "original_unchanged": True,
                "screenshot_sha256": hashlib.sha256(screenshot).hexdigest(),
            })
        except Exception as error:
            controller["error"] = f"{type(error).__name__}: {error}"
            raise
        finally:
            if process.poll() is None:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                                   capture_output=True, timeout=10)
                else:
                    os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=10)
            with report.with_suffix(".controller.json").open("x", encoding="utf-8") as evidence_file:
                json.dump(controller, evidence_file, indent=2)
                evidence_file.write("\n")
    print(json.dumps(controller))


if __name__ == "__main__":
    main()

# FVPROV1 14772 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI3ZDgyZjNhYWVlZDQ1OWQ1MjU4NTExYjY0ZmY1MjMxNTU4OWQ4MjFkNDUzMGI1ZTU3ODM5MjgzNGQ4YzRjOTMzIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4yIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMiIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL25hdGl2ZS1pbnRlcmFjdGlvbi5weSJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjU5ZTc5MDVhNjNmMjMyNzNjMTQ3OGE0Y2QwMTRlMDkyZGExZGJlOTE1YmE2ZTk4ODBiMGE5OTkzMDIwZDk1OWY0ODA4NmQ4YWY5YTUzNmU2NTRlMmY0MThkYzRiMzI3YjU0ZjhjNTUxMjUwODQwNzQ4MzFmZTI0ODY5YWRhZTBmIn1dfV0= FVPROV1-END
