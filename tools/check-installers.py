#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Exercise native installer installation, explicit replacement and removal."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(arguments: list[str], *, timeout: int = 180, env: dict | None = None) -> str:
    result = subprocess.run(arguments, capture_output=True, text=True,
                            timeout=timeout, env=env)
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    if result.returncode:
        print(result.stdout[-8000:], file=sys.stderr)
        raise RuntimeError(f"{Path(arguments[0]).name} exited with {result.returncode}")
    return result.stdout


def probe(cli: Path, gui: Path, version: str, temporary: Path,
          environment_overrides: dict | None = None) -> dict:
    environment = dict(os.environ)
    environment.update(environment_overrides or {})
    environment.pop("FILEVEIL_QPDF", None)
    assert run([str(cli), "--version"], env=environment).strip().split()[-1] == version
    capabilities = json.loads(run([str(cli), "capabilities", "--json"], env=environment))
    assert capabilities["pdf"]["available"] is True, capabilities["pdf"]
    report = temporary / "installed-gui.json"
    command = [str(gui), "--smoke-test-report", str(report)]
    if sys.platform.startswith("linux"):
        command = ["xvfb-run", "-a", *command]
    injected = []
    renderer = environment.get("FILEVEIL_CI_MESA_DIRECTORY") if os.name == "nt" else None
    try:
        if renderer:
            for source in sorted(Path(renderer).glob("*.dll")):
                destination = gui.parent / source.name
                if os.path.lexists(destination):
                    raise RuntimeError("CI renderer would overwrite an installed file")
                shutil.copyfile(source, destination)
                injected.append(destination)
            if not injected:
                raise RuntimeError("Configured CI renderer contains no DLLs")
        run(command, env=environment, timeout=120)
    finally:
        for destination in injected:
            destination.unlink()
    evidence = json.loads(report.read_text(encoding="utf-8-sig"))
    assert evidence["native_window_rendered"] is True, evidence
    image = report.with_suffix(".png")
    with image.open("rb") as stream:
        header = stream.read(24)
    assert header.startswith(b"\x89PNG\r\n\x1a\n")
    width, height = struct.unpack(">II", header[16:24])
    assert (width, height) == (evidence["width"], evidence["height"])
    assert width >= 320 and height >= 240
    return {"cli_version": version, "pdf_backend_available": True,
            "installed_gui_rendered": True, "framebuffer": evidence,
            "framebuffer_png_sha256": digest(image),
            "ci_renderer_injected_temporarily": bool(renderer)}


def macos(installer: Path, version: str, temporary: Path) -> dict:
    result = subprocess.run(
        ["hdiutil", "attach", "-readonly", "-nobrowse", "-plist", str(installer)],
        capture_output=True, timeout=120,
    )
    if result.returncode:
        raise RuntimeError(f"DMG mount failed. {result.stderr.decode(errors='replace')[-4000:]}")
    attached = plistlib.loads(result.stdout)
    volumes = [entry for entry in attached["system-entities"] if entry.get("mount-point")]
    devices = [entry["dev-entry"] for entry in volumes]
    try:
        if len(volumes) != 1:
            raise RuntimeError("The installer must mount exactly one filesystem volume")
        mounted = Path(volumes[0]["mount-point"])
        assert (mounted / "Applications").is_symlink()
        assert os.readlink(mounted / "Applications") == "/Applications"
        original = mounted / "FileVeil.app"
        installed = temporary / "Applications/FileVeil.app"
        installed.parent.mkdir()
        run(["ditto", str(original), str(installed)])
        run(["codesign", "--verify", "--strict", str(installed)])
        result = probe(installed / "Contents/MacOS/fileveil",
                       installed / "Contents/MacOS/fileveil-gui", version, temporary)
        # Exercise replacement solely inside this test's private Applications.
        # Finder provides the real interactive confirmation in normal installs.
        run(["ditto", str(original), str(installed)])
        run(["codesign", "--verify", "--strict", str(installed)])
        assert digest(installed / "Contents/MacOS/fileveil") == digest(original / "Contents/MacOS/fileveil")
        shutil.rmtree(installed)
        assert not installed.exists()
        result.update({"installation_scope": "temporary Applications directory",
                       "replacement_copy_verified": True, "removed": True,
                       "applications_link_valid": True})
        return result
    finally:
        for device in devices:
            run(["hdiutil", "detach", device], timeout=120)


def windows(installer: Path, version: str, temporary: Path) -> dict:
    import winreg

    installed = Path(os.environ["LOCALAPPDATA"]) / "Programs/FileVeil"
    if os.path.lexists(installed):
        raise RuntimeError("A FileVeil installation already exists. Refusing to modify it during acceptance")
    key = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\FileVeil.Desktop_is1"
    common = ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"]
    sentinel = installed / "unrelated-user-file.txt"
    installed_successfully = False
    try:
        run([str(installer), *common, f"/LOG={temporary / 'install.log'}"])
        installed_successfully = True
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as registry:
            assert winreg.QueryValueEx(registry, "DisplayVersion")[0] == version
            uninstall = winreg.QueryValueEx(registry, "UninstallString")[0].strip('"')
        result = probe(installed / "fileveil.exe", installed / "fileveil-gui.exe", version, temporary)
        sentinel.write_text("Preserve unrelated user data\n", encoding="utf-8")
        original_hash = digest(installed / "fileveil.exe")
        rejected = subprocess.run([str(installer), *common], capture_output=True, timeout=120)
        assert rejected.returncode != 0, "An unconfirmed silent replacement unexpectedly succeeded"
        assert digest(installed / "fileveil.exe") == original_hash
        run([str(installer), *common, "/FILEVEILUPGRADE=1", f"/LOG={temporary / 'upgrade.log'}"])
        assert sentinel.read_text(encoding="utf-8") == "Preserve unrelated user data\n"
        run([uninstall, *common])
        installed_successfully = False
        assert not (installed / "fileveil.exe").exists()
        assert sentinel.read_text(encoding="utf-8") == "Preserve unrelated user data\n"
        sentinel.unlink()
        installed.rmdir()
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key):
                raise AssertionError("Uninstall registry entry remains")
        except FileNotFoundError:
            pass
        result.update({"installation_scope": "current_user", "hkcu_uninstall_registration": True,
                       "unconfirmed_silent_replacement_blocked": True,
                       "explicit_upgrade_verified": True, "user_file_preserved": True, "removed": True})
        return result
    finally:
        if installed_successfully:
            uninstaller = installed / "unins000.exe"
            if uninstaller.is_file():
                run([str(uninstaller), *common])


def linux(installer: Path, version: str, temporary: Path) -> dict:
    present = subprocess.run(["dpkg-query", "-W", "-f=${db:Status-Status}", "fileveil"],
                             capture_output=True, text=True, timeout=30)
    if present.returncode == 0 and present.stdout.strip() == "installed":
        raise RuntimeError("A FileVeil installation already exists. Refusing to modify it during acceptance")
    installed = False
    config = temporary / "config"
    preferences = config / "FileVeil/preferences.json"
    preferences.parent.mkdir(parents=True)
    settings = b'{"language":"fr"}\n'
    preferences.write_bytes(settings)
    try:
        run(["sudo", "apt-get", "install", "--no-install-recommends", "-y", str(installer)], timeout=600)
        installed = True
        result = probe(Path("/usr/bin/fileveil"), Path("/usr/bin/fileveil-gui"), version, temporary,
                       {"XDG_CONFIG_HOME": str(config)})
        assert preferences.read_bytes() == settings
        desktop = Path("/usr/share/applications/com.fileveil.desktop.desktop")
        run(["desktop-file-validate", str(desktop)])
        assert Path("/usr/share/icons/hicolor/1024x1024/apps/com.fileveil.desktop.png").is_file()
        run(["sudo", "apt-get", "install", "--reinstall", "--no-install-recommends", "-y", str(installer)], timeout=600)
        assert run(["/usr/bin/fileveil", "--version"]).strip().split()[-1] == version
        assert preferences.read_bytes() == settings
        run(["sudo", "apt-get", "remove", "-y", "fileveil"], timeout=180)
        installed = False
        assert not Path("/usr/bin/fileveil").exists()
        assert not desktop.exists()
        assert preferences.read_bytes() == settings
        result.update({"installation_scope": "system_package_manager", "desktop_entry_valid": True,
                       "explicit_reinstall_verified": True, "user_settings_preserved": True,
                       "preserved_preference": {"language": "fr"},
                       "preference_scope": "isolated XDG_CONFIG_HOME/FileVeil/preferences.json",
                       "removed": True})
        return result
    finally:
        if installed:
            run(["sudo", "apt-get", "remove", "-y", "fileveil"], timeout=180)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installer", type=Path)
    parser.add_argument("--evidence", type=Path, default=ROOT / "work/installer-acceptance.json")
    parser.add_argument("--allow-system-install", action="store_true",
                        help="Allow apt install/remove of FileVeil on a disposable Linux CI runner")
    arguments = parser.parse_args()
    if os.path.lexists(arguments.evidence) or os.path.lexists(arguments.evidence.with_suffix(".png")):
        raise RuntimeError("Installer acceptance evidence destination already exists")
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    platform = "macos" if sys.platform == "darwin" else "windows" if os.name == "nt" else "linux"
    suffix = "macos.dmg" if platform == "macos" else "windows-installer.exe" if platform == "windows" else "linux-amd64.deb"
    installer = (arguments.installer or ROOT / "dist" / f"FileVeil-{version}-{suffix}").resolve()
    if platform == "linux" and not arguments.allow_system_install:
        raise RuntimeError("Linux acceptance requires --allow-system-install on a disposable test host")
    (ROOT / "work").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="installer-acceptance-", dir=ROOT / "work") as directory:
        if platform == "macos":
            checks = macos(installer, version, Path(directory))
        elif platform == "windows":
            checks = windows(installer, version, Path(directory))
        else:
            checks = linux(installer, version, Path(directory))
        result = {"schema": "fileveil.installer.acceptance.v1", "platform": platform,
                  "version": version, "artifact": installer.name,
                  "sha256": digest(installer),
                  **checks}
        arguments.evidence.parent.mkdir(parents=True, exist_ok=True)
        with (Path(directory) / "installed-gui.png").open("rb") as source:
            with arguments.evidence.with_suffix(".png").open("xb") as destination:
                shutil.copyfileobj(source, destination)
    arguments.evidence.parent.mkdir(parents=True, exist_ok=True)
    arguments.evidence.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, AssertionError, subprocess.SubprocessError) as error:
        print(f"FileVeil installer acceptance failed. {error}", file=sys.stderr)
        raise SystemExit(1)

# FVPROV1 12659 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJhNDRlNGVlZjkwYTRkMzI0NjE4ODIxNzViZTc0NDZmMjY5MTNiN2Y2ZjRlMzQzOTdiZjY0MWZiNmEwM2I3ZDYzIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4yIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMiIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL2NoZWNrLWluc3RhbGxlcnMucHkifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiJlOGVhZWJlNGY3MDdjMTNhNWVmOWUwODUzNzkwOTM5YjUyODE2MmI3Y2YzZTZkODlmOTkyOTA4MDc1ZTYwODUyZGI3YmQ1YjE1YWRlMmJhMzhhYWZmMmQwNTk2ODNlYTkzNGZlNzcxZTEyMWI4YzA2YTlkOWJhNTcwMTlkYmIwZiJ9XX1d FVPROV1-END
