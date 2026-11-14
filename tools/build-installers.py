#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Build a native installer from an existing, version-matched desktop package."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_ID = "com.fileveil.desktop"
WINDOWS_APP_ID = "FileVeil.Desktop"
DEBIAN_RUNTIME = (
    "libx11-6", "libxcursor1", "libxi6", "libxrandr2", "libxinerama1",
    "libxkbcommon0", "libxkbcommon-x11-0", "libwayland-client0", "libegl1",
    "libgl1", "libsecret-1-0", "qpdf", "poppler-utils",
)


class InstallerError(Exception):
    """A package or native installer prerequisite is invalid."""


def run(command: list[str], *, cwd: Path | None = None, timeout: int = 900) -> str:
    result = subprocess.run(command, cwd=cwd, capture_output=True,
                            text=True, timeout=timeout)
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    if result.returncode:
        print(result.stdout[-8000:], file=sys.stderr)
        raise InstallerError(f"{Path(command[0]).name} exited with {result.returncode}")
    return result.stdout


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_package(package: Path, version: str, platform: str) -> None:
    if package.is_symlink() or not package.is_dir():
        raise InstallerError("Input must be an existing desktop package directory")
    if platform == "macos":
        with (package / "Contents/Info.plist").open("rb") as stream:
            info = plistlib.load(stream)
        if (info.get("CFBundleIdentifier"), info.get("FileVeilReleaseVersion")) != (BUNDLE_ID, version):
            raise InstallerError("macOS app identity or version disagrees with the workspace")
        if info.get("CFBundleShortVersionString") != version.split("-", 1)[0]:
            raise InstallerError("macOS release version must contain the numeric SemVer core")
        build = info.get("CFBundleVersion", "")
        if not isinstance(build, str) or not re.fullmatch(r"[1-9]\d{0,3}\.\d{1,2}\.\d{1,2}", build):
            raise InstallerError("macOS build version must contain three numeric components")
        run(["codesign", "--verify", "--strict", str(package)], timeout=60)
        return
    manifest = json.loads((package / "fileveil-package.json").read_text(encoding="utf-8"))
    if (manifest.get("bundle_id"), manifest.get("version"), manifest.get("platform")) != (BUNDLE_ID, version, platform):
        raise InstallerError("Portable package identity, platform or version disagrees with the workspace")
    for name, hash_name in (("executable", "sha256"), ("cli_executable", "cli_sha256")):
        filename = manifest.get(name)
        if (not isinstance(filename, str) or Path(filename).name != filename
                or any(character in filename for character in ("/", "\\", ":"))):
            raise InstallerError("Portable executable name must be a single filename")
        binary = package / filename
        if binary.is_symlink() or not binary.is_file() or digest(binary) != manifest.get(hash_name):
            raise InstallerError("Portable executable does not match its package manifest")
    for path in package.rglob("*"):
        if path.is_symlink():
            raise InstallerError("Portable installer inputs must not contain symbolic links")


def debian_version(version: str) -> str:
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?", version):
        raise InstallerError("Unsupported release version syntax")
    return version.replace("-", "~", 1)


def windows_version(version: str) -> str:
    debian_version(version)
    core = version.split("-", 1)[0]
    revision = re.search(r"\.(\d+)$", version.split("-", 1)[1]) if "-" in version else None
    return f"{core}.{revision.group(1) if revision else '0'}"


def build_dmg(package: Path, staged: Path, temporary: Path) -> dict:
    contents = temporary / "image"
    contents.mkdir()
    run(["ditto", str(package), str(contents / "FileVeil.app")])
    (contents / "Applications").symlink_to("/Applications", target_is_directory=True)
    (contents / "Install.txt").write_text(
        "Drag FileVeil.app to Applications, then eject this disk image.\n"
        "将 FileVeil.app 拖到 Applications，然后推出磁盘映像。\n\n"
        "Existing copies are replaced only after Finder confirms the operation.\n"
        "This Alpha may require approval in macOS Privacy & Security.\n"
        "Developer ID signing and Apple notarization are recorded in the release notes.\n",
        encoding="utf-8",
    )
    run(["hdiutil", "create", "-volname", "FileVeil", "-srcfolder", str(contents),
         "-format", "UDZO", "-fs", "HFS+", str(staged)])
    run(["hdiutil", "verify", str(staged)], timeout=120)
    return {"tool": "hdiutil", "layout": ["FileVeil.app", "Applications", "Install.txt"],
            "installation": "Finder drag-and-drop with explicit replacement confirmation"}


def inno_script(package: Path, output: Path, version: str) -> str:
    # Windows paths cannot contain quotes. Reject control characters so no path
    # can inject another Inno Setup directive into the generated compiler input.
    for path in (package, output):
        if any(character in str(path) for character in ('"', "\r", "\n")):
            raise InstallerError("Installer source/output path contains unsupported characters")
    return r'''[Setup]
AppId=FileVeil.Desktop
AppName=FileVeil
AppVersion=@VERSION@
VersionInfoVersion=@NUMERIC_VERSION@
AppPublisher=J-x-Z
AppPublisherURL=https://github.com/J-x-Z/fileveil
AppSupportURL=https://github.com/J-x-Z/fileveil/issues
DefaultDirName={localappdata}\Programs\FileVeil
DefaultGroupName=FileVeil
PrivilegesRequired=lowest
DisableDirPage=yes
DisableProgramGroupPage=yes
UsePreviousAppDir=no
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
LicenseFile=@SOURCE@\resources\LICENSE
OutputDir=@OUTPUT@
OutputBaseFilename=FileVeil-@VERSION@-windows-installer
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\fileveil-gui.exe
CloseApplications=no
RestartApplications=no

[Files]
Source: "@SOURCE@\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\FileVeil"; Filename: "{app}\fileveil-gui.exe"; WorkingDir: "{app}"

[Code]
function GetFileAttributes(Name: String): Cardinal;
external 'GetFileAttributesW@kernel32.dll stdcall';

function ContainsRedirectedDirectory(Path: String): Boolean;
var
  Attributes: Cardinal;
  Parent: String;
begin
  Result := False;
  while Length(Path) > 3 do begin
    Attributes := GetFileAttributes(Path);
    if (Attributes <> $FFFFFFFF) and ((Attributes and $400) <> 0) then begin
      Result := True;
      Exit;
    end;
    Parent := ExtractFileDir(Path);
    if CompareText(Parent, Path) = 0 then
      Exit;
    Path := Parent;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Path: String;
  Manifest: AnsiString;
  Approved: Boolean;
  Index: Integer;
begin
  Result := '';
  Path := ExpandConstant('{app}');
  if CompareText(Path, ExpandConstant('{localappdata}\Programs\FileVeil')) <> 0 then begin
    Result := 'FileVeil must be installed in its current-user application directory.';
    Exit;
  end;
  if ContainsRedirectedDirectory(Path) then begin
    Result := 'The installation directory contains a symbolic link or junction.';
    Exit;
  end;
  if DirExists(Path) then begin
    if not LoadStringFromFile(Path + '\fileveil-package.json', Manifest) or
       (Pos('"bundle_id": "com.fileveil.desktop"', String(Manifest)) = 0) then begin
      Result := 'The destination already exists without a valid FileVeil identity. Move it before installing.';
      Exit;
    end;
    Approved := False;
    for Index := 1 to ParamCount do
      if CompareText(ParamStr(Index), '/FILEVEILUPGRADE=1') = 0 then
        Approved := True;
    if not Approved and not WizardSilent then
      Approved := MsgBox('Replace the installed FileVeil application? Your settings and other files will be preserved.', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
    if not Approved then
      Result := 'Replacing FileVeil requires confirmation. Automated upgrades require /FILEVEILUPGRADE=1.';
  end;
end;
'''.replace("@NUMERIC_VERSION@", windows_version(version)).replace("@VERSION@", version).replace(
        "@SOURCE@", str(package)).replace("@OUTPUT@", str(output))


def build_windows(package: Path, staged: Path, temporary: Path, version: str) -> dict:
    compiler = shutil.which("ISCC.exe") or shutil.which("iscc")
    if compiler is None:
        candidates = [Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Inno Setup 6/ISCC.exe"]
        compiler = next((str(path) for path in candidates if path.is_file()), None)
    if compiler is None:
        raise InstallerError("Inno Setup 6 ISCC.exe is required on the Windows build host")
    script = temporary / "FileVeil.iss"
    script.write_text(inno_script(package, temporary, version), encoding="utf-8-sig")
    output = run([compiler, str(script)])
    built = temporary / f"FileVeil-{version}-windows-installer.exe"
    built.rename(staged)
    return {"tool": "Inno Setup", "compiler_output": output[-8000:],
            "scope": "current_user", "elevation_requested": False,
            "automatic_replacement": False, "automatic_launch": False}


def build_deb(package: Path, staged: Path, temporary: Path, version: str) -> dict:
    architecture = run(["dpkg", "--print-architecture"]).strip()
    if architecture != "amd64":
        raise InstallerError("The current Linux release targets amd64")
    root = temporary / "debian-package"
    library = root / "usr/lib/fileveil"
    library.parent.mkdir(parents=True)
    shutil.copytree(package, library)
    for name in ("fileveil", "fileveil-gui"):
        (library / name).chmod(0o755)
        link = root / "usr/bin" / name
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(f"../lib/fileveil/{name}")
    desktop = root / "usr/share/applications/com.fileveil.desktop.desktop"
    desktop.parent.mkdir(parents=True)
    desktop.write_text(
        "[Desktop Entry]\nType=Application\nName=FileVeil\n"
        "Comment=Offline file privacy and watermark toolkit\n"
        "Comment[zh_CN]=离线文件隐私与水印工具\nExec=fileveil-gui\n"
        "Icon=com.fileveil.desktop\nTerminal=false\nCategories=Utility;Security;\n",
        encoding="utf-8",
    )
    icon = root / "usr/share/icons/hicolor/1024x1024/apps/com.fileveil.desktop.png"
    icon.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / "assets/icon.png", icon)
    documentation = root / "usr/share/doc/fileveil"
    documentation.mkdir(parents=True)
    shutil.copyfile(ROOT / "LICENSE", documentation / "copyright")
    # dpkg-shlibdeps reads the native distribution's symbol versions, avoiding
    # a hard-coded glibc minimum that may understate the build host's ABI.
    debian = temporary / "debian"
    debian.mkdir()
    (debian / "control").write_text(
        "Source: fileveil\nSection: utils\nPriority: optional\n"
        "Maintainer: JxZ <39978180+J-x-Z@users.noreply.github.com>\n\n"
        "Package: fileveil\nArchitecture: amd64\nDescription: File privacy toolkit\n",
        encoding="utf-8",
    )
    symbols = run(["dpkg-shlibdeps", "-O", f"-e{library / 'fileveil'}",
                   f"-e{library / 'fileveil-gui'}"], cwd=temporary)
    prefix = "shlibs:Depends="
    dependencies = next((line[len(prefix):] for line in symbols.splitlines() if line.startswith(prefix)), None)
    if not dependencies:
        raise InstallerError("dpkg-shlibdeps did not return native runtime dependencies")
    depends = ", ".join([dependencies, *DEBIAN_RUNTIME])
    metadata = root / "DEBIAN"
    metadata.mkdir()
    installed_size = sum(path.stat().st_size for path in root.rglob("*") if path.is_file() and not path.is_symlink())
    (metadata / "control").write_text(
        f"Package: fileveil\nVersion: {debian_version(version)}\nArchitecture: amd64\n"
        "Maintainer: JxZ <39978180+J-x-Z@users.noreply.github.com>\n"
        "Section: utils\nPriority: optional\n"
        f"Installed-Size: {(installed_size + 1023) // 1024}\nDepends: {depends}\n"
        "Recommends: xdg-desktop-portal, xdg-utils, gnome-keyring\n"
        "Homepage: https://github.com/J-x-Z/fileveil\n"
        "Description: Offline file privacy and watermark toolkit\n"
        " Native GUI, CLI and local MCP for privacy auditing, file sanitization,\n"
        " watermark analysis and provenance verification.\n",
        encoding="utf-8",
    )
    run(["dpkg-deb", "--root-owner-group", "--build", str(root), str(staged)])
    return {"tool": "dpkg-deb", "architecture": architecture, "depends": depends,
            "version": debian_version(version), "maintainer_scripts": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, help="Existing package from package-desktop.py")
    parser.add_argument("--output-directory", type=Path, default=ROOT / "dist")
    parser.add_argument("--evidence", type=Path, default=ROOT / "work/installer-build.json")
    arguments = parser.parse_args()
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    debian_version(version)
    platform = "macos" if sys.platform == "darwin" else "windows" if os.name == "nt" else "linux"
    package_name = "FileVeil.app" if platform == "macos" else f"FileVeil-{version}-{platform}"
    package = (arguments.package or ROOT / "dist" / package_name).expanduser().absolute()
    validate_package(package, version, platform)
    output = arguments.output_directory.resolve()
    output.mkdir(parents=True, exist_ok=True)
    name = (f"FileVeil-{version}-macos.dmg" if platform == "macos" else
            f"FileVeil-{version}-windows-installer.exe" if platform == "windows" else
            f"FileVeil-{version}-linux-amd64.deb")
    destination = output / name
    if os.path.lexists(destination):
        raise InstallerError(f"Installer output already exists ({destination})")
    with tempfile.TemporaryDirectory(prefix=".fileveil-installer-", dir=output) as directory:
        temporary = Path(directory)
        staged = temporary / name
        if platform == "macos":
            details = build_dmg(package, staged, temporary)
        elif platform == "windows":
            details = build_windows(package, staged, temporary, version)
        else:
            details = build_deb(package, staged, temporary, version)
        # Atomic publication leaves pre-existing files untouched, including a
        # destination created after the initial preflight.
        os.link(staged, destination)
    evidence = {"schema": "fileveil.installer.build.v1", "platform": platform,
                "version": version, "artifact": name, "sha256": digest(destination),
                "bytes": destination.stat().st_size, **details}
    arguments.evidence.parent.mkdir(parents=True, exist_ok=True)
    arguments.evidence.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(destination)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (InstallerError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"FileVeil installer build failed. {error}", file=sys.stderr)
        raise SystemExit(1)

# FVPROV1 15741 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJmN2MxZWE2ZmFjYzdmYzVhNjY4ZWEyOTQ1ODlhY2I5MzA2OTgwY2M5OGRkNWM3MzhjMzU1ODAxNjFjMmU3MjQ1IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4yIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMiIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL2J1aWxkLWluc3RhbGxlcnMucHkifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI4Zjk4MDQ0Y2YzODI4YjU2ZWU4NDQ1YzM1ZGM0MTgyNWU0MTAzOWYwZDg5NTkyYTQzMGMzZjAwYzEwN2Y1NzZlYzhhMjExNjhhNTg4NDkzZmFlMTZkNjRiM2I4MjA5ZTNkYTI5NTZiZTY2ZmQ1OWJlYzMxZjBkODQ3YjNkNzcwNSJ9XX1d FVPROV1-END
