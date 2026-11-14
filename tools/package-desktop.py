#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Build and package the native FileVeil desktop app on the current host."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_ID = "com.fileveil.desktop"
BINARY_NAME = "fileveil-gui"
PRIVATE_KEY_SCAN_CHUNK = 64 * 1024
PRIVATE_KEY_MAGIC = b"FILEVEIL-ED25519-KEY-V1\n"
PRIVATE_PEM_HEADER = re.compile(rb"-----BEGIN (?:[A-Z0-9_-]+ )*PRIVATE KEY-----")


class PackagingError(Exception):
    """An actionable build or package failure."""


def run(command: list[str], *, timeout: int = 900) -> None:
    try:
        subprocess.run(command, cwd=ROOT, check=True, timeout=timeout)
    except FileNotFoundError as error:
        raise PackagingError(f"Required command is unavailable ({command[0]})") from error
    except subprocess.CalledProcessError as error:
        raise PackagingError(f"Command failed with exit code {error.returncode} ({command[0]})") from error
    except subprocess.TimeoutExpired as error:
        raise PackagingError(f"Command exceeded its time budget ({command[0]})") from error


def no_clobber_rename(source: Path, destination: Path) -> None:
    """Publish a same-filesystem directory while atomically protecting collisions."""
    if sys.platform == "win32":
        os.rename(source, destination)
        return
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        rename = library.renamex_np
        rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        result = rename(os.fsencode(source), os.fsencode(destination), 4)  # RENAME_EXCL
    elif sys.platform.startswith("linux"):
        try:
            rename = library.renameat2
        except AttributeError as error:
            raise PackagingError("This libc does not expose atomic no-clobber directory publication") from error
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        result = rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1)  # RENAME_NOREPLACE
    else:
        raise PackagingError("Desktop packaging supports macOS, Windows and Linux")
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)


def verify_owned_package(destination: Path, platform: str) -> None:
    if destination.is_symlink() or not destination.is_dir():
        raise PackagingError("Existing output is not a FileVeil package directory")
    try:
        if platform == "macos":
            with (destination / "Contents" / "Info.plist").open("rb") as stream:
                identifier = plistlib.load(stream).get("CFBundleIdentifier")
        else:
            identifier = json.loads((destination / "fileveil-package.json").read_text()).get("bundle_id")
    except (OSError, ValueError, plistlib.InvalidFileException) as error:
        raise PackagingError("Existing output has no readable FileVeil package identity") from error
    if identifier != BUNDLE_ID:
        raise PackagingError("Existing output belongs to a different package")


def publish(staged: Path, destination: Path, *, replace: bool, platform: str) -> None:
    previous = None
    if os.path.lexists(destination):
        if not replace:
            raise PackagingError(f"Output already exists ({destination}). Use --replace to update a FileVeil package")
        verify_owned_package(destination, platform)
        previous = destination.with_name(f".{destination.name}.previous-{uuid.uuid4().hex}")
        no_clobber_rename(destination, previous)
    try:
        no_clobber_rename(staged, destination)
    except OSError as error:
        if previous is not None:
            try:
                no_clobber_rename(previous, destination)
            except OSError as restore_error:
                raise PackagingError(f"Publication failed. The previous package is preserved at {previous}") from restore_error
        raise PackagingError("Output appeared concurrently or could not be published") from error
    if previous is not None:
        try:
            shutil.rmtree(previous)
        except OSError:
            print(f"Packaged successfully. Previous package retained at {previous}", file=sys.stderr)


def has_private_key(path: Path) -> bool:
    """Inspect complete files with bounded memory, retaining source literals."""
    with path.open("rb") as stream:
        if stream.read(len(PRIVATE_KEY_MAGIC)) == PRIVATE_KEY_MAGIC:
            return True
        stream.seek(0)
        # A supported PEM boundary fits in 128 bytes. Long preamble lines are
        # discarded, while arbitrarily long indentation and trailing whitespace
        # consume no additional memory. readline's size cap also bounds binary
        # and single-line source files.
        prefix = bytearray()
        bom_prefix = bytearray()
        started = False
        boundary = False
        rejected = False
        while fragment := stream.readline(PRIVATE_KEY_SCAN_CHUNK):
            ended = fragment.endswith(b"\n")
            content = fragment[:-1] if ended else fragment
            if not rejected:
                if not started:
                    content = content.lstrip(b" \t")
                    if bom_prefix or content.startswith(b"\xef"):
                        count = min(3 - len(bom_prefix), len(content))
                        bom_prefix.extend(content[:count])
                        content = content[count:]
                        if len(bom_prefix) < 3:
                            content = b""
                        else:
                            if bom_prefix == b"\xef\xbb\xbf":
                                content = content.lstrip(b" \t")
                            else:
                                content = bytes(bom_prefix) + content
                            bom_prefix.clear()
                    started = bool(content)
                if boundary:
                    rejected = bool(content.strip(b" \t\r"))
                elif content:
                    available = 128 - len(prefix)
                    prefix.extend(content[:available])
                    boundary = PRIVATE_PEM_HEADER.fullmatch(prefix.rstrip(b" \t\r")) is not None
                    if boundary:
                        rejected = bool(content[available:].strip(b" \t\r"))
                    elif len(content) > available:
                        rejected = True
            if ended:
                if boundary and not rejected:
                    return True
                prefix.clear()
                bom_prefix.clear()
                started = boundary = rejected = False
        return boundary and not rejected


def private_resource_names(directory: str, names: list[str]) -> list[str]:
    """Keep operational keys out of recursively copied third-party notices."""
    return [
        name for name in names
        if (Path(directory) / name).is_file() and has_private_key(Path(directory) / name)
    ]


def copy_resources(destination: Path) -> None:
    project_license = ROOT / "LICENSE"
    if not project_license.is_file():
        raise PackagingError("Project LICENSE is required for desktop packaging")
    if has_private_key(project_license):
        raise PackagingError("Project LICENSE contains private-key material")
    notices = destination / "THIRD_PARTY_NOTICES"
    notices.mkdir(parents=True)
    shutil.copyfile(project_license, destination / "LICENSE")
    font_notices = notices / "assets" / "fonts"
    font_notices.mkdir(parents=True)
    for source in sorted((ROOT / "assets" / "fonts").glob("*.txt")):
        if not has_private_key(source):
            shutil.copyfile(source, font_notices / source.name)
    licenses = ROOT / "assets" / "licenses"
    if licenses.is_dir():
        shutil.copytree(licenses, notices / "assets" / "licenses", ignore=private_resource_names)
    for name in ("THIRD_PARTY_NOTICES.txt", "LICENSE", "LICENSE-MIT", "LICENSE-APACHE"):
        source = ROOT / name
        if source.is_file() and not has_private_key(source):
            shutil.copyfile(source, notices / name)
    for name in ("Cargo.lock", "docs/GUI.md"):
        source = ROOT / name
        if source.is_file() and not has_private_key(source):
            shutil.copyfile(source, destination / source.name)
    # Include the corresponding project source for MPL section 3.2 distributions.
    source_paths = None
    try:
        source_listing = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=ROOT, capture_output=True, check=False, timeout=30,
        )
        if source_listing.returncode == 0:
            source_paths = {os.fsdecode(path) for path in source_listing.stdout.split(b"\0") if path}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    with zipfile.ZipFile(destination / "FileVeil-source.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for base in ["Cargo.toml", "Cargo.lock", "LICENSE", "README.md", "README.zh-CN.md", ".gitignore", ".gitattributes", ".github", "crates", "tools", "docs", "tests", "assets", "provenance", "THIRD_PARTY_NOTICES.txt"]:
            source = ROOT / base
            paths = source.rglob("*") if source.is_dir() else [source]
            for path in sorted(paths):
                relative = path.relative_to(ROOT)
                if source_paths is not None and relative.as_posix() not in source_paths:
                    continue
                if any(part in ("__pycache__", ".git", "target") for part in relative.parts):
                    continue
                if path.name == ".DS_Store" or ".clean." in path.name:
                    continue
                if path.is_file() and not path.is_symlink():
                    if has_private_key(path):
                        continue
                    archive.write(path, relative)


def bundle_macos_qpdf(resources: Path) -> None:
    configured = os.environ.get("FILEVEIL_QPDF")
    source = Path(configured) if configured else Path("/opt/homebrew/bin/qpdf")
    if not source.is_file():
        print("PDF full rewrite requires a separately configured qpdf backend", file=sys.stderr)
        return
    source = source.resolve()
    destination = resources / "backends"
    destination.mkdir()
    pending = [source]
    copied: dict[Path, Path] = {}
    dependencies: dict[Path, list[tuple[str, Path]]] = {}
    while pending:
        current = pending.pop()
        if current in copied:
            continue
        target = destination / current.name
        if target.exists():
            raise PackagingError("Bundled PDF backend library names collide")
        shutil.copy2(current, target)
        target.chmod(target.stat().st_mode | 0o200)
        copied[current] = target
        listing = subprocess.check_output(["otool", "-L", str(current)], text=True)
        linked = [line.strip().split(" (", 1)[0] for line in listing.splitlines()[1:]]
        dependencies[current] = []
        for dependency in linked:
            if dependency.startswith(("/usr/lib/", "/System/Library/")):
                continue
            if dependency.startswith("@rpath/"):
                candidate = current.parent.parent / "lib" / Path(dependency).name
            elif dependency.startswith("@loader_path/"):
                candidate = current.parent / dependency.removeprefix("@loader_path/")
            else:
                candidate = Path(dependency)
            resolved = candidate.resolve()
            if resolved != current:
                if not resolved.is_file():
                    raise PackagingError(f"Cannot resolve PDF backend library ({dependency})")
                dependencies[current].append((dependency, resolved))
                pending.append(resolved)
    for current, target in copied.items():
        if target.suffix == ".dylib":
            run(["install_name_tool", "-id", f"@loader_path/{target.name}", str(target)])
        for dependency, resolved in dependencies[current]:
            run(["install_name_tool", "-change", dependency, f"@loader_path/{copied[resolved].name}", str(target)])
        run(["codesign", "--force", "--sign", "-", "--timestamp=none", str(target)])
        # Homebrew formulae preserve their applicable attribution files at this root.
        formula = current.parent.parent
        texts = [path for path in formula.iterdir() if path.is_file() and path.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE", "README"))]
        if not texts:
            raise PackagingError(f"PDF backend license texts are missing ({formula.name})")
        notices = resources / "THIRD_PARTY_NOTICES" / "pdf-backends" / formula.parent.name
        notices.mkdir(parents=True, exist_ok=True)
        for text in texts:
            shutil.copy2(text, notices / text.name)
    run([str(destination / source.name), "--version"], timeout=30)


def create_icon(source: Path | None, resources: Path, temporary: Path) -> str | None:
    if source is None:
        return None
    if not source.is_file():
        raise PackagingError(f"Icon input does not exist ({source})")
    icon = resources / "FileVeil.icns"
    if source.suffix.lower() == ".icns":
        shutil.copyfile(source, icon)
        return icon.name
    if source.suffix.lower() != ".png":
        raise PackagingError("The macOS icon input must be PNG or ICNS")
    iconset = temporary / "FileVeil.iconset"
    iconset.mkdir()
    for size in (16, 32, 128, 256, 512):
        for scale in (1, 2):
            suffix = "@2x" if scale == 2 else ""
            output = iconset / f"icon_{size}x{size}{suffix}.png"
            run(["sips", "-z", str(size * scale), str(size * scale), str(source), "--out", str(output)], timeout=30)
    run(["iconutil", "--convert", "icns", str(iconset), "--output", str(icon)], timeout=30)
    return icon.name


def minimum_macos(paths: list[Path]) -> str:
    versions = [(11, 0)]
    for path in paths:
        listing = subprocess.check_output(["otool", "-l", str(path)], text=True)
        for value in re.findall(r"^\s*minos\s+([\d.]+)", listing, re.MULTILINE):
            versions.append(tuple(int(part) for part in value.split(".")))
    return ".".join(str(part) for part in max(versions))


def macos_bundle_versions(version: str, build_override: str | None = None) -> tuple[str, str]:
    """Keep SemVer in FileVeilReleaseVersion and Apple's fields numeric.

    Build tuples preserve release order within the older 4/2/2 digit limits.
    The final component reserves ranges for alpha, beta, rc and stable releases.
    An explicit build version accommodates future version schemes.
    """
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-([A-Za-z0-9.]+))?", version)
    if match is None:
        raise PackagingError("Unsupported macOS release version syntax")
    major, minor, patch = (int(match[index]) for index in (1, 2, 3))
    release = f"{major}.{minor}.{patch}"
    if build_override is not None:
        if not re.fullmatch(r"[1-9]\d{0,3}\.\d{1,2}\.\d{1,2}", build_override):
            raise PackagingError("--macos-build-version requires three numeric components within 4/2/2 digits")
        return release, ".".join(str(int(part)) for part in build_override.split("."))
    build_major = major * 100 + minor + 1
    stage = 99
    if match[4] is not None:
        prerelease = re.fullmatch(r"(alpha|beta|rc)\.([1-9]\d*)", match[4])
        if prerelease is None or int(prerelease[2]) > 24:
            raise PackagingError("Use --macos-build-version for this prerelease version")
        stage = {"alpha": 0, "beta": 25, "rc": 50}[prerelease[1]] + int(prerelease[2])
    if minor > 99 or patch > 99 or build_major > 9999:
        raise PackagingError("Use --macos-build-version for this release version")
    return release, f"{build_major}.{patch}.{stage}"


def package_macos(binary: Path, stage: Path, version: str, icon: Path | None, temporary: Path,
                  build_version: str | None = None) -> None:
    release_version, bundle_version = macos_bundle_versions(version, build_version)
    contents = stage / "Contents"
    executable = contents / "MacOS" / BINARY_NAME
    executable.parent.mkdir(parents=True)
    resources = contents / "Resources"
    copy_resources(resources)
    bundle_macos_qpdf(resources)
    shutil.copyfile(binary, executable)
    executable.chmod(stat.S_IMODE(binary.stat().st_mode) | 0o111)
    cli_binary = binary.with_name("fileveil")
    cli = contents / "MacOS" / cli_binary.name
    shutil.copyfile(cli_binary, cli)
    cli.chmod(stat.S_IMODE(cli_binary.stat().st_mode) | 0o111)
    run(["codesign", "--force", "--sign", "-", "--timestamp=none", str(cli)], timeout=60)
    info = {
        "CFBundleName": "FileVeil",
        "CFBundleDisplayName": "FileVeil",
        "CFBundleIdentifier": BUNDLE_ID,
        "CFBundleExecutable": BINARY_NAME,
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": release_version,
        "CFBundleVersion": bundle_version,
        "FileVeilReleaseVersion": version,
        "CFBundleDevelopmentRegion": "en",
        "CFBundleLocalizations": ["en", "zh-Hans", "ja", "ko", "es", "fr", "de", "pt", "ru"],
        "CFBundleInfoDictionaryVersion": "6.0",
        "LSMinimumSystemVersion": minimum_macos([binary, cli_binary]),
        "NSHighResolutionCapable": True,
        "NSPrincipalClass": "NSApplication",
        "NSDocumentsFolderUsageDescription": "FileVeil reads the files you select for local privacy auditing.",
        "NSDownloadsFolderUsageDescription": "FileVeil reads the files you select for local privacy auditing.",
        "NSRemovableVolumesUsageDescription": "FileVeil reads selected files and saves copies in your chosen location.",
    }
    icon_name = create_icon(icon, resources, temporary)
    if icon_name is not None:
        info["CFBundleIconFile"] = icon_name
    with (contents / "Info.plist").open("wb") as stream:
        plistlib.dump(info, stream, sort_keys=True)
    backends = sorted((resources / "backends").glob("*"))
    if backends:
        (resources / "pdf-backend.json").write_text(json.dumps({
            "backend": "qpdf", "optional": True,
            "minimum_macos_version": minimum_macos(backends),
            "gui_minimum_macos_version": info["LSMinimumSystemVersion"],
            "override": "FILEVEIL_QPDF absolute path",
        }, indent=2) + "\n")
    (contents / "PkgInfo").write_bytes(b"APPL????")
    run(["codesign", "--force", "--sign", "-", "--timestamp=none", str(stage)], timeout=60)
    run(["codesign", "--verify", "--strict", "--verbose=2", str(stage)], timeout=60)


def package_portable(binary: Path, stage: Path, version: str, platform: str) -> None:
    stage.mkdir()
    executable = stage / binary.name
    shutil.copyfile(binary, executable)
    executable.chmod(stat.S_IMODE(binary.stat().st_mode) | 0o111)
    cli_binary = binary.with_name("fileveil.exe" if platform == "windows" else "fileveil")
    cli = stage / cli_binary.name
    shutil.copyfile(cli_binary, cli)
    cli.chmod(stat.S_IMODE(cli_binary.stat().st_mode) | 0o111)
    copy_resources(stage / "resources")
    pdf_backend = portable_pdf_backend(stage, platform)
    manifest = {
        "bundle_id": BUNDLE_ID,
        "name": "FileVeil",
        "version": version,
        "platform": platform,
        "executable": executable.name,
        "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "cli_executable": cli.name,
        "cli_sha256": hashlib.sha256(cli.read_bytes()).hexdigest(),
        "pdf_backend": pdf_backend,
    }
    (stage / "fileveil-package.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def portable_pdf_backend(stage: Path, platform: str) -> dict:
    """Bundle the configured Windows qpdf pair and probe the actual runtime."""
    configured = os.environ.get("FILEVEIL_QPDF")
    source = Path(configured) if configured else Path("/usr/bin/qpdf")
    if platform == "windows" and not configured:
        return {"mode": "external", "available_at_build": False,
                "runtime_requirement": "Configure an absolute FILEVEIL_QPDF path"}
    if not source.is_absolute() or not source.is_file():
        return {"mode": "external", "available_at_build": False,
                "runtime_requirement": "Install qpdf or configure an absolute FILEVEIL_QPDF path"}
    probe = source
    if platform == "windows":
        source = source.resolve()
        library = source.parent / "qpdf30.dll"
        if not library.is_file():
            raise PackagingError("Configured Windows qpdf requires its matching qpdf30.dll")
        destination = stage / "backends"
        destination.mkdir()
        probe = destination / "qpdf.exe"
        shutil.copy2(source, probe)
        shutil.copy2(library, destination / library.name)
        notices = stage / "resources" / "THIRD_PARTY_NOTICES" / "pdf-backends" / "qpdf"
        notices.mkdir(parents=True)
        for name in ("LICENSE.txt", "NOTICE.md"):
            license_file = ROOT / "assets" / "licenses" / "external-qpdf" / name
            if not license_file.is_file():
                raise PackagingError(f"qpdf distribution notice is missing ({name})")
            shutil.copy2(license_file, notices / name)
        for license_file in sorted((ROOT / "assets" / "licenses" / "external-qpdf").glob("windows-*")):
            if license_file.is_file():
                shutil.copy2(license_file, notices / license_file.name)
    try:
        result = subprocess.run([str(probe), "--version"], capture_output=True, text=True,
                                check=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as error:
        raise PackagingError("The packaged PDF backend runtime probe failed") from error
    return {
        "mode": "bundled" if platform == "windows" else "system",
        "available_at_build": True,
        "version": result.stdout.splitlines()[0][:200] if result.stdout else "unknown",
        "runtime_requirement": "Microsoft Visual C++ 2015-2022 x64 runtime" if platform == "windows"
                               else "A compatible system qpdf installation and its shared-library dependencies",
        "independent_pdf_validation": "Requires separately configured Poppler pdfinfo, pdftotext and pdftoppm",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-build", action="store_true", help="Package an existing release binary")
    parser.add_argument("--target-directory", type=Path, default=ROOT / "target", help="Cargo target directory")
    parser.add_argument("--output-directory", type=Path, default=ROOT / "dist", help="Destination for the app or portable directory")
    parser.add_argument("--replace", action="store_true", help="Update an existing package with the FileVeil identity")
    parser.add_argument("--icon", type=Path, help="macOS PNG or ICNS icon. Defaults to assets/FileVeil.icns")
    parser.add_argument("--macos-build-version", help="Explicit increasing numeric CFBundleVersion (for example 6.0.2)")
    arguments = parser.parse_args()
    target = arguments.target_directory.expanduser().resolve()
    output = arguments.output_directory.expanduser().resolve()
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    platform = "macos" if sys.platform == "darwin" else "windows" if sys.platform == "win32" else "linux"
    executable_name = BINARY_NAME + (".exe" if platform == "windows" else "")
    binary = target / "release" / executable_name
    name = "FileVeil.app" if platform == "macos" else f"FileVeil-{version}-{platform}"
    destination = output / name
    if os.path.lexists(destination):
        if not arguments.replace:
            raise PackagingError(f"Output already exists ({destination}). Use --replace to update a FileVeil package")
        verify_owned_package(destination, platform)
    if not arguments.skip_build:
        run(["cargo", "build", "--locked", "--release", "-p", "fileveil-gui", "-p", "fileveil-cli", "--target-dir", str(target)])
    if not binary.is_file():
        raise PackagingError(f"Release binary is missing ({binary})")
    try:
        probe = subprocess.run([str(binary), "--version"], cwd=ROOT, text=True, capture_output=True, timeout=60)
    except subprocess.TimeoutExpired as error:
        raise PackagingError("Desktop binary version probe exceeded 60 seconds") from error
    except OSError as error:
        raise PackagingError(f"Could not start the desktop binary version probe ({error})") from error
    if probe.returncode != 0:
        detail = probe.stderr.strip()[-2048:]
        raise PackagingError(f"Desktop binary version probe returned exit code {probe.returncode}. {detail}")
    actual = probe.stdout.strip()
    if actual.split()[-1:] != [version]:
        raise PackagingError(f"Release binary version disagrees with workspace version ({actual})")
    cli_binary = binary.with_name("fileveil.exe" if platform == "windows" else "fileveil")
    if not cli_binary.is_file():
        raise PackagingError("Matching release CLI is missing. Build fileveil-cli and fileveil-gui before --skip-build")
    try:
        cli_probe = subprocess.run([str(cli_binary), "--version"], cwd=ROOT, text=True, capture_output=True, timeout=60)
    except subprocess.TimeoutExpired as error:
        raise PackagingError("CLI version probe exceeded 60 seconds") from error
    if cli_probe.returncode != 0 or cli_probe.stdout.strip().split()[-1:] != [version]:
        raise PackagingError("Release CLI version disagrees with workspace version")
    output.mkdir(parents=True, exist_ok=True)
    icon = arguments.icon
    if icon is None and (ROOT / "assets" / "FileVeil.icns").is_file():
        icon = ROOT / "assets" / "FileVeil.icns"
    with tempfile.TemporaryDirectory(prefix=".fileveil-package-", dir=output) as directory:
        temporary = Path(directory)
        staged = temporary / name
        if platform == "macos":
            package_macos(binary, staged, version, icon, temporary, arguments.macos_build_version)
        else:
            package_portable(binary, staged, version, platform)
        publish(staged, destination, replace=arguments.replace, platform=platform)
    print(destination)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PackagingError, OSError) as error:
        print(f"FileVeil packaging failed. {error}", file=sys.stderr)
        raise SystemExit(1)

# FVPROV1 26903 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJlZDA4OGZhNTFkNTFmNjZiM2IyN2YyZTNiZjYwZmE2ZTA5YWY3Nzc1NWU5ODZkZTYwZmNhOTE3YTRjNzE4NjM0IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4zIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMyIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL3BhY2thZ2UtZGVza3RvcC5weSJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjA2YWRiNmVmZDMxOGJjNTIxN2FiMGEzNmQwYzQ1N2I0ZWVlZmYyNmNjNjkyNGI1YjlhMGIxZWQ3YjBkMDUwZTFiMjlhOGM3MTcyNTVhMzNhZjE2YzkzZTQ5NzlkNWQxN2I0ZWNmYzc1ZDYxOTIwM2I2MTZhMDgzMmRjZTIyNTAyIn1dfV0= FVPROV1-END
