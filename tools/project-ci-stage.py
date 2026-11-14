#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Transfer bounded build artifacts between separate build and signing jobs."""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import time
import zipfile

SPEC = importlib.util.spec_from_file_location("postprocess", Path(__file__).with_name("project-postprocess.py"))
POST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POST)
VERIFIER_SPEC = importlib.util.spec_from_file_location("fileveil_ci_snapshot_verifier", Path(__file__).with_name("verify-source-tree.py"))
VERIFIER = importlib.util.module_from_spec(VERIFIER_SPEC)
# Reuse the reviewed source's Windows-aware path/fd comparison directly. Excluded
# bytecode caches must not supply a replacement for these identity checks.
exec(compile(Path(VERIFIER_SPEC.origin).read_bytes(), VERIFIER_SPEC.origin, "exec"), VERIFIER.__dict__)
MAX_FILES = 20000
MAX_FILE = 1024 * 1024 * 1024
MAX_TOTAL = 8 * MAX_FILE


@contextmanager
def archive_new(output):
    with tempfile.NamedTemporaryFile(prefix=".fileveil-zip-", dir=output.parent, delete=False) as stream:
        temporary = Path(stream.name)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            yield archive
        POST.publish_directory(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def file_stamp(info):
    return VERIFIER.identity(info)


@contextmanager
def open_snapshot(path, expected=None):
    before_path = path.lstat()
    if not VERIFIER.no_link(before_path) or not stat.S_ISREG(before_path.st_mode):
        raise ValueError("Transfer input must be a regular non-reparse file")
    if expected is not None and file_stamp(before_path) != file_stamp(expected):
        raise ValueError("Transfer input changed before it could be frozen")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as source:
        before_fd = os.fstat(source.fileno())
        if not VERIFIER.matches_opened_file(before_fd, before_path):
            raise ValueError("Transfer input was replaced before it could be frozen")
        yield source, before_fd
        after_fd = os.fstat(source.fileno())
        after_path = path.lstat()
        if (file_stamp(after_fd) != file_stamp(before_fd)
                or not VERIFIER.no_link(after_path)
                or file_stamp(after_path) != file_stamp(before_path)
                or not VERIFIER.matches_opened_file(after_fd, after_path)):
            raise ValueError("Transfer input changed during snapshot reading")


def write_member(archive, path, name, expected):
    with open_snapshot(path, expected) as (source, before):
        info = zipfile.ZipInfo(name)
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | stat.S_IMODE(before.st_mode)) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        written = 0
        with archive.open(info, "w", force_zip64=True) as target:
            while chunk := source.read(1024 * 1024):
                written += len(chunk)
                if written > before.st_size:
                    raise ValueError("Transfer input grew during export")
                target.write(chunk)
        if written != before.st_size:
            raise ValueError("Transfer input changed during export")


def portable(name):
    path = Path(name)
    reserved = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    reserved.update("COM" + str(index) for index in range(1, 10))
    reserved.update("LPT" + str(index) for index in range(1, 10))
    return (bool(name) and not path.is_absolute() and ".." not in path.parts
            and not any(char in name for char in "\\:\0\n\r<>\"|?*")
            and all(part and part[-1] not in " ." and part.split(".", 1)[0].upper() not in reserved
                    for part in name.split("/")))


def prepare(config_path, output):
    config = POST.read_config(config_path)
    root = config_path.absolute().parent.resolve()
    artifacts = POST.relative_directory(root, config.get("artifact_directory", "dist"))
    release_output = POST.relative_directory(root, config.get("output_directory", "fileveil-release"))
    if artifacts == release_output or artifacts in release_output.parents or release_output in artifacts.parents:
        raise ValueError("Release history must be outside the artifact input directory")
    if artifacts == output or artifacts in output.parents:
        raise ValueError("Build transfer must be outside the artifact input")
    if os.getenv("FILEVEIL_SIGNING_KEY_BASE64"):
        raise ValueError("Build preparation must run without the signing secret")
    context = {"schema": "fileveil.ci.build-context.v1", "build_assessed": False, "test_assessed": False,
               "github_commit": os.getenv("GITHUB_SHA"), "github_ref": os.getenv("GITHUB_REF"),
               "build_number": os.getenv("GITHUB_RUN_NUMBER"), "platform": sys.platform,
               "scope": "upstream_build_job_observations"}
    for field, assessed in (("build_argv", "build_assessed"), ("test_argv", "test_assessed")):
        command = config.get(field, [])
        if command:
            if command[0] in ("python", "python3"):
                command = [sys.executable, *command[1:]]
            started = time.monotonic()
            subprocess.run(command, cwd=root, env=POST.clean_environment(), check=True, timeout=7200)
            context[assessed] = True
            context[field + "_milliseconds"] = round((time.monotonic() - started) * 1000)
    if not artifacts.is_dir() or artifacts.is_symlink():
        raise ValueError("Build artifact directory is unavailable")
    files = []
    total = 0
    aliases = set()
    for directory, directories, names in os.walk(artifacts, followlinks=False):
        if any((Path(directory) / name).is_symlink() for name in directories):
            raise ValueError("Build artifacts cannot contain symbolic directories")
        for name in sorted(names):
            path = Path(directory) / name
            relative = path.relative_to(artifacts).as_posix()
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or not portable(relative) or relative.casefold() in aliases:
                raise ValueError("Build artifact is non-regular or has a colliding path")
            aliases.add(relative.casefold())
            if info.st_size > MAX_FILE or len(files) >= MAX_FILES:
                raise ValueError("Build artifact exceeds its per-file budget")
            total += info.st_size
            if total > MAX_TOTAL:
                raise ValueError("Build artifact transfer exceeds 8 GiB")
            with path.open("rb") as stream:
                prefix = stream.read(8192).lstrip()
            if prefix.startswith(POST.KEY_MAGIC) or (prefix.startswith(b"-----BEGIN ") and b"PRIVATE KEY-----" in prefix.split(b"\n", 1)[0]):
                raise ValueError("Private signing keys cannot enter a build transfer")
            files.append((path, relative, info))
    if not files:
        raise ValueError("Build artifact directory is empty")
    config["artifact_directory"] = "artifacts"
    config["output_directory"] = "copyright"
    config["build_argv"] = []
    config["test_argv"] = []
    with archive_new(output) as archive:
        for path, relative, info in files:
            write_member(archive, path, "artifacts/" + relative, info)
        archive.writestr("ci-config.json", json.dumps(config, ensure_ascii=True))
        archive.writestr("build-context.json", json.dumps(context, ensure_ascii=True))


def check_zip_directory(source):
    # Bound central-directory allocation before ZipFile constructs every ZipInfo.
    source.seek(0, os.SEEK_END)
    size = source.tell()
    tail_size = min(size, 65535 + 22)
    source.seek(size - tail_size)
    tail = source.read(tail_size)
    offset = tail.rfind(b"PK\x05\x06")
    if offset < 0 or len(tail) - offset < 22:
        raise ValueError("Transfer has no bounded ZIP directory")
    record = struct.unpack_from("<4s4H2LH", tail, offset)
    _, disk, directory_disk, disk_entries, entries, directory_size, directory_offset, comment = record
    if offset + 22 + comment != len(tail) or disk or directory_disk:
        raise ValueError("Transfer has an unsupported ZIP directory")
    end_offset = size - tail_size + offset
    locator = None
    if end_offset >= 20:
        source.seek(end_offset - 20)
        candidate = struct.unpack("<4sLQL", source.read(20))
        if candidate[0] == b"PK\x06\x07":
            locator = candidate
    # zipfile applies a present ZIP64 record even when legacy fields fit in 32 bits.
    if locator is not None:
        if locator[1] or locator[3] != 1 or locator[2] != end_offset - 76:
            raise ValueError("Transfer has an unsupported ZIP64 locator")
        source.seek(locator[2])
        large = struct.unpack("<4sQ2H2L4Q", source.read(56))
        if large[0] != b"PK\x06\x06" or large[1] != 44 or large[4] or large[5]:
            raise ValueError("Transfer has an unsupported ZIP64 directory")
        disk_entries, entries, directory_size, directory_offset = large[6:]
    elif entries == 65535 or directory_size == 0xffffffff or directory_offset == 0xffffffff:
        raise ValueError("Transfer has a missing ZIP64 directory")
    if (disk_entries != entries or entries > MAX_FILES + 2 or directory_size > 32 * 1024 * 1024
            or directory_offset + directory_size > end_offset):
        raise ValueError("Transfer exceeds its ZIP directory budget")


def receive(bundle, destination, history=False):
    if destination.exists() or destination.is_symlink():
        raise ValueError("Transfer extraction requires a new output directory")
    temporary = Path(tempfile.mkdtemp(prefix=".fileveil-transfer-", dir=destination.parent))
    try:
        with bundle.open("rb") as source_stream:
            check_zip_directory(source_stream)
            source_stream.seek(0)
            with zipfile.ZipFile(source_stream) as archive:
                members = archive.infolist()
                if len(members) > MAX_FILES + 2:
                    raise ValueError("Transfer exceeds its member budget")
                total = 0
                aliases = set()
                for member in members:
                    mode = member.external_attr >> 16
                    if member.is_dir():
                        continue
                    if (not portable(member.filename) or member.filename.casefold() in aliases
                            or stat.S_IFMT(mode) not in (0, stat.S_IFREG) or member.file_size > MAX_FILE):
                        raise ValueError("Transfer contains an unsafe member")
                    if history and (Path(member.filename).name not in ("manifest.json", "evidence.json", "COMMITTED")
                                    or member.file_size > 64 * 1024 * 1024):
                        raise ValueError("History transfer contains executable or private data")
                    aliases.add(member.filename.casefold())
                    total += member.file_size
                    total_limit = 256 * 1024 * 1024 if history else MAX_TOTAL
                    if total > total_limit or member.file_size > max(member.compress_size, 1) * 1000:
                        raise ValueError("Transfer exceeds its expansion budget")
                    path = temporary / member.filename
                    path.parent.mkdir(parents=True, exist_ok=True)
                    written = 0
                    with archive.open(member) as source, path.open("xb") as target:
                        while chunk := source.read(1024 * 1024):
                            written += len(chunk)
                            if written > member.file_size:
                                raise ValueError("Transfer member exceeded its declared size")
                            target.write(chunk)
                    if written != member.file_size:
                        raise ValueError("Truncated transfer member")
                    os.chmod(path, 0o700 if mode & 0o111 else 0o600)
        POST.publish_directory(temporary, destination)
    finally:
        if temporary.exists():
            import shutil
            shutil.rmtree(temporary)


def history_bundle(root, output):
    paths = []
    total = 0
    visited = 0
    for directory, directories, files in os.walk(root, followlinks=False):
        visited += 1
        if visited > MAX_FILES:
            raise ValueError("CI history exceeds its directory budget")
        if any((Path(directory) / name).is_symlink() for name in directories):
            raise ValueError("History cannot contain symbolic directories")
        # Generated asset copies are regenerated from current, hash-verified inputs.
        # Retained CI history transports signed public metadata only.
        if len(Path(directory).relative_to(root).parts) == 2:
            directories[:] = [name for name in directories if name not in ("files", "derived")]
        for name in files:
            if len(paths) >= MAX_FILES:
                raise ValueError("History exceeds its retained metadata budget")
            if name not in ("manifest.json", "evidence.json", "COMMITTED"):
                raise ValueError("CI history contains unexpected metadata files")
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("History contains a non-regular file")
            size = path.stat().st_size
            total += size
            if size > 64 * 1024 * 1024 or total > 256 * 1024 * 1024:
                raise ValueError("CI history exceeds its 256 MiB retained metadata budget")
            paths.append((path, path.stat()))
    if not paths or len(paths) > MAX_FILES:
        raise ValueError("History exceeds its retained metadata budget")
    with archive_new(output) as archive:
        for path, info in sorted(paths, key=lambda item: item[0]):
            write_member(archive, path, path.relative_to(root).as_posix(), info)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "receive", "history"))
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--history-only", action="store_true")
    args = parser.parse_args()
    if args.action == "prepare":
        prepare(args.input, args.output.absolute())
    elif args.action == "receive":
        receive(args.input, args.output.absolute(), args.history_only)
    else:
        history_bundle(args.input, args.output)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        print(f"FileVeil build transfer failed ({error})", file=sys.stderr)
        sys.exit(1)

# FVPROV1 15153 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJhMGU1OTAyNmYyZWFjYWY2MDRmMzgzMGU3ZjMxZmNmNGZkOWNkMGM0MTJhYTIyZGU4MjA0N2FhNTI5MDk4MTYwIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL3Byb2plY3QtY2ktc3RhZ2UucHkifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI3MjFhYzRkNjQ2Yzg0NTE1OWJmNzExMmE4YjA3YWQzMTM3ZGFlOTlhZjVlZjFiNGQyZDU0N2VlYWJlZGUyY2Y1NmZmNWNhODllMmM2MTBhY2JmNzMwNzlmNWY5NmRkYzI2ZGRkMGMzZTgyOGVkMzE3Mzg4NmY5MjA5NDU2NmYwYyJ9XX1d FVPROV1-END
