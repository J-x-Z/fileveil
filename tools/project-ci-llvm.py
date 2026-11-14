#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Install the fixed LLVM SDK used by isolated compiler-watermark CI jobs."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import platform
import sys
import tarfile
import tempfile
import urllib.request

VERSION = "23.1.5"
ASSETS = {
    ("linux", "x86_64"): ("LLVM-23.1.5-Linux-X64.tar.xz", "f72edb0b36580ece7f52e23858f00c18fad4e87395ea7ad05d7e55c39f8fc78a"),
    ("darwin", "arm64"): ("LLVM-23.1.5-macOS-ARM64.tar.xz", "aba592b4a15e8f90c634c5367b51ec8418b8bcd2829865db331a17dc9418dcff"),
    ("win32", "amd64"): ("clang+llvm-23.1.5-x86_64-pc-windows-msvc.tar.xz", "62fdada7f6fa2b73856486dfbbdba3d2c1882991621615bcb55c60207611c6d4"),
}
SPEC = importlib.util.spec_from_file_location("fileveil_sdk_postprocess", Path(__file__).with_name("project-postprocess.py"))
POST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POST)


def install(destination):
    if destination.exists() or destination.is_symlink():
        raise ValueError("LLVM SDK installation requires a new directory")
    platform_id = (sys.platform, platform.machine().lower())
    selected = ASSETS.get(platform_id)
    if selected is None:
        raise ValueError("The fixed compiler SDK does not support " + "/".join(platform_id))
    asset, expected = selected
    with tempfile.TemporaryDirectory(prefix="fileveil-llvm-", dir=destination.parent) as name:
        root = Path(name)
        archive = root / "sdk.tar.xz"
        digest = hashlib.sha256()
        size = 0
        url = "https://github.com/llvm/llvm-project/releases/download/llvmorg-" + VERSION + "/" + asset
        with urllib.request.urlopen(url, timeout=120) as source, archive.open("xb") as target:
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                if size > 3 * 1024**3:
                    raise ValueError("LLVM SDK download exceeded its size limit")
                digest.update(chunk)
                target.write(chunk)
        if digest.hexdigest() != expected:
            raise ValueError("LLVM SDK checksum differs from the pinned upstream release")
        extracted = root / "extracted"
        extracted.mkdir()
        with tarfile.open(archive, mode="r|xz") as package:
            package.extractall(extracted, filter="data")
        roots = list(extracted.iterdir())
        if len(roots) != 1 or not roots[0].is_dir() or roots[0].is_symlink():
            raise ValueError("LLVM SDK archive has an unexpected root")
        sdk = roots[0]
        if not (sdk / "lib/cmake/llvm/LLVMConfig.cmake").is_file():
            raise ValueError("LLVM SDK does not include the compiler plugin development files")
        # Keep all LLVM package targets consistent for its generated CMake imports.
        POST.publish_directory(sdk, destination)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    destination = args.destination.absolute()
    destination.parent.mkdir(parents=True, exist_ok=True)
    install(destination)
    print("Installed LLVM " + VERSION)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        print("FileVeil LLVM SDK setup failed (" + str(error) + ")", file=sys.stderr)
        sys.exit(1)

# FVPROV1 3431 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJlMWM1NjIyZjc3YTcyMjhlMDE3ZWVmODJkZTU0NTRmYWUzNDgwNWM4ZDhiZWI5NjI0ZWM4NzkyMWQzOGQyOTRlIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL3Byb2plY3QtY2ktbGx2bS5weSJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6ImM5YTZkMDBlMGRiMDQzN2E2ZDUzZjBjMGEyMGJlZTVhNzFlZmEwZTZhYzdmMTU3MTNlMzA5NTRhYjM3NDUzNjg4NGY5ZjhmMGIxMzRkNWQ4YTFiZjdkNGRjZGYzNjY1ZDhkNDU1N2NkNmZiOWQ2ZTE2MDQ4YWZkZDM4YzZmODBlIn1dfV0= FVPROV1-END
