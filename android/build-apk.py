#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Build the ARM64 Rust/Compose client and sign with a separate persistent key.

Secrets stay in the private signing directory and are passed by filename only.
No platform developer certificate or paid signing service is involved.
"""
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import secrets
import shutil
import stat
import struct
import subprocess
import zipfile


def inspect_native(data):
    """Release gate for the exact generated ELF64/ARM64 shared libraries."""
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 183:
        raise ValueError("Android native library is not ELF64 little-endian ARM64")
    offset = struct.unpack_from("<Q", data, 32)[0]
    width, count = struct.unpack_from("<HH", data, 54)
    if width != 56 or not 1 <= count <= 128 or offset + width * count > len(data):
        raise ValueError("Invalid Android ELF program headers")
    headers = [struct.unpack_from("<IIQQQQQQ", data, offset + index * width) for index in range(count)]
    loads = [header for header in headers if header[0] == 1]
    if not loads or any(header[7] < 16384 or header[2] % header[7] != header[3] % header[7] for header in loads):
        raise ValueError("Android ELF does not meet the 16 KiB page alignment gate")
    dynamic = next((header for header in headers if header[0] == 2), None)
    if not dynamic or dynamic[5] > 1024 * 1024 or dynamic[2] + dynamic[5] > len(data) or dynamic[5] % 16:
        raise ValueError("Invalid Android ELF dynamic table")
    values = [struct.unpack_from("<QQ", data, index) for index in range(dynamic[2], dynamic[2] + dynamic[5], 16)]
    string_address = next((value for tag, value in values if tag == 5), None)
    string_size = next((value for tag, value in values if tag == 10), None)
    segment = next((header for header in loads if string_address is not None and header[3] <= string_address < header[3] + header[5]), None)
    if not segment or not string_size or string_size > 1024 * 1024:
        raise ValueError("Missing bounded Android ELF string table")
    start = segment[2] + string_address - segment[3]
    if start + string_size > len(data):
        raise ValueError("Android ELF string table exceeds the file")
    table = data[start:start + string_size]
    dependencies = []
    for tag, value in values:
        if tag != 1:
            continue
        end = table.find(b"\0", value) if value < len(table) else -1
        if end < 0 or end - value > 255:
            raise ValueError("Invalid Android native dependency")
        name = table[value:end].decode("ascii")
        if not name or "/" in name or "\\" in name:
            raise ValueError("Android native dependency contains a build-host path")
        dependencies.append(name)
    return {"machine": "aarch64", "page_alignment": 16384, "dependencies": dependencies}


def inspect_apk(path):
    native = {}
    with path.open("rb") as handle, zipfile.ZipFile(handle) as archive:
        for item in archive.infolist():
            if not item.filename.startswith("lib/") or not item.filename.endswith(".so"):
                continue
            if item.filename not in {"lib/arm64-v8a/libfileveil_android.so", "lib/arm64-v8a/libfileveil_jni.so"} or item.filename in native or item.file_size > 64 * 1024 * 1024:
                raise ValueError("Unexpected native APK member")
            handle.seek(item.header_offset)
            header = handle.read(30)
            name_size, extra_size = struct.unpack_from("<HH", header, 26)
            if item.compress_type != zipfile.ZIP_STORED or (item.header_offset + 30 + name_size + extra_size) % 16384:
                raise ValueError("Native APK entry is not stored with 16 KiB alignment")
            native[item.filename] = inspect_native(archive.read(item))
    if len(native) != 2:
        raise ValueError("Both Rust Core and JNI bridge must be present")
    return native


def run(args, *, env=None, cwd=None):
    subprocess.run([str(arg) for arg in args], check=True, env=env, cwd=cwd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", type=Path, default=Path(os.environ.get("ANDROID_HOME", Path.home() / "Library/Android/sdk")))
    parser.add_argument("--ndk", default="25.1.8937393")
    parser.add_argument("--java-home", type=Path, default=Path(os.environ.get("JAVA_HOME", "/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home")))
    parser.add_argument("--gradle", default=os.environ.get("FILEVEIL_GRADLE"))
    parser.add_argument("--rustc", default=os.environ.get("RUSTC", "rustc"))
    parser.add_argument("--cargo", default=os.environ.get("CARGO", "cargo"))
    parser.add_argument("--signing-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--skip-rust", action="store_true")
    parser.add_argument("--offline", action="store_true", help="Use only already cached Cargo and Gradle dependencies")
    args = parser.parse_args()
    android = Path(__file__).resolve().parent
    root = android.parent
    signing_path = args.signing_dir.absolute()
    if signing_path.resolve().is_relative_to(root.resolve()):
        raise SystemExit("The APK signing directory must be outside the repository and build outputs")
    if signing_path.resolve().is_relative_to(args.output.absolute().parent.resolve()):
        raise SystemExit("The APK signing directory must be outside the public output directory")
    for ancestor in (signing_path, *signing_path.parents):
        if ancestor.is_symlink():
            raise SystemExit("Signing directory ancestors must not be symbolic links")
    env = os.environ.copy()
    gradle_home = Path(env.get("GRADLE_USER_HOME", root / "work/android-gradle-home"))
    temporary = root / "work/android-tmp"
    gradle_home.mkdir(parents=True, exist_ok=True)
    temporary.mkdir(parents=True, exist_ok=True)
    env.update(ANDROID_HOME=str(args.sdk), JAVA_HOME=str(args.java_home), CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="2", CARGO_TARGET_DIR=str(root / "target"), RUSTC=args.rustc, GRADLE_USER_HOME=str(gradle_home), TMPDIR=str(temporary), TEMP=str(temporary), TMP=str(temporary))
    system = platform.system()
    host = {"Darwin":"darwin-x86_64", "Linux":"linux-x86_64", "Windows":"windows-x86_64"}.get(system)
    if not host:
        raise SystemExit("Unsupported Android build host")
    tools = args.sdk / "ndk" / args.ndk / "toolchains/llvm/prebuilt" / host / "bin"
    clang = tools / ("aarch64-linux-android26-clang.cmd" if system == "Windows" else "aarch64-linux-android26-clang")
    env.update(CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=str(clang), CC_aarch64_linux_android=str(clang), AR_aarch64_linux_android=str(tools / ("llvm-ar.exe" if system == "Windows" else "llvm-ar")), RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384")
    if not args.skip_rust:
        run([args.cargo, "build", "--locked", "--release", "--target", "aarch64-linux-android", "-p", "fileveil-android"] + (["--offline"] if args.offline else []), env=env, cwd=root)
    native = android / "app/src/main/jniLibs/arm64-v8a"
    native.mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / "target/aarch64-linux-android/release/libfileveil_android.so", native)
    gradle = args.gradle or android / ("gradlew.bat" if system == "Windows" else "gradlew")
    escaped_temporary = str(temporary).replace('\\', '\\\\').replace('"', '\\"')
    jvm_args = f'-Xmx2g -Dfile.encoding=UTF-8 "-Djava.io.tmpdir={escaped_temporary}"'
    run([gradle, "--no-daemon", "--max-workers=2", f"-Djava.io.tmpdir={temporary}", f"-Dorg.gradle.jvmargs={jvm_args}"] + (["--offline"] if args.offline else []) + [":app:assembleRelease", ":app:assembleDebug", ":app:assembleDebugAndroidTest"], env=env, cwd=android)
    native_receipt = inspect_apk(android / "app/build/outputs/apk/release/app-release-unsigned.apk")
    if args.signing_dir.is_symlink():
        raise SystemExit("Signing directory must not be a symbolic link")
    args.signing_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.signing_dir.chmod(0o700)
    password = args.signing_dir / "apk-signing.password"
    keystore = args.signing_dir / "fileveil-android-release.jks"
    if any(path.is_symlink() for path in (password, keystore)):
        raise SystemExit("Signing files must not be symbolic links")
    for path in (password, keystore):
        if path.exists():
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or (os.name != "nt" and (info.st_mode & 0o077 or info.st_uid != os.getuid())):
                raise SystemExit("Existing signing files require private, owner-only regular-file permissions")
    if not keystore.exists():
        if password.exists():
            raise SystemExit("Signing password exists without its keystore; restore the existing identity first")
        fd = os.open(password, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(secrets.token_hex(32) + "\n")
        run([args.java_home / "bin/keytool", "-genkeypair", "-keystore", keystore, "-alias", "fileveil-release", "-keyalg", "RSA", "-keysize", "3072", "-validity", "10950", "-dname", "CN=FileVeil Android, O=FileVeil", "-storepass:file", password, "-keypass:file", password])
        keystore.chmod(0o600)
    if not password.is_file():
        raise SystemExit("Restore the signing password file; never replace an existing upgrade identity")
    build_tools = args.sdk / "build-tools/34.0.0"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists():
        raise SystemExit("Refusing to overwrite an existing APK")
    env["PATH"] = str(args.java_home / "bin") + os.pathsep + env.get("PATH", "")
    # apksigner reuses the store password for the key by default. Passing the
    # same one-line password file twice consumes its stream and fails at EOF.
    run([build_tools / "apksigner", "sign", "--ks", keystore, "--ks-key-alias", "fileveil-release", "--ks-pass", f"file:{password}", "--out", args.output, android / "app/build/outputs/apk/release/app-release-unsigned.apk"], env=env)
    verified = subprocess.check_output([str(build_tools / "apksigner"), "verify", "--verbose", "--print-certs", str(args.output)], env=env, text=True)
    with args.output.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    receipt = {"schema": "fileveil.android.apk-build.v1", "apk": args.output.name, "sha256": digest, "bytes": args.output.stat().st_size, "signature_verification": verified, "native_libraries": native_receipt, "abi": "arm64-v8a", "min_sdk": 26, "platform_certificate": "independent_persistent_android_key", "runtime_acceptance": "not_assessed"}
    args.output.with_suffix(".json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"apk": str(args.output), "sha256": receipt["sha256"], "bytes": receipt["bytes"]}))


if __name__ == "__main__":
    main()

# FVPROV1 11109 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIyOTlmZTFiYTA1MTVlYjVhMjVjNjM5YWY2MGViMGY3MzJhYjNmYzFjODU3ZGEzMzcyZTU4ZWNhN2FkOWVlY2Q4IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL2FuZHJvaWQvYnVpbGQtYXBrLnB5In0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiNDAzMzIyZDY5MTI1NzRhYzJmYWI3MjEzYzQ0NjFiM2FmODE4ZjZkODgzY2VmY2M1YmI4OTcxNmQzZGNhNTE1OTM5Njk5OWQ2NDJlNTZlNWVmNmY5ZWViMWIyMTMyZGE1MDViNzk1YjVhOTEyZDEzNDg2NDZlOWVmOWU2NmFhMDMifV19XQ== FVPROV1-END
