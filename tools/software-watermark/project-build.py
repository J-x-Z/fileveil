#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Explicit Cargo/CMake compiler-companion integration, without source edits.

Uses the existing signed software IR protocol. A separately compiled CRT module
is linked into named executable targets. This is not a rustc LLVM plugin and
does not claim semantic entanglement or resistance to deliberate removal.
"""
import argparse
from contextlib import contextmanager, nullcontext
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
MAX_LOG = 2 * 1024 * 1024
MAX_ARTIFACT = 512 * 1024 * 1024


def load_oracle():
    spec = importlib.util.spec_from_file_location("fileveil_independent_oracle", HERE / "oracle.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def execute(argv, cwd, timeout=600, env=None, accepted_codes=(0,)):
    """Bound logs, elapsed time and the owned process group, including failures."""
    start = time.monotonic()
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        measured = platform.system() in ("Darwin", "Linux") and Path("/usr/bin/time").is_file()
        timer = ["/usr/bin/time", "-l" if platform.system() == "Darwin" else "-v"] if measured else []
        process = subprocess.Popen(timer + list(map(str, argv)), cwd=cwd, env=env,
                                   stdout=out, stderr=err, start_new_session=os.name == "posix")
        try:
            while process.poll() is None:
                if time.monotonic() - start > timeout:
                    raise ValueError("project command exceeded its timeout")
                if os.fstat(out.fileno()).st_size > MAX_LOG or os.fstat(err.fileno()).st_size > MAX_LOG:
                    raise ValueError("project command exceeded the 2 MiB log budget")
                try:
                    process.wait(timeout=0.02)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            elif process.poll() is None:
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                               capture_output=True, timeout=20, check=False)
            process.wait()
        out.seek(0)
        err.seek(0)
        stdout, stderr = out.read(MAX_LOG + 1), err.read(MAX_LOG + 1)
        if max(len(stdout), len(stderr)) > MAX_LOG:
            raise ValueError("project command exceeded the 2 MiB log budget")
        if process.returncode not in accepted_codes:
            # Arguments may contain a local key path, so do not echo the command.
            raise ValueError(f"project command exited {process.returncode}: " + stderr.decode(errors="replace")[-4000:])
        diagnostic = stderr.decode(errors="replace")
        rss = re.search(r"(\d+)\s+maximum resident set size", diagnostic)
        if rss:
            peak = int(rss.group(1))
        else:
            rss = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", diagnostic)
            peak = int(rss.group(1)) * 1024 if rss else None
        user = re.search(r"([\d.]+) user", diagnostic) or re.search(r"User time \(seconds\):\s*([\d.]+)", diagnostic)
        system = re.search(r"([\d.]+) sys", diagnostic) or re.search(r"System time \(seconds\):\s*([\d.]+)", diagnostic)
        return stdout, {"wall_seconds": time.monotonic() - start, "exit_code": process.returncode,
                        "peak_rss_bytes": peak,
                        "cpu_seconds": float(user.group(1)) + float(system.group(1)) if user and system else None}


def targets(values):
    if not 1 <= len(values) <= 32 or len(set(values)) != len(values):
        raise ValueError("select between 1 and 32 unique executable targets")
    if any(not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,127}", value) for value in values):
        raise ValueError("target names must be simple build identifiers")
    return values


def cmake_hook(target_names, companion):
    # Quoted CMake arguments still evaluate ${...}; bracket arguments do not.
    path = companion.as_posix()
    if "]]" in path or ";" in path or "\n" in path or "\r" in path:
        raise ValueError("CMake companion path cannot be represented safely")
    lines = ["# Generated FileVeil compiler-companion hook; no source changes.",
             "get_property(_fv_companion_set GLOBAL PROPERTY FILEVEIL_COMPANION_ATTACHED)",
             "if(_fv_companion_set)", "  return()", "endif()",
             "set_property(GLOBAL PROPERTY FILEVEIL_COMPANION_ATTACHED TRUE)"]
    for name in targets(target_names):
        lines.append(f"cmake_language(DEFER DIRECTORY \"${{CMAKE_SOURCE_DIR}}\" CALL target_link_libraries [[{name}]] PRIVATE [[{path}]])")
    return "\n".join(lines) + "\n"


def cmake_generator_arguments(windows=None):
    if windows is None:
        windows = os.name == "nt"
    if not windows:
        return []
    ninja = shutil.which("ninja")
    if not ninja:
        raise ValueError("Windows compiler-companion builds require Ninja to select SDK Clang explicitly")
    return ["-G", "Ninja", "-DCMAKE_MAKE_PROGRAM=" + str(Path(ninja).resolve())]


def check_cmake_compilers(build, expected):
    evidence = {}
    for language, selected in expected.items():
        candidates = list((build / "CMakeFiles").glob("*/CMake" + language + "Compiler.cmake"))
        if not candidates:
            continue
        if len(candidates) != 1 or candidates[0].stat().st_size > 512 * 1024:
            raise ValueError("CMake did not report one bounded compiler identity")
        text = candidates[0].read_text(encoding="utf-8", errors="strict")
        fields = {}
        for suffix in ("", "_ID", "_VERSION"):
            match = re.search(r'set\(CMAKE_' + language + r'_COMPILER' + suffix + r' "([^"\r\n]*)"\)', text)
            if not match:
                raise ValueError("CMake compiler identity is incomplete")
            fields[suffix] = match.group(1)
        if Path(fields[""]).resolve() != selected.resolve() or fields["_ID"] != "Clang":
            raise ValueError("CMake selected a compiler other than the requested SDK Clang")
        evidence[language] = {"path": fields[""], "id": fields["_ID"], "version": fields["_VERSION"]}
    if not evidence:
        raise ValueError("CMake did not configure a supported C or C++ compiler")
    return evidence


def cargo_executable(raw, package_id, target, target_directory):
    paths = []
    for line in raw.splitlines():
        item = json.loads(line)
        if (item.get("reason") == "compiler-artifact" and item.get("package_id") == package_id
                and item.get("target", {}).get("name") == target and "bin" in item["target"].get("kind", [])
                and item.get("executable") and not item.get("profile", {}).get("test")):
            paths.append(Path(item["executable"]))
    if len(paths) != 1 or not paths[0].is_absolute() or not paths[0].resolve().is_relative_to(target_directory.resolve()):
        raise ValueError("Cargo did not report one executable inside the authorized shared target")
    return paths[0]


def require_packet(actual, expected):
    if not expected or actual.get("packet_sha256") != expected:
        raise ValueError("linked artifact does not contain this run's exact authenticated companion packet")


@contextmanager
def cargo_cache_lock(directory, timeout):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / ".fileveil-companion.lock"
    if path.is_symlink():
        raise ValueError("Cargo companion lock must not be a link")
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    locked = False
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("Cargo companion lock must be a regular single-link file")
        if metadata.st_size == 0:
            os.write(fd, b"\0")
        started = time.monotonic()
        while not locked:
            try:
                if os.name == "nt":
                    import msvcrt
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
            except OSError:
                if time.monotonic() - started >= timeout:
                    raise ValueError("shared Cargo companion target is locked by another build")
                time.sleep(0.05)
        yield
    finally:
        if locked:
            if os.name == "nt":
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def snapshot(root):
    """Fingerprint the selected source tree, excluding Git's internal database.

    Build output is external. A directory merely named build/target might hold
    real inputs, so it must not silently disappear from the immutability claim.
    """
    result = {}
    count, total = 0, 0
    def fail(error):
        raise error
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=fail):
        for name in dirs:
            if (Path(directory) / name).is_symlink():
                raise ValueError("source tree contains a directory link")
        dirs[:] = sorted(d for d in dirs if d != ".git")
        for filename in sorted(files):
            path = Path(directory) / filename
            if path.is_symlink() or not path.is_file():
                raise ValueError("source tree contains a link or special file")
            size = path.stat().st_size
            count += 1
            total += size
            if count > 20000 or size > MAX_ARTIFACT or total > 2 * 1024 ** 3:
                raise ValueError("source snapshot exceeds its bounded scope")
            result[path.relative_to(root).as_posix()] = sha(path)
    return result


def mark_companion(args, output):
    companion = output / "companion.c"
    companion.write_text("/* SPDX-License-Identifier: MPL-2.0 */\nstatic const unsigned fv_project_companion = 1;\n", encoding="utf-8")
    ir = output / "companion.ll"
    argv = [args.fileveil, "--json", "software", "mark", companion, "--mode", "ir", "--output", ir,
            "--key", args.key, "--llvm-directory", args.llvm_directory, "--plugin", args.plugin,
            "--work-id", args.work_id, "--copy-id", args.copy_id, "--author", args.author,
            "--version", args.version, "--created-at", args.created_at]
    raw, metrics = execute(argv, output, args.timeout)
    report = json.loads(raw)
    if report.get("result") != "verified_within_scope" or not report.get("integrity", {}).get("original_unchanged"):
        raise ValueError("companion Mark did not verify")
    (output / "companion-mark.json").write_text(json.dumps(report, indent=2) + "\n")
    extension = ".obj" if os.name == "nt" else ".o"
    obj = output / ("companion" + extension)
    clang = args.llvm_directory / "bin" / ("clang.exe" if os.name == "nt" else "clang")
    _, compile_metrics = execute([clang, "-O2", "-c", ir, "-o", obj], output, args.timeout)
    if not load_oracle().inspect(obj)["carrier_present"]:
        raise ValueError("independent extractor did not recognize the companion object")
    return obj, {"mark": metrics, "compile": compile_metrics, "packet": report["advanced"]["software"]["packet"]}


def cmake_lto_arguments(llvm_directory, lto, system=None):
    if not lto:
        return []
    arguments = ["-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON"]
    system = system or platform.system()
    if system in ("Linux", "Windows"):
        linker = Path(llvm_directory) / "bin" / ("lld-link.exe" if system == "Windows" else "ld.lld")
        if not linker.is_file():
            raise ValueError("CMake LTO requires the LLVM SDK linker: " + str(linker))
        # SDK Clang finds lld in its own bin directory, avoiding host ld.bfd's
        # unavailable LLVMgold plugin. Darwin retains its existing ld64 path.
        arguments.extend("-DCMAKE_" + kind + "_LINKER_FLAGS=-fuse-ld=lld"
                         for kind in ("EXE", "SHARED", "MODULE"))
    return arguments


def compile_targets(args, mode, directory, companion, expected_packet=None):
    directory.mkdir()
    metrics = []
    artifact_paths = {}
    configured_compilers = None
    if args.build_system == "cargo":
        # Cargo's per-invocation extra rustc arguments apply to the selected
        # binary, not build scripts/proc macros/dependencies. No RUSTC_WRAPPER,
        # RUSTFLAGS, unstable plugin ABI or global Cargo configuration is used.
        cargo = args.build_tool or shutil.which("cargo")
        if not cargo:
            raise ValueError("Cargo is unavailable")
        metadata_raw, _ = execute([cargo, "metadata", "--locked", "--offline", "--no-deps", "--format-version", "1", "--manifest-path", args.source / "Cargo.toml"], args.source, args.timeout)
        metadata = json.loads(metadata_raw)
        root_manifest = (args.source / "Cargo.toml").resolve()
        packages = [p for p in metadata["packages"] if Path(p["manifest_path"]).resolve() == root_manifest]
        if len(packages) != 1:
            raise ValueError("select a concrete Cargo package manifest, not a virtual workspace")
        bins = {t["name"] for t in packages[0]["targets"] if "bin" in t["kind"]}
        if not set(args.target).issubset(bins):
            raise ValueError("selected Cargo target is not an executable in this package")
        target_dir = args.cargo_target_directory.resolve()
        target_dir.mkdir(parents=True, exist_ok=True)
        for name in args.target:
            extra = []
            if companion:
                extra += ["-C", "link-arg=" + str(companion)]
            # Cargo must propagate LTO/bitcode and optimization to dependencies
            # as well as the final crate. A leaf-only rustc -Clto flag fails on
            # cached rlibs built without bitcode.
            env = dict(os.environ, CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="2",
                       CARGO_PROFILE_RELEASE_OPT_LEVEL=args.optimization[1:],
                       CARGO_PROFILE_RELEASE_LTO="thin" if args.lto else "off")
            # Linker/compiler injection through ambient flags invalidates this
            # bounded recipe. Explicitly reject rather than silently override it.
            if any(env.get(k) for k in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER")):
                raise ValueError("clear ambient Rust flags/wrappers before a controlled build")
            raw, elapsed = execute([cargo, "rustc", "--locked", "--offline", "--message-format", "json-render-diagnostics", "--manifest-path", root_manifest,
                                  "--target-dir", target_dir, "--profile", "release", "--bin", name, "--", *extra],
                                 args.source, args.timeout, env)
            metrics.append(elapsed)
            artifact_paths[name] = cargo_executable(raw, packages[0]["id"], name, target_dir)
    else:
        cmake = args.build_tool or shutil.which("cmake")
        if not cmake:
            raise ValueError("CMake is unavailable")
        build = directory / "build"
        clang = args.llvm_directory / "bin" / ("clang.exe" if os.name == "nt" else "clang")
        clangxx = args.llvm_directory / "bin" / ("clang++.exe" if os.name == "nt" else "clang++")
        configure = [cmake, "-S", args.source, "-B", build, *cmake_generator_arguments(), "-DCMAKE_BUILD_TYPE=Release",
                     "-DCMAKE_C_COMPILER=" + str(clang), "-DCMAKE_CXX_COMPILER=" + str(clangxx),
                     "-DCMAKE_C_FLAGS_RELEASE=-" + args.optimization,
                     "-DCMAKE_CXX_FLAGS_RELEASE=-" + args.optimization]
        configure.extend(cmake_lto_arguments(args.llvm_directory, args.lto))
        if companion:
            hook = directory / "fileveil.cmake"
            hook.write_text(cmake_hook(args.target, companion), encoding="utf-8")
            configure.append("-DCMAKE_PROJECT_INCLUDE=" + str(hook))
        _, metric = execute(configure, args.source, args.timeout)
        metrics.append(metric)
        configured_compilers = check_cmake_compilers(build, {"C": clang, "CXX": clangxx})
        _, metric = execute([cmake, "--build", build, "--config", "Release", "--parallel", "2", "--target", *args.target], args.source, args.timeout)
        metrics.append(metric)
        for name in args.target:
            candidates = [build / name, build / "Release" / (name + ".exe"), build / (name + ".exe")]
            available = [p for p in candidates if p.is_file()]
            if len(available) != 1:
                raise ValueError("CMake target must emit a uniquely located top-level executable")
            artifact_paths[name] = available[0]
    result = {}
    oracle = load_oracle()
    for name, path in artifact_paths.items():
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARTIFACT:
            raise ValueError("generated executable is unsafe or oversized")
        final = directory / (name + (".exe" if os.name == "nt" else ""))
        shutil.copyfile(path, final)
        final.chmod(0o700)
        inspection = oracle.inspect(final)
        detected = inspection["carrier_present"]
        if detected != (mode == "marked"):
            raise ValueError("independent known-carrier detection disagrees with build mode")
        row = {"sha256": sha(final), "bytes": final.stat().st_size, "carrier_detected": detected,
               "artifact": final.name, "execution": "not_assessed"}
        if detected:
            require_packet(inspection, expected_packet)
            raw, _ = execute([args.fileveil, "--json", "software", "verify", final, "--key", args.key], directory, args.timeout, accepted_codes=(0, 4))
            verification = json.loads(raw)
            known = verification["advanced"]["software"]["binary"]["packets"]
            if not known or any(p.get("signature") != "valid" or p.get("decryption") != "valid" for p in known):
                raise ValueError("linked artifact did not retain its authenticated decodable packet")
            row["packet_verification"] = "valid"
            if args.independent_crypto:
                raw, _ = execute([sys.executable, HERE / "crypto_oracle.py", final, "--key", args.key], directory, args.timeout)
                row["independent_crypto"] = json.loads(raw)
                if row["independent_crypto"].get("decryption") != "valid":
                    raise ValueError("independent decoder did not confirm the packet")
        if args.allow_execution:
            observations = []
            for vector in args.test_arguments:
                raw, metric = execute([final, *vector], directory, args.timeout)
                observations.append({"stdout_sha256": hashlib.sha256(raw).hexdigest(), **metric})
            row["execution"] = observations
        if detected and args.strip:
            stripped = directory / (final.name + ".stripped")
            shutil.copy2(final, stripped)
            strip_tool = args.llvm_directory / "bin" / ("llvm-strip.exe" if os.name == "nt" else "llvm-strip")
            execute([strip_tool, "--strip-all", stripped], directory, args.timeout)
            row["strip"] = {"sha256": sha(stripped), "bytes": stripped.stat().st_size,
                            "carrier_detected": oracle.inspect(stripped)["carrier_present"],
                            "execution": "not_assessed"}
            if not row["strip"]["carrier_detected"]:
                raise ValueError("the selected strip recipe removed the known carrier")
            require_packet(oracle.inspect(stripped), expected_packet)
            if args.allow_execution:
                values = []
                for vector in args.test_arguments:
                    raw, metric = execute([stripped, *vector], directory, args.timeout)
                    values.append({"stdout_sha256": hashlib.sha256(raw).hexdigest(), **metric})
                if [v["stdout_sha256"] for v in values] != [v["stdout_sha256"] for v in row["execution"]]:
                    raise ValueError("stripping changed the selected program outputs")
                row["strip"]["execution"] = values
        result[name] = row
    return {"build": metrics, "configured_compilers": configured_compilers, "targets": result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-system", choices=("cargo", "cmake"), required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--target", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fileveil", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--llvm-directory", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--cargo-target-directory", type=Path)
    parser.add_argument("--build-tool", type=Path)
    parser.add_argument("--work-id", required=True)
    parser.add_argument("--copy-id", required=True)
    parser.add_argument("--author", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--optimization", choices=("O0", "O2", "O3"), default="O2")
    parser.add_argument("--lto", action="store_true")
    parser.add_argument("--strip", action="store_true", help="Also test LLVM strip on an independent marked copy")
    parser.add_argument("--independent-crypto", action="store_true", help="Require Python cryptography independent signature/decryption oracle")
    parser.add_argument("--allow-execution", action="store_true")
    parser.add_argument("--test-arguments-json", default="[[]]")
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()
    try:
        targets(args.target)
        args.test_arguments = json.loads(args.test_arguments_json)
        if not isinstance(args.test_arguments, list) or not 1 <= len(args.test_arguments) <= 32 or any(
                not isinstance(v, list) or len(v) > 32 or any(not isinstance(s, str) or len(s) > 1024 or "\0" in s for s in v)
                for v in args.test_arguments):
            raise ValueError("test arguments must contain 1–32 bounded string arrays")
        if not 1 <= args.timeout <= 3600:
            raise ValueError("timeout must be between 1 and 3600 seconds")
        for field in ("source", "fileveil", "key", "llvm_directory", "plugin"):
            setattr(args, field, getattr(args, field).resolve(strict=True))
        output = args.output.resolve()
        if output == args.source or output.is_relative_to(args.source) or args.source.is_relative_to(output):
            raise ValueError("output and source must be disjoint")
        if args.key.is_relative_to(args.source) or args.key.is_relative_to(output):
            raise ValueError("the signing key must be outside source and output")
        if args.build_system == "cargo" and args.cargo_target_directory is None:
            raise ValueError("Cargo integration requires an explicit existing shared target directory")
        if args.build_system == "cargo":
            cache = args.cargo_target_directory.resolve()
            if cache == args.source or cache.is_relative_to(args.source) or cache.is_relative_to(output):
                raise ValueError("the shared Cargo target directory must be outside source and output")
        before = snapshot(args.source)
        output.mkdir(parents=True, exist_ok=False)
        report = {"schema": "fileveil.software.project-build.v1", "status": "failed", "mode": "compiler_companion",
                  "support_status": "experimental", "build_system": args.build_system,
                  "platform": platform.platform(), "machine": platform.machine(), "optimization": args.optimization,
                  "lto": args.lto, "work_id": args.work_id, "copy_id": args.copy_id,
                  "content_binding_scope": "signed_companion_IR; use Project Sync to bind final executable bytes",
                  "process_lifecycle": "windows_running_leader_taskkill_only" if os.name == "nt" else "posix_session_cleanup",
                  "background_services": "caller_managed; Windows descendants surviving an exited leader are not contained by this adapter",
                  "source_unchanged": False, "runtime_semantic_entanglement": "not_claimed"}
        try:
            obj, evidence = mark_companion(args, output)
            report["companion"] = evidence
            lock = cargo_cache_lock(args.cargo_target_directory.resolve(), args.timeout) if args.build_system == "cargo" else nullcontext()
            with lock:
                for mode in ("baseline", "marked", "clean"):
                    report[mode] = compile_targets(args, mode, output / mode, obj if mode == "marked" else None,
                                                   evidence["packet"]["packet_sha256"] if mode == "marked" else None)
            for name in args.target:
                rows = [report[m]["targets"][name] for m in ("baseline", "marked", "clean")]
                if args.allow_execution:
                    if not all([o["stdout_sha256"] for o in row["execution"]] == [o["stdout_sha256"] for o in rows[0]["execution"]] for row in rows):
                        raise ValueError("marked or clean rebuild changed the selected program outputs")
                rows[1]["size_overhead_bytes"] = rows[1]["bytes"] - rows[0]["bytes"]
            report["source_unchanged"] = snapshot(args.source) == before
            if not report["source_unchanged"]:
                raise ValueError("project source changed during the build")
            report["status"] = "verified_within_scope" if args.allow_execution else "partially_verified"
            report["clean_verification"] = "independent_absence_and_controlled_clean_rebuild_output_comparison" if args.allow_execution else "independent_absence_and_controlled_clean_rebuild; program_execution_not_assessed"
        except BaseException as error:
            report["error"] = str(error)[:4000]
            raise
        finally:
            (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "failed", "error": str(error)[:4000]}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

# FVPROV1 27434 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJlMmUzM2QyNDlhNjU0NmQ5NzVkZmMwNWQ5MjdiMjdkZTg4YWE1ZDQ1NmUyMWQ2ODU2NWNhMDc0ZWNmNGE3YTRiIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL3NvZnR3YXJlLXdhdGVybWFyay9wcm9qZWN0LWJ1aWxkLnB5In0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiODBmYjg1ODQwNTQ0YzgxMzQ0NjEyNTJkNGNiZjdlNjhmMmI3NDRkZmQyYTg5NjgxMTRjMzA0Yjg0ZDEyZDViNmEzMTUxMGU3NzAxMGZmODIxNmY0OTVkNjEwNzk4YWQ4YzViNzc2NTcxYzgwOGYzYWY4M2Y2M2EzY2ZhYzU1MDYifV19XQ== FVPROV1-END
