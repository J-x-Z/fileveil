#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Explicit Cargo/CMake compiler-companion integration, without source edits.

Uses the existing signed software IR protocol. A separately compiled CRT module
is linked into named executable targets. This is not a rustc LLVM plugin and
does not claim semantic entanglement or resistance to deliberate removal.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
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


def snapshot(root):
    """Fingerprint source inputs, excluding known build and VCS directories."""
    result = {}
    count, total = 0, 0
    def fail(error):
        raise error
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=fail):
        for name in dirs:
            if (Path(directory) / name).is_symlink():
                raise ValueError("source tree contains a directory link")
        dirs[:] = sorted(d for d in dirs if d not in (".git", "target", "build", ".gradle"))
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


def compile_targets(args, mode, directory, companion):
    directory.mkdir()
    metrics = []
    artifact_paths = {}
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
            _, elapsed = execute([cargo, "rustc", "--locked", "--offline", "--manifest-path", root_manifest,
                                  "--target-dir", target_dir, "--profile", "release", "--bin", name, "--", *extra],
                                 args.source, args.timeout, env)
            metrics.append(elapsed)
            artifact_paths[name] = target_dir / "release" / (name + (".exe" if os.name == "nt" else ""))
    else:
        cmake = args.build_tool or shutil.which("cmake")
        if not cmake:
            raise ValueError("CMake is unavailable")
        build = directory / "build"
        clang = args.llvm_directory / "bin" / ("clang.exe" if os.name == "nt" else "clang")
        clangxx = args.llvm_directory / "bin" / ("clang++.exe" if os.name == "nt" else "clang++")
        configure = [cmake, "-S", args.source, "-B", build, "-DCMAKE_BUILD_TYPE=Release",
                     "-DCMAKE_C_COMPILER=" + str(clang), "-DCMAKE_CXX_COMPILER=" + str(clangxx),
                     "-DCMAKE_C_FLAGS_RELEASE=-" + args.optimization,
                     "-DCMAKE_CXX_FLAGS_RELEASE=-" + args.optimization]
        if args.lto:
            configure.append("-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON")
        if companion:
            hook = directory / "fileveil.cmake"
            hook.write_text(cmake_hook(args.target, companion), encoding="utf-8")
            configure.append("-DCMAKE_PROJECT_INCLUDE=" + str(hook))
        _, metric = execute(configure, args.source, args.timeout)
        metrics.append(metric)
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
        detected = oracle.inspect(final)["carrier_present"]
        if detected != (mode == "marked"):
            raise ValueError("independent known-carrier detection disagrees with build mode")
        row = {"sha256": sha(final), "bytes": final.stat().st_size, "carrier_detected": detected,
               "artifact": final.name, "execution": "not_assessed"}
        if detected:
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
            if args.allow_execution:
                values = []
                for vector in args.test_arguments:
                    raw, metric = execute([stripped, *vector], directory, args.timeout)
                    values.append({"stdout_sha256": hashlib.sha256(raw).hexdigest(), **metric})
                if [v["stdout_sha256"] for v in values] != [v["stdout_sha256"] for v in row["execution"]]:
                    raise ValueError("stripping changed the selected program outputs")
                row["strip"]["execution"] = values
        result[name] = row
    return {"build": metrics, "targets": result}


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
                  "source_unchanged": False, "runtime_semantic_entanglement": "not_claimed"}
        try:
            obj, evidence = mark_companion(args, output)
            report["companion"] = evidence
            for mode in ("baseline", "marked", "clean"):
                report[mode] = compile_targets(args, mode, output / mode, obj if mode == "marked" else None)
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
