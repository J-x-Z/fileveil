#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Reproducible compiler/IR/runtime matrix; stores reports, never private keys."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("fv_oracle", ROOT / "oracle.py")
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def run(argv, env=None, expect=0):
    start = time.perf_counter()
    measured = platform.system() in ("Darwin", "Linux")
    timer = ["/usr/bin/time", "-l" if platform.system() == "Darwin" else "-v"] if measured else []
    process = subprocess.run(timer + list(map(str, argv)), text=True, capture_output=True,
                             env=env, timeout=120)
    elapsed = time.perf_counter() - start
    if process.returncode != expect:
        raise RuntimeError(f"command failed ({process.returncode}): {argv}\n{process.stderr[-8000:]}")
    rss = re.search(r"(\d+)\s+maximum resident set size", process.stderr)
    if rss:
        peak = int(rss.group(1))
    else:
        rss = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", process.stderr)
        peak = int(rss.group(1)) * 1024 if rss else None
    user = re.search(r"([\d.]+) user", process.stderr) or re.search(r"User time \(seconds\):\s*([\d.]+)", process.stderr)
    system = re.search(r"([\d.]+) sys", process.stderr) or re.search(r"System time \(seconds\):\s*([\d.]+)", process.stderr)
    metrics = {"wall_seconds": elapsed, "peak_rss_bytes": peak,
               "cpu_seconds": float(user.group(1)) + float(system.group(1)) if user and system else None}
    return process.stdout, metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--llvm", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--packet", type=Path, help="Public pass packet; a deterministic test packet is generated when omitted")
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    clang = args.llvm / "bin/clang"
    opt = args.llvm / "bin/opt"
    plugin = args.plugin.resolve()
    packet_path = args.packet.resolve() if args.packet else out / "test-packet.json"
    if not args.packet:
        packet_path.write_text(json.dumps({"schema": "fileveil.software.pass_packet.v1",
            "packet_hex": b"independent unsigned compiler fixture; Rust authentication assessed separately".hex(),
            "witness_hex": "0123456789abcdef", "challenge_hex": "13579bdf2468ace0"}))
    packet = json.loads(packet_path.read_text())
    witness = int(packet["witness_hex"], 16)
    challenge = int(packet.get("challenge_hex", "0"), 16)
    env = dict(os.environ, FILEVEIL_SOFTWARE_PACKET=str(packet_path))
    native_flags = []
    if platform.system() == "Darwin":
        sdk = subprocess.check_output(["/usr/bin/xcrun", "--show-sdk-path"], text=True).strip()
        native_flags = ["-isysroot", sdk, "-mmacosx-version-min=11.0"]
    base = out / "base.ll"
    marked = out / "marked.ll"
    clean = out / "clean.ll"
    run([clang, *native_flags, "-O1", "-Xclang", "-disable-llvm-passes", "-S", "-emit-llvm", ROOT / "fixtures/workload.c", "-o", base])
    inspect_base, _ = run([opt, f"-load-pass-plugin={plugin}", "-passes=fileveil-inspect", "-disable-output", base])
    run([opt, f"-load-pass-plugin={plugin}", "-passes=fileveil-mark", "-S", base, "-o", marked], env)
    run([opt, f"-load-pass-plugin={plugin}", "-passes=fileveil-mark", "-S", marked, "-o", out / "marked-again.ll"], env)
    again, _ = run([opt, f"-load-pass-plugin={plugin}", "-passes=fileveil-inspect", "-disable-output", out / "marked-again.ll"])
    clean_report, _ = run([opt, f"-load-pass-plugin={plugin}", "-passes=fileveil-clean", "-S", marked, "-o", clean])
    restoration = json.loads(clean_report)
    assert restoration["canonical_base_restored"], restoration
    assert json.loads(again)["base_ir_sha256"] == json.loads(inspect_base)["canonical_ir_sha256"]
    # Exercise existing ownership metadata in addition to the real C constructor.
    bookkeeping = out / "original-bookkeeping.ll"
    bookkeeping.write_text(base.read_text() + '\n@llvm.used = appending global [1 x ptr] [ptr @original_constructor], section "llvm.metadata"\n'
                          '@llvm.compiler.used = appending global [1 x ptr] [ptr @fileveil_fixture_workload], section "llvm.metadata"\n')
    book_mark = out / "original-bookkeeping-marked.ll"
    run([opt, f"-load-pass-plugin={plugin}", "-passes=fileveil-mark", "-S", bookkeeping, "-o", book_mark], env)
    book_clean, _ = run([opt, f"-load-pass-plugin={plugin}", "-passes=fileveil-clean", "-S", book_mark, "-o", out / "original-bookkeeping-clean.ll"])
    assert json.loads(book_clean)["canonical_base_restored"]
    empty = out / "empty-bookkeeping.ll"
    empty.write_text('target triple = "' + ("arm64-apple-macos11" if platform.system() == "Darwin" else "x86_64-unknown-linux-gnu") + '"\n'
                     '@llvm.global_ctors = appending global [0 x {i32, ptr, ptr}] zeroinitializer\n'
                     'define i32 @original() { ret i32 7 }\n')
    empty_mark = out / "empty-bookkeeping-marked.ll"
    run([opt, f"-load-pass-plugin={plugin}", "-passes=fileveil-mark", "-S", empty, "-o", empty_mark], env)
    empty_clean, _ = run([opt, f"-load-pass-plugin={plugin}", "-passes=fileveil-clean", "-S", empty_mark, "-o", out / "empty-bookkeeping-clean.ll"])
    assert json.loads(empty_clean)["canonical_base_restored"]
    conflict = out / "conflict.ll"
    conflict.write_text(base.read_text() + '\n@__fileveil_swm_user = global i32 1\n')
    run([opt, f"-load-pass-plugin={plugin}", "-passes=fileveil-mark", "-disable-output", conflict], env, expect=2)
    foreign = out / "foreign-user.ll"
    foreign.write_text(marked.read_text() + '\ndefine i32 @foreign_user() {\n%r = call i32 @fileveil_swm_probe_v1(i32 0, i64 0)\nret i32 %r\n}\n')
    run([opt, f"-load-pass-plugin={plugin}", "-passes=fileveil-clean", "-disable-output", foreign], expect=2)
    changed_packet = out / "changed-challenge.json"
    changed_packet.write_text(json.dumps(dict(packet, challenge_hex=f"{challenge ^ 1:016x}")))
    run([opt, f"-load-pass-plugin={plugin}", "-passes=fileveil-mark", "-disable-output", marked],
        dict(env, FILEVEIL_SOFTWARE_PACKET=str(changed_packet)), expect=2)
    rows, failures = [], []
    expected_output = None
    native = platform.machine() + "-" + platform.system().lower()
    extension = ".dylib" if platform.system() == "Darwin" else ".so"
    auto_checks = {}
    for level in ("O0", "O2"):
        binary = out / ("automatic-two-tu-" + level)
        run([clang, *native_flags, "-" + level, f"-fpass-plugin={plugin}",
             ROOT / "fixtures/workload.c", ROOT / "fixtures/runner.c", "-o", binary], env)
        assert oracle.inspect(binary)["carrier_present"]
        output, _ = run([binary, "20000000"])
        expected_output = output if expected_output is None else expected_output
        assert output == expected_output
        auto_checks[level] = "main_translation_unit_only_detected_and_functionally_equal"
    auto_library = out / ("automatic-selected" + extension)
    shared_flags = ["-dynamiclib"] if platform.system() == "Darwin" else ["-shared", "-fPIC"]
    run([clang, *native_flags, "-O2", *shared_flags, f"-fpass-plugin={plugin}",
         ROOT / "fixtures/workload.c", "-o", auto_library],
        dict(env, FILEVEIL_SOFTWARE_MODULE=str(ROOT / "fixtures/workload.c")))
    assert oracle.probe(auto_library, challenge, witness)["runtime_witness_matches"]
    auto_checks["explicit_module_selector"] = "shared_library_actual_runtime_probe_passed"
    for optimization in ("O0", "O2", "O3", "LTO"):
        flags = ["-O3", "-flto"] if optimization == "LTO" else ["-" + optimization]
        if optimization == "LTO" and platform.system() == "Darwin":
            flags += ["-Wl,-lto_library," + str(args.llvm / "lib/libLTO.dylib")]
        for mode, ir in (("baseline", base), ("marked", marked), ("clean", clean)):
            binary = out / f"{mode}-{optimization}"
            library = out / f"{mode}-{optimization}{extension}"
            try:
                _, build = run([clang, *native_flags, *flags, ir, ROOT / "fixtures/runner.c", "-o", binary])
                output, execution = run([binary, "20000000"])
                expected_output = output if expected_output is None else expected_output
                assert output == expected_output, (mode, optimization, output)
                inspected = oracle.inspect(binary)
                assert inspected["carrier_present"] == (mode == "marked")
                row = {"target": native, "optimization": optimization, "mode": mode,
                       "evidence": "native_execution", "build": build, "execution": execution,
                       "file_bytes": binary.stat().st_size, "functional_output": output.strip(),
                       "carrier_detected": inspected["carrier_present"]}
                shared = ["-dynamiclib"] if platform.system() == "Darwin" else ["-shared", "-fPIC"]
                run([clang, *native_flags, *flags, *shared, ir, "-o", library])
                if mode == "marked":
                    actual = oracle.probe(library, challenge, witness)
                    wrong = oracle.probe(library, challenge ^ 0x12345678, witness)
                    assert actual["runtime_witness_matches"] and not wrong["runtime_witness_matches"]
                    row.update(runtime_probe=actual, wrong_challenge_matches=wrong["runtime_witness_matches"])
                    stripped = out / f"marked-{optimization}-stripped{extension}"
                    shutil.copyfile(library, stripped)
                    run([args.llvm / "bin/llvm-strip", "--strip-all", stripped])
                    row["stripped_carrier_detected"] = oracle.inspect(stripped)["carrier_present"]
                    row["stripped_runtime_matches"] = oracle.probe(stripped, challenge, witness)["runtime_witness_matches"]
                    assert row["stripped_carrier_detected"] and row["stripped_runtime_matches"]
                    removed = out / f"marked-{optimization}-carrier-zeroed{extension}"
                    data = bytearray(library.read_bytes())
                    _, table = oracle.sections(data)
                    for label, offset, size in table:
                        if label in (".fvwm", ".fvcalc", "__DATA_CONST,__fvwm", "__DATA_CONST,__fvcalc"):
                            data[offset:offset + size] = bytes(size)
                    removed.write_bytes(data)
                    # macOS ad-hoc signatures cover file bytes; own modified fixture must be re-signed.
                    if platform.system() == "Darwin":
                        run(["/usr/bin/codesign", "--force", "--sign", "-", removed])
                    assert not oracle.inspect(removed)["carrier_present"]
                    row["carrier_clean_runtime_residual"] = oracle.probe(removed, challenge, witness)["runtime_witness_matches"]
                    assert row["carrier_clean_runtime_residual"]
                rows.append(row)
            except (RuntimeError, AssertionError, ValueError, OSError) as error:
                failures.append({"target": native, "optimization": optimization, "mode": mode, "error": str(error)})
    for target in ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"):
        for optimization in ("O0", "O2", "O3"):
            output = out / f"cross-{target}-{optimization}.o"
            try:
                # Different target triples require target-native data layout, so mark each fresh module.
                ir = out / f"cross-{target}.ll"
                marked_ir = out / f"cross-{target}-marked.ll"
                run([clang, "-target", target, "-O1", "-Xclang", "-disable-llvm-passes", "-S", "-emit-llvm", ROOT / "fixtures/workload.c", "-o", ir])
                run([opt, f"-load-pass-plugin={plugin}", "-passes=fileveil-mark", "-S", ir, "-o", marked_ir], env)
                _, build = run([clang, "-target", target, "-" + optimization, "-c", marked_ir, "-o", output])
                inspected = oracle.inspect(output)
                assert inspected["carrier_present"] and inspected["descriptor_present"]
                linker = shutil.which("lld-link" if "windows" in target else "ld.lld")
                linked_report = None
                if linker:
                    linked = out / f"cross-{target}-{optimization}.bin"
                    if "windows" in target:
                        link_args = [linker, "/entry:fileveil_fixture_workload", "/subsystem:console", "/nodefaultlib", "/out:" + str(linked), output]
                    else:
                        link_args = [linker, "-e", "fileveil_fixture_workload", "-static", output, "-o", linked]
                    run(link_args)
                    final = oracle.inspect(linked)
                    assert final["carrier_present"] and final["descriptor_present"]
                    stripped = out / f"cross-{target}-{optimization}-stripped.bin"
                    shutil.copyfile(linked, stripped)
                    run([args.llvm / "bin/llvm-strip", "--strip-all", stripped])
                    assert oracle.inspect(stripped)["carrier_present"]
                    linked_report = {"format": final["format"], "file_bytes": linked.stat().st_size,
                                     "carrier_detected": True, "stripped_carrier_detected": True,
                                     "native_execution_assessed": False}
                rows.append({"target": target, "optimization": optimization, "mode": "marked",
                             "evidence": "cross_compiled_object_only", "build": build,
                             "file_bytes": output.stat().st_size, "carrier_detected": True,
                             "linked_binary": linked_report,
                             "runtime_assessed": False})
            except (RuntimeError, AssertionError, ValueError, OSError) as error:
                failures.append({"target": target, "optimization": optimization, "error": str(error)})
    report = {"schema": "fileveil.software.compiler-benchmark.v1", "llvm_version": run([clang, "--version"])[0].splitlines()[0],
              "protocol_checks": {"existing_ctors_used_compiler_used_restored": True,
                  "original_empty_constructor_array_restored": True, "repeat_mark_idempotent": True,
                  "reserved_user_symbol_rejected": True, "foreign_probe_user_cleanup_rejected": True,
                  "changed_challenge_repeat_mark_rejected": True},
              "clang_automatic_checks": auto_checks,
              "ir_clean": restoration, "rows": rows, "failures": failures,
              "native_runs": sum(row["evidence"] == "native_execution" for row in rows),
              "cross_object_runs": sum(row["evidence"] == "cross_compiled_object_only" for row in rows),
              "packet_authentication_scope": "compiler fixture only; authenticated packet is checked by Rust engine"}
    (out / "benchmark.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"report": str(out / "benchmark.json"), "rows": len(rows), "failures": failures}, indent=2))
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
