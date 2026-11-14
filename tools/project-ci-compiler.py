#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Isolated prepare, IR-sign and final-build stages for compiler watermark CI."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


POST = module("fileveil_compiler_postprocess", "project-postprocess.py")
STAGE = module("fileveil_compiler_transfer", "project-ci-stage.py")
SCHEMA = "fileveil.ci.compiler-stage.v1"
MAX_IR = 64 * 1024 * 1024


def read_json(path, maximum=1024 * 1024):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError("Compiler stage metadata must be a bounded regular file")
    result = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(result, dict):
        raise ValueError("Compiler stage metadata must be an object")
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()


def declaration(config):
    return {key: config.get(key) for key in ("work_id", "author", "copy_id", "policy", "rules", "compiler")}


def sha(path, maximum=STAGE.MAX_FILE):
    with STAGE.open_snapshot(path) as (source, before):
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError("Compiler stage input exceeds its regular-file budget")
        result = hashlib.sha256()
        count = 0
        while chunk := source.read(1024 * 1024):
            count += len(chunk)
            if count > maximum:
                raise ValueError("Compiler stage input grew beyond its budget")
            result.update(chunk)
        if count != before.st_size:
            raise ValueError("Compiler stage input changed during hashing")
    return result.hexdigest()


def no_secret():
    if os.getenv("FILEVEIL_SIGNING_KEY_BASE64"):
        raise ValueError("Compiler preparation and final build require a job without the signing secret")


def tools(prefix):
    prefix = prefix.resolve(strict=True)
    extension = ".exe" if os.name == "nt" else ""
    result = {name: prefix / "bin" / (name + extension) for name in ("clang", "clang++", "opt")}
    if not all(path.is_file() for path in result.values()):
        raise ValueError("Select a complete trusted LLVM installation prefix")
    return result


def stop(process):
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    else:
        process.kill()
    process.wait()


def execute(argv, directory, extra_environment=None, timeout=120):
    environment = POST.clean_environment()
    if extra_environment:
        environment.update(extra_environment)
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen([str(value) for value in argv], cwd=directory, env=environment,
            stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=os.name == "posix")
        deadline = time.monotonic() + timeout
        while process.poll() is None:
            if time.monotonic() > deadline or os.fstat(stdout.fileno()).st_size > 8 * 1024 * 1024 or os.fstat(stderr.fileno()).st_size > 8 * 1024 * 1024:
                stop(process)
                raise ValueError("Compiler/test subprocess exceeded its time or output budget")
            time.sleep(0.02)
        stdout.seek(0)
        stderr.seek(0)
        output, errors = stdout.read(8 * 1024 * 1024 + 1), stderr.read(8 * 1024 * 1024 + 1)
        if len(output) > 8 * 1024 * 1024 or len(errors) > 8 * 1024 * 1024:
            raise ValueError("Compiler/test subprocess exceeded its output budget")
        return {"returncode": process.returncode, "stdout_sha256": hashlib.sha256(output).hexdigest(),
                "stderr_sha256": hashlib.sha256(errors).hexdigest()}


def checked(argv, directory, extra_environment=None, timeout=120):
    result = execute(argv, directory, extra_environment, timeout)
    if result["returncode"] != 0:
        raise ValueError("Configured compiler or test command failed")
    return result


def flags(config):
    compiler = config["compiler"]
    arguments = compiler.get("compiler_arguments", [])
    protected = ("-o", "--output", "-MF", "-MJ", "-Xclang", "-Xlinker", "-load", "-plugin", "-S", "-c", "-E", "-emit-llvm", "-serialize-diagnostics")
    for value in arguments:
        if (value in protected or value.startswith(("@", "--output=", "-fplugin", "-fpass-plugin", "-Wl,", "-Wa,", "-Wp,", "-fmodule-output", "-fprofile-"))
                or value.startswith("-o") and len(value) > 2):
            raise ValueError("Compiler flags cannot redirect managed outputs or load project plugins")
    result = list(arguments)
    if sys.platform == "darwin":
        sdk = subprocess.check_output(["/usr/bin/xcrun", "--show-sdk-path"], text=True, env=POST.clean_environment(), timeout=30).strip()
        result.extend(["-isysroot", sdk])
    if compiler.get("target_triple"):
        result.extend(["--target", compiler["target_triple"]])
    return result


def optimization(config):
    value = config["compiler"].get("optimization") or "O2"
    return ["-O2", "-flto", "-fuse-ld=lld"] if value == "LTO" else ["-" + value]


def tree(root, prefix):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Compiler stage requires a regular input directory")
    result = {}
    for directory, directories, files in os.walk(root, followlinks=False):
        if any((Path(directory) / name).is_symlink() for name in directories):
            raise ValueError("Compiler stages cannot transfer symbolic directories")
        for name in files:
            path = Path(directory) / name
            relative = POST.relative_name(path.relative_to(root).as_posix())
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError("Compiler stages cannot transfer special files")
            result[prefix + relative] = path
            if len(result) > STAGE.MAX_FILES:
                raise ValueError("Compiler stage exceeds its file budget")
    return result


def bundle(output, entries, metadata):
    if len(entries) + len(metadata) > STAGE.MAX_FILES:
        raise ValueError("Compiler transfer exceeds its combined file budget")
    total = 0
    aliases = set()
    for name, path in entries.items():
        POST.relative_name(name)
        info = path.lstat()
        if name.casefold() in aliases or not stat.S_ISREG(info.st_mode) or info.st_size > STAGE.MAX_FILE:
            raise ValueError("Compiler transfer contains aliases or oversized files")
        aliases.add(name.casefold())
        total += info.st_size
    if total > STAGE.MAX_TOTAL:
        raise ValueError("Compiler transfer exceeds eight GiB")
    with STAGE.archive_new(output) as archive:
        for name, path in sorted(entries.items()):
            with path.open("rb") as source:
                prefix = source.read(8192).lstrip()
            if prefix.startswith(POST.KEY_MAGIC) or prefix.startswith(b"-----BEGIN ") and b"PRIVATE KEY-----" in prefix.split(b"\n", 1)[0]:
                raise ValueError("Private keys cannot enter a compiler transfer")
            STAGE.write_member(archive, path, name, path.lstat())
        for name, value in metadata.items():
            if name.casefold() in aliases:
                raise ValueError("Compiler stage metadata collides with an artifact")
            data = canonical(value)
            if len(data) > 1024 * 1024:
                raise ValueError("Compiler stage metadata exceeds its budget")
            archive.writestr(name, data)


def context(config):
    return {"schema": "fileveil.ci.build-context.v1", "build_assessed": True, "test_assessed": False,
        "github_commit": os.getenv("FILEVEIL_PROJECT_COMMIT", os.getenv("GITHUB_SHA")),
        "github_ref": os.getenv("GITHUB_REF"), "build_number": os.getenv("GITHUB_RUN_NUMBER"),
        "platform": sys.platform, "scope": "upstream_compiler_build_observations"}


def prepare(args):
    no_secret()
    config = POST.read_config(args.config.absolute())
    if config["policy"] not in ("compiler_watermark", "hybrid"):
        raise ValueError("Compiler preparation requires Compiler or Hybrid policy")
    root = args.config.absolute().parent.resolve()
    chain = tools(args.llvm_directory)
    observed = context(config)
    observed["upstream_configured_tests_assessed"] = False
    for field in ("build_argv", "test_argv"):
        command = config.get(field, [])
        if command:
            command = [sys.executable, *command[1:]] if command[0] in ("python", "python3") else command
            checked(command, root, timeout=7200)
            if field == "test_argv":
                observed.update(test_assessed=True, upstream_configured_tests_assessed=True,
                    upstream_configured_test_scope="original_build_tests_only")
    artifacts = POST.relative_directory(root, config.get("artifact_directory", "dist"))
    entries = tree(artifacts, "artifacts/")
    declaration_sha = hashlib.sha256(canonical(declaration(config))).hexdigest()
    output_config = dict(config, artifact_directory="artifacts", output_directory="copyright", build_argv=[], test_argv=[])
    stage = {"schema": SCHEMA, "stage": "prepared", "configuration_sha256": declaration_sha,
        "version": args.version, "created_at": args.created_at, "targets": []}
    with tempfile.TemporaryDirectory(prefix=".fileveil-compiler-prepare-", dir=args.output.parent) as directory:
        work = Path(directory)
        for index, target in enumerate(config["compiler"]["targets"]):
            source = POST.relative_directory(root, target["input"])
            source_sha = sha(source, MAX_IR)
            language = "clang++" if source.suffix.lower() in (".cc", ".cpp", ".cxx", ".c++") else "clang"
            ir, baseline = work / f"{index:04}.ll", work / f"{index:04}{'.exe' if os.name == 'nt' else ''}"
            if target["backend"] == "llvm_ir":
                shutil.copyfile(source, ir)
            else:
                checked([chain[language], *flags(config), "-S", "-emit-llvm", "-O0", "-Xclang", "-disable-O0-optnone", source, "-o", ir], root)
            checked([chain[language], *flags(config), *optimization(config), ir, "-o", baseline], root)
            if sha(source, MAX_IR) != source_sha:
                raise ValueError("Original compiler source changed during preparation")
            ir_name, baseline_name = f"ir/{index:04}.ll", f"baseline/{index:04}{'.exe' if os.name == 'nt' else ''}"
            entries[ir_name], entries[baseline_name] = ir, baseline
            stage["targets"].append({"input": target["input"], "output": target["output"], "language": language,
                "base_ir": ir_name, "baseline": baseline_name, "source_sha256": source_sha,
                "base_ir_sha256": sha(ir, MAX_IR), "baseline_sha256": sha(baseline)})
        bundle(args.output, entries, {"ci-config.json": output_config, "compiler-stage.json": stage, "build-context.json": observed})


def load_stage(args, expected):
    config = POST.read_config(args.input / "ci-config.json")
    stage = read_json(args.input / "compiler-stage.json")
    if (stage.get("schema") != SCHEMA or stage.get("stage") != expected
            or stage.get("configuration_sha256") != hashlib.sha256(canonical(declaration(config))).hexdigest()
            or len(stage.get("targets", [])) != len(config["compiler"]["targets"])):
        raise ValueError("Compiler transfer policy or stage identity changed")
    for row, target in zip(stage["targets"], config["compiler"]["targets"]):
        if row.get("input") != target["input"] or row.get("output") != target["output"]:
            raise ValueError("Compiler target identity changed between stages")
    return config, stage


def mark(args):
    config, stage = load_stage(args, "prepared")
    selected = POST.read_config(args.config)
    if declaration(selected) != declaration(config):
        raise ValueError("IR signing configuration does not match its selected project")
    chain = tools(args.llvm_directory)
    if not args.plugin or not args.plugin.is_file():
        raise ValueError("IR signing requires the trusted FileVeil LLVM pass plugin")
    version = args.version or stage.get("version") or "ci-" + os.getenv("GITHUB_RUN_ID", "local")
    created_at = args.created_at or stage.get("created_at") or "unix:" + str(int(time.time()))
    entries = tree(args.input / "artifacts", "artifacts/")
    entries.update(tree(args.input / "baseline", "baseline/"))
    with tempfile.TemporaryDirectory(prefix="fileveil-ci-key-") as name, tempfile.TemporaryDirectory(prefix=".fileveil-compiler-mark-", dir=args.output.parent) as work_name:
        private, work = Path(name), Path(work_name)
        key = POST.signing_identity(private, args.key)
        for index, row in enumerate(stage["targets"]):
            source = args.input / POST.relative_name(row["base_ir"])
            if sha(source, MAX_IR) != row["base_ir_sha256"]:
                raise ValueError("Prepared LLVM input changed before signing")
            isolated = work / f"input-{index:04}.ll"
            shutil.copyfile(source, isolated)
            output = work / f"marked-{index:04}.ll"
            common = ["--mode", "ir", "--key", str(key), "--llvm-directory", str(args.llvm_directory), "--plugin", str(args.plugin)]
            report = POST.run_cli(args.fileveil, ["software", "mark", str(isolated), "--output", str(output), *common,
                "--work-id", config["work_id"], "--copy-id", config["copy_id"], "--author", config["author"],
                "--version", version, "--created-at", created_at], private, index * 2)
            packet = report.get("advanced", {}).get("software", {}).get("packet", {})
            checked_report = POST.run_cli(args.fileveil, ["software", "verify", str(output), *common], private, index * 2 + 1)
            verified = checked_report.get("advanced", {}).get("software", {}).get("packet", {})
            if (report.get("result") != "verified_within_scope" or packet.get("signature") != "valid"
                    or packet.get("decoded") is not True or packet.get("input_sha256") != row["base_ir_sha256"]
                    or verified.get("packet_sha256") != packet.get("packet_sha256") or verified.get("signature") != "valid"
                    or verified.get("decoded") is not True):
                raise ValueError("IR watermark did not independently verify")
            name = f"marked/{index:04}.ll"
            entries[name] = output
            row.update({"marked_ir": name, "marked_ir_sha256": sha(output, MAX_IR), "packet_sha256": packet["packet_sha256"],
                "key_id": packet["key_id"], "canonical_input_ir_sha256": packet["ir_sha256"]})
        stage.update(stage="marked", version=version, created_at=created_at)
        bundle(args.output, entries, {"ci-config.json": config, "compiler-stage.json": stage,
            "build-context.json": read_json(args.input / "build-context.json")})


def build(args):
    no_secret()
    config, stage = load_stage(args, "marked")
    chain = tools(args.llvm_directory)
    project = (args.project_root or args.input).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix=".fileveil-compiler-build-", dir=args.output.parent) as directory:
        work = Path(directory)
        artifacts = work / "artifacts"
        shutil.copytree(args.input / "artifacts", artifacts, symlinks=False)
        rows = []
        tests = 0
        for row in stage["targets"]:
            ir = args.input / POST.relative_name(row["marked_ir"])
            baseline = args.input / POST.relative_name(row["baseline"])
            if sha(ir, MAX_IR) != row["marked_ir_sha256"] or sha(baseline) != row["baseline_sha256"]:
                raise ValueError("Marked LLVM or baseline control changed before final build")
            output = artifacts / POST.relative_name(row["output"])
            output.parent.mkdir(parents=True, exist_ok=True)
            output.unlink(missing_ok=True)
            checked([chain[row["language"]], *flags(config), *optimization(config), ir, "-o", output], project)
            vectors = []
            if config["compiler"].get("allow_execution", False):
                for arguments in config["compiler"].get("test_arguments", []):
                    before = execute([baseline, *arguments], project)
                    after = execute([output, *arguments], project)
                    if before != after:
                        raise ValueError("Marked program differs from its baseline on a configured native test vector")
                    vectors.append({"arguments_sha256": hashlib.sha256(canonical(arguments)).hexdigest(), **after})
                    tests += 1
            rows.append({**{key: row[key] for key in ("input", "output", "source_sha256", "base_ir_sha256", "marked_ir_sha256",
                "baseline_sha256", "packet_sha256", "key_id", "canonical_input_ir_sha256")}, "artifact_sha256": sha(output),
                "native_tests": vectors, "native_test_scope": "configured_arguments_exitcode_stdout_stderr" if vectors else "not_assessed"})
        # Freeze the produced files after supplied native vectors as build output.
        for row in rows:
            row["artifact_sha256"] = sha(artifacts / row["output"])
        build_context = read_json(args.input / "build-context.json")
        build_context.update(build_assessed=True, test_assessed=bool(tests) or bool(build_context.get("test_assessed")),
            native_test_vectors=tests, marked_native_tests_assessed=bool(tests),
            marked_function_scope="supplied_native_test_vectors" if tests else "not_assessed",
            scope="upstream_final_compiler_build_and_test_observations")
        receipt = {"schema": "fileveil.ci.compiler-context.v1", "configuration_sha256": stage["configuration_sha256"],
            "version": stage["version"], "created_at": stage["created_at"], "targets": rows,
            "build_derivation_scope": "upstream_build_observations_not_a_cryptographic_compiler_derivation_proof"}
        bundle(args.output, tree(artifacts, "artifacts/"), {"ci-config.json": config,
            "build-context.json": build_context, "compiler-context.json": receipt})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "mark", "build"))
    parser.add_argument("--config", type=Path)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--llvm-directory", type=Path, required=True)
    parser.add_argument("--fileveil", type=Path)
    parser.add_argument("--plugin", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--project-root", type=Path)
    parser.add_argument("--version", default="")
    parser.add_argument("--created-at", default="")
    args = parser.parse_args()
    args.output = args.output.absolute()
    if args.output.exists() or args.output.is_symlink() or not args.output.parent.is_dir():
        raise ValueError("Compiler stages require a new output beneath an existing directory")
    if args.action == "prepare" and args.config is None or args.action != "prepare" and args.input is None:
        raise ValueError("Select the configuration or safely extracted stage input")
    if args.action == "mark" and (args.fileveil is None or args.config is None):
        raise ValueError("IR signing requires a trusted FileVeil CLI and selected configuration")
    {"prepare": prepare, "mark": mark, "build": build}[args.action](args)
    print(json.dumps({"schema": "fileveil.ci.compiler-stage-receipt.v1", "stage": args.action, "output_sha256": sha(args.output, STAGE.MAX_TOTAL)}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"FileVeil compiler stage failed ({error})", file=sys.stderr)
        sys.exit(1)

# FVPROV1 20449 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIyYTVlNmIyZmJlOGFkYTUzYzA0YTZlN2NjZjEwOTUxY2ExYTA1ZWRlZGNlYTgyN2I3Nzg5ZmIwYmFmODI1MmU1IiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL3Byb2plY3QtY2ktY29tcGlsZXIucHkifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI0ZmE3MzVmYzU5NzM3MzM5YmRlZTNhMDBhNmMyNTQ2ODRkOWFjZjViMjUwODg4ZmRiODU1YjE4ZDljMTY4ZDc5OGE0OTdhMDUxM2QxYmNiZDM5ZDFkZDM4ZTE4ZTljODgxMTM2ZGNiNTdiMTE4ODRiZDg1N2JmMzVmNjdlYTAwNyJ9XX1d FVPROV1-END
