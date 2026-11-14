#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Build/test, synchronize, independently verify and package a project generation."""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

FIELDS = {"name", "work_id", "author", "copy_id", "artifact_directory", "output_directory",
          "build_argv", "test_argv", "engine_ref", "runner", "policy", "rules", "compiler"}
KEY_MAGIC = b"FILEVEIL-ED25519-KEY-V1\n"
POLICIES = ("manifest_only", "asset_watermark", "compiler_watermark", "hybrid")


def default_asset_rules():
    return [{"pattern": "**/*." + extension, "mode": "structure", "strength": 12}
            for extension in ("jpg", "jpeg", "png", "heic", "heif", "avif")]


def relative_name(value):
    if (not isinstance(value, str) or not value or len(value) > 4096
            or any(character in value for character in "\\:\n\r\0")
            or Path(value).is_absolute() or any(part in ("", ".", "..") for part in value.split("/"))):
        raise ValueError("CI paths require bounded portable relative file names")
    return value


def validate_policy(config):
    config.setdefault("policy", "manifest_only")
    config.setdefault("rules", default_asset_rules())
    config.setdefault("compiler", None)
    if config["policy"] not in POLICIES or not isinstance(config["rules"], list) or len(config["rules"]) > 128:
        raise ValueError("CI policy or asset rule budget is invalid")
    for rule in config["rules"]:
        if (not isinstance(rule, dict) or set(rule) - {"pattern", "mode", "strength"}
                or not isinstance(rule.get("pattern"), str) or not rule["pattern"] or len(rule["pattern"]) > 512
                or rule["pattern"].startswith("/") or ".." in rule["pattern"].split("/")
                or any(character in rule["pattern"] for character in "\\:\0")
                or rule.get("mode", "external") not in ("external", "structure", "invisible")
                or type(rule.get("strength", 12)) is not int or not 1 <= rule.get("strength", 12) <= 40):
            raise ValueError("CI asset rules must be bounded relative patterns")
    if config["policy"] not in ("compiler_watermark", "hybrid"):
        return
    compiler = config["compiler"]
    fields = {"targets", "llvm_directory", "plugin_path", "optimization", "target_triple", "compiler_arguments", "allow_execution", "test_arguments"}
    if (not isinstance(compiler, dict) or set(compiler) - fields or not isinstance(compiler.get("targets"), list)
            or not 1 <= len(compiler["targets"]) <= 16):
        raise ValueError("Compiler and Hybrid CI require one to sixteen explicit targets")
    outputs = set()
    for target in compiler["targets"]:
        if not isinstance(target, dict) or set(target) != {"input", "output", "backend"}:
            raise ValueError("CI compiler target shape is invalid")
        source = relative_name(target["input"])
        output = relative_name(target["output"])
        extension = Path(source).suffix.lower()
        if (target["backend"] not in ("clang_source", "llvm_ir") or output.casefold() in outputs
                or target["backend"] == "clang_source" and extension not in (".c", ".cc", ".cpp", ".cxx", ".c++")
                or target["backend"] == "llvm_ir" and extension != ".ll"):
            raise ValueError("CI compiler target backend, extension or output alias is invalid")
        outputs.add(output.casefold())
    if compiler.get("optimization", "") not in ("", "O0", "O1", "O2", "O3", "Os", "Oz", "LTO"):
        raise ValueError("Unsupported CI compiler optimization")
    for field in ("llvm_directory", "plugin_path", "target_triple"):
        value = compiler.get(field)
        if value is not None and (not isinstance(value, str) or len(value) > 4096 or "\0" in value):
            raise ValueError("CI compiler path and target declarations must be bounded strings")
    if type(compiler.get("allow_execution", False)) is not bool:
        raise ValueError("CI execution authorization must be explicit")
    arguments = compiler.get("compiler_arguments", [])
    vectors = compiler.get("test_arguments", [])
    if not isinstance(arguments, list) or len(arguments) > 128 or not isinstance(vectors, list) or len(vectors) > 32:
        raise ValueError("CI compiler argument budget is invalid")
    if any(not isinstance(vector, list) or len(vector) > 128 for vector in vectors):
        raise ValueError("CI test vectors must be bounded argument arrays")
    if any(not isinstance(value, str) or len(value) > 16384 or "\0" in value for value in arguments + [value for vector in vectors for value in vector]):
        raise ValueError("CI compiler arguments exceed their bounded contract")


def publish_directory(source, destination):
    """Reuse the desktop packager's platform-specific no-clobber publication."""
    spec = importlib.util.spec_from_file_location("fileveil_packaging", Path(__file__).with_name("package-desktop.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        module.no_clobber_rename(source, destination)
    except module.PackagingError as error:
        raise ValueError(str(error)) from error


def read_config(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024:
        raise ValueError("CI configuration must be a bounded regular JSON file")
    config = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or set(config) - FIELDS:
        raise ValueError("Unknown CI configuration fields")
    for field in ("work_id", "author", "copy_id"):
        if not isinstance(config.get(field), str) or not config[field] or len(config[field]) > 4096:
            raise ValueError("A bounded project, author and copy identity is required")
    for field in ("build_argv", "test_argv"):
        command = config.get(field, [])
        if not isinstance(command, list) or len(command) > 128 or any(
                not isinstance(item, str) or not item or "\0" in item or len(item) > 16384 for item in command):
            raise ValueError("Build and test commands must be bounded argument arrays")
    validate_policy(config)
    return config


def relative_directory(root, value):
    if not isinstance(value, str) or not value or any(char in value for char in "\\:\n\r\0"):
        raise ValueError("Select a portable repository-relative directory")
    path = Path(value)
    if path.root or ".." in path.parts:
        raise ValueError("CI paths must remain within the project")
    current = root
    for part in path.parts:
        current /= part
        if current.is_symlink():
            raise ValueError("CI directory paths cannot traverse symbolic links")
    return current


def run_cli(executable, arguments, private, sequence):
    # Report files bound output memory and never contain the private key bytes.
    path = private / f"report-{sequence}.json"
    with path.open("xb") as stream:
        result = subprocess.run([str(executable), "--json", *arguments],
                                stdin=subprocess.DEVNULL, stdout=stream,
                                stderr=subprocess.DEVNULL, timeout=3600, env=clean_environment())
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError(f"FileVeil operation failed without a bounded report (exit {result.returncode})")
    report = json.loads(path.read_text(encoding="utf-8"))
    # The CLI emits the standard report envelope for all three operations.
    if isinstance(report, list):
        report = report[0] if len(report) == 1 else {}
    if isinstance(report, dict) and "reports" in report:
        rows = report["reports"]
        report = rows[0] if len(rows) == 1 else {}
    if (not isinstance(report, dict) or result.returncode not in (0, 4)
            or report.get("result") not in ("verified_within_scope", "partially_verified")):
        warnings = report.get("warnings", []) if isinstance(report, dict) else []
        summary = " | ".join(str(value)[:1024] for value in warnings[:3])
        raise ValueError(f"FileVeil operation failed (exit {result.returncode}, {summary})")
    return report


def project_details(report):
    details = report.get("advanced", {}).get("project")
    if not isinstance(details, dict):
        raise ValueError("FileVeil project details are missing")
    return details


def clean_environment():
    # Build/test programs receive their normal environment with the signing secret removed.
    return {key: value for key, value in os.environ.items() if key != "FILEVEIL_SIGNING_KEY_BASE64"}


def signing_identity(private, selected=None):
    if selected:
        return selected.resolve(strict=True)
    encoded = os.getenv("FILEVEIL_SIGNING_KEY_BASE64", "")
    if not encoded or len(encoded) > 1024:
        raise ValueError("Provide a local key or FILEVEIL_SIGNING_KEY_BASE64 CI secret")
    secret = base64.b64decode(encoded, validate=True)
    if not secret.startswith(KEY_MAGIC) or len(secret) != len(KEY_MAGIC) + 32:
        raise ValueError("CI signing key has an unsupported format")
    path = private / "signing.key"
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(secret)
    return path


def verify_compiler_artifacts(executable, config, artifacts, context_path, signing_key, private, version):
    if context_path is None or context_path.is_symlink() or not context_path.is_file() or context_path.stat().st_size > 1024 * 1024:
        raise ValueError("Compiler/Hybrid final signing requires a bounded final compiler context")
    context = json.loads(context_path.read_text(encoding="utf-8"))
    declaration = {key: config.get(key) for key in ("work_id", "author", "copy_id", "policy", "rules", "compiler")}
    expected_config = hashlib.sha256(json.dumps(declaration, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()
    if (not isinstance(context, dict) or context.get("schema") != "fileveil.ci.compiler-context.v1"
            or context.get("configuration_sha256") != expected_config or not isinstance(context.get("targets"), list)
            or len(context["targets"]) != len(config["compiler"]["targets"])
            or version and context.get("version") != version):
        raise ValueError("Final compiler context does not match the selected release declaration")
    disabled = private / "no-compiler-tools"
    disabled.mkdir()
    summaries = []
    for index, (row, target) in enumerate(zip(context["targets"], config["compiler"]["targets"])):
        if not isinstance(row, dict) or row.get("input") != target["input"] or row.get("output") != target["output"]:
            raise ValueError("Final compiler target differs from the configured release")
        relative = relative_name(row["output"])
        path = relative_directory(artifacts, relative)
        if path.is_symlink() or not path.is_file():
            raise ValueError("Final compiler artifact is unavailable")
        hasher = hashlib.sha256()
        with path.open("rb") as source:
            total = 0
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                total += len(chunk)
                if total > 1024 * 1024 * 1024:
                    raise ValueError("Final compiler artifact exceeds its byte budget")
                hasher.update(chunk)
        artifact_sha256 = hasher.hexdigest()
        if row.get("artifact_sha256") != artifact_sha256:
            raise ValueError("Final compiler artifact differs from the final build observations")
        report = run_cli(executable, ["software", "verify", str(path), "--mode", "structure", "--key", str(signing_key),
            "--disclose-private", "--llvm-directory", str(disabled)], private, 1000 + index)
        packets = report.get("advanced", {}).get("software", {}).get("binary", {}).get("packets", [])
        accepted = None
        for packet in packets:
            claims = packet.get("claims", {})
            if (packet.get("signature") == "valid" and packet.get("decoded") is True
                    and packet.get("carrier_witness_matches") is True
                    and packet.get("packet_sha256") == row.get("packet_sha256")
                    and packet.get("key_id") == row.get("key_id")
                    and packet.get("input_sha256") == row.get("base_ir_sha256")
                    and packet.get("ir_sha256") == row.get("canonical_input_ir_sha256")
                    and claims.get("work_id") == config["work_id"] and claims.get("copy_id") == config["copy_id"]
                    and claims.get("author") == config["author"] and claims.get("version") == context.get("version")):
                accepted = packet
                break
        if accepted is None or report.get("input_sha256") != artifact_sha256:
            raise ValueError("Final compiler artifact lacks the selected owner's authenticated watermark")
        summaries.append({"path": relative, "artifact_sha256": artifact_sha256, "packet_sha256": accepted["packet_sha256"],
            "key_id": accepted["key_id"], "input_ir_sha256": accepted["input_sha256"], "signature": "valid",
            "carrier_witness_matches": True, "native_test_scope": row.get("native_test_scope", "not_assessed"),
            "native_test_observations": len(row.get("native_tests", [])), "build_derivation": "upstream_observation"})
    return summaries


def literal_pattern(path):
    return "".join({"[": "[[]", "]": "[]]", "*": "[*]", "?": "[?]"}.get(character, character) for character in path)


def write_frozen_member(archive, path, name, expected_sha256, maximum):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0))
    hasher = hashlib.sha256()
    written = 0
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("Generation export requires a bounded regular file")
        member = zipfile.ZipInfo(name)
        member.create_system = 3
        member.external_attr = (stat.S_IFREG | stat.S_IMODE(info.st_mode)) << 16
        member.compress_type = zipfile.ZIP_DEFLATED
        with archive.open(member, "w", force_zip64=True) as target:
            prefix = source.read(len(KEY_MAGIC))
            if prefix == KEY_MAGIC:
                raise ValueError("A private signing key cannot enter an evidence package")
            hasher.update(prefix)
            target.write(prefix)
            written += len(prefix)
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                written += len(chunk)
                if written > maximum:
                    raise ValueError("Generation member exceeded its export budget")
                hasher.update(chunk)
                target.write(chunk)
    if hasher.hexdigest() != expected_sha256:
        raise ValueError("Generation member changed after verification")
    return written


def public_report(report):
    fields = ("schema_version", "tool", "version", "operation", "result", "input_sha256", "output_sha256")
    public = {key: report[key] for key in fields if key in report}
    details = report.get("advanced", {}).get("project", {})
    project_fields = ("schema", "action", "project_id", "work_id", "generation", "revision",
        "manifest_sha256", "evidence_sha256", "history_metadata", "integrity", "signature", "trust", "history",
        "trust_scope", "history_assessment_scope", "source_assessment_scope", "source_fingerprint",
        "published", "added", "modified", "deleted", "renamed", "unchanged", "files_total", "bytes_total")
    public["project"] = {key: details[key] for key in project_fields if key in details}
    return public


def validate_compiler_manifest(manifest, summaries):
    if not summaries:
        return
    files = {}
    aliases = set()
    for item in manifest["files"]:
        path = relative_name(item["path"])
        if path in files or path.casefold() in aliases:
            raise ValueError("Final compiler manifest contains duplicate artifact paths")
        files[path] = item
        aliases.add(path.casefold())
    checked = set()
    for summary in summaries:
        path = relative_name(summary["path"])
        actual = files.get(path)
        if (path in checked or actual is None or actual.get("mode") != "external"
                or actual.get("source_sha256") != summary.get("artifact_sha256")):
            raise ValueError("Final signed manifest differs from the authenticated compiler artifact snapshot")
        checked.add(path)


def stage_evidence(generation, destination, reports, metadata, artifacts=None):
    if destination.exists() or destination.is_symlink():
        raise ValueError("Evidence destination already exists")
    temporary = Path(tempfile.mkdtemp(prefix=".fileveil-evidence-", dir=destination.parent))
    try:
        manifest_path = generation / "manifest.json"
        if manifest_path.is_symlink() or manifest_path.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("Generation manifest exceeds its package budget")
        manifest_bytes = manifest_path.read_bytes()
        expected_manifest = project_details(reports["verify"])["manifest_sha256"]
        if hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest:
            raise ValueError("Generation manifest changed after verification")
        manifest = json.loads(manifest_bytes)
        validate_compiler_manifest(manifest, metadata.get("compiler_verification", []))
        expected = {"manifest.json": expected_manifest,
                    "COMMITTED": hashlib.sha256(expected_manifest.encode("ascii")).hexdigest()}
        for item in manifest["files"]:
            if item.get("output_sha256"):
                expected["files/" + item["path"]] = item["output_sha256"]
        for item in manifest.get("derived_artifacts", []):
            expected["derived/" + item["path"]] = item["sha256"]
        evidence_path = generation / "evidence.json"
        if evidence_path.is_symlink() or evidence_path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("Generation evidence exceeds its package budget")
        expected_evidence = project_details(reports["verify"]).get("evidence_sha256")
        if not isinstance(expected_evidence, str) or len(expected_evidence) != 64:
            raise ValueError("Project report lacks the verified evidence digest")
        expected["evidence.json"] = expected_evidence
        visited = set()
        package = temporary / "fileveil-evidence.zip"
        with zipfile.ZipFile(package, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for root, directories, files in os.walk(generation, followlinks=False):
                if any((Path(root) / name).is_symlink() for name in directories):
                    raise ValueError("Verified generation contains a symbolic directory")
                for name in sorted(files):
                    path = Path(root) / name
                    if path.is_symlink() or not path.is_file():
                        raise ValueError("Verified generation contains a non-regular file")
                    relative = path.relative_to(generation).as_posix()
                    if relative not in expected or relative in visited:
                        raise ValueError("Generation contains an unexpected evidence member")
                    visited.add(relative)
                    write_frozen_member(archive, path, "generation/" + relative, expected[relative], 1024*1024*1024)
            if visited != set(expected):
                raise ValueError("A signed generation member is missing")
            history = project_details(reports["verify"]).get("history_metadata")
            if not isinstance(history, list) or not history or len(history) > 20000:
                raise ValueError("Project report lacks the frozen retained history metadata")
            total_history = 0
            for item in history:
                name = item["generation"]
                if not name or Path(name).name != name or name in (".", "..") or "\\" in name:
                    raise ValueError("Historical generation identity is invalid")
                directory = generation.parent / name
                for filename, checksum in (("manifest.json", item["manifest_sha256"]),
                        ("evidence.json", item["evidence_sha256"]),
                        ("COMMITTED", hashlib.sha256(item["manifest_sha256"].encode("ascii")).hexdigest())):
                    total_history += write_frozen_member(archive, directory / filename,
                        f"history/{generation.parent.name}/{name}/{filename}", checksum, 64*1024*1024)
                    if total_history > 256*1024*1024:
                        raise ValueError("Retained portable history exceeds its 256 MiB metadata budget")
            archive.writestr("verification.json", json.dumps({key: public_report(value) for key, value in reports.items()}, ensure_ascii=True, indent=2))
            archive.writestr("build-context.json", json.dumps(metadata, ensure_ascii=True, indent=2))
        hasher = hashlib.sha256()
        with package.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(chunk)
        checksum = hasher.hexdigest()
        sums = f"{checksum}  fileveil-evidence.zip\n"
        if artifacts is not None:
            build_package = temporary / "fileveil-build.zip"
            total_build = 0
            with zipfile.ZipFile(build_package, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                for item in manifest["files"]:
                    relative = relative_name(item["path"])
                    selected = generation / "files" / relative if item.get("output_sha256") else artifacts / relative
                    file_checksum = item.get("output_sha256") or item["source_sha256"]
                    total_build += write_frozen_member(archive, selected, relative, file_checksum, 1024 * 1024 * 1024)
                    if total_build > 8 * 1024 * 1024 * 1024:
                        raise ValueError("Processed release attachment exceeds its eight GiB export budget")
            build_hasher = hashlib.sha256()
            with build_package.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    build_hasher.update(chunk)
            sums += f"{build_hasher.hexdigest()}  fileveil-build.zip\n"
        (temporary / "SHA256SUMS").write_text(sums, encoding="ascii")
        publish_directory(temporary, destination)
        return checksum
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fileveil", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path("fileveil-ci.json"))
    parser.add_argument("--key", type=Path)
    parser.add_argument("--state-directory", type=Path)
    parser.add_argument("--evidence-directory", type=Path, default=Path("fileveil-evidence"))
    parser.add_argument("--output-directory", type=Path, help="Explicit local caller override for persistent release generations")
    parser.add_argument("--version", default="")
    parser.add_argument("--created-at", default="")
    parser.add_argument("--after-build", action="store_true", help="Use artifacts from an already completed caller build/test")
    parser.add_argument("--build-context", type=Path, help="Bounded observations from the separate upstream build job")
    parser.add_argument("--compiler-context", type=Path, help="Final marked binary observations from the separate compiler build job")
    args = parser.parse_args()
    root = args.config.absolute().parent.resolve()
    config = read_config(args.config.absolute())
    compiler_policy = config["policy"] in ("compiler_watermark", "hybrid")
    if compiler_policy and (not args.after_build or args.compiler_context is None):
        raise ValueError("Compiler/Hybrid requires the isolated IR-mark/final-build pipeline and final compiler context")
    if (not args.after_build and os.getenv("FILEVEIL_SIGNING_KEY_BASE64")
            and any(config.get(field) for field in ("build_argv", "test_argv"))):
        raise ValueError("CI secret signing requires a separate build job and --after-build")
    artifacts = relative_directory(root, config.get("artifact_directory", "dist"))
    output = args.output_directory.absolute() if args.output_directory else relative_directory(root, config.get("output_directory", "fileveil-release"))
    if artifacts == output or artifacts in output.parents or output in artifacts.parents:
        raise ValueError("Release generations must be outside the artifact input directory")
    executable = args.fileveil.resolve(strict=True)
    evidence = args.evidence_directory.absolute()
    if artifacts == evidence or artifacts in evidence.parents:
        raise ValueError("Evidence export must be outside the artifact input directory")
    if not evidence.parent.is_dir() or evidence.exists() or evidence.is_symlink():
        raise ValueError("Choose a new evidence directory beneath an existing directory")
    metadata = {"schema": "fileveil.ci.context.v1", "version": args.version,
                "build_assessed": False, "test_assessed": False,
                "upstream_build_declared": args.after_build,
                "github_commit": os.getenv("GITHUB_SHA"), "github_ref": os.getenv("GITHUB_REF"),
                "build_number": os.getenv("GITHUB_RUN_NUMBER"), "engine_revision": os.getenv("FILEVEIL_ENGINE_REVISION"),
                "platform": sys.platform, "history_restore_scope": os.getenv("FILEVEIL_HISTORY_RESTORE_SCOPE", "local_retained_history")}
    if args.build_context:
        if not args.after_build or args.build_context.is_symlink() or args.build_context.stat().st_size > 65536:
            raise ValueError("Upstream build observations require --after-build and a bounded regular context")
        context = json.loads(args.build_context.read_text(encoding="utf-8"))
        if not isinstance(context, dict) or context.get("schema") != "fileveil.ci.build-context.v1":
            raise ValueError("Unsupported upstream build observations")
        for key in ("build_assessed", "test_assessed", "github_commit", "github_ref", "build_number", "platform",
                "upstream_configured_tests_assessed", "upstream_configured_test_scope", "marked_native_tests_assessed",
                "marked_function_scope", "native_test_vectors"):
            if key in context:
                metadata[key] = context[key]
        metadata["build_context_scope"] = "upstream_job_observations"
    environment = clean_environment()
    for field, assessed in (("build_argv", "build_assessed"), ("test_argv", "test_assessed")):
        command = config.get(field, [])
        if command and not args.after_build:
            if command[0] in ("python", "python3"):
                command = [sys.executable, *command[1:]]
            started = time.monotonic()
            subprocess.run(command, cwd=root, env=environment, check=True, timeout=7200)
            metadata[assessed] = True
            metadata[field + "_milliseconds"] = round((time.monotonic() - started) * 1000)
    if not artifacts.is_dir():
        raise ValueError("Build artifact directory is unavailable")
    with tempfile.TemporaryDirectory(prefix="fileveil-ci-private-") as name:
        private = Path(name)
        signing_key = signing_identity(private, args.key)
        compiler_summary = verify_compiler_artifacts(executable, config, artifacts, args.compiler_context,
            signing_key, private, args.version) if compiler_policy else []
        metadata.update(policy=config["policy"], compiler_verification=compiler_summary,
            compiler_verification_scope="authenticated_container_packet_and_current_artifact_hash" if compiler_policy else "not_requested",
            compiler_build_test_scope="upstream_build_observations" if compiler_policy else "not_requested")
        rules = list(config["rules"]) if config["policy"] in ("asset_watermark", "hybrid") else []
        for row in compiler_summary:
            rules.append({"pattern": literal_pattern(row["path"]), "mode": "external", "strength": 12})
        if len(rules) > 128:
            raise ValueError("Hybrid rules and protected compiler outputs exceed the project rule budget")
        edition = config["work_id"] + "\0" + config["copy_id"] + "\0" + metadata["platform"]
        project_id = hashlib.sha256(("FileVeil CI edition v1\0" + edition).encode()).hexdigest()[:32]
        project = {"schema": "fileveil.project.config.v1", "project_id": project_id,
                   "work_id": config["work_id"], "author": config["author"], "copy_id": config["copy_id"],
                   "source_root": str(artifacts), "output_directory": str(output),
                   "provenance": {key: value for key, value in metadata.items() if not key.endswith("_milliseconds")},
                   "trigger": "build_release", "copy_external_files": False, "rules": rules,
                   "include": ["**"], "exclude": []}
        template = private / "template.json"
        template.write_text(json.dumps(project), encoding="utf-8")
        state = args.state_directory.absolute() if args.state_directory else private / "state"
        if args.state_directory:
            state.mkdir(parents=True, exist_ok=True, mode=0o700)
        config_directory = state.parent / "fileveil-ci-configs"
        config_directory.mkdir(mode=0o700, exist_ok=True)
        project_config = config_directory / ("ci-project-" + project_id + ".json")
        common = [str(project_config), "--state-directory", str(state)]
        if project_config.exists():
            if not args.key:
                raise ValueError("Persistent local state requires a stable local key reference")
            previous = json.loads(project_config.read_text(encoding="utf-8"))
            if previous.get("project_id") != project_id or previous.get("work_id") != config["work_id"]:
                raise ValueError("Persistent CI configuration belongs to another project")
            # This script owns the private CI config. Approve the current explicit
            # source/output settings and signed build context while preserving its ID.
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix=".fileveil-config-",
                    dir=project_config.parent, delete=False) as stream:
                replacement = Path(stream.name)
                json.dump(project, stream)
            try:
                os.replace(replacement, project_config)
            finally:
                replacement.unlink(missing_ok=True)
            init = run_cli(executable, ["project", "init", *common, "--update"], private, 0)
        else:
            init = run_cli(executable, ["project", "init", *common, "--template", str(template), "--key", str(signing_key)], private, 0)
        sync_arguments = ["project", "sync", *common, "--version", args.version, "--created-at", args.created_at]
        if compiler_summary:
            expected_sources = {row["path"]: row["artifact_sha256"] for row in compiler_summary}
            sync_arguments += ["--expected-sources-json", json.dumps(expected_sources, sort_keys=True)]
        sync = run_cli(executable, sync_arguments, private, 1)
        verify = run_cli(executable, ["project", "verify", *common], private, 2)
        details = project_details(verify)
        if any(details.get(field) != "valid" for field in ("integrity", "signature", "history", "trust")):
            raise ValueError("Project verification did not establish integrity, signature, history and selected-key trust")
        generation_id = details.get("generation")
        if not isinstance(generation_id, str) or not generation_id or Path(generation_id).name != generation_id:
            raise ValueError("Verified project generation identity is invalid")
        relative_manifest = details.get("manifest_relative_path")
        if not isinstance(relative_manifest, str) or ".." in Path(relative_manifest).parts:
            raise ValueError("Verified generation manifest path is invalid")
        generation = (output / relative_manifest).parent
        if generation.is_symlink() or not (generation / "COMMITTED").is_file():
            raise ValueError("Verified project generation is uncommitted")
        manifest_bytes = (generation / "manifest.json").read_bytes()
        if hashlib.sha256(manifest_bytes).hexdigest() != details["manifest_sha256"]:
            raise ValueError("Final manifest changed before evidence publication")
        manifest = json.loads(manifest_bytes)
        checksum = stage_evidence(generation, evidence, {"init": init, "sync": sync, "verify": verify}, metadata, artifacts)
        asset_marks = sum(item.get("mode") != "external" and bool(item.get("output_sha256")) for item in manifest["files"])
        receipt = {"schema": "fileveil.ci.receipt.v1", "status": "verified_within_scope",
                   "evidence_sha256": checksum, "generation": generation_id,
                   "integrity": details["integrity"], "signature": details["signature"],
                   "history": details["history"], "trust": details.get("trust", "not_assessed"),
                   "build_assessed": metadata["build_assessed"], "test_assessed": metadata["test_assessed"],
                   "build_context_scope": metadata.get("build_context_scope", "local_child_process_observations"),
                   "history_restore_scope": metadata["history_restore_scope"]}
        receipt.update(policy=config["policy"], asset_marked_files=asset_marks, compiler_verified_files=len(compiler_summary),
            asset_scope="selected_rules" if config["policy"] in ("asset_watermark", "hybrid") and config["rules"] else "no_asset_rules_selected",
            build_attachment_scope="processed_copies_with_original_bytes_for_external_files")
        print(json.dumps(receipt, ensure_ascii=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"FileVeil postprocessing failed ({error})", file=sys.stderr)
        sys.exit(1)

# FVPROV1 34784 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJiYTY3ODg1ZjJjZjczYTc0YzNhNGNhMDEzMzk3NWU1YmZmZDZjY2EwMzBkZmRiZTEzY2Y0ZTEwMzllMzA4MGMzIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL3Byb2plY3QtcG9zdHByb2Nlc3MucHkifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI5OTNmOWEwYTljNzBlMzc3Y2IyYWI5NjFhYTZhYjUzM2M4ZGQ1NGY2OGIyY2Q2MDg1MTU4ZDgzNDEyMTBmNmZmZWJhY2U4NGY4MTZiZTJkM2ViNzNjODY3ODZlYmNhOWY3MDBjZjI0YTlmODYwZmU4NWJmNGExY2VhYmQ0YTgwMiJ9XX1d FVPROV1-END
