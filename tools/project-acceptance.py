#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Run real dependency/multi-target Registry and CI acceptance in a new isolated directory.

No production project or signing identity is used. The generated test key stays in
private/ outside the copied project. Requires CMake, C/C++, Python and zlib headers.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
WORK_ID = "fileveil-registry-zlib-acceptance-v1"


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def snapshot(directory):
    return {str(path.relative_to(directory)).replace(os.sep, "/"): sha(path)
            for path in sorted(directory.rglob("*")) if path.is_file()}


def envelope(value):
    if isinstance(value, list):
        assert len(value) == 1
        value = value[0]
    if "reports" in value:
        assert len(value["reports"]) == 1
        value = value["reports"][0]
    return value


def run_acceptance(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    logs = output / "logs"
    logs.mkdir()
    private = output / "private"
    private.mkdir(mode=0o700)
    project = output / "project"
    shutil.copytree(ROOT / "tests/fixtures/registry-zlib-project", project,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    source_before = snapshot(project)
    executable = args.fileveil.resolve(strict=True)
    operations = []

    def execute(name, command, *, expect=True, env=None):
        start = time.monotonic()
        result = subprocess.run([str(value) for value in command], cwd=project,
                                env=env, capture_output=True, timeout=300)
        (logs / (name + ".stdout")).write_bytes(result.stdout)
        (logs / (name + ".stderr")).write_bytes(result.stderr)
        operations.append({"name": name, "exit": result.returncode,
                           "elapsed_seconds": round(time.monotonic() - start, 6)})
        if expect and result.returncode not in (0, 4):
            raise RuntimeError(f"{name} failed with {result.returncode}: {result.stderr[-1200:].decode(errors='replace')}")
        return result

    def cli(name, *arguments, expect=True):
        result = execute(name, [executable, "--json", *arguments], expect=expect)
        return envelope(json.loads(result.stdout)) if result.stdout else {}

    key = private / "acceptance.key"
    cli("keygen", "heritage-keygen", "--output", key)
    execute("build", [sys.executable, project / "build.py"])
    execute("ctest", ["ctest", "--test-dir", project / "build", "-C", "Release", "--output-on-failure"])
    artifacts = project / "dist"
    # Opaque EFI/kernel names deliberately retain original bytes under the default
    # policy; these are preservation controls, not native EFI/kernel acceptance.
    (artifacts / "BOOTAA64.EFI").write_bytes(b"MZ\x00FileVeil preservation control\x00" * 50)
    (artifacts / "kernel.img").write_bytes(bytes(range(256)) * 10)
    (artifacts / "notes.txt").write_text("release notes v1\n")
    artifact_before = snapshot(artifacts)
    config = {"name": "zlib archive tools", "work_id": WORK_ID,
              "author": "FileVeil acceptance", "copy_id": "public-test", "policy": "manifest_only",
              "artifact_directory": "dist", "output_directory": "copyright",
              "build_argv": [sys.executable, "build.py"],
              "test_argv": ["ctest", "--test-dir", "build", "-C", "Release", "--output-on-failure"]}
    config_path = project / "fileveil-ci.json"
    config_path.write_text(json.dumps(config, indent=2))
    state = private / "ci-state"
    inherited = dict(os.environ, FILEVEIL_SIGNING_KEY_BASE64="acceptance-sentinel-must-not-reach-build")

    def publish(name, version, *, expect=True):
        evidence = output / ("evidence-" + name)
        result = execute(name, [sys.executable, ROOT / "tools/project-ci-local.py",
            "--fileveil", executable, "--config", config_path, "--key", key,
            "--state-directory", state, "--evidence-directory", evidence,
            "--version", version, "--created-at", "2026-11-15"], expect=expect, env=inherited)
        if not expect:
            assert result.returncode != 0 and not evidence.exists()
            return None
        receipt = json.loads(result.stdout.decode().splitlines()[-1])
        assert receipt["post_cleanup_verification"] == "valid"
        return receipt

    first = publish("release-v1", "v1")
    assert snapshot(artifacts) == artifact_before, "default policy changed original build output"
    repeat = publish("repeat-v1", "v1")
    assert repeat["generation"] == first["generation"], "same version added a generation"
    (artifacts / "notes.txt").rename(artifacts / "release-notes.txt")
    (artifacts / "added.txt").write_text("new member\n")
    publish("release-v2", "v2")
    (artifacts / "added.txt").unlink()
    (artifacts / "release-notes.txt").write_text("release notes v3\n")
    publish("release-v3", "v3")
    generation_paths = sorted((project / "copyright").glob("*/*/COMMITTED"))
    assert len(generation_paths) == 3
    manifests = [json.loads(path.with_name("manifest.json").read_text()) for path in generation_paths]
    assert all(value["work_id"] == WORK_ID for value in manifests)
    assert [value["revision"] for value in manifests] == [1, 2, 3]
    assert any(value["kind"] == "renamed" for value in manifests[1]["changes"])
    assert any(value["kind"] == "added" for value in manifests[1]["changes"])
    assert any(value["kind"] == "deleted" for value in manifests[2]["changes"])
    assert any(value["kind"] == "modified" for value in manifests[2]["changes"])
    for previous, current in zip(manifests, manifests[1:]):
        assert current["previous_manifest_sha256"] == sha(generation_paths[current["revision"] - 2].with_name("manifest.json"))
    for index, marker in enumerate(generation_paths):
        execute(f"independent-evidence-{index + 1}", [sys.executable, ROOT / "tools/verify-evidence.py",
                marker.with_name("evidence.json"), "--asset", marker.with_name("manifest.json")])
    committed_before_failure = {str(path): sha(path) for path in generation_paths}
    (project / "fail-build").write_text("deliberate build failure")
    publish("failed-build", "must-not-publish", expect=False)
    assert {str(path): sha(path) for path in (project / "copyright").glob("*/*/COMMITTED")} == committed_before_failure
    (project / "fail-build").unlink()
    # Real Registry calls detect the copied CMake project and track its independently
    # selected manifest-only edition without altering the CI edition or native bytes.
    registry = private / "registry.json"
    registry_state = private / "registry-state"
    registry_options = ["--registry", registry, "--state-directory", registry_state]
    cli("registry-init", "registry", "init", *registry_options, "--author", "FileVeil acceptance", "--key", key)
    cli("registry-add", "registry", "add", project, *registry_options, "--name", "zlib archive tools",
        "--work-id", WORK_ID, "--copy-id", "registry-test", "--source", artifacts,
        "--output", project / "registry-copyright", "--policy", "manifest-only", "--key", key)
    registered = json.loads(registry.read_text())["projects"][0]
    assert "cmake" in registered["detected_kinds"]
    cli("registry-sync-v1", "registry", "sync", *registry_options, "--all", "--version", "registry-v1")
    cli("registry-sync-repeat", "registry", "sync", *registry_options, "--all", "--version", "registry-v1")
    namespace = project / "registry-copyright" / registered["project_id"]
    assert len(list(namespace.glob("*/COMMITTED"))) == 1
    (artifacts / "registry-new.txt").write_text("registry v2 member\n")
    cli("registry-sync-v2", "registry", "sync", *registry_options, "--all", "--version", "registry-v2")
    cli("registry-sync-repeat-v2", "registry", "sync", *registry_options, "--all", "--version", "registry-v2")
    registry_markers = sorted(namespace.glob("*/COMMITTED"))
    assert len(registry_markers) == 2
    registry_manifests = [json.loads(path.with_name("manifest.json").read_text()) for path in registry_markers]
    assert all(manifest["work_id"] == WORK_ID for manifest in registry_manifests)
    assert registry_manifests[1]["previous_generation"] == registry_markers[0].parent.name
    cli("registry-verify", "registry", "verify", *registry_options, "--all")
    if sys.platform == "darwin":
        for native in ("fvpack", "fvchecksum"):
            execute("codesign-verify-" + native, ["codesign", "--verify", "--strict", artifacts / native])
    assert all(sha(project / name) == checksum for name, checksum in source_before.items()), "original project source changed"
    for name, checksum in artifact_before.items():
        if name not in ("notes.txt",):
            assert sha(artifacts / name) == checksum, "original native/EFI/kernel artifact changed"
    leaked = False
    for evidence in output.glob("evidence-*/*.zip"):
        import zipfile
        with zipfile.ZipFile(evidence) as archive:
            for member in archive.infolist():
                if member.file_size <= 1024 * 1024:
                    data = archive.read(member)
                    assert b"FILEVEIL-ED25519-KEY-V1" not in data
                    assert b"acceptance-sentinel-must-not-reach-build" not in data
    result = {"schema": "fileveil.project.acceptance.v1", "status": "verified_within_scope",
        "platform": sys.platform, "fileveil_sha256": sha(executable), "work_id": WORK_ID,
        "project": "multi-file C/C++ zlib archive tools", "targets": ["fvcodec", "fvpack", "fvchecksum"],
        "dependency": "ZLIB::ZLIB", "native_tests": 4, "versions": 3,
        "idempotent_repeat": repeat["generation"] == first["generation"],
        "build_failure_published": False, "private_key_or_inherited_secret_in_evidence": leaked,
        "source_and_default_native_efi_kernel_bytes_preserved": True,
        "efi_kernel_scope": "opaque byte-preservation controls, not boot/runtime tests",
        "registry_kind": registered["detected_kinds"], "registry_versions": 2, "independent_evidence_packages": 3,
        "operations": operations}
    (output / "summary.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fileveil", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="New isolated evidence directory")
    run_acceptance(parser.parse_args())


if __name__ == "__main__":
    main()
