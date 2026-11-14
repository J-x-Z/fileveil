#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Run a local project release using an existing FileVeil CLI and signing key."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import uuid


def sibling(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


POST = sibling("fileveil_local_postprocess", "project-postprocess.py")
STAGE = sibling("fileveil_local_transfer", "project-ci-stage.py")
COMPILER = sibling("fileveil_local_compiler", "project-ci-compiler.py")


def contained(path, directory):
    return path == directory or path.is_relative_to(directory)


def resolve_tool(value, declared, root, label):
    if value is not None:
        return value.resolve(strict=True)
    if not declared:
        raise ValueError("Compiler/Hybrid local releases require an explicit " + label)
    selected = Path(declared)
    return (selected if selected.is_absolute() else root / selected).resolve(strict=True)


def configuration(args):
    # Retain the caller's spelling as well as its resolved identity for key placement.
    original_key = Path(os.path.abspath(args.key))
    args.key = args.key.resolve(strict=True)
    args.config = args.config.resolve(strict=True)
    args.fileveil = args.fileveil.resolve(strict=True)
    if not args.key.is_file() or not args.fileveil.is_file():
        raise ValueError("Select regular local key and FileVeil executable files")
    config = POST.read_config(args.config)
    root = args.config.parent
    artifacts = POST.relative_directory(root, config.get("artifact_directory", "dist")).resolve()
    output = POST.relative_directory(root, config.get("output_directory", "fileveil-release")).resolve()
    if contained(artifacts, output) or contained(output, artifacts):
        raise ValueError("Release output must remain separate from original artifacts")
    if any(contained(path, directory) for path in (original_key, args.key)
           for directory in (root, artifacts, output)):
        raise ValueError("The original signing key path must remain outside project source, artifacts and release output")
    edition = config["work_id"] + "\0" + config["copy_id"] + "\0" + sys.platform
    project_id = hashlib.sha256(("FileVeil CI edition v1\0" + edition).encode()).hexdigest()[:32]
    default_state = args.key.parent / ".fileveil-ci-state" / project_id / "state"
    args.state_directory = (args.state_directory or default_state).resolve()
    if any(contained(args.state_directory, directory) for directory in (root, artifacts, output)):
        raise ValueError("Private local state must remain outside project source, artifacts and release output")
    default_evidence = args.evidence_directory is None
    args.evidence_directory = (args.evidence_directory or
        args.state_directory.parent / "evidence" / uuid.uuid4().hex).resolve()
    if (args.evidence_directory.exists()
            or not default_evidence and not args.evidence_directory.parent.is_dir()
            or any(contained(args.evidence_directory, directory) or contained(directory, args.evidence_directory)
                   for directory in (artifacts, output))):
        raise ValueError("Choose a new evidence directory separate from artifact input and release output")
    compiler_policy = config["policy"] in ("compiler_watermark", "hybrid")
    if compiler_policy:
        compiler = config["compiler"]
        args.llvm_directory = resolve_tool(args.llvm_directory, compiler.get("llvm_directory"), root, "LLVM directory")
        args.plugin = resolve_tool(args.plugin, compiler.get("plugin_path"), root, "LLVM pass plugin")
        if not args.llvm_directory.is_dir() or not args.plugin.is_file():
            raise ValueError("Select an installed LLVM directory and an existing matching pass plugin")
    return SimpleNamespace(config=config, root=root, artifacts=artifacts, output=output,
                           project_id=project_id, compiler_policy=compiler_policy)


def postprocess(args, config, output=None, received=None):
    command = [sys.executable, str(Path(__file__).with_name("project-postprocess.py")),
               "--fileveil", str(args.fileveil), "--config", str(config), "--key", str(args.key),
               "--state-directory", str(args.state_directory),
               "--evidence-directory", str(args.evidence_directory),
               "--version", args.version, "--created-at", args.created_at]
    if output is not None:
        command += ["--output-directory", str(output)]
    if received is not None:
        command += ["--after-build", "--build-context", str(received / "build-context.json"),
                    "--compiler-context", str(received / "compiler-context.json")]
    subprocess.run(command, check=True, env=POST.clean_environment())


def verify_current(args, project_id):
    config = args.state_directory.parent / "fileveil-ci-configs" / ("ci-project-" + project_id + ".json")
    with tempfile.TemporaryDirectory(prefix=".fileveil-local-verify-", dir=args.state_directory.parent) as name:
        report = POST.run_cli(args.fileveil, ["project", "verify", str(config),
            "--state-directory", str(args.state_directory)], Path(name), 0)
    details = POST.project_details(report)
    if any(details.get(field) != "valid" for field in ("integrity", "signature", "history", "trust")):
        raise ValueError("Persistent project verification failed after intermediate cleanup")
    return details


def tree_digest(directory):
    digest = hashlib.sha256(b"FileVeil local release tree v1\0")
    total = 0
    for name, path in sorted(COMPILER.tree(directory, "").items()):
        total += path.stat().st_size
        if total > STAGE.MAX_TOTAL + 3 * 1024 * 1024:
            raise ValueError("Local release cache exceeds its byte budget")
        encoded = name.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "little"))
        digest.update(encoded)
        digest.update(bytes.fromhex(COMPILER.sha(path)))
    return digest.hexdigest()


def cache_identity(args, prepared):
    stage = COMPILER.read_json(prepared / "compiler-stage.json")
    config = POST.read_config(prepared / "ci-config.json")
    identity = {"declaration": COMPILER.declaration(config),
                "version": args.version, "created_at": args.created_at,
                "targets": [{key: row[key] for key in ("input", "output", "source_sha256", "base_ir_sha256")}
                            for row in stage["targets"]],
                "original_artifacts": tree_digest(prepared / "artifacts"),
                "plugin_sha256": COMPILER.sha(args.plugin), "llvm_directory": str(args.llvm_directory),
                # Only the combined opaque cache identifier is stored. Key bytes
                # and their intermediate fingerprint never enter a receipt.
                "key_binding": COMPILER.sha(args.key, 1024 * 1024)}
    return hashlib.sha256(b"FileVeil local compiler cache v1\0" + COMPILER.canonical(identity)).hexdigest()


def cached_release(cache, releases):
    if not cache.exists():
        return None
    value = COMPILER.read_json(cache)
    name = value.get("release", "")
    if (value.get("schema") != "fileveil.ci.local-cache.v1" or len(name) != 32
            or any(character not in "0123456789abcdef" for character in name)):
        raise ValueError("Local release cache has an invalid publication identity")
    selected = releases / name
    if selected.is_symlink() or not selected.is_dir() or tree_digest(selected) != value.get("tree_sha256"):
        raise ValueError("Previously verified cached release changed or is missing")
    return selected


def save_cache(cache, persistent):
    cache.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    value = {"schema": "fileveil.ci.local-cache.v1", "release": persistent.name,
             "tree_sha256": tree_digest(persistent)}
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix=".fileveil-cache-",
                                     dir=cache.parent, delete=False) as stream:
        temporary = Path(stream.name)
        json.dump(value, stream, sort_keys=True)
    try:
        os.replace(temporary, cache)
    finally:
        temporary.unlink(missing_ok=True)


def run(args):
    selected = configuration(args)
    args.state_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.evidence_directory.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    persistent = None
    cache = None
    cache_hit = False
    if selected.compiler_policy:
        # Intermediates reuse this checkout's ignored work directory. Final assets
        # have a separate durable source root so later Project Verify still works.
        work_root = Path(__file__).resolve().parent.parent / "work"
        work_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".fileveil-ci-local-", dir=work_root) as name:
            work = Path(name)
            if contained(args.key, work):
                raise ValueError("The signing key cannot be stored in temporary compiler work")
            common = dict(llvm_directory=args.llvm_directory, plugin=args.plugin, key=args.key,
                          fileveil=args.fileveil, version=args.version, created_at=args.created_at)
            prepared = work / "prepared"
            COMPILER.prepare(SimpleNamespace(**common, config=args.config, output=work / "prepared.zip"))
            STAGE.receive(work / "prepared.zip", prepared)
            (work / "prepared.zip").unlink()
            releases = args.state_directory.parent / "compiler-artifacts" / selected.project_id
            cache = args.state_directory.parent / "compiler-cache" / selected.project_id / (cache_identity(args, prepared) + ".json")
            persistent = cached_release(cache, releases)
            cache_hit = persistent is not None
            if not cache_hit:
                marked = work / "marked"
                COMPILER.mark(SimpleNamespace(**common, input=prepared, config=prepared / "ci-config.json",
                                              output=work / "marked.zip"))
                shutil.rmtree(prepared)
                STAGE.receive(work / "marked.zip", marked)
                (work / "marked.zip").unlink()
                COMPILER.build(SimpleNamespace(**common, input=marked, project_root=selected.root,
                                               output=work / "built.zip"))
                shutil.rmtree(marked)
                releases.mkdir(parents=True, exist_ok=True, mode=0o700)
                persistent = releases / uuid.uuid4().hex
                STAGE.receive(work / "built.zip", persistent)
                (work / "built.zip").unlink()
            # Preserve this directory even if signing fails after publication. It
            # may already be referenced by a committed project generation.
            postprocess(args, persistent / "ci-config.json", selected.output, persistent)
    else:
        postprocess(args, args.config)
    details = verify_current(args, selected.project_id)
    if cache is not None:
        save_cache(cache, persistent)
    receipt = {"schema": "fileveil.ci.local-receipt.v1", "status": "verified_within_scope",
               "policy": selected.config["policy"], "generation": details.get("generation"),
               "output_directory": str(selected.output), "evidence_directory": str(args.evidence_directory),
               "persistent_source_directory": str(persistent / "artifacts") if persistent else str(selected.artifacts),
               "compiler_cache_hit": cache_hit,
               "post_cleanup_verification": "valid"}
    print(json.dumps(receipt, ensure_ascii=True))
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fileveil", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path("fileveil-ci.json"))
    parser.add_argument("--key", type=Path, required=True, help="Existing local key outside project source and release directories")
    parser.add_argument("--llvm-directory", type=Path)
    parser.add_argument("--plugin", type=Path)
    parser.add_argument("--state-directory", type=Path)
    parser.add_argument("--evidence-directory", type=Path)
    parser.add_argument("--version", default="")
    parser.add_argument("--created-at", default="")
    args = parser.parse_args(argv)
    # Local builds use the explicit file key. Inherited CI secrets never reach
    # the compiler preparation/final-build stages in this process.
    inherited = os.environ.pop("FILEVEIL_SIGNING_KEY_BASE64", None)
    try:
        return run(args)
    finally:
        if inherited is not None:
            os.environ["FILEVEIL_SIGNING_KEY_BASE64"] = inherited


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"FileVeil local release failed ({error})", file=sys.stderr)
        sys.exit(1)

# FVPROV1 13300 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIwOGY3ZTNkOGVmZDk3MmExYzE1YmM5MDIyNzRiYzhhYjhhZDE3MjUzM2ZmMDE5YWFkY2ZhNTRjMjIxOTA2MThmIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL3Byb2plY3QtY2ktbG9jYWwucHkifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiIzZjUzY2YyMGZjYjk5NTM1YTVjODkzMjE0NWIyNTUzZjYyM2JmYzIxOGVmNDUxNTJlMWQxNTA5ZDczOWI0ZTBhYTNlN2NmMDJlOWM1Y2I0MzcyNTU3MzY3NTY4NDIwNGQ3NWU4ZTlkZWY4ZGQwZjdhNzBlOTM4MTcxMDRhYzEwMyJ9XX1d FVPROV1-END
