#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Prepare a signed FileVeil source release using the normal FileVeil CLI."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


CATALOG = "provenance/source-catalog.toml"
EVIDENCE = "provenance/source-catalog.evidence.json"
SOURCE_SUFFIXES = {".rs", ".py", ".swift", ".sh", ".toml", ".yml", ".yaml"}
MARKER = re.compile(rb"(?:\/\/|#|--|;) FVPROV1 [0-9]+ ([A-Za-z0-9+/=]+) FVPROV1-END\n\Z")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def project_source(path, data):
    if path.suffix not in SOURCE_SUFFIXES or "fixtures" in path.parts:
        return False
    if path.as_posix() == "crates/fileveil-engine/src/watermark/dwt_dct.rs":
        return False
    if b"SPDX-License-Identifier: MPL-2.0" in data[:4096]:
        return True
    return path.name == "Cargo.toml" or path.as_posix() in {
        ".github/deny.toml", ".github/workflows/ci.yml", ".github/workflows/security.yml"
    }


def command(executable, arguments):
    result = subprocess.run([str(executable), *arguments, "--json"], capture_output=True, text=True, timeout=120)
    if result.returncode not in (0, 4):
        raise ValueError(f"FileVeil {arguments[0]} failed: {result.stderr.strip()}")
    report = json.loads(result.stdout)
    if report["result"] not in ("verified_within_scope", "partially_verified"):
        raise ValueError(f"FileVeil {arguments[0]} did not verify its result")
    return report


def require_signature(report):
    verified = report["advanced"]["heritage"]["verification"]
    if any(verified[name] != "valid" for name in ("signature", "content_binding", "chain")):
        raise ValueError("Source signature, binding or chain is invalid")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--executable", type=Path, required=True)
    keys = parser.add_mutually_exclusive_group(required=True)
    keys.add_argument("--key-ref")
    keys.add_argument("--key", type=Path)
    parser.add_argument("--release", required=True)
    parser.add_argument("--created-at", required=True, help="Explicit asserted date or timestamp")
    parser.add_argument("--renew-release", action="store_true", help="Verify and Clean older signatures by this release key before signing the new release")
    parser.add_argument("--apply", action="store_true", help="Replace project files only after staged checks pass")
    args = parser.parse_args()
    root = args.root.resolve()
    executable = args.executable.resolve()
    repository = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=root, text=True).strip()
    if Path(repository).resolve() != root:
        raise ValueError("Root must be the Git source repository")
    public = json.loads((root / "provenance/release-key.json").read_text())
    key_id = public["key_id"]
    if args.key_ref is not None and key_id != args.key_ref:
        raise ValueError("Key reference differs from the declared release key")
    credential = ["--key-ref", args.key_ref] if args.key_ref else ["--key", str(args.key.resolve())]
    listed = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root)
    paths = sorted({os.fsdecode(path) for path in listed.split(b"\0") if path})
    paths = [path for path in paths if path not in (CATALOG, EVIDENCE)]
    originals = {}
    marked = []
    for name in paths:
        path = root / name
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            raise ValueError(f"Source tree contains a symlink or special file: {name}")
        data = path.read_bytes()
        originals[name] = data
        if project_source(Path(name), data):
            marked.append(name)
    if not args.apply:
        print(json.dumps({"release": args.release, "catalog_files": len(paths), "source_files_to_mark": len(marked), "apply_required": True}))
        return
    work = root / "work"
    work.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="source-release-", dir=work) as temporary:
        stage = Path(temporary)
        replacements = {}
        for index, name in enumerate(marked):
            path = root / name
            data = originals[name]
            match = MARKER.search(data)
            work_id = "https://github.com/J-x-Z/fileveil/source/" + name
            if match:
                record = json.loads(base64.b64decode(match[1], validate=True))[-1]
                if (record["body"]["work_id"] != work_id
                    or record["body"]["actor_key_id"] != key_id):
                    raise ValueError(f"Existing provenance belongs to a different publisher or file: {name}")
                require_signature(command(executable, ["verify", str(path)]))
                if record["body"].get("copy_id") == args.release:
                    continue
                if not args.renew_release:
                    raise ValueError(f"Use --renew-release to replace an older release signature: {name}")
                restored = stage / f"{index}.previous{path.suffix}"
                command(executable, ["clean", str(path), "-o", str(restored)])
                data = restored.read_bytes()
                path = restored
            output = stage / f"{index}{path.suffix}"
            options = json.dumps({"mark": {"version": args.release, "edition": "alpha"}})
            report = command(executable, ["mark", str(path), "-o", str(output), *credential,
                "--work-id", work_id, "--copy-id", args.release, "--author", "J-x-Z/FileVeil",
                "--created-at", args.created_at, "--options-json", options])
            require_signature(report)
            require_signature(command(executable, ["verify", str(output)]))
            clean = stage / f"{index}.restored{path.suffix}"
            command(executable, ["clean", str(output), "-o", str(clean)])
            if clean.read_bytes() != data:
                raise ValueError(f"Source roundtrip changed content: {name}")
            replacements[name] = output
        for name in paths:
            if (root / name).read_bytes() != originals[name]:
                raise ValueError(f"Source changed during preparation: {name}")
        catalog = ["# SPDX-License-Identifier: MPL-2.0", 'schema = "fileveil.source-catalog.v1"',
            'repository = "https://github.com/J-x-Z/fileveil"', f"release = {json.dumps(args.release)}",
            f"created_at = {json.dumps(args.created_at)}", ""]
        for name in paths:
            data = replacements[name].read_bytes() if name in replacements else originals[name]
            catalog.extend(["[[files]]", f"path = {json.dumps(name)}", f"sha256 = {json.dumps(sha(data))}",
                f"size_bytes = {len(data)}", f"marked = {str(name in marked).lower()}", ""])
        raw = stage / "source-catalog.toml"
        raw.write_text("\n".join(catalog), encoding="utf-8", newline="\n")
        signed = stage / "catalog.marked.toml"
        require_signature(command(executable, ["mark", str(raw), "-o", str(signed), *credential,
            "--work-id", "https://github.com/J-x-Z/fileveil/source-tree", "--copy-id", args.release,
            "--author", "J-x-Z/FileVeil", "--created-at", args.created_at,
            "--options-json", json.dumps({"mark": {"version": args.release, "edition": "alpha"}})]))
        evidence = stage / "source-catalog.evidence.json"
        command(executable, ["evidence", "export", str(signed), "-o", str(evidence), *credential])
        for name, output in replacements.items():
            output.chmod(stat.S_IMODE((root / name).stat().st_mode))
            os.replace(output, root / name)
        for name, output in ((CATALOG, signed), (EVIDENCE, evidence)):
            output.chmod(0o644)
            os.replace(output, root / name)
    print(json.dumps({"release": args.release, "catalog_files": len(paths), "marked_source_files": len(marked),
        "source_roundtrip_verified": len(replacements), "key_id": key_id}))


if __name__ == "__main__":
    try:
        main()
    except (KeyError, ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(f"Source release preparation failed. {error}") from None
