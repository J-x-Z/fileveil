#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Authorize transferred configuration against a separately checked-out caller commit."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys


SPEC = importlib.util.spec_from_file_location("fileveil_authorization_postprocess",
                                           Path(__file__).with_name("project-postprocess.py"))
POST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POST)


def authorize_history(config, directory, producer_run_id):
    """Bind public history to its artifact producer before Core verifies the signed chain."""
    if not isinstance(producer_run_id, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", producer_run_id):
        raise ValueError("History authorization requires the artifact API's producer run ID")
    edition = config["work_id"] + "\0" + config["copy_id"] + "\0" + sys.platform
    project_id = hashlib.sha256(("FileVeil CI edition v1\0" + edition).encode()).hexdigest()[:32]
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Signed public history directory is unavailable")
    namespaces = list(directory.iterdir())
    if (len(namespaces) != 1 or namespaces[0].name != project_id
            or namespaces[0].is_symlink() or not namespaces[0].is_dir()):
        raise ValueError("History contains a different project edition namespace")
    latest = None
    revisions = set()
    total = 0
    for generation in namespaces[0].iterdir():
        if len(revisions) >= 20_000 or generation.is_symlink() or not generation.is_dir():
            raise ValueError("History generation shape or count exceeds its bounded contract")
        members = list(generation.iterdir())
        if ({path.name for path in members} != {"manifest.json", "evidence.json", "COMMITTED"}
                or any(path.is_symlink() or not path.is_file() for path in members)):
            raise ValueError("History must contain only committed public generation metadata")
        manifest_path = generation / "manifest.json"
        size = manifest_path.stat().st_size
        total += size
        if size > 64 * 1024 * 1024 or total > 256 * 1024 * 1024:
            raise ValueError("History manifests exceed their bounded metadata budget")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if (not isinstance(manifest, dict) or manifest.get("schema") != "fileveil.project.manifest.v1"
                or manifest.get("project_id") != project_id or manifest.get("work_id") != config["work_id"]
                or manifest.get("copy_id") != config["copy_id"]):
            raise ValueError("History manifest belongs to a different project edition")
        revision = manifest.get("revision")
        if type(revision) is not int or revision < 1 or revision in revisions:
            raise ValueError("History has an invalid or duplicate generation revision")
        revisions.add(revision)
        if latest is None or revision > latest["revision"]:
            latest = manifest
    if latest is None:
        raise ValueError("Retained history has no committed generation")
    version = latest.get("version")
    if (not isinstance(version, str) or len(version) > 128
            or not re.fullmatch(r"ci\." + re.escape(producer_run_id) + r"\.[1-9][0-9]*", version)):
        raise ValueError("Latest retained signed version differs from its artifact producer run")
    return {"producer_run_id": producer_run_id, "latest_revision": latest["revision"], "version": version,
            "freshness_scope": "retained_artifact_producer_run_binding",
            "cryptographic_verification": "pending_core_verification"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--caller-root", type=Path, required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--received-config", type=Path, required=True)
    parser.add_argument("--policy", choices=POST.POLICIES, required=True)
    parser.add_argument("--history-directory", type=Path)
    parser.add_argument("--history-producer-run-id")
    args = parser.parse_args()
    config = POST.authorize_transfer(args.caller_root, args.config, args.received_config, args.policy)
    report = {"schema": "fileveil.ci.authorization.v1", "configuration_authorized": True,
              "policy": config["policy"], "scope": "independent_caller_commit_configuration"}
    if args.history_directory is not None or args.history_producer_run_id is not None:
        if args.history_directory is None or args.history_producer_run_id is None:
            raise ValueError("History authorization requires both its directory and artifact producer run ID")
        report["history"] = authorize_history(config, args.history_directory, args.history_producer_run_id)
    print(json.dumps(report))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"FileVeil transfer authorization failed ({error})", file=sys.stderr)
        sys.exit(1)

# FVPROV1 5152 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJlMDcwYWQ5OTdlZDU4ZDdiMDg0Njg1NDc4NWM5YzU5ZjViM2E0MDU5NGExODE3NTEyNzc3OThlZmIzODJmNzRmIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL3Byb2plY3QtY2ktYXV0aG9yaXplLnB5In0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiZmUxYjQxNmMxODE0Nzk1MWJjZDNkM2E3Y2UwOWVkZWNmNjhmYTY1NTVlMzYxNjBiNTc0NjljZjhlZTVhZmY2NjkzZGZmNTc1MDAwMDc4YzY2YmYyNzBlZTM0ZWI5MjNlNDNhMzgyODBhMjgyYTUxZjcwYWE5ZTE1ZDZhN2Q4MDMifV19XQ== FVPROV1-END
