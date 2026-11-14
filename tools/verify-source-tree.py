#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Verify a FileVeil alpha source inventory with Python and OpenSSL.

The bundled release key authenticates the supplied tree. Pass --key-id from an
independent source to pin that key. Third-party files are covered for integrity
and retain their own authorship and licenses.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import runpy
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from types import SimpleNamespace


SCHEMA = "fileveil.source-catalog.v1"
RELEASE = "v0.5.0-alpha.1"
REPOSITORY = "https://github.com/J-x-Z/fileveil"
CATALOG = "provenance/source-catalog.toml"
EVIDENCE = "provenance/source-catalog.evidence.json"
RELEASE_KEY = "provenance/release-key.json"
ROOT_IGNORED = {".git", "target", "work", "dist"}
MAX_FILES = 20_000
MAX_MARKED_FILES = 4096
MAX_TREE_ENTRIES = 50_000
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_CATALOG_BYTES = 8 * 1024 * 1024
MAX_RUNTIME_SECONDS = 120
WINDOWS = sys.platform == "win32"

# Execute the adjacent reviewed source directly. Excluded bytecode caches must
# not replace the cryptographic verifier through Python's import cache.
CRYPTO = SimpleNamespace(**runpy.run_path(str(Path(__file__).with_name("verify-evidence.py"))))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def ignored(parts):
    return (
        parts[0] in ROOT_IGNORED
        or "__pycache__" in parts
        or parts[-1] == ".DS_Store"
    )


def relative_path(value):
    require(isinstance(value, str) and 0 < len(value.encode()) <= 4096, "Invalid inventory path")
    path = PurePosixPath(value)
    require(
        not path.is_absolute()
        and bool(path.parts)
        and path.as_posix() == value
        and all(part not in (".", "..") for part in path.parts)
        and "\\" not in value
        and ":" not in value
        and "\0" not in value,
        "Inventory path must be a canonical relative POSIX path",
    )
    require(not ignored(path.parts), "Inventory path uses an excluded location")
    return path


def no_link(info):
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return not stat.S_ISLNK(info.st_mode) and not (
        getattr(info, "st_file_attributes", 0) & reparse
    )


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def matches_opened_file(opened, by_path):
    if not no_link(opened) or not stat.S_ISREG(opened.st_mode):
        return False
    if not WINDOWS:
        return identity(opened) == identity(by_path)
    # CPython 3.12+ path stat exposes creation time as ctime, while fstat
    # exposes ChangeTime. Compare file IDs and compatible metadata across
    # these APIs. Full ctime checks remain within each API before/after I/O.
    # https://github.com/python/cpython/issues/157671
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_birthtime_ns")
    return tuple(getattr(opened, field, None) for field in fields) == tuple(
        getattr(by_path, field, None) for field in fields
    )


class TreeReader:
    def __init__(self, root):
        selected = Path(root).expanduser().absolute()
        require(no_link(selected.lstat()), "Source root must not be a symlink or reparse point")
        self.root = selected.resolve(strict=True)
        require(self.root.is_dir(), "Source root is not a directory")
        self.total_bytes = 0
        self.deadline = time.monotonic() + MAX_RUNTIME_SECONDS
        self.use_directory_fds = (
            os.open in os.supports_dir_fd
            and hasattr(os, "O_NOFOLLOW")
            and hasattr(os, "O_DIRECTORY")
        )

    def check_time(self):
        require(time.monotonic() <= self.deadline, "Source verification time budget exceeded")

    def open_file(self, parts, path):
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        if not self.use_directory_fds:
            return os.open(path, flags)
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptor = os.open(self.root, directory_flags)
        try:
            for part in parts[:-1]:
                child = os.open(part, directory_flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            return os.open(parts[-1], flags, dir_fd=descriptor)
        finally:
            os.close(descriptor)

    def read(self, name, limit=MAX_FILE_BYTES):
        self.check_time()
        parts = relative_path(name).parts
        observed = []
        path = self.root
        for index, part in enumerate(parts):
            path = path / part
            info = path.lstat()
            require(no_link(info), f"Symlink or reparse point refused at {name}")
            if index + 1 < len(parts):
                require(stat.S_ISDIR(info.st_mode), f"Non-directory parent at {name}")
            observed.append((path, identity(info)))
        before = info
        require(stat.S_ISREG(before.st_mode), f"Non-regular file refused at {name}")
        require(before.st_size <= limit, f"File exceeds byte budget at {name}")
        self.total_bytes += before.st_size
        require(self.total_bytes <= MAX_TOTAL_BYTES, "Source tree exceeds aggregate byte budget")
        descriptor = self.open_file(parts, path)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            require(matches_opened_file(opened, before), f"File identity changed at {name}")
            data = stream.read(limit + 1)
            require(len(data) <= limit, f"File exceeds byte budget at {name}")
            require(identity(os.fstat(stream.fileno())) == identity(opened), f"File changed during verification at {name}")
        for observed_path, original_identity in observed:
            current = observed_path.lstat()
            require(no_link(current) and identity(current) == original_identity, f"Path changed during verification at {name}")
        return data

    def files(self):
        pending = [self.root]
        found = set()
        entries_seen = 0
        while pending:
            self.check_time()
            directory = pending.pop()
            before = directory.lstat()
            require(no_link(before), "Symlink directory refused during traversal")
            with os.scandir(directory) as entries:
                for entry in entries:
                    entries_seen += 1
                    require(entries_seen <= MAX_TREE_ENTRIES, "Source tree entry budget exceeded")
                    path = directory / entry.name
                    parts = path.relative_to(self.root).parts
                    if ignored(parts):
                        continue
                    info = entry.stat(follow_symlinks=False)
                    require(no_link(info), f"Symlink or reparse point refused at {'/'.join(parts)}")
                    if stat.S_ISDIR(info.st_mode):
                        pending.append(path)
                    else:
                        require(stat.S_ISREG(info.st_mode), f"Non-regular file refused at {'/'.join(parts)}")
                        found.add('/'.join(parts))
                        require(len(found) <= MAX_FILES + 2, "Source tree file budget exceeded")
            after = directory.lstat()
            require(no_link(after) and identity(after) == identity(before), "Directory changed during traversal")
        return found


def json_object(data):
    return json.loads(data, object_pairs_hook=CRYPTO.unique_object)


def release_key(data, pinned_key_id):
    key = json_object(data)
    require(set(key) == {"schema", "repository", "subject", "algorithm", "key_id", "public_key_hex"}, "Unexpected release-key fields")
    require(key.get("schema") == "fileveil.release.signing-key.v1", "Unknown release-key schema")
    require(key.get("algorithm") == "Ed25519" and key.get("repository") == REPOSITORY, "Unexpected release-key algorithm or repository")
    raw = CRYPTO.lower_hex(key.get("public_key_hex"), 32)
    require(CRYPTO.sha(raw) == key.get("key_id"), "Release key identifier mismatch")
    if pinned_key_id is not None:
        CRYPTO.lower_hex(pinned_key_id, 32)
        require(key["key_id"] == pinned_key_id, "Release key differs from external pin")
    return key


def openssl_path(requested):
    import shutil

    candidates = [requested, "/opt/homebrew/opt/openssl@3/bin/openssl", "/usr/local/opt/openssl@3/bin/openssl", shutil.which("openssl")]
    selected = next((Path(item).resolve() for item in candidates if item and Path(item).is_file()), None)
    require(selected is not None, "OpenSSL prerequisite unavailable")
    return str(selected)


def verify_source_statement(data, key, openssl, directory):
    base, encoded = CRYPTO.extract_source_carrier(data)
    require(encoded is not None, "Declared marked source has no provenance carrier")
    records = json_object(encoded)
    require(isinstance(records, list) and len(records) == 1, "Source inventory requires one initial source statement")
    record = records[0]
    require(set(record) == {"body", "signatures"}, "Unexpected source record fields")
    body = record["body"]
    CRYPTO.validate_statement(body)
    require(
        body["schema"] == CRYPTO.V2
        and body["kind"] == "create"
        and body["mode"] == "self_sign"
        and body["sequence"] == 0
        and body["previous_record_sha256"] is None
        and body["parent_version"] is None
        and body.get("transformation") is None,
        "Source inventory requires an initial version-two self signature",
    )
    require(body["content_sha256"] == CRYPTO.sha(base), "Source statement content binding differs")
    require(body["actor_key_id"] == key["key_id"], "Source actor differs from release key")
    require(len(record["signatures"]) == 1, "Source statement must have one release signature")
    signature = record["signatures"][0]
    require(signature["public_key_hex"] == key["public_key_hex"], "Source signature uses another public key")
    CRYPTO.verify_signature(openssl, directory, b"FileVeil provenance signature v2\0", body, signature)
    return records


def verify(root, pinned_key_id=None, requested_openssl=None):
    reader = TreeReader(root)
    key = release_key(reader.read(RELEASE_KEY, 64 * 1024), pinned_key_id)
    catalog_bytes = reader.read(CATALOG, MAX_CATALOG_BYTES)
    evidence_bytes = reader.read(EVIDENCE, MAX_CATALOG_BYTES)
    package = json_object(evidence_bytes)
    require(isinstance(package, dict) and set(package) == {"body", "signature"}, "Unexpected evidence envelope")
    require(package["signature"].get("key_id") == key["key_id"] and package["signature"].get("public_key_hex") == key["public_key_hex"], "Evidence signer differs from release key")
    openssl = openssl_path(requested_openssl)
    with tempfile.TemporaryDirectory(prefix="fileveil-source-verification-") as temporary:
        directory = Path(temporary)
        records = verify_source_statement(catalog_bytes, key, openssl, directory)
        require(CRYPTO.canonical(records) == CRYPTO.canonical(package["body"]["records"]), "Catalog carrier and evidence histories differ")
        catalog_snapshot = directory / "catalog.toml"
        evidence_snapshot = directory / "evidence.json"
        catalog_snapshot.write_bytes(catalog_bytes)
        evidence_snapshot.write_bytes(evidence_bytes)
        result = CRYPTO.verify(SimpleNamespace(
            evidence=str(evidence_snapshot), asset=[str(catalog_snapshot)],
            checkpoint_key=[], tsa_roots=None, openssl=openssl,
        ))
        require(result["provided_assets_verified"] == 1, "Catalog asset was not verified")
        catalog = tomllib.loads(catalog_bytes.decode("utf-8"))
        required = {"schema", "release", "repository", "files"}
        require(required.issubset(catalog) and set(catalog).issubset(required | {"created_at"}), "Unexpected source catalog fields")
        require(catalog["schema"] == SCHEMA and catalog["release"] == RELEASE and catalog["repository"] == REPOSITORY, "Source catalog identity differs")
        if "created_at" in catalog:
            require(catalog["created_at"] == records[0]["body"]["created_at"], "Catalog creation declaration differs from its signed statement")
        entries = catalog["files"]
        require(isinstance(entries, list) and 0 < len(entries) <= MAX_FILES, "Inventory file count exceeds budget")
        expected = set()
        portable_names = set()
        marked_count = 0
        file_bytes = 0
        for entry in entries:
            require(isinstance(entry, dict) and set(entry) == {"path", "sha256", "size_bytes", "marked"}, "Unexpected inventory entry")
            name = relative_path(entry["path"]).as_posix()
            require(name not in (CATALOG, EVIDENCE), "Catalog and evidence must use their signed fixed exceptions")
            require(name not in expected and name.casefold() not in portable_names, "Duplicate or case-aliased inventory path")
            expected.add(name)
            portable_names.add(name.casefold())
            require(type(entry["size_bytes"]) is int and 0 <= entry["size_bytes"] <= MAX_FILE_BYTES, "Invalid inventory size")
            require(type(entry["marked"]) is bool, "Invalid inventory marked flag")
            CRYPTO.lower_hex(entry["sha256"], 32)
            data = reader.read(name)
            require(len(data) == entry["size_bytes"] and CRYPTO.sha(data) == entry["sha256"], f"Inventory hash or size differs at {name}")
            file_bytes += len(data)
            if entry["marked"]:
                marked_count += 1
                require(marked_count <= MAX_MARKED_FILES, "Marked source count exceeds signature budget")
                reader.check_time()
                verify_source_statement(data, key, openssl, directory)
        require(RELEASE_KEY in expected, "Release-key file must be included in the signed inventory")
        observed = reader.files()
        require(observed == expected | {CATALOG, EVIDENCE}, "Source tree contains missing or unlisted files")
    return {
        "result": "verified_within_scope",
        "schema": SCHEMA,
        "release": RELEASE,
        "repository": REPOSITORY,
        "release_key_id": key["key_id"],
        "release_key_trust": "externally_pinned" if pinned_key_id else "bundled_key",
        "catalog_signature": "valid",
        "catalog_asset_binding": "valid",
        "files_verified": len(entries),
        "marked_source_signatures_verified": marked_count,
        "listed_file_bytes": file_bytes,
        "copyright_identity": "not_assessed",
        "ignored_root_entries": sorted(ROOT_IGNORED),
        "ignored_anywhere": ["__pycache__", ".DS_Store"],
        "signed_fixed_exceptions": [CATALOG, EVIDENCE],
        "scope": "Signed inventory, exact listed bytes, initial v2 source signatures and absence of additional files within the stated exclusions. Third-party entries receive integrity coverage. External copyright identity, timestamp trust and complete distribution history require separate evidence.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", help="Source tree root, default current directory")
    parser.add_argument("--key-id", help="Expected release key identifier from an independent source")
    parser.add_argument("--openssl", help="Explicit OpenSSL executable")
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.root, args.key_id, args.openssl), ensure_ascii=False, sort_keys=True))
    except (ValueError, KeyError, TypeError, AttributeError, OSError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"result": "failed", "reason": str(error)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
