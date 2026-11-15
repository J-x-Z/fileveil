#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Verify exact source ZIP contents with the independent Python/OpenSSL verifier."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import zipfile
import zlib


TOOLS = Path(__file__).resolve().parent
STAGE = SimpleNamespace(**runpy.run_path(str(TOOLS / "project-ci-stage.py")))
VERIFIER = STAGE.VERIFIER
WORK = TOOLS.parent / "work"
MAX_FILES = STAGE.MAX_FILES + 2
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_BYTES = MAX_TOTAL_BYTES
CHUNK = 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


class BoundedInflater:
    """Count DEFLATE output before ZipExtFile truncates it to the ZIP size field."""
    def __init__(self, decoder, declared):
        self.decoder = decoder
        self.declared = declared
        self.total = 0

    def __getattr__(self, name):
        return getattr(self.decoder, name)

    def account(self, data):
        self.total += len(data)
        require(self.total <= self.declared and self.total <= MAX_FILE_BYTES,
                "Source member expanded beyond its declared byte budget")
        return data

    def decompress(self, *arguments):
        return self.account(self.decoder.decompress(*arguments))

    def flush(self):
        return self.account(self.decoder.flush())


def members(archive):
    entries = archive.infolist()
    require(0 < len(entries) <= MAX_FILES, "Source archive member count exceeds its budget")
    names = set()
    spellings = {}
    total = 0
    for entry in entries:
        require(entry.orig_filename == entry.filename and STAGE.portable(entry.filename),
                "Source archive contains an unsafe member path")
        parts = VERIFIER.relative_path(entry.filename).parts
        mode = entry.external_attr >> 16
        require(not entry.is_dir() and stat.S_IFMT(mode) in (0, stat.S_IFREG),
                "Source archive members must be regular files")
        require(not entry.flag_bits & 1, "Encrypted source archive members are unsupported")
        require(entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                "Source archive compression is unsupported")
        require(entry.filename not in names, "Source archive contains a duplicate member")
        for index in range(1, len(parts) + 1):
            prefix = "/".join(parts[:index])
            folded = prefix.casefold()
            require(spellings.get(folded, prefix) == prefix,
                    "Source archive contains case-aliased paths")
            require(prefix not in names, "Source archive contains a file/directory path collision")
            if index == len(parts):
                require(folded not in spellings, "Source archive contains a file/directory path collision")
            spellings[folded] = prefix
            require(len(spellings) <= VERIFIER.MAX_TREE_ENTRIES,
                    "Source archive directory count exceeds its budget")
        names.add(entry.filename)
        require(0 <= entry.file_size <= MAX_FILE_BYTES, "Source member exceeds its file byte budget")
        total += entry.file_size
        require(total <= MAX_TOTAL_BYTES, "Source archive exceeds its total expanded byte budget")
        if entry.compress_type == zipfile.ZIP_STORED:
            require(entry.compress_size == entry.file_size, "Stored source member size fields differ")
    return entries


def extract(archive, destination, deadline):
    entries = members(archive)
    total = 0
    for entry in entries:
        path = destination / entry.filename
        path.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with archive.open(entry) as source, path.open("xb") as output:
            inflater = None
            if entry.compress_type == zipfile.ZIP_DEFLATED:
                # CPython's ZIP reader otherwise hides excess decoded bytes when
                # an attacker understates file_size in both ZIP headers.
                inflater = BoundedInflater(source._decompressor, entry.file_size)
                source._decompressor = inflater
            while data := source.read(CHUNK):
                written += len(data)
                total += len(data)
                require(time.monotonic() <= deadline, "Source archive extraction time budget exceeded")
                require(written <= entry.file_size and written <= MAX_FILE_BYTES,
                        "Source member exceeded its expanded byte budget")
                require(total <= MAX_TOTAL_BYTES, "Source archive exceeded its expanded byte budget")
                output.write(data)
            require(written == entry.file_size, "Source archive contains a truncated member")
            if inflater is not None:
                require(inflater.eof and not inflater.unused_data and inflater.total == written,
                        "Source archive contains an incomplete or overlong compressed stream")
    return len(entries), total


def verify(source_archive, key_id=None, openssl=None):
    selected = Path(source_archive).expanduser().absolute()
    WORK.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + VERIFIER.MAX_RUNTIME_SECONDS
    with tempfile.TemporaryDirectory(prefix=".fileveil-source-package-", dir=WORK) as name:
        tree = Path(name) / "source"
        tree.mkdir()
        with STAGE.open_snapshot(selected) as (source, before):
            require(before.st_size <= MAX_ARCHIVE_BYTES, "Source archive exceeds its compressed byte budget")
            STAGE.check_zip_directory(source)
            source.seek(0)
            digest = hashlib.sha256()
            read_bytes = 0
            while data := source.read(CHUNK):
                read_bytes += len(data)
                require(read_bytes <= MAX_ARCHIVE_BYTES, "Source archive grew beyond its read byte budget")
                require(time.monotonic() <= deadline, "Source archive reading time budget exceeded")
                digest.update(data)
            require(read_bytes == before.st_size, "Source archive changed during reading")
            source.seek(0)
            with zipfile.ZipFile(source) as archive:
                count, expanded = extract(archive, tree, deadline)
        # The reviewed verifier adjacent to this tool reads the extracted files.
        # Archive-provided Python files are data throughout this operation.
        independent = VERIFIER.verify(tree, key_id, openssl)
    return {"schema": "fileveil.source-package-verification.v1",
            "result": "verified_within_scope", "archive_sha256": digest.hexdigest(),
            "archive_bytes": read_bytes, "members": count, "expanded_bytes": expanded,
            "independent_verifier": independent,
            "scope": "Exact extracted source bytes and signed inventory verified with Python/OpenSSL"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_archive", type=Path)
    parser.add_argument("--key-id", help="Externally pinned release public-key identifier")
    parser.add_argument("--openssl", help="Explicit OpenSSL executable")
    parser.add_argument("--report", type=Path, help="Write a new JSON report without overwriting a file")
    args = parser.parse_args(argv)
    if args.report is not None and (args.report.exists() or args.report.is_symlink()):
        parser.error("Report output already exists")
    try:
        report = verify(args.source_archive, args.key_id, args.openssl)
        code = 0
    except (ValueError, KeyError, TypeError, AttributeError, OSError, RuntimeError,
            NotImplementedError, zipfile.BadZipFile, zlib.error, subprocess.TimeoutExpired) as error:
        report = {"schema": "fileveil.source-package-verification.v1", "result": "failed", "reason": str(error)}
        code = 1
    encoded = json.dumps(report, ensure_ascii=False, sort_keys=True) + "\n"
    if args.report is not None:
        with args.report.open("x", encoding="utf-8", newline="\n") as output:
            output.write(encoded)
    print(encoded, end="", file=sys.stdout if code == 0 else sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())

# FVPROV1 8392 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI5ZWE2NTczZTFkNWU2NDRmNmQ5ZDk3YTVmMzU0NDE0OGQ5ODI5MzBhYzQwNDNiZjAzMDMzNDc2ZDBiOGQ3OTU1IiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL3ZlcmlmeS1zb3VyY2UtcGFja2FnZS5weSJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6ImJmZGYyYzU0NTI3OThlMDFmNWY4M2M1MDI1NjIwYzUwMDkwOGM4OTEwNDQxOWNjYmZmNDI3NWFiMDQ1YWNhYjRlYjhhN2RkNDk4YTg3YTBiMzI4M2JkMGM4MTQ3YmI0NTA1NmRkMmJkNTY3NzM0OTU3MWQ1ZWViZjBhNzc1OTBmIn1dfV0= FVPROV1-END
