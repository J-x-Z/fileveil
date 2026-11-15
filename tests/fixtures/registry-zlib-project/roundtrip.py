#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Exercise two native targets against Python's independent zlib implementation."""
from pathlib import Path
import subprocess
import sys
import tempfile
import zlib

pack, checksum, kind = sys.argv[1:]
with tempfile.TemporaryDirectory() as name:
    directory = Path(name)
    data = {"empty": b"", "text": "FileVeil 文档\n".encode() * 100,
            "binary": bytes(range(256)) * 4096, "corrupt": b"control"}[kind]
    original = directory / "input.bin"
    original.write_bytes(data)
    archive, restored = directory / "archive.fvz", directory / "restored.bin"
    if kind == "corrupt":
        archive.write_bytes(b"\xff\xff\xff\xffinvalid")
        result = subprocess.run([pack, "decode", archive, restored], capture_output=True)
        assert result.returncode == 2 and not restored.exists()
    else:
        subprocess.run([pack, "encode", original, archive], check=True)
        assert zlib.decompress(archive.read_bytes()[4:]) == data
        subprocess.run([pack, "decode", archive, restored], check=True)
        assert restored.read_bytes() == data
        observed = subprocess.check_output([checksum, restored], text=True).strip()
        assert observed == f"{zlib.crc32(data):08x}"
