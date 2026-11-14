#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Fetch four pinned historical data samples for explicit compatibility tests.

Research data stays under ignored work/. Original programs are never downloaded
or executed by this script, and existing samples are protected by their hashes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "760ce17a45b7ddf84049e6c477c682cedc995b78"
FILES = {
    "preview_bottle_original.jpg": "5fa55db03f0cee1209939ace1576a8b42da3855af567fed222e479d5ed50a451",
    "preview_bottle_firstuser.jpg": "eae1a707d2dab40eb6e8c25c96bb919af63640567bc40fec3c4ce29aaa76a9da",
    "preview_bottle_seconduser.jpg": "ab090c32f1a82228daf34a0827653bb4f9bd3191974f0c3053e1a05123b5acc1",
    "love.docx": "ad90dd10a4520ad042878ea72f030795b8e51911ce913e4338b2115b1cd31976",
}


def main() -> None:
    destination = ROOT / "work/v04-research"
    destination.mkdir(parents=True, exist_ok=True)
    for name, expected in FILES.items():
        path = destination / name
        if path.exists():
            data = path.read_bytes()
        else:
            url = f"https://raw.githubusercontent.com/takeshixx/redstar-tools/{COMMIT}/watermarked/{name}"
            with urlopen(url, timeout=30) as response:
                data = response.read(65_537)
            if len(data) > 65_536 or hashlib.sha256(data).hexdigest() != expected:
                raise RuntimeError(f"Pinned reference hash mismatch for {name}")
            with path.open("xb") as stream:
                stream.write(data)
        if len(data) > 65_536 or hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError(f"Existing reference hash mismatch for {name}")
    oracle = destination / "legacy-openssl-oracle.json"
    if not oracle.exists():
        with oracle.open("x", encoding="utf-8") as stream:
            stream.write((ROOT / "tests/fixtures/heritage-evidence.json").read_text())
    print(json.dumps({"commit": COMMIT, "data_samples_verified": len(FILES), "original_programs_executed": False}))


if __name__ == "__main__":
    main()

# FVPROV1 2194 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIxYTA0ZjQ4ZWFiNjVjMjJiY2VjMmJlMTcwOWNiZTFkYmRiYTRjZDRiNjVkNGRhNmMxNzA0YTRiZWNhYTc4MzZiIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4yIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMiIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL2ZldGNoLWhlcml0YWdlLXJlZmVyZW5jZS1zYW1wbGVzLnB5In0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiOWJlYThmYmU0YjZjYjM1YTE2Y2FiZDExMzU0ZDBjNjg0Y2NkMDIwZWFhNTZiMzJlOWEyNGM2MGFlYjliZjk0ZjE3MmQzYzk0OGIyNjkzODkwYmU1NjhlNWY3MjRjZTY3OGZlYTllMWRkYjc0OTU1ZTlhMjYwOTdmMDRmZGYzMDcifV19XQ== FVPROV1-END
