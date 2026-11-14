#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Independent public evidence verification using Python and OpenSSL Ed25519.

This tool uses no FileVeil Rust parser or private keys. Explicit --asset files may
be raw assets or supported FileVeil native carriers. Copyright identity and
unprovided historical asset bytes retain their separate evidence requirements.
"""
from __future__ import annotations

import argparse
import base64
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

V1 = "fileveil.heritage.signature.v1"
V2 = "fileveil.provenance.signature.v2"
MAGIC = b"FVHERIT1"
MEDIA_UUID = bytes.fromhex("c12f9572d95b4f2ca7b81b3812f5e002")
MAX_ASSET = 256 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON property")
        result[key] = value
    return result


def canonical(value):
    def valid(item):
        if isinstance(item, dict):
            require(all(key.isascii() for key in item), "Non-ASCII property name")
            for child in item.values():
                valid(child)
        elif isinstance(item, list):
            for child in item:
                valid(child)
        elif isinstance(item, int) and not isinstance(item, bool):
            require(0 <= item <= 9007199254740991, "Integer outside canonical range")
        elif isinstance(item, float):
            raise ValueError("Floating-point evidence fields are unsupported")
    valid(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def lower_hex(text, size):
    require(isinstance(text, str) and re.fullmatch(r"[0-9a-f]{%d}" % (size * 2), text), "Invalid hex field")
    return bytes.fromhex(text)


def verify_signature(openssl, directory, domain, body, signature):
    require(set(signature) == {"key_id", "public_key_hex", "signature_hex"}, "Unexpected signature fields")
    raw = lower_hex(signature["public_key_hex"], 32)
    require(sha(raw) == signature["key_id"], "Public key identifier mismatch")
    encoded = lower_hex(signature["signature_hex"], 64)
    (directory / "public.der").write_bytes(bytes.fromhex("302a300506032b6570032100") + raw)
    (directory / "signature.bin").write_bytes(encoded)
    (directory / "message.bin").write_bytes(domain + canonical(body))
    checked = subprocess.run([openssl, "pkeyutl", "-verify", "-pubin", "-inkey", "public.der", "-keyform", "DER", "-rawin", "-in", "message.bin", "-sigfile", "signature.bin"], cwd=directory, capture_output=True, timeout=15)
    require(checked.returncode == 0, "Ed25519 signature verification failed")
    return signature["key_id"]


def validate_statement(statement):
    required = {"schema", "algorithm", "kind", "mode", "sequence", "previous_record_sha256", "content_sha256", "work_id", "author", "edition", "version", "parent_version", "created_at", "actor_key_id", "transfer_to_key_id", "issuer_policy"}
    optional = {"copy_id", "rotation_to_key_id", "transformation"}
    require(required.issubset(statement) and set(statement).issubset(required | optional), "Unexpected record body fields")
    require(statement["schema"] in (V1, V2) and statement["algorithm"] == "Ed25519", "Unsupported signature protocol")
    require(statement["kind"] in ("create", "modify", "issue", "transfer", "rotate_key"), "Unknown event kind")
    for name in ("content_sha256", "actor_key_id", "previous_record_sha256", "transfer_to_key_id", "rotation_to_key_id"):
        if statement.get(name) is not None:
            lower_hex(statement[name], 32)
    for name in ("work_id", "author", "edition", "version", "created_at", "copy_id", "parent_version"):
        if statement.get(name) is not None:
            require(isinstance(statement[name], str) and len(statement[name].encode()) <= 4096, "Unbounded statement text")
    require(all(statement[name] for name in ("work_id", "version", "created_at")), "Missing work/version/time")
    require((statement["kind"] == "transfer") == (statement["transfer_to_key_id"] is not None), "Transfer target mismatch")
    require(statement["transfer_to_key_id"] != statement["actor_key_id"], "Custody transfer must have distinct keys")
    if statement["schema"] == V1:
        require(not any(statement.get(name) is not None for name in optional) and statement["kind"] != "rotate_key", "Version-one body has version-two fields")
    else:
        require(statement.get("copy_id"), "Missing version-two copy identifier")
        require((statement["kind"] == "rotate_key") == (statement.get("rotation_to_key_id") is not None), "Rotation target mismatch")
        require(statement.get("rotation_to_key_id") != statement["actor_key_id"], "Key rotation must have distinct keys")
    policy = statement["issuer_policy"]
    if statement["mode"] == "self_sign":
        require(policy is None, "Self signature has issuer policy")
    else:
        require(statement["mode"] == "nati_sign" and isinstance(policy, dict) and set(policy) == {"threshold", "allowed_key_ids"}, "Invalid issuer policy")
        require(0 < policy["threshold"] <= len(set(policy["allowed_key_ids"])) == len(policy["allowed_key_ids"]) <= 32, "Invalid distinct-issuer threshold")
        for key in policy["allowed_key_ids"]:
            lower_hex(key, 32)


def record_hash(record):
    value = copy.deepcopy(record)
    value["signatures"].sort(key=lambda entry: entry["key_id"])
    domain = b"FileVeil provenance finalized record v2\0" if value["body"]["schema"] == V2 else b"FileVeil Heritage finalized record v1\0"
    return sha(domain + canonical(value))


def extract_source_carrier(data):
    marker = re.compile(rb"(?m)^(?:// |# |-- |; )FVPROV1 [^\n]*")
    for candidate in marker.finditer(data):
        terminal = candidate.end() == len(data) or candidate.end() + 1 == len(data)
        if candidate.end() - candidate.start() > 256 * 1024 * 2 + 128:
            require(not terminal, "Oversized source provenance carrier")
            continue
        line = candidate.group()
        match = re.fullmatch(rb"(?:// |# |-- |; )FVPROV1 (0|[1-9][0-9]{0,19}) ([A-Za-z0-9+/=]+) FVPROV1-END", line)
        if match is None:
            require(not terminal, "Malformed source provenance carrier")
            continue
        size = int(match[1])
        if size + 1 != candidate.start() or data[size:size + 1] != b"\n":
            require(not terminal, "Source provenance byte boundary mismatch")
            continue
        require(candidate.end() + 1 == len(data) and data.endswith(b"\n"), "Source provenance must be terminal")
        require(len(match[2]) <= 256 * 1024 * 2, "Oversized source provenance payload")
        packet = base64.b64decode(match[2], validate=True)
        require(0 < len(packet) <= 256 * 1024, "Invalid source provenance payload size")
        require(base64.b64encode(packet) == match[2], "Noncanonical source provenance base64")
        data.decode("utf-8")
        require(b"\0" not in data, "Source provenance cannot contain NUL bytes")
        return data[:size], packet
    return data, None


def unwrap_source(data):
    return extract_source_carrier(data)[0]


def unwrap(data):
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        result, offset, found = bytearray(data[:8]), 8, False
        while offset < len(data):
            require(offset + 12 <= len(data), "Truncated PNG chunk")
            length = int.from_bytes(data[offset:offset + 4], "big")
            end = offset + length + 12
            require(end <= len(data), "Truncated PNG payload")
            kind, packet = data[offset + 4:offset + 8], data[offset + 8:end - 4]
            if kind == b"fvHl":
                require(not found and packet.startswith(MAGIC), "Invalid duplicate PNG carrier")
                require(zlib.crc32(data[offset + 4:end - 4]) == int.from_bytes(data[end - 4:end], "big"), "PNG carrier CRC mismatch")
                found = True
            else:
                result.extend(data[offset:end])
            offset = end
            if kind == b"IEND":
                result.extend(data[offset:])
                return bytes(result)
        raise ValueError("PNG IEND is absent")
    if data.startswith(b"\xff\xd8"):
        result, offset, count, next_index = bytearray(data[:2]), 2, None, 0
        while offset < len(data):
            start = offset
            require(data[offset] == 255, "Invalid JPEG marker")
            while data[offset] == 255:
                offset += 1
            marker = data[offset]
            offset += 1
            if marker in (0xDA, 0xD9):
                result.extend(data[start:])
                break
            if marker == 1:
                result.extend(data[start:offset])
                continue
            length = int.from_bytes(data[offset:offset + 2], "big")
            end = offset + length
            require(length >= 2 and end <= len(data), "Invalid JPEG segment")
            payload = data[offset + 2:end]
            if marker == 0xEF and payload.startswith(MAGIC):
                require(len(payload) >= 12, "Short JPEG carrier")
                index, fragments = struct.unpack(">HH", payload[8:12])
                require(index == next_index and 1 <= fragments <= 8 and count in (None, fragments), "Invalid JPEG carrier fragments")
                count, next_index = fragments, next_index + 1
            else:
                result.extend(data[start:end])
            offset = end
        require(count is None or count == next_index, "Incomplete JPEG carrier")
        return bytes(result)
    if data.startswith(b"PK"):
        for offset in range(len(data) - 22, max(-1, len(data) - 65558), -1):
            if data[offset:offset + 4] == b"PK\x05\x06" and offset + 22 + int.from_bytes(data[offset + 20:offset + 22], "little") == len(data):
                comment = data[offset + 22:]
                if comment.startswith(MAGIC):
                    require(len(comment) >= 10, "Short Office carrier")
                    length = int.from_bytes(comment[8:10], "little")
                    require(10 + length <= len(comment), "Invalid Office comment size")
                    return data[:offset + 20] + length.to_bytes(2, "little") + comment[10:10 + length]
                return data
        raise ValueError("Office EOCD is absent")
    if data.startswith(b"%PDF-"):
        match = re.search(rb"(?m)^startxref[\r\n ]+([0-9]+)[\r\n ]+%%EOF\s*\Z", data)
        require(match is not None, "PDF final startxref is absent")
        before = data[:match.start()]
        marker = b"\n%FVHERIT1-BEGIN\n"
        begin = before.rfind(marker)
        if begin >= 0:
            rest = before[begin + len(marker):]
            require(rest.endswith(b"%FVHERIT1-END\n"), "Invalid PDF carrier end")
            encoded = b"".join(line[2:] for line in rest[:-len(b"%FVHERIT1-END\n")].splitlines() if line.startswith(b"% "))
            base64.b64decode(encoded, validate=True)
            return data[:begin] + data[match.start():]
        return data
    if len(data) >= 12 and data[4:8] == b"ftyp":
        offset, carrier = 0, None
        while offset < len(data):
            require(offset + 8 <= len(data), "Short ISO media box")
            length = int.from_bytes(data[offset:offset + 4], "big")
            header = 8
            if length == 1:
                length, header = int.from_bytes(data[offset + 8:offset + 16], "big"), 16
            elif length == 0:
                length = len(data) - offset
            end = offset + length
            require(length >= header and end <= len(data), "Invalid ISO media box")
            if data[offset + 4:offset + 8] == b"uuid" and data[offset + header:offset + header + 16] == MEDIA_UUID:
                require(carrier is None and end == len(data) and data[offset + header + 16:offset + header + 24] == MAGIC, "Invalid terminal media carrier")
                carrier = offset
            offset = end
        return data[:carrier] if carrier is not None else data
    return unwrap_source(data)


def timestamp_epoch(openssl, directory):
    for arguments in (["ts", "-reply", "-in", "response.der", "-token_out", "-out", "token.der"],
                      ["cms", "-verify", "-inform", "DER", "-in", "token.der", "-binary", "-nosigs", "-noverify", "-out", "tstinfo.der"]):
        result = subprocess.run([openssl, *arguments], cwd=directory, capture_output=True, timeout=15)
        require(result.returncode == 0, "Timestamp content extraction failed")
    info = (directory / "tstinfo.der").read_bytes()
    require(len(info) <= 65536, "Timestamp content exceeds budget")

    def tlv(data, tag):
        require(len(data) >= 2 and data[0] == tag, "Invalid timestamp DER tag")
        length, header = data[1], 2
        if length >= 128:
            count = length & 127
            require(1 <= count <= 3 and len(data) >= 2 + count and data[2] != 0, "Invalid timestamp DER length")
            length, header = int.from_bytes(data[2:2 + count], "big"), 2 + count
            require(length >= 128, "Noncanonical timestamp DER length")
        require(header + length <= len(data), "Truncated timestamp DER")
        return data[header:header + length], data[header + length:]

    info, remainder = tlv(info, 0x30)
    require(not remainder, "Trailing timestamp content")
    version, info = tlv(info, 0x02)
    require(version == b"\x01", "Unknown timestamp content version")
    for tag in (0x06, 0x30, 0x02):
        _, info = tlv(info, tag)
    moment, _ = tlv(info, 0x18)
    text = moment.decode("ascii")
    require(re.fullmatch(r"[0-9]{14}(?:\.[0-9]{1,32})?Z", text), "Unsupported timestamp time")
    values = [int(text[start:end]) for start, end in ((0, 4), (4, 6), (6, 8), (8, 10), (10, 12), (12, 14))]
    return int(datetime.datetime(*values, tzinfo=datetime.timezone.utc).timestamp())


def verify(args):
    path = Path(args.evidence)
    require(path.stat().st_size <= 8 * 1024 * 1024, "Evidence exceeds byte budget")
    package = json.loads(path.read_bytes(), object_pairs_hook=unique_object)
    require(set(package) == {"body", "signature"}, "Unexpected evidence package fields")
    body = package["body"]
    require(set(body) == {"schema", "work_id", "copy_id", "records", "assets", "checkpoints", "timestamps"}, "Unexpected evidence body fields")
    require(body["schema"] == "fileveil.provenance.evidence.v1", "Unknown evidence schema")
    history = body["records"]
    require(0 < len(history) <= 256 and len(body["assets"]) <= 256 and len(body["checkpoints"]) <= 32 and len(body["timestamps"]) <= 8, "Evidence collection budget exceeded")
    for record in history:
        for key in ("copy_id", "rotation_to_key_id", "transformation"):
            if record["body"].get(key) is None:
                record["body"].pop(key, None)
    candidates = [args.openssl, "/opt/homebrew/opt/openssl@3/bin/openssl", "/usr/local/opt/openssl@3/bin/openssl", shutil.which("openssl")]
    openssl = next((str(candidate) for candidate in candidates if candidate and Path(candidate).is_file()), None)
    require(openssl is not None, "OpenSSL prerequisite unavailable")
    with tempfile.TemporaryDirectory(prefix="fileveil-public-evidence-") as name:
        directory = Path(name)
        envelope_signer = verify_signature(openssl, directory, b"FileVeil copyright evidence package v1\0", body, package["signature"])
        custodian, previous = None, None
        hashes = []
        for index, record in enumerate(history):
            require(set(record) == {"body", "signatures"}, "Unexpected record fields")
            statement = record["body"]
            validate_statement(statement)
            require(statement["schema"] in (V1, V2) and statement["algorithm"] == "Ed25519", "Unsupported signature protocol")
            require(statement["sequence"] == index and 0 < len(record["signatures"]) <= 32, "Invalid record sequence or signatures")
            domain = b"FileVeil provenance signature v2\0" if statement["schema"] == V2 else b"FileVeil Heritage signature v1\0"
            signers = [verify_signature(openssl, directory, domain, statement, entry) for entry in record["signatures"]]
            require(len(set(signers)) == len(signers) and statement["actor_key_id"] in signers, "Duplicate signer or missing custody actor")
            if previous is None:
                require(statement["kind"] == "create" and statement["previous_record_sha256"] is None and statement["parent_version"] is None, "Initial creation required")
            else:
                require(statement["work_id"] == previous["work_id"] and statement["actor_key_id"] == custodian and statement["previous_record_sha256"] == hashes[-1] and statement["kind"] != "create", "Custody/predecessor mismatch")
                require(not (previous["schema"] == V2 and statement["schema"] == V1), "Protocol downgrade")
                if statement["schema"] == V2 and previous["schema"] == V2 and statement["kind"] != "issue":
                    require(statement.get("copy_id") == previous.get("copy_id"), "Unexpected copy identifier transition")
                if statement["kind"] == "modify":
                    require(statement["version"] != previous["version"] and statement["parent_version"] == previous["version"], "Version parent mismatch")
                else:
                    require(all(statement[key] == previous[key] for key in ("version", "content_sha256", "parent_version", "author")), "Unmodified event changed asset/version")
                    require(statement["kind"] == "issue" or statement["edition"] == previous["edition"], "Unexpected edition transition")
            successor = statement.get("transfer_to_key_id") or statement.get("rotation_to_key_id")
            if statement["schema"] == V2:
                require(statement.get("copy_id"), "Version-two copy identifier required")
                require(not successor or successor in signers, "Successor acceptance signature required")
                if statement.get("transformation"):
                    require(previous is not None and statement["kind"] == "modify" and statement["transformation"]["source_sha256"] == previous["content_sha256"], "Transformation source mismatch")
            custodian = successor or statement["actor_key_id"]
            previous = statement
            hashes.append(record_hash(record))
        require(envelope_signer == custodian, "Evidence envelope lacks active custodian signature")
        require(body["work_id"] == previous["work_id"] and body["copy_id"] == previous.get("copy_id"), "Evidence work/copy mismatch")
        for asset in body["assets"]:
            require(any(r["body"]["version"] == asset["version"] and r["body"]["content_sha256"] == asset["sha256"] for r in history), "Unbound asset declaration")
        require(any(a["version"] == previous["version"] and a["sha256"] == previous["content_sha256"] for a in body["assets"]), "Current asset declaration absent")
        checkpoint_digests = []
        trusted_checkpoints = 0
        for checkpoint in body["checkpoints"]:
            entry = checkpoint["body"]
            require(entry["schema"] == "fileveil.provenance.checkpoint.v1", "Invalid checkpoint schema")
            signer = verify_signature(openssl, directory, b"FileVeil external chain checkpoint v1\0", entry, checkpoint["signature"])
            sequence = entry["sequence"]
            require(sequence < len(history) and hashes[sequence] == entry["record_sha256"] and entry["work_id"] == history[sequence]["body"]["work_id"] and entry["copy_id"] == history[sequence]["body"].get("copy_id") and entry["content_sha256"] == history[sequence]["body"]["content_sha256"], "Checkpoint detects a truncated or forked supplied history")
            trusted_checkpoints += checkpoint["signature"]["public_key_hex"] in args.checkpoint_key
            checkpoint_digests.append(sha(canonical(checkpoint)))
        verified_assets = 0
        for source in args.asset:
            file = Path(source)
            require(file.stat().st_size <= MAX_ASSET, "Asset exceeds byte budget")
            content = unwrap(file.read_bytes())
            require(any(a["sha256"] == sha(content) and a["size_bytes"] == len(content) for a in body["assets"]), "Provided asset hash/size differs from signed declaration")
            verified_assets += 1
        verified_timestamps = 0
        for attachment in body["timestamps"]:
            pools = {"record": hashes, "checkpoint": checkpoint_digests, "asset": [a["sha256"] for a in body["assets"]]}
            require(attachment["subject_sha256"] in pools[attachment["subject"]], "Unbound timestamp subject")
            response = base64.b64decode(attachment["response_der_base64"], validate=True)
            require(len(response) <= 1024 * 1024, "Timestamp exceeds byte budget")
            if args.tsa_roots:
                (directory / "response.der").write_bytes(response)
                root = Path(args.tsa_roots).resolve()
                require(root.stat().st_size <= 262144, "TSA roots exceed byte budget")
                epoch = timestamp_epoch(openssl, directory)
                query = subprocess.run([openssl, "ts", "-query", "-digest", attachment["subject_sha256"], "-sha256", "-no_nonce", "-cert", "-out", "oracle-query.der"], cwd=directory, capture_output=True, timeout=15)
                require(query.returncode == 0, "Timestamp reference query failed")
                result = subprocess.run([openssl, "ts", "-verify", "-in", "response.der", "-queryfile", "oracle-query.der", "-CAfile", str(root), "-attime", str(epoch)], cwd=directory, capture_output=True, timeout=15)
                require(result.returncode == 0, "RFC3161 TSA signature/imprint/trust failed")
                verified_timestamps += 1
    return {"package_signature": "valid", "chain": "valid", "record_count": len(history), "provided_assets_verified": verified_assets, "trusted_external_checkpoints": trusted_checkpoints, "trusted_timestamps": verified_timestamps, "copyright_identity": "not_assessed", "issuer_trust": "not_assessed", "scope": "Explicitly supplied assets, checkpoint keys and TSA roots. Unprovided historical assets and global history completeness retain separate evidence requirements."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence")
    parser.add_argument("--asset", action="append", default=[])
    parser.add_argument("--checkpoint-key", action="append", default=[])
    parser.add_argument("--tsa-roots")
    parser.add_argument("--openssl")
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args), ensure_ascii=False, sort_keys=True))
    except (ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"result": "failed", "reason": str(error)}), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()

# FVPROV1 23234 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJkZGI1MzdkNmMxZDcwMmQ5MzQxNTQ4ZmJjNWIyMjQ4MThhOTBlMWZiNmNiZTA5MTMyMjVjZGM2NjBiMDdhMzNkIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4zIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMyIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL3ZlcmlmeS1ldmlkZW5jZS5weSJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjQ3MTRmZjEzNjIzMDlhYmVmZjdjNmI3NWVhMDkzZjlkODQ4ZjQ3MTNmNGQ3ZjY0Zjk3MDk4MWE4YmJlZWIyNjQ5YmQwNDQwNWNkMDI4ZjEzMmM4MGNkNDgxNWEwYTc4MmQ4ZDlmN2I5YjlkNzgwMjc4ZjQ5ZTgyNjYxNTUzOTA5In1dfV0= FVPROV1-END
