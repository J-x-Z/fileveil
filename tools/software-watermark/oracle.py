#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Independent, stdlib-only section and CRT oracle for controlled test artifacts."""

import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import struct


MAX_FILE = 512 * 1024 * 1024
PRIMES = (251, 241, 239, 233, 229, 227, 223, 211, 199)


def bounded(data, offset, size):
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise ValueError("section or header exceeds file bounds")
    return data[offset:offset + size]


def unpack(data, offset, fmt):
    return struct.unpack(fmt, bounded(data, offset, struct.calcsize(fmt)))


def name(data):
    return data.split(b"\0", 1)[0].decode("ascii", errors="replace")


def sections(data):
    """Parse tables independently of LLVM and the Rust goblin backend."""
    result = []
    if data[:4] == b"\x7fELF":
        if data[4] not in (1, 2) or data[5] not in (1, 2):
            raise ValueError("unsupported ELF class or byte order")
        wide = data[4] == 2
        order = "<" if data[5] == 1 else ">"
        offset = unpack(data, 40 if wide else 32, order + ("Q" if wide else "I"))[0]
        size, count, strings = unpack(data, 58 if wide else 46, order + "HHH")
        fmt = order + ("IIQQQQIIQQ" if wide else "IIIIIIIIII")
        if count == 0 or count > 8192 or strings >= count or size < struct.calcsize(fmt):
            raise ValueError("unsupported or excessive ELF section table")
        table = [unpack(data, offset + i * size, fmt) for i in range(count)]
        string_data = bounded(data, table[strings][4], table[strings][5])
        for entry in table:
            label = name(bounded(string_data, entry[0], len(string_data) - entry[0]))
            if entry[1] != 8:  # SHT_NOBITS has no file payload.
                result.append((label, entry[4], entry[5]))
        kind = "elf"
    elif data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        wide = data[0] == 0xCF
        count, commands_size = unpack(data, 16, "<II")
        if count > 8192:
            raise ValueError("excessive Mach-O load commands")
        position = 32 if wide else 28
        commands_end = position + commands_size
        bounded(data, position, commands_size)
        for _ in range(count):
            command, size = unpack(data, position, "<II")
            if size < 8 or position + size > commands_end:
                raise ValueError("invalid Mach-O load command")
            if command in (1, 0x19):
                section_count = unpack(data, position + (64 if command == 0x19 else 48), "<I")[0]
                section_size = 80 if command == 0x19 else 68
                section_start = position + (72 if command == 0x19 else 56)
                if section_count > 8192 or section_start + section_count * section_size > position + size:
                    raise ValueError("invalid Mach-O section table")
                for i in range(section_count):
                    base = section_start + i * section_size
                    section_name = name(bounded(data, base, 16))
                    segment_name = name(bounded(data, base + 16, 16))
                    length, file_offset = unpack(data, base + (40 if command == 0x19 else 36), "<QI" if command == 0x19 else "<II")
                    flags = unpack(data, base + (64 if command == 0x19 else 56), "<I")[0]
                    if flags & 0xFF not in (1, 0xC, 0x12):
                        result.append((segment_name + "," + section_name, file_offset, length))
            position += size
        kind = "mach_o"
    else:
        if data[:2] == b"MZ":
            header = unpack(data, 60, "<I")[0]
            if bounded(data, header, 4) != b"PE\0\0":
                raise ValueError("invalid PE header")
            header += 4
            kind = "pe"
        else:
            header = 0
            machine = unpack(data, 0, "<H")[0]
            if machine not in (0x14C, 0x8664, 0xAA64):
                raise ValueError("unsupported object format")
            kind = "coff"
        _, count, _, symbol_offset, symbol_count, optional_size, _ = unpack(data, header, "<HHIIIHH")
        if count > 8192:
            raise ValueError("excessive PE/COFF section count")
        string_offset = symbol_offset + symbol_count * 18
        for i in range(count):
            base = header + 20 + optional_size + i * 40
            label = name(bounded(data, base, 8))
            if label.startswith("/") and label[1:].isdigit() and symbol_offset:
                offset = string_offset + int(label[1:])
                label = name(bounded(data, offset, min(256, len(data) - offset)))
            length, file_offset = unpack(data, base + 16, "<II")
            if file_offset:
                result.append((label, file_offset, length))
    for _, offset, length in result:
        bounded(data, offset, length)
    return kind, result


def crt(residues, primes=PRIMES):
    value, modulus = 0, 1
    for residue, prime in zip(residues, primes, strict=True):
        if not 0 <= residue < prime:
            raise ValueError("residue exceeds its modulus")
        value += ((residue - value) * pow(modulus, -1, prime) % prime) * modulus
        modulus *= prime
    return value


def inspect(path):
    if path.stat().st_size > MAX_FILE:
        raise ValueError("oracle input exceeds 512 MiB")
    with path.open("rb") as stream:
        data = stream.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise ValueError("oracle input exceeds 512 MiB")
    kind, table = sections(data)
    result = {"schema": "fileveil.software.independent-oracle.v1", "format": kind,
              "sha256": hashlib.sha256(data).hexdigest(), "carrier_present": False,
              "descriptor_present": False, "runtime_assessed": False,
              "sections": [{"name": label, "offset": offset, "size": size}
                           for label, offset, size in table if "fv" in label]}
    for label, offset, size in table:
        content = bounded(data, offset, size)
        if label in (".fvwm", "__DATA_CONST,__fvwm") and content[:8] == b"FVSWM01\0":
            version, length, witness, encoding, count = unpack(content, 8, "<IIQII")
            if version != 1 or encoding != 1 or count != 9 or not 0 < length <= 32768:
                raise ValueError("invalid carrier header")
            body = bounded(content, 64, length * 2)
            packet = bytes(body[i] ^ body[i + 1] for i in range(0, len(body), 2))
            digest = hashlib.sha256(packet).digest()
            if digest != bounded(content, 32, 32):
                raise ValueError("carrier packet checksum mismatch")
            if result["carrier_present"]:
                raise ValueError("multiple carriers require separate module attribution")
            result.update(carrier_present=True, packet_hex=packet.hex(), packet_sha256=digest.hex(),
                          witness_hex=f"{witness:016x}")
        if label in (".fvcalc", "__DATA_CONST,__fvcalc") and content[:8] == b"FVSWD01\0":
            version, count, seed = unpack(content, 8, "<IIQ")
            records = [unpack(content, 24 + i * 12, "<III") for i in range(count)] if count == 9 else []
            if version != 1 or tuple(row[0] for row in records) != PRIMES:
                raise ValueError("invalid semantic descriptor")
            if any(not 1 <= a < p or b >= p for p, a, b in records):
                raise ValueError("invalid descriptor factors")
            result.update(descriptor_present=True, descriptor_seed_hex=f"{seed:016x}",
                          descriptor_records=records)
    return result


def probe(path, challenge, expected):
    """Execute only an explicitly supplied controlled test library."""
    library = ctypes.CDLL(str(path.resolve()))
    function = library.fileveil_swm_probe_v1
    function.argtypes = (ctypes.c_uint32, ctypes.c_uint64)
    function.restype = ctypes.c_uint32
    residues = [int(function(index, challenge)) for index in range(9)]
    if function(9, challenge) != 0xFFFFFFFF:
        raise ValueError("probe index guard failed")
    recovered = crt(residues)
    return {"runtime_assessed": True, "runtime_residues": residues,
            "runtime_recovered_hex": f"{recovered:x}", "runtime_witness_matches": recovered == expected}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--execute-controlled-library", action="store_true")
    parser.add_argument("--challenge-hex", default="0000000000000000")
    parser.add_argument("--expected-witness-hex")
    args = parser.parse_args()
    result = inspect(args.artifact)
    if args.execute_controlled_library:
        witness = args.expected_witness_hex or result.get("witness_hex")
        if witness is None:
            parser.error("an expected witness is required without a carrier")
        result.update(probe(args.artifact, int(args.challenge_hex, 16), int(witness, 16)))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

# FVPROV1 9111 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiJlMWVhZjk5NDBkOTY3NmVjNWM5MDQ2MjJmNWUxZTdkZjE3YzZkNGE2NjRkMmZkZjk3MzgxYmI1NDllMjliMzM1IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL3NvZnR3YXJlLXdhdGVybWFyay9vcmFjbGUucHkifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiIwYzI5M2M3YmFmY2RlMDVjNDViNTQ2OWY4MGY4N2M4NDVhNzM1NGY2NjBjMjlhYzJmMzkxMGVhODljN2RjNzMyYzY4NzNjZTE1YzRjNGMwYmQ5NzQ2YzExMDZkMjZmZTZmMTc3ZGM0NTBkYjJiYjdhOGM3N2Q3OTUxYjNjMDMwZiJ9XX1d FVPROV1-END
