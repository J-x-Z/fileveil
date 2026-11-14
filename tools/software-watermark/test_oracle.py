#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
import oracle


class OracleTests(unittest.TestCase):
    def test_crt_recovers_full_64_bit_witness(self):
        for value in (0, 1, 0x123456789ABCDEF, (1 << 64) - 1):
            self.assertEqual(oracle.crt([value % prime for prime in oracle.PRIMES]), value)

    def test_wrong_residue_is_not_the_witness(self):
        value = 0x123456789ABCDEF
        residues = [value % prime for prime in oracle.PRIMES]
        residues[0] = (residues[0] + 1) % oracle.PRIMES[0]
        self.assertNotEqual(oracle.crt(residues), value)

    def test_invalid_residue_fails(self):
        with self.assertRaises(ValueError):
            oracle.crt([251] + [0] * 8)

    def test_parser_rejects_truncated_inputs(self):
        for data in (b"", b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe"):
            with self.subTest(data=data), self.assertRaises((ValueError, IndexError)):
                oracle.sections(data)

    def test_parser_rejects_out_of_bounds_coff_section(self):
        header = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0, 0)
        section = b".fvwm\0\0\0" + struct.pack("<IIIIIIHHI", 0, 0, 100, 1000, 0, 0, 0, 0, 0)
        with self.assertRaises(ValueError):
            oracle.sections(header + section)

    def test_carrier_checksum_and_bounds(self):
        raw = b"independent bounded packet"
        shares = bytes(value for index, byte in enumerate(raw) for value in (index, byte ^ index))
        carrier = b"FVSWM01\0" + struct.pack("<IIQII", 1, len(raw), 9, 1, 9) + hashlib.sha256(raw).digest() + shares
        header = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0, 0)
        section = b".fvwm\0\0\0" + struct.pack("<IIIIIIHHI", 0, 0, len(carrier), 60, 0, 0, 0, 0, 0)
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "own.obj"
            artifact.write_bytes(header + section + carrier)
            result = oracle.inspect(artifact)
            self.assertTrue(result["carrier_present"])
            self.assertFalse(result["runtime_assessed"])
            self.assertEqual(result["packet_hex"], raw.hex())
            tampered = bytearray(artifact.read_bytes())
            tampered[-1] ^= 1
            artifact.write_bytes(tampered)
            with self.assertRaisesRegex(ValueError, "checksum"):
                oracle.inspect(artifact)


if __name__ == "__main__":
    unittest.main()
