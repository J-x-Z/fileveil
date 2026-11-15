#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Independent source-carrier boundary checks for the public evidence verifier."""
import base64
from pathlib import Path
import runpy
import unittest


VERIFY = runpy.run_path(str(Path(__file__).resolve().parents[1] / "tools/verify-evidence.py"))


class SourceProvenanceTests(unittest.TestCase):
    def marked(self, source, prefix=b"// "):
        return source + b"\n" + prefix + b"FVPROV1 " + str(len(source)).encode() + b" " + base64.b64encode(b"[]") + b" FVPROV1-END\n"

    def test_source_comments_restore_every_original_byte(self):
        for prefix in (b"// ", b"# ", b"-- ", b"; "):
            source = b"content\r\nwithout trailing newline"
            self.assertEqual(VERIFY["unwrap"](self.marked(source, prefix)), source)

    def test_malformed_or_nonterminal_comments_fail(self):
        marked = self.marked(b"fn main() {}\n")
        for changed in (marked + b"\n", marked + b"fn injected() {}\n", marked[:-1], marked.replace(b"W10=", b"!!!!")):
            with self.assertRaises(ValueError):
                VERIFY["unwrap"](changed)

    def test_string_literal_examples_preserve_source(self):
        source = b'const EXAMPLE: &str = r#"\n// FVPROV1 0 W10= FVPROV1-END\n"#;\n'
        self.assertEqual(VERIFY["unwrap"](source), source)


if __name__ == "__main__":
    unittest.main()

# FVPROV1 1369 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIxYjAwMzdmM2JkOGQwODljZGRkOGUxMDdhZjAwZTA2MmQxNmJlYmJmZWQ1YmEzNTRjZmQxNzVmM2E5YWJhMzVjIiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rlc3RzL3Rlc3Rfc291cmNlX3Byb3ZlbmFuY2UucHkifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiI2MWVjNTYxZWFiZjI3ZGMxNWZiYzM4OTIxNTg3ZjJiMDA4NmZiNDQ0Y2YzYWJhMzhkNmYxODVlMjQxNDUxN2U3NTRjMDMwYzlhN2UzZjc5NjZiNTE5ZjkxMTE3MGU0M2Q0ZmUyNDAxZThhMDgxNTA2NGU3NWZmNjIyZTY0NzgwNCJ9XX1d FVPROV1-END
