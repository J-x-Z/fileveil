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

# FVPROV1 1369 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIxYjAwMzdmM2JkOGQwODljZGRkOGUxMDdhZjAwZTA2MmQxNmJlYmJmZWQ1YmEzNTRjZmQxNzVmM2E5YWJhMzVjIiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rlc3RzL3Rlc3Rfc291cmNlX3Byb3ZlbmFuY2UucHkifSwic2lnbmF0dXJlcyI6W3sia2V5X2lkIjoiOTllYTYzZWZjY2ZkMGZkYmQ2OGUxNmVkOGYwM2QzMzdmMTVlYzJlNGE2YTNkNjRlMTFkNzE0ZWExZTU0MjUzMyIsInB1YmxpY19rZXlfaGV4IjoiYWRiM2UxN2NkMTJmOTU2ZDAwNzBlMTY2M2Y1MzE1MzdmY2VkZjczMDhkMDE2NThmZWE0NTZmZWVhOGY3ZmJjNSIsInNpZ25hdHVyZV9oZXgiOiIzNjdmY2JmMmJlOTIwZjgyYTdkZDcyNDQzMGE3MmYxYjg1MGI2N2I5YzJhYjJmZjViMGIyZTNmZDNlMmY2NTg1NzVlZTA5ZmZhYjU5Y2RhY2U2ZDllMDMzOTg4ZTRiOWQ1YTUwM2RhOGRiODM0NzcxZTBkM2RmZGEzZWFlMjAwMyJ9XX1d FVPROV1-END
