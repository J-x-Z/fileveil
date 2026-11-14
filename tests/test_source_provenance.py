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
