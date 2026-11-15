#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Build the isolated multi-target project, leaving source and key files untouched."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parent
assert "FILEVEIL_SIGNING_KEY_BASE64" not in os.environ, "signing secret reached project build"
if (root / "fail-build").exists():
    sys.exit(7)
subprocess.run(["cmake", "-S", str(root), "-B", str(root / "build"), "-DCMAKE_BUILD_TYPE=Release"], check=True)
subprocess.run(["cmake", "--build", str(root / "build"), "--config", "Release", "--parallel", "2"], check=True)
if sys.platform == "darwin" and shutil.which("codesign"):
    for executable in ("fvpack", "fvchecksum"):
        subprocess.run(["codesign", "--force", "--sign", "-", str(root / "dist" / executable)], check=True)
(root / "build-observation.json").write_text(json.dumps({"secret_present": False, "targets": ["fvcodec", "fvpack", "fvchecksum"]}))
