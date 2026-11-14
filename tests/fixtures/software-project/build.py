#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Small native CMake project used by the actual reusable-workflow acceptance."""
from pathlib import Path
import subprocess
import shutil

ROOT = Path(__file__).resolve().parent
subprocess.run(["cmake", "-S", str(ROOT), "-B", str(ROOT / "build"), "-DCMAKE_BUILD_TYPE=Release"], check=True)
subprocess.run(["cmake", "--build", str(ROOT / "build"), "--config", "Release", "--parallel", "2"], check=True)

shutil.copyfile(ROOT / "asset.png", ROOT / "dist/asset.png")
