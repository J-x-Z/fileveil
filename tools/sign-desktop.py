#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Audit desktop signatures, or sign with an explicitly selected local identity."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


DEVELOPER_ID = "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"


def run(arguments, *, required=True, timeout=120):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout)
    if required and result.returncode:
        raise ValueError(f"{Path(arguments[0]).name} failed with exit code {result.returncode}")
    return result


def fingerprint(value):
    if not re.fullmatch(r"[A-Fa-f0-9]{40}", value):
        raise argparse.ArgumentTypeError("Use the 40-digit local signing certificate thumbprint")
    return value.upper()


def powershell(script):
    executable = shutil.which("pwsh") or shutil.which("powershell")
    if executable is None:
        raise ValueError("PowerShell is required to inspect Authenticode")
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return run([executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded])


def macos(path, identity, profile):
    if identity:
        identities = run(["security", "find-identity", "-v", "-p", "codesigning"]).stdout
        if not any(identity in line.upper() and "Developer ID Application:" in line for line in identities.splitlines()):
            raise ValueError("Selected Developer ID Application identity is unavailable")
        nested = []
        if path.suffix == ".app":
            nested = list((path / "Contents/MacOS").glob("*"))
            nested += list((path / "Contents/Resources/backends").glob("*"))
        for binary in sorted(nested):
            if binary.is_symlink() or not binary.is_file():
                raise ValueError("App signing inputs must be regular files")
            run(["codesign", "--force", "--sign", identity, "--options", "runtime", "--timestamp", str(binary)])
        run(["codesign", "--force", "--sign", identity, "--options", "runtime", "--timestamp", str(path)])
        run(["codesign", "--verify", "--strict", "--deep", "-R", DEVELOPER_ID, str(path)])
    if profile:
        trusted = run(["codesign", "--verify", "--strict", "-R", DEVELOPER_ID, str(path)], required=False)
        if trusted.returncode:
            raise ValueError("Notarization requires a Developer ID signed artifact")
        # Profile credentials remain in the selected local keychain. Upload is
        # enabled only by the explicit --notary-profile command line option.
        with tempfile.TemporaryDirectory(prefix=".fileveil-notary-", dir=path.parent) as temporary:
            submission = path
            if path.suffix == ".app":
                submission = Path(temporary) / "upload.zip"
                run(["ditto", "-c", "-k", "--keepParent", str(path), str(submission)])
            response = run(["xcrun", "notarytool", "submit", str(submission), "--keychain-profile", profile, "--wait", "--output-format", "json"], timeout=1800)
            if json.loads(response.stdout).get("status") != "Accepted":
                raise ValueError("Apple notarization did not accept the artifact")
            run(["xcrun", "stapler", "staple", str(path)])
    signature = run(["codesign", "--verify", "--strict", "--deep", str(path)], required=False)
    developer = run(["codesign", "--verify", "--strict", "-R", DEVELOPER_ID, str(path)], required=False)
    ticket = run(["xcrun", "stapler", "validate", str(path)], required=False)
    kind = "open" if path.suffix == ".dmg" else "execute"
    assessment = ["spctl", "--assess", "--type", kind, "--verbose=2"]
    if path.suffix == ".dmg":
        assessment += ["--context", "context:primary-signature"]
    gatekeeper = run([*assessment, str(path)], required=False)
    return {
        "signature_valid": signature.returncode == 0,
        "developer_id": developer.returncode == 0,
        "notarization_ticket": ticket.returncode == 0,
        "gatekeeper_accepted": gatekeeper.returncode == 0,
        "signed_this_run": bool(identity),
    }


def windows(path, identity):
    if identity:
        executable = shutil.which("signtool") or os.environ.get("FILEVEIL_SIGNTOOL")
        if not executable:
            raise ValueError("signtool is unavailable. Set FILEVEIL_SIGNTOOL to the Windows SDK tool")
        run([executable, "sign", "/sha1", identity, "/s", "My", "/fd", "SHA256", "/tr", "https://timestamp.digicert.com", "/td", "SHA256", str(path)])
        run([executable, "verify", "/pa", "/all", "/v", str(path)])
    literal = "'" + str(path).replace("'", "''") + "'"
    result = powershell(
        "$ErrorActionPreference='Stop'; "
        f"$s=Get-AuthenticodeSignature -LiteralPath {literal}; "
        "@{status=$s.Status.ToString();timestamped=($null -ne $s.TimeStamperCertificate)}|ConvertTo-Json -Compress"
    )
    report = json.loads(result.stdout)
    if identity and (report["status"] != "Valid" or not report["timestamped"]):
        raise ValueError("Authenticode signature and timestamp verification failed")
    return {"authenticode_status": report["status"], "timestamped": report["timestamped"], "signed_this_run": bool(identity)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--identity", type=fingerprint, help="macOS Developer ID SHA-1 or Windows current-user certificate thumbprint")
    parser.add_argument("--notary-profile", help="Explicitly upload to Apple using an existing notarytool keychain profile")
    parser.add_argument("--report", type=Path, help="New JSON receipt path")
    args = parser.parse_args()
    path = args.path.absolute()
    if path.is_symlink() or not path.exists():
        raise ValueError("Signing input must exist and must not be a symlink")
    if args.report and (args.report.exists() or args.report.is_symlink()):
        raise ValueError("Report destination already exists")
    if sys.platform == "darwin" and path.suffix in (".app", ".dmg"):
        report = macos(path, args.identity, args.notary_profile)
    elif sys.platform == "win32" and path.is_file() and path.suffix.lower() == ".exe":
        if args.notary_profile:
            raise ValueError("Apple notarization applies to macOS packages")
        report = windows(path, args.identity)
    else:
        raise ValueError("Use a macOS app/DMG on macOS or an EXE on Windows")
    report.update({"schema": "fileveil.desktop-signature.v1", "artifact": path.name, "platform": sys.platform})
    if path.is_file():
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        report["sha256"] = digest.hexdigest()
    encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.report:
        with args.report.open("x", encoding="utf-8") as stream:
            stream.write(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(f"Desktop signing failed. {error}") from None

# FVPROV1 7407 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI5MDU4YWFhOWRiYTU2MmVhMzc4NGQzN2Q4MGY5MjBkMThiN2FlOWY0MzQ0Y2NjY2U5NWY3MDYzNDZkNDZjNTFmIiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS40IiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuNCIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rvb2xzL3NpZ24tZGVza3RvcC5weSJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6ImUwMzU3ODcyNjFjNjIyNTk1YWE0ZjA0N2VhM2RhNjg4MzI4NWJhNzM5ZTMwMmMzZTlmYzBhNTA1ZWNiZmE3NmQ2NDk2NWVkYjY0YjQ0MDkxYmFlZDZjYmEzYWZlYmY4ODA4M2ZlM2VhODY2MmQ3OTg2ZDMwZTFmZGVkN2JlMjAwIn1dfV0= FVPROV1-END
