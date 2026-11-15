#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Validate workflow structure and the project's bounded CI trigger policy."""

from pathlib import Path

import yaml
from jsonschema import Draft202012Validator


SCHEMA = {
    "type": "object",
    "required": ["name", "on", "permissions", "concurrency", "jobs"],
    "properties": {
        "name": {"type": "string", "minLength": 1},
        "on": {"type": "object", "minProperties": 1},
        "permissions": {"type": "object"},
        "env": {"type": "object"},
        "concurrency": {
            "type": "object",
            "required": ["group", "cancel-in-progress"],
            "properties": {
                "group": {"type": "string", "minLength": 1},
                "cancel-in-progress": {"type": ["string", "boolean"]},
            },
        },
        "jobs": {
            "type": "object",
            "minProperties": 1,
            "additionalProperties": {
                "type": "object",
                "oneOf": [
                    {"required": ["runs-on", "timeout-minutes", "steps"]},
                    {"required": ["uses"], "not": {"anyOf": [
                        {"required": ["runs-on"]}, {"required": ["steps"]},
                        {"required": ["timeout-minutes"]}
                    ]}},
                ],
                "properties": {
                    "uses": {"type": "string", "minLength": 1},
                    "runs-on": {"type": "string"},
                    "if": {"type": "string"},
                    "steps": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "type": "object",
                            "oneOf": [
                                {"required": ["uses"]},
                                {"required": ["run"]},
                            ],
                            "properties": {
                                "uses": {"type": "string", "minLength": 1},
                                "run": {"type": "string", "minLength": 1},
                                "with": {"type": "object"},
                            },
                        },
                    },
                },
            },
        },
    },
}


def main():
    directory = Path(__file__).resolve().parent / "workflows"
    workflows = {}
    validator = Draft202012Validator(SCHEMA)
    for path in sorted(directory.glob("*.yml")):
        # BaseLoader preserves YAML 1.2's `on` key instead of converting it to
        # YAML 1.1's boolean. Scalar policy values are checked explicitly below.
        workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        validator.validate(workflow)
        workflows[path.name] = workflow
        for job in workflow["jobs"].values():
            if "uses" in job:
                assert job["uses"].startswith("./.github/workflows/") or "@" in job["uses"]
                continue
            assert 0 < int(job["timeout-minutes"]) <= 90
            for step in job["steps"]:
                settings = step.get("with", {})
                action = step.get("uses", "")
                if action.startswith("actions/upload-artifact@"):
                    assert 0 < int(settings["retention-days"]) <= 14
                if action.startswith("actions/cache/"):
                    assert "github.sha" not in settings["key"]
                    assert "target" not in settings["path"].splitlines()

    ci = workflows["ci.yml"]
    assert ci["jobs"]["project-copyright"]["permissions"]["actions"] == "read"
    assert ci["on"]["push"]["branches"] == ["main"]
    assert ci["on"]["push"]["tags"] == ["v*"]
    assert ci["jobs"]["core"]["runs-on"] == "ubuntu-latest"
    assert ci["jobs"]["core"]["if"] == (
        "github.event_name != 'workflow_dispatch' && "
        "!startsWith(github.ref, 'refs/tags/')"
    )
    assert ci["jobs"]["check"]["if"] == (
        "(github.event_name == 'workflow_dispatch' && inputs.native-checks) || "
        "startsWith(github.ref, 'refs/tags/v')"
    )
    platforms = ["all", "ubuntu-latest", "macos-latest", "windows-latest"]
    assert ci["on"]["workflow_dispatch"]["inputs"]["platform"]["options"] == platforms
    for job in ("check", "project-copyright"):
        matrix = ci["jobs"][job]["strategy"]["matrix"]["os"]
        assert matrix.startswith("${{ fromJSON(inputs.platform ==")
        assert all(platform in matrix for platform in platforms[1:])
    assert ci["on"]["workflow_dispatch"]["inputs"]["native-checks"]["default"] == "true"
    native_steps = ci["jobs"]["check"]["steps"]
    source_check = next(step for step in native_steps if step.get("name") == "Verify signed source distribution")
    assert source_check["if"] == "hashFiles('provenance/source-catalog.toml') != ''"
    native_names = [step.get("name", "") for step in native_steps]
    assert (native_names.index("Package desktop application")
            < native_names.index("Independently verify packaged source bytes")
            < native_names.index("Build native installer"))
    security = workflows["security.yml"]
    assert set(security["on"]) == {"workflow_dispatch", "push", "schedule"}
    assert security["on"]["push"]["branches"] == ["main"]
    assert security["concurrency"]["cancel-in-progress"] == "true"
    print(f"Validated {len(workflows)} workflows and bounded CI policy")


if __name__ == "__main__":
    main()

# FVPROV1 5443 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI4MmY4Zjk2NDMwYzA2YWQzNGNhZGZlNTc5MDU3ZTAyYzc1MzE2MzdiZjJkNDA2YzRkNjMxMTIwYTNjZDNkMGY0IiwiY29weV9pZCI6InYwLjcuMC1iZXRhLjEiLCJjcmVhdGVkX2F0IjoiMjAyNi0xMS0xNSIsImVkaXRpb24iOiJiZXRhIiwiaXNzdWVyX3BvbGljeSI6bnVsbCwia2luZCI6ImNyZWF0ZSIsIm1vZGUiOiJzZWxmX3NpZ24iLCJwYXJlbnRfdmVyc2lvbiI6bnVsbCwicHJldmlvdXNfcmVjb3JkX3NoYTI1NiI6bnVsbCwic2NoZW1hIjoiZmlsZXZlaWwucHJvdmVuYW5jZS5zaWduYXR1cmUudjIiLCJzZXF1ZW5jZSI6MCwidHJhbnNmZXJfdG9fa2V5X2lkIjpudWxsLCJ2ZXJzaW9uIjoidjAuNy4wLWJldGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlLy5naXRodWIvY2hlY2std29ya2Zsb3dzLnB5In0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiYjA3MjVhZmMxODI5YjU4N2YwZTNkYzczOGNmNDMzMzU0OGNmOTc4ODZkY2QwZTM2MzM0ZDk0NjJiOTVmNjI1NDRjMzUxNjg1NWM1MDJkN2VjYWE1NzVhZTE1NjNlNWJiODNjNzBiYzg3MmVlZmRmYTMzZGFjMDVmODZkMzM0MDUifV19XQ== FVPROV1-END
