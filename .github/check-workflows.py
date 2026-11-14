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
                "required": ["runs-on", "timeout-minutes", "steps"],
                "properties": {
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
    assert ci["on"]["push"]["branches"] == ["main"]
    assert ci["on"]["push"]["tags"] == ["v*"]
    assert ci["jobs"]["core"]["runs-on"] == "ubuntu-latest"
    assert ci["jobs"]["core"]["if"] == (
        "github.event_name != 'workflow_dispatch' && "
        "!startsWith(github.ref, 'refs/tags/')"
    )
    assert ci["jobs"]["check"]["if"] == (
        "github.event_name == 'workflow_dispatch' || "
        "startsWith(github.ref, 'refs/tags/v')"
    )
    assert ci["jobs"]["check"]["strategy"]["matrix"]["os"] == [
        "ubuntu-latest", "macos-latest", "windows-latest"
    ]
    security = workflows["security.yml"]
    assert set(security["on"]) == {"workflow_dispatch", "push", "schedule"}
    assert security["on"]["push"]["branches"] == ["main"]
    assert security["concurrency"]["cancel-in-progress"] == "true"
    print(f"Validated {len(workflows)} workflows and bounded CI policy")


if __name__ == "__main__":
    main()

# FVPROV1 3971 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiIyY2JmMjBlOThlZjAyODFhMjllYTVjMWU4YTQxMDRlMmFmOGQzNjMwZDczNzcxMDU3MDNhNTA5MzVkYjlmMDg1IiwiY29weV9pZCI6InYwLjUuMC1hbHBoYS4yIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC41LjAtYWxwaGEuMiIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlLy5naXRodWIvY2hlY2std29ya2Zsb3dzLnB5In0sInNpZ25hdHVyZXMiOlt7ImtleV9pZCI6Ijk5ZWE2M2VmY2NmZDBmZGJkNjhlMTZlZDhmMDNkMzM3ZjE1ZWMyZTRhNmEzZDY0ZTExZDcxNGVhMWU1NDI1MzMiLCJwdWJsaWNfa2V5X2hleCI6ImFkYjNlMTdjZDEyZjk1NmQwMDcwZTE2NjNmNTMxNTM3ZmNlZGY3MzA4ZDAxNjU4ZmVhNDU2ZmVlYThmN2ZiYzUiLCJzaWduYXR1cmVfaGV4IjoiMzQxMjhhNzY5ZmJhZDQxYTFjNmY0NzgzMzczODRkZjViNjU5YjdlNGZmMDdjZDU2OGVkMzY0MWFhNTQ2ZDEyZDk1YzZkZWJhYjBlNmMwYjY2ZmE3ZTllYzkwMjVkMzJhNmJmYTBjMmM5YjM0NjVlYTZhNDU1MDA4MzUwNWU1MDkifV19XQ== FVPROV1-END
