# SPDX-License-Identifier: MPL-2.0
"""Focused installer identity, dependency and non-destructive upgrade regressions."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "tools/build-installers.py"
SPEC = importlib.util.spec_from_file_location("fileveil_installers", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
installers = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installers)


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="fileveil-installer-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.package = self.root / "package"
        self.package.mkdir()
        self.manifest = {
            "bundle_id": "com.fileveil.desktop", "version": "0.5.0-alpha.2", "platform": "linux",
            "executable": "fileveil-gui", "cli_executable": "fileveil",
        }
        for filename, field in (("fileveil-gui", "sha256"), ("fileveil", "cli_sha256")):
            data = f"synthetic {filename}\n".encode()
            (self.package / filename).write_bytes(data)
            self.manifest[field] = hashlib.sha256(data).hexdigest()
        self.save_manifest()

    def save_manifest(self):
        (self.package / "fileveil-package.json").write_text(json.dumps(self.manifest), encoding="utf-8")

    def test_version_formats_preserve_prerelease_ordering(self):
        self.assertEqual(installers.debian_version("0.5.0-alpha.2"), "0.5.0~alpha.2")
        self.assertEqual(installers.windows_version("0.5.0-alpha.2"), "0.5.0.2")
        self.assertEqual(installers.windows_version("0.5.0"), "0.5.0.0")
        for value in ("../../other", "1.2.3\nAppId=other", "1.2", "1.2.3+illegal"):
            with self.subTest(value=value), self.assertRaises(installers.InstallerError):
                installers.debian_version(value)

    def test_package_requires_matching_identity_version_platform_and_hashes(self):
        installers.validate_package(self.package, "0.5.0-alpha.2", "linux")
        for field, value in (("bundle_id", "other"), ("version", "0.1.0"), ("platform", "windows"),
                             ("sha256", "0" * 64), ("executable", "../elsewhere")):
            with self.subTest(field=field):
                previous = self.manifest[field]
                self.manifest[field] = value
                self.save_manifest()
                with self.assertRaises(installers.InstallerError):
                    installers.validate_package(self.package, "0.5.0-alpha.2", "linux")
                self.manifest[field] = previous
        self.save_manifest()

    def test_portable_symlink_payload_is_rejected(self):
        link = self.package / "external"
        try:
            link.symlink_to(self.root)
        except OSError:
            self.skipTest("Host does not allow unprivileged symlink creation")
        with self.assertRaisesRegex(installers.InstallerError, "symbolic"):
            installers.validate_package(self.package, "0.5.0-alpha.2", "linux")

    def test_macos_identity_checked_before_code_signature(self):
        contents = self.package / "Contents"
        contents.mkdir()
        with (contents / "Info.plist").open("wb") as stream:
            plistlib.dump({"CFBundleIdentifier": "other", "CFBundleShortVersionString": "0.5.0-alpha.2"}, stream)
        with mock.patch.object(installers, "run") as command:
            with self.assertRaises(installers.InstallerError):
                installers.validate_package(self.package, "0.5.0-alpha.2", "macos")
            command.assert_not_called()

    def test_inno_is_per_user_and_requires_explicit_replacement(self):
        text = installers.inno_script(self.package, self.root, "0.5.0-alpha.2")
        for expected in (
            "PrivilegesRequired=lowest", "AppId=FileVeil.Desktop", "VersionInfoVersion=0.5.0.2",
            "DefaultDirName={localappdata}\\Programs\\FileVeil", "CloseApplications=no",
            "'/FILEVEILUPGRADE=1'", "not WizardSilent", "ContainsRedirectedDirectory(Path)",
            "The destination already exists without a valid FileVeil identity",
        ):
            self.assertIn(expected, text)
        self.assertNotIn("[Run]", text)
        self.assertNotIn("[UninstallDelete]", text)
        self.assertNotIn("PrivilegesRequiredOverridesAllowed", text)

    def test_inno_rejects_path_directive_injection(self):
        for path in (self.root / 'bad"path', self.root / "bad\npath"):
            with self.assertRaises(installers.InstallerError):
                installers.inno_script(path, self.root, "0.5.0-alpha.2")

    def test_installer_source_payload_keeps_chinese_readme(self):
        spec = importlib.util.spec_from_file_location("installer_source_package", SCRIPT.with_name("package-desktop.py"))
        packager = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(packager)
        (self.root / "LICENSE").write_text("MPL-2.0\n")
        contents = "# FileVeil\n中文说明\n".encode()
        (self.root / "README.zh-CN.md").write_bytes(contents)
        destination = self.root / "payload"
        with mock.patch.object(packager, "ROOT", self.root), mock.patch.object(packager.subprocess, "run", side_effect=FileNotFoundError):
            packager.copy_resources(destination)
        with zipfile.ZipFile(destination / "FileVeil-source.zip") as archive:
            self.assertEqual(archive.read("README.zh-CN.md"), contents)

    def test_macos_numeric_versions_preserve_prerelease_and_upgrade_order(self):
        spec = importlib.util.spec_from_file_location("installer_numeric_version", SCRIPT.with_name("package-desktop.py"))
        packager = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(packager)
        releases = ["0.5.0-alpha.1", "0.5.0-alpha.2", "0.5.0-alpha.24", "0.5.0-beta.1",
                    "0.5.0-beta.24", "0.5.0-rc.1", "0.5.0-rc.24", "0.5.0", "0.5.1-alpha.1",
                    "0.6.0-alpha.1", "1.0.0-alpha.1"]
        builds = []
        for release in releases:
            short, build = packager.macos_bundle_versions(release)
            self.assertEqual(short, release.split("-", 1)[0])
            builds.append(tuple(int(value) for value in build.split(".")))
        self.assertEqual(builds, sorted(set(builds)))
        self.assertEqual(packager.macos_bundle_versions("0.5.0-alpha.2"), ("0.5.0", "6.0.2"))
        self.assertEqual(packager.macos_bundle_versions("0.5.0-alpha.25", "6.1.0"), ("0.5.0", "6.1.0"))
        for release in ("0.5.0-alpha.25", "0.5.0-preview.1", "0.100.0", "100.0.0"):
            with self.subTest(release=release), self.assertRaises(packager.PackagingError):
                packager.macos_bundle_versions(release)
        for value in ("0.1.2", "1.2", "1.2.3.4", "10000.0.0", "1.100.0", "1.0.100", "1.2.3a1"):
            with self.subTest(value=value), self.assertRaises(packager.PackagingError):
                packager.macos_bundle_versions("0.5.0", value)

    @unittest.skipIf(os.name == "nt", "Debian staging requires Unix symbolic links")
    def test_deb_uses_native_symbols_and_desktop_runtime(self):
        assets = self.root / "assets"
        assets.mkdir()
        (assets / "icon.png").write_bytes(b"synthetic PNG")
        (self.root / "LICENSE").write_text("MPL-2.0\n")
        temporary = self.root / "staging"
        temporary.mkdir()
        commands = []

        def command(arguments, **kwargs):
            commands.append(arguments)
            if arguments[0] == "dpkg":
                return "amd64\n"
            if arguments[0] == "dpkg-shlibdeps":
                self.assertEqual(kwargs["cwd"], temporary)
                return "shlibs:Depends=libc6 (>= 2.39), libgcc-s1 (>= 4.2)\n"
            return ""

        with mock.patch.object(installers, "ROOT", self.root), mock.patch.object(installers, "run", side_effect=command):
            result = installers.build_deb(self.package, temporary / "output.deb", temporary, "0.5.0-alpha.2")
        control = (temporary / "debian-package/DEBIAN/control").read_text()
        self.assertIn("Version: 0.5.0~alpha.2", control)
        self.assertIn("libc6 (>= 2.39)", control)
        self.assertIn("libwayland-client0", control)
        self.assertIn("qpdf", control)
        self.assertFalse(result["maintainer_scripts"])
        self.assertEqual(commands[-1][:3], ["dpkg-deb", "--root-owner-group", "--build"])
        self.assertEqual((temporary / "debian-package/usr/bin/fileveil").readlink(), Path("../lib/fileveil/fileveil"))
        self.assertIn("Exec=fileveil-gui", (temporary / "debian-package/usr/share/applications/com.fileveil.desktop.desktop").read_text())

    @unittest.skipIf(os.name == "nt", "Debian staging requires Unix symbolic links")
    def test_deb_rejects_missing_symbol_dependency_information(self):
        temporary = self.root / "staging"
        temporary.mkdir()
        (self.root / "assets").mkdir()
        (self.root / "assets/icon.png").write_bytes(b"icon")
        (self.root / "LICENSE").write_text("MPL-2.0\n")
        with mock.patch.object(installers, "ROOT", self.root), mock.patch.object(installers, "run", side_effect=["amd64\n", ""]):
            with self.assertRaisesRegex(installers.InstallerError, "runtime dependencies"):
                installers.build_deb(self.package, temporary / "output.deb", temporary, "0.5.0-alpha.2")

    def test_deb_rejects_wrong_native_architecture(self):
        with mock.patch.object(installers, "run", return_value="arm64\n"):
            with self.assertRaisesRegex(installers.InstallerError, "amd64"):
                installers.build_deb(self.package, self.root / "output.deb", self.root, "0.5.0-alpha.2")


if __name__ == "__main__":
    unittest.main()
