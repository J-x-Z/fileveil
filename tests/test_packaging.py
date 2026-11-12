# SPDX-License-Identifier: MPL-2.0
"""Small, offline packaging regressions with synthetic source and backend trees."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile


SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "package-desktop.py"
SPEC = importlib.util.spec_from_file_location("fileveil_package_desktop", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
packaging = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packaging)


class PackagingTests(unittest.TestCase):
    SOURCE_FILES = {
        "Cargo.toml": '[workspace.package]\nversion = "0.3.0"\n',
        "Cargo.lock": "# synthetic dependency lock\n",
        "LICENSE": "Synthetic project license\n",
        "README.md": "Synthetic FileVeil source\n",
        ".gitignore": "*.clean.*\n__pycache__/\nassets/ignored.txt\n",
        "crates/fileveil-gui/Cargo.toml": '[package]\nname = "fileveil-gui"\n',
        "crates/fileveil-gui/src/main.rs": "// synthetic GUI source\n",
        "crates/fileveil-cli/Cargo.toml": '[package]\nname = "fileveil-cli"\n',
        "crates/fileveil-cli/src/main.rs": "// synthetic CLI source\n",
        "tools/package-desktop.py": "# synthetic packager source\n",
        "docs/GUI.md": "Synthetic GUI instructions\n",
        "assets/fonts/LICENSE.txt": "Synthetic font notice\n",
        "assets/licenses/dependency/COPYRIGHT.txt": "Synthetic dependency notice\n",
        "THIRD_PARTY_NOTICES.txt": "Synthetic third-party notices\n",
    }

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="fileveil-packaging-test-")
        self.addCleanup(self.directory.cleanup)
        self.temporary = Path(self.directory.name).resolve()
        self.root = self.temporary / "source"
        self.root.mkdir()
        for relative, contents in self.SOURCE_FILES.items():
            self.write(self.root / relative, contents)
        self.root_patch = mock.patch.object(packaging, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    @staticmethod
    def write(path: Path, contents: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8", newline="\n")

    def assert_sources(self, destination: Path) -> set[str]:
        self.assertEqual((destination / "LICENSE").read_bytes(), (self.root / "LICENSE").read_bytes())
        self.assertEqual(
            (destination / "THIRD_PARTY_NOTICES" / "assets" / "licenses" / "dependency" / "COPYRIGHT.txt").read_bytes(),
            (self.root / "assets" / "licenses" / "dependency" / "COPYRIGHT.txt").read_bytes(),
        )
        with zipfile.ZipFile(destination / "FileVeil-source.zip") as archive:
            self.assertIsNone(archive.testzip())
            names = set(archive.namelist())
            self.assertTrue(set(self.SOURCE_FILES).issubset(names))
            for name, contents in self.SOURCE_FILES.items():
                self.assertEqual(archive.read(name), contents.encode("utf-8"))
        return names

    def add_local_artifacts(self) -> None:
        for relative in (
            "assets/ignored.txt",
            "tests/fixture.clean.png",
            "tools/__pycache__/package-desktop.pyc",
            "crates/fileveil-cli/target/local-artifact",
            "assets/.DS_Store",
            "work/local-private-input.pdf",
        ):
            self.write(self.root / relative, "Synthetic local artifact\n")

    def test_source_zip_uses_git_selection_and_excludes_local_artifacts(self) -> None:
        self.add_local_artifacts()
        # Tracked cache or clean-output names remain excluded even if Git lists them.
        listed = list(self.SOURCE_FILES) + [
            "tests/fixture.clean.png",
            "tools/__pycache__/package-desktop.pyc",
            "crates/fileveil-cli/target/local-artifact",
            "assets/.DS_Store",
        ]
        result = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=b"\0".join(name.encode() for name in listed) + b"\0",
            stderr=b"",
        )
        destination = self.temporary / "resources"
        with mock.patch.object(packaging.subprocess, "run", return_value=result) as git:
            packaging.copy_resources(destination)
        git.assert_called_once_with(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=self.root, capture_output=True, check=False, timeout=30,
        )
        names = self.assert_sources(destination)
        self.assertEqual(names, set(self.SOURCE_FILES))

    def test_source_zip_falls_back_when_git_is_missing_or_unavailable(self) -> None:
        self.add_local_artifacts()
        cases = (
            ("missing", FileNotFoundError("synthetic Git absence")),
            ("timeout", subprocess.TimeoutExpired("git", 30)),
            ("outside-repository", subprocess.CompletedProcess([], 128, stdout=b"", stderr=b"")),
        )
        for name, response in cases:
            with self.subTest(name=name):
                arguments = {"side_effect": response} if isinstance(response, Exception) else {"return_value": response}
                destination = self.temporary / f"resources-{name}"
                with mock.patch.object(packaging.subprocess, "run", **arguments):
                    packaging.copy_resources(destination)
                names = self.assert_sources(destination)
                self.assertNotIn("tests/fixture.clean.png", names)
                self.assertNotIn("tools/__pycache__/package-desktop.pyc", names)
                self.assertNotIn("crates/fileveil-cli/target/local-artifact", names)
                self.assertNotIn("assets/.DS_Store", names)
                self.assertNotIn("work/local-private-input.pdf", names)

    def test_packaging_requires_the_project_license(self) -> None:
        (self.root / "LICENSE").unlink()
        with self.assertRaisesRegex(packaging.PackagingError, "Project LICENSE"):
            packaging.copy_resources(self.temporary / "resources")

    def test_portable_package_contains_gui_cli_sources_and_licenses(self) -> None:
        binary = self.temporary / "build" / "fileveil-gui"
        self.write(binary, "Synthetic GUI executable\n")
        cli = binary.with_name("fileveil")
        self.write(cli, "Synthetic CLI executable\n")
        destination = self.temporary / "portable"
        backend = {"mode": "external", "available_at_build": False}
        with (
            mock.patch.object(packaging.subprocess, "run", side_effect=FileNotFoundError),
            mock.patch.object(packaging, "portable_pdf_backend", return_value=backend),
        ):
            packaging.package_portable(binary, destination, "0.3.0", "linux")
        self.assertEqual((destination / binary.name).read_bytes(), binary.read_bytes())
        self.assertEqual((destination / cli.name).read_bytes(), cli.read_bytes())
        manifest = json.loads((destination / "fileveil-package.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["executable"], binary.name)
        self.assertEqual(manifest["cli_executable"], cli.name)
        self.assertEqual(manifest["pdf_backend"], backend)
        self.assert_sources(destination / "resources")

    def test_macos_dylib_aliases_rewrite_to_copied_versioned_filenames(self) -> None:
        self.assert_macos_versioned_aliases()

    def test_macos_dylib_aliases_support_unprivileged_symlink_fallback(self) -> None:
        with mock.patch.object(Path, "symlink_to", side_effect=OSError("Synthetic symlink restriction")):
            self.assert_macos_versioned_aliases()

    def assert_macos_versioned_aliases(self) -> None:
        cellar = self.temporary / "Cellar"
        qpdf_formula = cellar / "qpdf" / "12.4.2_1"
        jpeg_formula = cellar / "jpeg-turbo" / "3.2.1"
        executable = qpdf_formula / "bin" / "qpdf"
        library = qpdf_formula / "lib" / "libqpdf.30.4.2.dylib"
        jpeg = jpeg_formula / "lib" / "libjpeg.62.5.0.dylib"
        for path in (executable, library, jpeg):
            self.write(path, f"Synthetic Mach-O {path.name}\n")
        for formula in (qpdf_formula, jpeg_formula):
            self.write(formula / "LICENSE.txt", f"Synthetic {formula.parent.name} license\n")
        installed = self.temporary / "brew" / "bin" / "qpdf"
        installed.parent.mkdir(parents=True)
        qpdf_alias = library.with_name("libqpdf.30.dylib")
        jpeg_alias = jpeg.with_name("libjpeg.62.dylib")
        aliases = {installed: executable, qpdf_alias: library, jpeg_alias: jpeg}
        # Windows runners can restrict symlink creation. The resolver fallback models
        # the same alias identities while keeping this macOS-only algorithm testable.
        virtual_aliases = {}
        for alias, target in aliases.items():
            try:
                alias.symlink_to(target)
            except OSError:
                self.write(alias, "Synthetic alias\n")
                virtual_aliases[alias] = target
        real_resolve = Path.resolve

        def resolve(path: Path, *arguments, **keywords) -> Path:
            return virtual_aliases.get(path, real_resolve(path, *arguments, **keywords))

        listings = {
            executable: f"{executable}:\n\t@rpath/{qpdf_alias.name} (compatibility version 30.0.0)\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n",
            library: f"{library}:\n\t{qpdf_alias} (compatibility version 30.0.0)\n\t{jpeg_alias} (compatibility version 62.0.0)\n",
            jpeg: f"{jpeg}:\n\t{jpeg_alias} (compatibility version 62.0.0)\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n",
        }

        def otool(command: list[str], *, text: bool) -> str:
            self.assertEqual(command[:2], ["otool", "-L"])
            self.assertTrue(text)
            return listings[Path(command[2])]

        resources = self.temporary / "mac-resources"
        resources.mkdir()
        with (
            mock.patch.dict(os.environ, {"FILEVEIL_QPDF": str(installed)}),
            mock.patch.object(Path, "resolve", resolve),
            mock.patch.object(packaging.subprocess, "check_output", side_effect=otool),
            mock.patch.object(packaging, "run") as run,
        ):
            packaging.bundle_macos_qpdf(resources)
        backends = resources / "backends"
        self.assertEqual({path.name for path in backends.iterdir()}, {executable.name, library.name, jpeg.name})
        changes = [call.args[0] for call in run.call_args_list if call.args[0][:2] == ["install_name_tool", "-change"]]
        self.assertEqual(len(changes), 2)
        self.assertIn(
            ["install_name_tool", "-change", f"@rpath/{qpdf_alias.name}", f"@loader_path/{library.name}", str(backends / executable.name)],
            changes,
        )
        self.assertIn(
            ["install_name_tool", "-change", str(jpeg_alias), f"@loader_path/{jpeg.name}", str(backends / library.name)],
            changes,
        )
        for change in changes:
            self.assertTrue((backends / change[3].removeprefix("@loader_path/")).is_file())
        self.assertEqual(run.call_args_list[-1], mock.call([str(backends / executable.name), "--version"], timeout=30))
        for name in ("qpdf", "jpeg-turbo"):
            self.assertTrue((resources / "THIRD_PARTY_NOTICES" / "pdf-backends" / name / "LICENSE.txt").is_file())


if __name__ == "__main__":
    unittest.main()
