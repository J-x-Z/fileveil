#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Atomic owner-only CI signing-key creation and handle ownership failures."""
import base64
import ctypes
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("private_ci_postprocess", ROOT / "tools/project-postprocess.py")
POST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POST)


def pointer_value(value):
    return value.value if hasattr(value, "value") else value


class WindowsApi:
    token = 0x1010
    handle = 0x2020
    owner = "S-1-5-21-111-222-333-1001"

    def __init__(self, failure=None):
        self.failure = failure
        self.events = []
        self.kernel = SimpleNamespace(**{name: Mock() for name in (
            "GetCurrentProcess", "CloseHandle", "LocalFree", "CreateFileW")})
        self.security = SimpleNamespace(**{name: Mock() for name in (
            "OpenProcessToken", "GetTokenInformation", "ConvertSidToStringSidW",
            "ConvertStringSecurityDescriptorToSecurityDescriptorW")})
        self.owner_buffer = ctypes.create_unicode_buffer(self.owner)
        self.descriptor_buffer = ctypes.create_string_buffer(32)
        self.kernel.GetCurrentProcess.return_value = 0x3030
        self.kernel.CloseHandle.side_effect = self.close
        self.kernel.LocalFree.side_effect = lambda value: self.events.append(("free", pointer_value(value)))
        self.kernel.CreateFileW.side_effect = self.create
        self.security.OpenProcessToken.side_effect = self.open_token
        self.security.GetTokenInformation.side_effect = self.token_information
        self.security.ConvertSidToStringSidW.side_effect = self.convert_sid
        self.security.ConvertStringSecurityDescriptorToSecurityDescriptorW.side_effect = self.convert_descriptor
        self.crt = SimpleNamespace(open_osfhandle=Mock(side_effect=self.transfer))
        self.raw_descriptor = None
        self.transferred_descriptor = None

    def dll(self, name, **_options):
        return {"kernel32": self.kernel, "advapi32": self.security}[name]

    def open_token(self, process, access, result):
        assert process == 0x3030 and access == 0x0008
        if self.failure == "token":
            return 0
        ctypes.cast(result, ctypes.POINTER(ctypes.c_void_p))[0] = self.token
        return 1

    def token_information(self, _token, kind, data, _size, length):
        assert kind == 1
        ctypes.cast(length, ctypes.POINTER(ctypes.c_uint32))[0] = 16
        if data is None:
            return 0
        if self.failure == "information":
            return 0
        ctypes.cast(data, ctypes.POINTER(ctypes.c_void_p))[0] = 0x4040
        return 1

    def convert_sid(self, sid, result):
        assert sid == 0x4040
        if self.failure == "sid":
            return 0
        ctypes.cast(result, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(self.owner_buffer)
        return 1

    def convert_descriptor(self, sddl, revision, result, size):
        assert sddl == f"O:{self.owner}D:P(A;;FA;;;{self.owner})" and revision == 1 and size is None
        self.events.append(("protected_descriptor", sddl))
        if self.failure == "descriptor":
            return 0
        ctypes.cast(result, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(self.descriptor_buffer)
        return 1

    def create(self, path, access, share, attributes, disposition, flags, template):
        attributes = attributes._obj
        assert attributes.nLength == ctypes.sizeof(attributes)
        assert attributes.lpSecurityDescriptor == ctypes.addressof(self.descriptor_buffer)
        assert attributes.bInheritHandle == 0
        assert access == 0x00120196 and share == 1 and disposition == 1
        assert flags == 0x00200000 and template is None
        self.events.append(("create", path))
        if self.failure == "create":
            return ctypes.c_void_p(-1).value
        self.raw_descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        return self.handle

    def transfer(self, handle, flags):
        assert handle == self.handle and flags & os.O_WRONLY
        if self.failure == "transfer":
            raise OSError("mock CRT handoff failed")
        self.transferred_descriptor = self.raw_descriptor
        self.raw_descriptor = None
        return self.transferred_descriptor

    def close(self, handle):
        handle = pointer_value(handle)
        self.events.append(("close", handle))
        if handle == self.handle and self.raw_descriptor is not None:
            os.close(self.raw_descriptor)
            self.raw_descriptor = None
        return 1


class ProjectCiPrivateKeyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.secret = POST.KEY_MAGIC + bytes(range(32))

    def create_with_api(self, api, **extra):
        with patch.object(ctypes, "WinDLL", side_effect=api.dll, create=True), patch.dict(
            sys.modules, {"msvcrt": api.crt}
        ), patch.object(POST, "WINDOWS", True), patch.dict(
            os.environ, {"FILEVEIL_SIGNING_KEY_BASE64": base64.b64encode(self.secret).decode()}
        ):
            if extra.get("fdopen_failure"):
                with patch.object(POST.os, "fdopen", side_effect=OSError("mock fdopen failed")):
                    return POST.signing_identity(self.root)
            return POST.signing_identity(self.root)

    def test_native_creation_preserves_secret_and_refuses_replacement(self):
        with patch.dict(os.environ, {"FILEVEIL_SIGNING_KEY_BASE64": base64.b64encode(self.secret).decode()}):
            path = POST.signing_identity(self.root)
            self.assertEqual(path.read_bytes(), self.secret)
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(OSError):
                POST.signing_identity(self.root)
            self.assertEqual(path.read_bytes(), self.secret)

    def test_windows_permissions_exist_before_any_secret_write(self):
        api = WindowsApi()
        path = self.create_with_api(api)
        self.assertEqual(path.read_bytes(), self.secret)
        self.assertEqual([event[0] for event in api.events[:2]], ["protected_descriptor", "create"])
        self.assertEqual(api.kernel.LocalFree.call_count, 2)
        self.assertEqual(api.kernel.CloseHandle.call_count, 1)
        self.assertEqual(api.events[-1], ("close", api.token))
        with self.assertRaises(OSError):
            os.fstat(api.transferred_descriptor)

    def test_windows_creation_failures_release_security_resources_without_secret(self):
        for stage, free_count in [("token", 0), ("information", 0), ("sid", 0), ("descriptor", 1), ("create", 2)]:
            with self.subTest(stage=stage):
                api = WindowsApi(stage)
                with self.assertRaises(OSError):
                    self.create_with_api(api)
                self.assertFalse((self.root / "signing.key").exists())
                api.crt.open_osfhandle.assert_not_called()
                self.assertEqual(api.kernel.LocalFree.call_count, free_count)
                self.assertEqual(api.kernel.CloseHandle.call_count, 0 if stage == "token" else 1)

    def test_windows_crt_failure_closes_untransferred_handle_before_secret_write(self):
        api = WindowsApi("transfer")
        with self.assertRaisesRegex(OSError, "CRT handoff"):
            self.create_with_api(api)
        self.assertEqual((self.root / "signing.key").read_bytes(), b"")
        self.assertIsNone(api.raw_descriptor)
        self.assertIn(("close", api.handle), api.events)
        self.assertEqual(api.kernel.LocalFree.call_count, 2)

    def test_fdopen_failure_closes_transferred_descriptor_without_secret_write(self):
        api = WindowsApi()
        with self.assertRaisesRegex(OSError, "fdopen failed"):
            self.create_with_api(api, fdopen_failure=True)
        self.assertEqual((self.root / "signing.key").read_bytes(), b"")
        self.assertNotIn(("close", api.handle), api.events)
        with self.assertRaises(OSError):
            os.fstat(api.transferred_descriptor)

    def test_windows_create_new_preserves_an_existing_file(self):
        path = self.root / "signing.key"
        path.write_bytes(b"existing private file")
        api = WindowsApi()
        with self.assertRaises(OSError):
            self.create_with_api(api)
        self.assertEqual(path.read_bytes(), b"existing private file")
        api.crt.open_osfhandle.assert_not_called()
        self.assertEqual(api.kernel.LocalFree.call_count, 2)
        self.assertEqual(api.kernel.CloseHandle.call_count, 1)


if __name__ == "__main__":
    unittest.main()

# FVPROV1 9003 W3siYm9keSI6eyJhY3Rvcl9rZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwiYWxnb3JpdGhtIjoiRWQyNTUxOSIsImF1dGhvciI6IkoteC1aL0ZpbGVWZWlsIiwiY29udGVudF9zaGEyNTYiOiI5YWRjMzY0MTYxOWNiNGRkMGEwMGQ3ZThlYzYwMGYwNTdhOWYzOGUyMTdhMDE3ZGM1ODk1OWYzMjZkYmQxY2Y3IiwiY29weV9pZCI6InYwLjYuMC1hbHBoYS4xIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTEtMTQiLCJlZGl0aW9uIjoiYWxwaGEiLCJpc3N1ZXJfcG9saWN5IjpudWxsLCJraW5kIjoiY3JlYXRlIiwibW9kZSI6InNlbGZfc2lnbiIsInBhcmVudF92ZXJzaW9uIjpudWxsLCJwcmV2aW91c19yZWNvcmRfc2hhMjU2IjpudWxsLCJzY2hlbWEiOiJmaWxldmVpbC5wcm92ZW5hbmNlLnNpZ25hdHVyZS52MiIsInNlcXVlbmNlIjowLCJ0cmFuc2Zlcl90b19rZXlfaWQiOm51bGwsInZlcnNpb24iOiJ2MC42LjAtYWxwaGEuMSIsIndvcmtfaWQiOiJodHRwczovL2dpdGh1Yi5jb20vSi14LVovZmlsZXZlaWwvc291cmNlL3Rlc3RzL3Rlc3RfcHJvamVjdF9jaV9wcml2YXRlX2tleS5weSJ9LCJzaWduYXR1cmVzIjpbeyJrZXlfaWQiOiI5OWVhNjNlZmNjZmQwZmRiZDY4ZTE2ZWQ4ZjAzZDMzN2YxNWVjMmU0YTZhM2Q2NGUxMWQ3MTRlYTFlNTQyNTMzIiwicHVibGljX2tleV9oZXgiOiJhZGIzZTE3Y2QxMmY5NTZkMDA3MGUxNjYzZjUzMTUzN2ZjZWRmNzMwOGQwMTY1OGZlYTQ1NmZlZWE4ZjdmYmM1Iiwic2lnbmF0dXJlX2hleCI6IjNjODAyMGVhNWIzNDJkNjMyZmMyMTY2MGEyN2Q4MmZkZDRmYWFlNmIxM2MzMGM5MmVjMjZkZjc1YWQ3ZmEzMzg3NzBiMGIyY2RjZTc3NmUyYTRiZTA5MjYwYzRiZjI3ZDgwNjhkZWI2NTIzZTM4MTM2NDE4ZDg1ZTk2ZGIxODBkIn1dfV0= FVPROV1-END
