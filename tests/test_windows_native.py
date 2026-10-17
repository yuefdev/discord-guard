import base64
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from discord_guard import windows


class Mapping(ctypes.Structure):
    _fields_ = [("read", wintypes.DWORD), ("write", wintypes.DWORD),
                ("execute", wintypes.DWORD), ("all", wintypes.DWORD)]


@unittest.skipUnless(os.name == "nt", "Native Windows verification")
class WindowsNativeTests(unittest.TestCase):
    def access_check(self, descriptor):
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
        advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        advapi.DuplicateToken.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.POINTER(wintypes.HANDLE)]
        advapi.AccessCheck.argtypes = [ctypes.c_void_p, wintypes.HANDLE, wintypes.DWORD,
            ctypes.POINTER(Mapping), ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.BOOL)]
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        security = ctypes.c_void_p()
        primary = wintypes.HANDLE()
        impersonation = wintypes.HANDLE()
        self.assertTrue(advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(descriptor, 1, ctypes.byref(security), None))
        try:
            self.assertTrue(advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0xA, ctypes.byref(primary)))
            self.assertTrue(advapi.DuplicateToken(primary, 2, ctypes.byref(impersonation)))
            mapping = Mapping(0x120089, 0x120116, 0x1200A0, 0x1F01FF)
            privileges = ctypes.create_string_buffer(4096)
            length = wintypes.DWORD(len(privileges))
            granted = wintypes.DWORD()
            allowed = wintypes.BOOL()
            result = advapi.AccessCheck(security, impersonation, 1, ctypes.byref(mapping), privileges,
                ctypes.byref(length), ctypes.byref(granted), ctypes.byref(allowed))
            self.assertTrue(result, ctypes.get_last_error())
            return bool(allowed.value)
        finally:
            if impersonation:
                kernel.CloseHandle(impersonation)
            if primary:
                kernel.CloseHandle(primary)
            kernel.LocalFree(security)

    def test_windows_actually_denies_read_for_a_different_user_acl(self):
        if windows.is_admin():
            self.skipTest("Run unprivileged to model the original user's ordinary malware token")
        private = ("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
                   "(A;;FA;;;S-1-5-21-111-222-333-424242)")
        self.assertFalse(self.access_check(private))
        self.assertTrue(self.access_check(private + "(A;;FR;;;WD)"))

    def test_bundled_powershell_parses_without_running_any_setup(self):
        command = (
            "$source=[Console]::In.ReadToEnd(); $tokens=$null; $errors=$null; "
            "[void][Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors); "
            "@{errors=@($errors | ForEach-Object {$_.Message})} | ConvertTo-Json -Compress"
        )
        encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
        root = Path(__file__).resolve().parents[1]
        scripts = [windows.script_path(name) for name in ("inspect", "provision", "uninstall", "verify-installer")]
        scripts += [root / "native" / name for name in ("install-vm.ps1", "remove-vm.ps1")]
        scripts += [root / "tools" / name for name in ("sign-app.ps1", "verify-driver.ps1")]
        for script in scripts:
            with self.subTest(script=script.name):
                result = subprocess.run([str(windows.powershell_path()), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                    input=script.read_text(encoding="utf-8"), capture_output=True,
                    text=True, encoding="utf-8", timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)["errors"], [])

    def test_atomic_directory_helper_compiles_without_creating_directories(self):
        source = windows.script_path("provision").read_text(encoding="utf-8")
        helper = re.search(r"Add-Type -TypeDefinition @'\n(.*?)\n'@", source, re.DOTALL)
        self.assertIsNotNone(helper)
        command = (
            "$source=[Console]::In.ReadToEnd(); Add-Type -TypeDefinition $source -ErrorAction Stop; "
            "@{method=[bool][DiscordGuardDirectory].GetMethod('Create')} | ConvertTo-Json -Compress"
        )
        encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
        result = subprocess.run([str(windows.powershell_path()), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            input=helper.group(1), capture_output=True, text=True, encoding="utf-8",
            timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["method"])


if __name__ == "__main__":
    unittest.main()
