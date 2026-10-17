"""Windows adapters. No Discord tokens, passwords-on-disk or external services."""

import base64
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib import request
from urllib.parse import urlparse
import uuid

from . import __version__, startup
from .core import acl_is_safe, decide, discord_signature_is_valid, policy_is_valid


class GuardError(RuntimeError):
    pass


class GUID(ctypes.Structure):
    _fields_ = [("data1", wintypes.DWORD), ("data2", wintypes.WORD),
                ("data3", wintypes.WORD), ("data4", ctypes.c_ubyte * 8)]


def known_folder(identifier: str) -> Path:
    if os.name != "nt":
        raise GuardError("Bu uygulama Windows 10/11 gerektirir.")
    guid = GUID.from_buffer_copy(uuid.UUID(identifier).bytes_le)
    output = ctypes.c_void_p()
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.SHGetKnownFolderPath.argtypes = [ctypes.POINTER(GUID), wintypes.DWORD,
                                         wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p)]
    shell.SHGetKnownFolderPath.restype = ctypes.c_long
    ole = ctypes.WinDLL("ole32", use_last_error=True)
    ole.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    result = shell.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(output))
    if result != 0 or not output.value:
        raise GuardError("Windows sistem klasörü doğrulanamadı.")
    try:
        return Path(ctypes.wstring_at(output))
    finally:
        ole.CoTaskMemFree(output)


@dataclass(frozen=True)
class Paths:
    program_files: Path
    program_data: Path
    common_programs: Path
    local_app_data: Path
    roaming_app_data: Path

    @classmethod
    def current(cls) -> "Paths":
        return cls(
            known_folder("905e63b6-c1bf-494e-b29c-65b732d3d21a"),  # ProgramFiles
            known_folder("62ab5d82-fdc1-4dc3-a9dd-070d1d495d97"),  # ProgramData
            known_folder("0139d44e-6afe-49f2-8690-3dafcae6ffb8"),  # CommonPrograms
            known_folder("f1b32785-6fba-4fcf-9d55-7b8e7f157091"),  # LocalAppData
            known_folder("3eb685db-65f9-4cf6-a03a-e3ef65729f3d"),  # RoamingAppData
        )

    @property
    def program_dir(self) -> Path:
        return self.program_files / "DiscordGuard"

    @property
    def data_dir(self) -> Path:
        return self.program_data / "DiscordGuard"

    @property
    def discord_profile(self) -> Path:
        return self.roaming_app_data / "discord"

    @property
    def discord_install_root(self) -> Path:
        return self.local_app_data / "Discord"

    @property
    def staging(self) -> Path:
        return self.local_app_data / "DiscordGuard" / "Installers"

    def config(self) -> dict:
        return {
            "program_parent": str(self.program_files), "program_dir": str(self.program_dir),
            "installed_exe": str(self.program_dir / "DiscordGuard.exe"),
            "data_dir": str(self.data_dir), "policy_path": str(self.data_dir / "policy.json"),
            "shortcut_path": str(self.common_programs / "DiscordGuard.lnk"),
            "discord_profile": str(self.discord_profile),
            "discord_install_root": str(self.discord_install_root), "staging": str(self.staging),
        }


def powershell_path() -> Path:
    # Use the Windows API, not PATH or caller-controlled environment variables.
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetWindowsDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    kernel.GetWindowsDirectoryW.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    size = kernel.GetWindowsDirectoryW(buffer, len(buffer))
    if not size or size >= len(buffer):
        raise GuardError("Windows dizini bulunamadı.")
    return Path(buffer.value) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"


def script_path(name: str) -> Path:
    if name not in ("inspect", "provision", "uninstall", "verify-installer"):
        raise GuardError("Bilinmeyen sistem işlemi.")
    return Path(__file__).parent / "scripts" / f"{name}.ps1"


def run_script(name: str, config: dict, *, secret_input: dict | None = None, timeout: int = 60) -> dict:
    payload = base64.b64encode(json.dumps(config).encode("utf-8")).decode("ascii")
    source = script_path(name).read_text(encoding="utf-8")
    # Invoke the embedded script block with an encoded, non-secret configuration.
    command = ("[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); "
               f"& {{\n{source}\n}} -ConfigBase64 '{payload}'")
    encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
    try:
        result = subprocess.run(
            [str(powershell_path()), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            input=json.dumps(secret_input, ensure_ascii=True) if secret_input is not None else "",
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW, timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise GuardError("Windows işlemi zaman aşımına uğradı; Discord başlatılmadı.") from error
    try:
        data = json.loads(result.stdout.lstrip("\ufeff").strip())
    except (ValueError, TypeError) as error:
        # Never display full PowerShell output: setup input contains a password.
        raise GuardError("Windows işlemi doğrulanabilir sonuç döndürmedi. Hiçbir güvenlik kontrolü atlanmadı.") from error
    if result.returncode != 0 or data.get("ok") is False:
        raise GuardError(data.get("error", "Windows işlemi tamamlanamadı."))
    return data


def inspect(paths: Paths | None = None) -> dict:
    if os.name != "nt":
        return {"windows": False}
    paths = paths or Paths.current()
    snapshot = run_script("inspect", paths.config())
    if (snapshot.get("policy") or {}).get("guardcore_required") is True:
        acls = snapshot.get("system_acls", {})
        trusted = policy_is_valid(snapshot.get("policy")) and all(acl_is_safe(acls.get(key, {})) for key in
            ("program_parent", "program_dir", "app", "data_dir", "policy", "native_helper"))
        snapshot["guardcore"] = guardcore_command(paths, "--query") if trusted else {"available": False}
    snapshot["autostart_enabled"] = None
    policy = snapshot.get("policy") or {}
    if policy.get("guard_sid") == snapshot.get("current", {}).get("sid"):
        try:
            entry = startup.RegistryStore().read(startup.RUN_KEY, startup.GUARD_VALUE)
            snapshot["autostart_enabled"] = entry == startup.Entry(autostart_command(paths))
        except OSError:
            pass
    return snapshot


def is_admin() -> bool:
    return os.name == "nt" and bool(ctypes.windll.shell32.IsUserAnAdmin())


def request_setup(origin_sid: str) -> None:
    if not getattr(sys, "frozen", False):
        raise GuardError("Hesap kurulumu paketlenmiş DiscordGuard.exe üzerinden yapılır.")
    if not origin_sid.startswith("S-1-5-21-"):
        raise GuardError("Başlangıç hesabı doğrulanamadı.")
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.ShellExecuteW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                  wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_int]
    shell.ShellExecuteW.restype = wintypes.HINSTANCE
    arguments = subprocess.list2cmdline(["--setup", "--origin-sid", origin_sid])
    result = shell.ShellExecuteW(None, "runas", sys.executable, arguments, None, 1)
    if not result or int(result) <= 32:
        raise GuardError("Yönetici izni verilmedi; kurulum başlatılmadı.")


def provision(password: str, origin_sid: str, paths: Paths | None = None) -> dict:
    if not is_admin() or not getattr(sys, "frozen", False):
        raise GuardError("Kurulum için paketlenmiş uygulama ve Windows yönetici izni gerekir.")
    if len(password) < 14:
        raise GuardError("En az 14 karakterlik, başka yerde kullanılmayan bir parola seçin.")
    paths = paths or Paths.current()
    config = paths.config()
    config.update(source_exe=sys.executable, uninstall_source=str(script_path("uninstall")))
    bundle = Path(sys.executable).parent / "_internal"
    config["source_internal"] = str(bundle) if bundle.is_dir() else None
    secret = {"password": password, "origin_sid": origin_sid}
    try:
        return run_script("provision", config, secret_input=secret, timeout=120)
    finally:
        # Python strings cannot be guaranteed zeroised. They are never persisted or logged.
        secret.clear()


def _reject_reparse_chain(path: Path) -> None:
    for current in [path, *path.parents]:
        if current.exists() and getattr(current.lstat(), "st_file_attributes", 0) & 0x400:
            raise GuardError("Korumalı profil yolunda yönlendirme bağlantısı var.")


def prepare_profile(paths: Paths, inspector, *, require_client: bool = True) -> dict:
    """Check identity first; create private directories; recheck every ACL."""
    first = inspector(paths)
    preliminary = decide(first, require_profile=False, require_client=require_client)
    if not preliminary.allowed:
        raise GuardError("\n".join(check.detail for check in preliminary.checks if not check.passed))
    for directory in (paths.discord_profile, paths.staging):
        _reject_reparse_chain(directory)
        directory.mkdir(parents=True, exist_ok=True)
    current = inspector(paths)
    decision = decide(current, require_client=require_client)
    if not decision.allowed:
        raise GuardError("\n".join(check.detail for check in decision.checks if not check.passed))
    return current


def clean_client_environment() -> dict[str, str]:
    return {key: value for key, value in os.environ.items()
            if not key.upper().startswith(("ELECTRON_", "NODE_", "CHROME_", "CHROMIUM_"))}


def desktop_arguments(binary: Path, install_root: Path) -> list[str]:
    if not binary.is_absolute() or not install_root.is_absolute() or \
            binary.name != "Discord.exe" or binary.parent.parent != install_root or \
            not re.fullmatch(r"app-\d+\.\d+\.\d+", binary.parent.name):
        raise GuardError("Discord yalnızca korumalı hesabın standart kurulumundan başlatılabilir.")
    return [str(binary)]


def launch(paths: Paths | None = None, *, inspector=None, popen=None):
    paths = paths or Paths.current()
    inspector = inspector or inspect
    initial = inspector(paths)
    if (initial.get("policy") or {}).get("guardcore_required") is True:
        decision = decide(initial, require_stopped=False)
        if not decision.allowed:
            raise GuardError("\n".join(check.detail for check in decision.checks if not check.passed))
        result = guardcore_command(paths, "--launch")
        if result.get("available") is not True or result.get("error") not in (0, 183):
            raise GuardError("GuardCore denetimli açılışı reddetti. Discord normal yoldan başlatılmadı.")
        return result
    # Reuse the first snapshot, but always obtain fresh evidence after directory creation.
    evidence = iter([initial])
    current = prepare_profile(paths, lambda value: next(evidence, None) or inspector(value))
    binary = Path(current["client"]["path"])
    args = desktop_arguments(binary, paths.discord_install_root)
    return (popen or subprocess.Popen)(args, close_fds=True, cwd=str(binary.parent), env=clean_client_environment())


def guardcore_command(paths: Paths, operation: str) -> dict:
    if operation not in ("--query", "--launch"):
        raise GuardError("Bilinmeyen GuardCore işlemi.")
    helper = paths.program_dir / "GuardCoreCtl.exe"
    if not helper.is_file():
        return {"available": False, "error": "GuardCore kontrol aracı kurulu değil"}
    try:
        result = subprocess.run([str(helper), operation], capture_output=True, text=True,
                                encoding="utf-8", timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
        value = json.loads(result.stdout)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {"available": False, "error": "GuardCore hizmetinden doğrulanabilir yanıt alınamadı"}


def autostart_command(paths: Paths) -> str:
    return subprocess.list2cmdline([str(paths.program_dir / "DiscordGuard.exe"), "--autostart"])


def run_autostart(paths: Paths | None = None, *, inspector=None, popen=None) -> None:
    paths = paths or Paths.current()
    inspector = inspector or inspect
    snapshot = inspector(paths)
    if snapshot.get("client_running") is True:
        decision = decide(snapshot, require_stopped=False)
        if not decision.allowed:
            raise GuardError("\n".join(check.detail for check in decision.checks if not check.passed))
        return
    launch(paths, inspector=inspector, popen=popen)


def set_autostart(enabled: bool, paths: Paths | None = None, *, inspector=None, store=None) -> dict:
    paths = paths or Paths.current()
    snapshot = (inspector or inspect)(paths)
    checks = decide(snapshot, require_profile=False, require_client=False, require_stopped=False).checks
    identity_checks = {"windows", "installed", "policy_acl", "account", "identity", "elevation"}
    failed = [check for check in checks if check.key in identity_checks and not check.passed]
    if failed:
        raise GuardError("\n".join(check.detail for check in failed))
    installed = paths.program_dir / "DiscordGuard.exe"
    if not getattr(sys, "frozen", False) or Path(sys.executable).resolve() != installed.resolve():
        raise GuardError("Otomatik açılışı, korumalı hesaptaki Başlat menüsünden açılan yüklü uygulamada ayarlayın.")
    try:
        return startup.configure(store or startup.RegistryStore(), autostart_command(paths),
                                 str(paths.discord_install_root / "Update.exe"), enabled=enabled)
    except startup.StartupError as error:
        raise GuardError(str(error)) from error


def download_url_is_official(url: str) -> bool:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return parsed.scheme == "https" and parsed.port in (None, 443) and not parsed.username and not parsed.password and (
        host in ("discord.com", "discordapp.com", "discordapp.net")
        or any(host.endswith("." + suffix) for suffix in ("discord.com", "discordapp.com", "discordapp.net")))


class OfficialRedirects(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not download_url_is_official(newurl):
            raise GuardError("Discord kurucusu resmî olmayan bir adrese yönlendirildi.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def install_discord(paths: Paths | None = None):
    """Download the official installer into the protected account and verify its signer."""
    paths = paths or Paths.current()
    if (inspect(paths).get("policy") or {}).get("guardcore_required") is True:
        raise GuardError("GuardCore VM prototipi açıkken kurulum/güncelleme yapılmaz. VM geri alma yönergesini uygulayın.")
    prepare_profile(paths, inspect, require_client=False)
    opener = request.build_opener(OfficialRedirects())
    source = request.Request("https://discord.com/api/download?platform=win", headers={"User-Agent": f"DiscordGuard/{__version__}"})
    destination = None
    try:
        with opener.open(source, timeout=40) as response:
            if not download_url_is_official(response.geturl()):
                raise GuardError("Kurucunun son indirme adresi doğrulanamadı.")
            size = 0
            with tempfile.NamedTemporaryFile(prefix="DiscordSetup-", suffix=".exe", dir=paths.staging, delete=False) as output:
                destination = Path(output.name)
                while chunk := response.read(65536):
                    size += len(chunk)
                    if size > 200_000_000:
                        raise GuardError("Discord kurucusu beklenen boyut sınırını aştı.")
                    output.write(chunk)
        signature = run_script("verify-installer", {"path": str(destination)})
        if not discord_signature_is_valid(signature):
            raise GuardError("İndirilen kurucunun Discord Inc. dijital imzası geçerli değil; çalıştırılmadı.")
        # Recheck the account, private staging directory and process state after downloading.
        decision = decide(inspect(paths), require_client=False)
        if not decision.allowed:
            raise GuardError("İndirme sırasında başlatma koşulları değişti; kurucu çalıştırılmadı.")
        return subprocess.Popen([str(destination)], close_fds=True, cwd=str(paths.staging), env=clean_client_environment())
    except Exception:
        if destination is not None:
            destination.unlink(missing_ok=True)
        raise


def lock_for_user_switch() -> None:
    if os.name != "nt" or not ctypes.windll.user32.LockWorkStation():
        raise GuardError("Windows kilit ekranı açılamadı. Ctrl+Alt+Delete ile kullanıcı değiştirin.")


def account_settings() -> None:
    os.startfile("ms-settings:otherusers")


def app_security_settings() -> None:
    os.startfile("windowsdefender://appbrowser")


def memory_security_settings() -> None:
    os.startfile("windowsdefender://coreisolation")
