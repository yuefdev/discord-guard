"""Reversible, per-user startup. Never alters system-wide application control."""

from dataclasses import dataclass
import json
import ntpath
import re


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
STATE_KEY = r"Software\DiscordGuard\Startup"
GUARD_VALUE = "DiscordGuard"
STATE_VALUE = "RestoreState"
SZ = 1
EXPAND_SZ = 2


class StartupError(RuntimeError):
    pass


@dataclass(frozen=True)
class Entry:
    value: str
    kind: int = SZ


class RegistryStore:
    def read(self, key: str, name: str) -> Entry | None:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_READ) as handle:
                value, kind = winreg.QueryValueEx(handle, name)
        except FileNotFoundError:
            return None
        return Entry(value, kind)

    def write(self, key: str, name: str, entry: Entry | None) -> None:
        import winreg
        if entry is None:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as handle:
                    winreg.DeleteValue(handle, name)
            except FileNotFoundError:
                pass
        else:
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as handle:
                winreg.SetValueEx(handle, name, 0, entry.kind, entry.value)


def is_official_startup(entry: Entry, expected_updater: str) -> bool:
    if entry.kind not in (SZ, EXPAND_SZ) or not isinstance(entry.value, str):
        return False
    match = re.fullmatch(
        r'\s*"([^"\r\n]+)"\s+--processStart\s+Discord\.exe'
        r'(?:\s+--process-start-args\s+"--start-(?:inactive|minimized)")?\s*',
        entry.value, re.IGNORECASE)
    return bool(match and ntpath.normcase(match[1]) == ntpath.normcase(expected_updater))


def decode_state(entry: Entry | None) -> dict | None:
    if entry is None:
        return None
    try:
        if entry.kind != SZ or not isinstance(entry.value, str) or len(entry.value) > 8192:
            raise ValueError()
        state = json.loads(entry.value)
        if state.get("version") != 1 or not isinstance(state.get("command"), str):
            raise ValueError()
        original = state.get("discord")
        if original is not None and (not isinstance(original, dict)
                or set(original) != {"value", "kind"}
                or not isinstance(original.get("value"), str) or original.get("kind") not in (SZ, EXPAND_SZ)):
            raise ValueError()
        return state
    except (ValueError, TypeError, AttributeError):
        raise StartupError("Otomatik açılışın geri dönüş kaydı doğrulanamadı; mevcut ayarlar korunuyor.") from None


def _apply_changes(store, original: dict, changes: list) -> None:
    changed = []
    try:
        for key, name, entry in changes:
            changed.append((key, name))
            store.write(key, name, entry)
    except Exception as error:
        rollback_failed = False
        for key, name in reversed(changed):
            try:
                store.write(key, name, original[(key, name)])
            except Exception:
                rollback_failed = True
        message = "Başlangıç ayarı tamamlanamadı."
        message += " Geri dönüş eksik kaldı; Windows Başlangıç Uygulamaları’nı kontrol edin." if rollback_failed else " Önceki ayarlar geri yüklendi."
        raise StartupError(message) from error


def retire_discord(store, command: str, expected_updater: str, *, validate_only=False) -> None:
    """Retire an uninstalled client's startup without restoring a dead updater later."""
    locations = ((RUN_KEY, GUARD_VALUE), (RUN_KEY, "Discord"), (STATE_KEY, STATE_VALUE))
    original = {location: store.read(*location) for location in locations}
    guard, discord, saved = (original[location] for location in locations)
    state = decode_state(saved)
    if guard is not None and guard != Entry(command):
        raise StartupError("DiscordGuard başlangıç girdisi başka bir komuta ait; geçiş durduruldu.")
    if discord is not None and not is_official_startup(discord, expected_updater):
        raise StartupError("Discord başlangıç girdisi standart değil; eski uygulama kaldırılmadı.")
    if state is not None:
        if state["command"] != command or (state["discord"] is not None and
                not is_official_startup(Entry(**state["discord"]), expected_updater)):
            raise StartupError("Başlangıç geri dönüş kaydı bu kuruluma ait değil; geçiş durduruldu.")
    if validate_only:
        return
    changes = []
    if discord is not None:
        changes.append((RUN_KEY, "Discord", None))
    if state is not None and state["discord"] is not None:
        state["discord"] = None
        changes.append((STATE_KEY, STATE_VALUE, Entry(json.dumps(state))))
    _apply_changes(store, original, changes)


def configure(store, command: str, expected_updater: str, *, enabled: bool) -> dict:
    locations = ((RUN_KEY, GUARD_VALUE), (RUN_KEY, "Discord"), (STATE_KEY, STATE_VALUE))
    original = {location: store.read(*location) for location in locations}
    guard, discord, saved = (original[location] for location in locations)
    state = decode_state(saved)
    expected_guard = Entry(command)
    if guard is not None and guard != expected_guard:
        raise StartupError("DiscordGuard başlangıç girdisi farklı bir komuta ait; değiştirilmedi.")
    if state is not None and state["command"] != command:
        raise StartupError("Başka kuruluma ait başlangıç kaydı var; değiştirilmedi.")
    if enabled and discord is not None and not is_official_startup(discord, expected_updater):
        raise StartupError("Discord başlangıç girdisi standart değil. Discord ayarlarından otomatik açılışı kapatın.")
    if state and state["discord"] is not None:
        previous = Entry(**state["discord"])
        if not is_official_startup(previous, expected_updater):
            raise StartupError("Geri yüklenecek Discord komutu doğrulanamadı; çalıştırılmadı veya değiştirilmedi.")
    else:
        previous = None
    if enabled and state is not None and discord is not None and discord != previous:
        raise StartupError("Discord başlangıcı sonradan değiştirilmiş; mevcut ayara dokunulmadı.")
    # Do not overwrite a new Discord startup setting when undoing our own change.
    if not enabled and discord is not None and previous is not None and discord != previous:
        raise StartupError("Discord başlangıcı sonradan değiştirilmiş. Mevcut ayar ve geri dönüş kaydı korundu.")
    changes = []
    if enabled:
        if state is None:
            state = {"version": 1, "command": command, "discord":
                     {"value": discord.value, "kind": discord.kind} if discord is not None else None}
            changes.append((STATE_KEY, STATE_VALUE, Entry(json.dumps(state))))
        changes.append((RUN_KEY, GUARD_VALUE, expected_guard))
        if discord is not None:
            changes.append((RUN_KEY, "Discord", None))
    else:
        if guard is not None:
            changes.append((RUN_KEY, GUARD_VALUE, None))
        if discord is None and previous is not None:
            changes.append((RUN_KEY, "Discord", previous))
        if saved is not None:
            changes.append((STATE_KEY, STATE_VALUE, None))
    _apply_changes(store, original, changes)
    return {"enabled": enabled, "discord_startup_paused": enabled and discord is not None,
            "discord_startup_restored": not enabled and discord is None and previous is not None}
