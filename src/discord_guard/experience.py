"""One primary action, without confusing an inspection with live protection."""

from dataclasses import dataclass
from pathlib import Path

from .core import acl_is_safe, decide, discord_signature_is_valid
from . import windows


@dataclass(frozen=True)
class Dashboard:
    mode: str
    badge: str
    heading: str
    description: str
    button: str
    detail: str
    launchable: bool


def installed_checks(snapshot: dict) -> tuple[tuple[str, bool], ...]:
    client = snapshot.get("installed_discord") or {}
    sid = snapshot.get("current", {}).get("sid")
    acls = client.get("acls", [])
    defender = snapshot.get("defender", {})
    return (
        ("Resmî Discord imzası", discord_signature_is_valid(client)),
        ("Standart başlangıç dosyası", client.get("entry_clean") is True),
        ("Kurulum izinleri", bool(sid) and bool(acls) and all(acl_is_safe(acl, private_sid=sid) for acl in acls)),
        ("Defender gerçek zamanlı koruma", defender.get("realtime") is True
            and defender.get("behavior") is True and defender.get("antivirus") is True),
        ("Yönetici olmayan açılış", snapshot.get("current", {}).get("elevated") is False),
    )


def present(snapshot: dict) -> Dashboard:
    policy = snapshot.get("policy") or {}
    decision = decide(snapshot, require_stopped=False)
    if policy.get("guardcore_required") is True:
        if decision.allowed:
            return Dashboard("kernel", "DENEYSEL SÜRÜCÜ BAĞLI", "Discord’un hazır.",
                "Yüklü masaüstü Discord, doğrulanan SYSTEM hizmeti üzerinden açılacak.",
                "Denetimli Discord’u aç", "Sürücü bağlantısı doğrulandı. Bu bir virüssüzlük garantisi değil.", True)
        return Dashboard("blocked", "KORUMA DEVREDE DEĞİL", "Önce motor hazır olmalı.",
            "Bu kurulum sürücü gerektiriyor. Hizmet ve kimlik doğrulanmadan Discord başlatılmaz.",
            "Durumu yeniden kontrol et", "İmzalı sürücü ve hazırlanmış test ortamı gerekiyor.", False)
    if decision.allowed:
        return Dashboard("isolated", "AYRI HESAP DOĞRULANDI", "Discord’un hazır.",
            "Normal Discord hesabın. Ayrı Windows kimliği ve özel oturum dosyaları.",
            "Yalıtılmış Discord’u aç", "Windows erişim sınırı hazır. Çekirdek koruması seçili değil.", True)
    client = snapshot.get("installed_discord") or {}
    if client.get("found") is not True:
        return Dashboard("missing", "DISCORD BULUNAMADI", "Discord’u bulalım.",
            "Bu Windows kullanıcısının normal Discord kurulumu henüz bulunamadı.",
            "Yeniden kontrol et", "Discord kuruluysa bu kullanıcı hesabında bir kez açıp tekrar dene.", False)
    checks = installed_checks(snapshot)
    if not all(passed for _, passed in checks):
        return Dashboard("blocked", "AÇILIŞ DOĞRULANAMADI", "Bir kontrol tamamlanmadı.",
            "İmza, başlangıç dosyası veya Windows koruması doğrulanamadı. Discord başlatılmadı.",
            "Yeniden kontrol et", "Eksik kontrolü Ayrıntılar ekranından görebilirsin.", False)
    return Dashboard("checked", "CANLI KORUMA KAPALI", "Discord’un. Tek bir adım.",
        "Yüklü Discord’u buldum. İmzasını ve başlangıç dosyasını kontrol ederek açabilirim.",
        "Kontrol et ve Discord’u aç", "Bu açılış kontrolüdür. Token çalınmasını veya RAT’ı canlı olarak engellemez.", True)


def one_click(paths=None, *, inspector=None, popen=None) -> dict:
    paths = paths or windows.Paths.current()
    inspector = inspector or windows.inspect
    snapshot = inspector(paths)
    state = present(snapshot)
    if not state.launchable:
        return {"snapshot": snapshot, "opened": False, "state": state}
    if state.mode in ("kernel", "isolated"):
        if state.mode == "isolated" and snapshot.get("client_running") is True:
            return {"snapshot": snapshot, "opened": True, "state": state}
        windows.launch(paths, inspector=inspector, popen=popen)
    else:
        binary = Path(snapshot["installed_discord"]["path"])
        windows._reject_reparse_chain(binary)
        arguments = windows.desktop_arguments(binary, paths.discord_install_root)
        (popen or windows.subprocess.Popen)(arguments, close_fds=True, cwd=str(binary.parent),
                                            env=windows.clean_client_environment())
    return {"snapshot": snapshot, "opened": True, "state": state}
