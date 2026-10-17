"""One primary action, without confusing an inspection with live protection."""

from dataclasses import dataclass
from .core import acl_is_safe, decide, desktop_policy_is_valid, discord_signature_is_valid, policy_is_valid
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
    if snapshot.get("windows") is not True:
        return Dashboard("blocked", "WINDOWS GEREKLİ", "Windows doğrulanamadı.",
            "Korumalı açılış için Windows 10/11 gerekiyor.", "Yeniden kontrol et",
            "Güvenlik koşulları okunamadığında Discord başlatılmaz.", False)
    if desktop_policy_is_valid(policy):
        if not decision.allowed:
            failed = next(check for check in decision.checks if not check.passed)
            return Dashboard("blocked", "SERVİS HAZIR DEĞİL", "Bir kontrol tamamlanmadı.", failed.detail,
                "Yeniden kontrol et", "Aynı masaüstünde açılış için arka plan servisi doğrulanmalı.", False)
        installed = snapshot.get("desktop_service", {}).get("installed") == 1
        return Dashboard("desktop", "ÖZEL SERVİS KİMLİĞİ HAZIR", "Discord’un. Aynı masaüstünde.",
            "Dosyalar ve çalışan işlem ayrı Windows servis kimliğinde. Hesap değiştirmen gerekmez.",
            "Korumalı Discord’u aç" if installed else "Discord’u otomatik kur ve aç",
            "İlk Discord girişi sana ait. Aynı masaüstündeki klavye ve ekran kaydı bu sınırın dışında.", True)
    if not policy:
        residue = any(snapshot.get("system_acls", {}).get(key, {}).get("exists") is True
                      for key in ("program_dir", "data_dir", "policy")) or bool(snapshot.get("account"))
        if residue:
            return Dashboard("blocked", "KURULUM DENETLENMELİ", "Kurulum tamamlanmamış.",
                "Mevcut hesap veya dosyalar var; geçerli kurulum politikası bulunamadı.",
                "Yeniden kontrol et", "Mevcut hesabın üzerine yazılmaz. Ayrıntılardaki kurulum denetimlerini incele.", False)
        return Dashboard("setup", "OTOMATİK KURULUM", "Tek onayla hazırlanır.",
            "Discord için özel arka plan servisi kurulur. Hesap değiştirme ve Windows parolası yok.",
            "Tek tıkla kur ve aç", "Bir Windows yönetici onayı gerekir. Resmî Discord otomatik indirilir.", False)
    if not policy_is_valid(policy):
        return Dashboard("blocked", "POLİTİKA DOĞRULANAMADI", "Kurulumu kontrol et.",
            "Korumalı hesabın kimliği doğrulanamadı.", "Yeniden kontrol et",
            "Geçersiz politikayla Discord başlatılmaz.", False)
    current = snapshot.get("current", {})
    if current.get("sid") == policy["origin_sid"] and current.get("session_sid") == policy["origin_sid"] \
            and policy.get("guardcore_required") is not True:
        trusted = {"installed", "policy_acl", "account"}
        if all(check.passed for check in decision.checks if check.key in trusted):
            return Dashboard("upgrade", "OTOMATİK KULLANIMA GEÇ", "Hesap değiştirme bitti.",
                "Eski kurulum yedeklenerek aynı masaüstünde çalışan özel servis kurulacak.",
                "Otomatik kullanıma geçir", "Bir Windows onayı gerekir. Eski hesap ve Discord verileri silinmez.", False)
    if current.get("sid") != policy["guard_sid"] or current.get("session_sid") != policy["guard_sid"]:
        required = {"windows", "installed", "policy_acl", "account", "switching"}
        failed = [check for check in decision.checks if check.key in required and not check.passed]
        if not failed:
            return Dashboard("switch", "KORUMALI OTURUMA GEÇ", "Alan hazır. Hesaba geç.",
                "Discord, DiscordGuard Windows hesabının kendi masaüstünde çalışacak.",
                "Korumalı hesaba geç", "Windows kilit ekranında DiscordGuard hesabını seç. Mevcut Discord oturumu taşınmaz.", False)
        return Dashboard("blocked", "KURULUM DOĞRULANAMADI", "Bir kontrol tamamlanmadı.",
            failed[0].detail, "Yeniden kontrol et", "Korumalı hesaba geçmeden önce kurulum düzeltilmeli.", False)
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
    preliminary = decide(snapshot, require_profile=False, require_client=False, require_stopped=False)
    if preliminary.allowed:
        client = snapshot.get("client") or {}
        if client.get("found") is False:
            return Dashboard("install", "KORUMALI HESAP HAZIR", "Resmî Discord’u kur.",
                "Discord bu ayrı Windows hesabına indirilecek ve yayıncı imzası doğrulanacak.",
                "Discord’u indir ve kur", "Kurulumdan sonra aynı Discord hesabınla giriş yap. İndirme resmî Discord sunucusundan yapılır.", False)
        # Only absent profile directories may be prepared automatically. Existing
        # insecure ACLs are never repaired implicitly or hidden by this action.
        without_profile = decide(snapshot, require_profile=False, require_stopped=False)
        if without_profile.allowed and any(acl.get("exists") is False and not acl.get("error")
                                          for acl in snapshot.get("profile_acls", [])):
            return Dashboard("prepare", "PROFİL HAZIRLANACAK", "Son kontrol kaldı.",
                "Eksik özel profil klasörleri hazırlanıp erişim izinleri yeniden doğrulanacak.",
                "Profili hazırla ve Discord’u aç", "Doğrulama başarısızsa Discord açılmaz.", True)
    failed = next(check for check in decision.checks if not check.passed)
    return Dashboard("blocked", "AÇILIŞ DOĞRULANAMADI", "Bir kontrol tamamlanmadı.",
        failed.detail, "Yeniden kontrol et", "Eksik kontrolü Ayrıntılar ekranından görebilirsin. Korumalı açılış durduruldu.", False)


def one_click(paths=None, *, inspector=None, popen=None, enable_startup=False) -> dict:
    paths = paths or windows.Paths.current()
    inspector = inspector or windows.inspect
    snapshot = inspector(paths)
    state = present(snapshot)
    if not state.launchable:
        return {"snapshot": snapshot, "opened": False, "state": state}
    if state.mode == "isolated" and snapshot.get("client_running") is True:
        if enable_startup:
            windows.set_autostart(True, paths, inspector=inspector)
        return {"snapshot": snapshot, "opened": True, "state": state}
    windows.launch(paths, inspector=inspector, popen=popen)
    if enable_startup:
        windows.set_autostart(True, paths, inspector=inspector)
    return {"snapshot": snapshot, "opened": True, "state": state}
