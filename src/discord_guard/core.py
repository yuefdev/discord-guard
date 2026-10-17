"""Pure, fail-closed launch decisions. No credentials or network access."""

from dataclasses import asdict, dataclass
import re
from typing import Any


ACCOUNT_NAME = "DiscordGuard"
APP_MARKER = "DiscordGuard isolated Discord account v1"
POLICY_VERSION = 1
PRIVILEGED_SIDS = frozenset({
    "S-1-5-18", "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",  # TrustedInstaller
})
LOCAL_USER_SID = re.compile(r"S-1-5-21-\d+-\d+-\d+-\d+\Z")
# Read data, write data/EA/attributes, delete and ACL/ownership changes.
PRIVATE_ACCESS = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0xD0000000
WRITE_ACCESS = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x50000000


@dataclass(frozen=True)
class Check:
    key: str
    title: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class Decision:
    checks: tuple[Check, ...]
    advisories: tuple[Check, ...] = ()

    @property
    def allowed(self) -> bool:
        return bool(self.checks) and all(check.passed for check in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {"launch_allowed": self.allowed, "checks": [asdict(check) for check in self.checks],
                "advisories": [asdict(check) for check in self.advisories]}


def acl_is_safe(acl: dict[str, Any], *, private_sid: str | None = None) -> bool:
    """Conservative ACL test: an explicit deny never hides a broad allow."""
    if acl.get("exists") is not True or acl.get("error") or acl.get("reparse") is not False:
        return False
    trusted = set(PRIVILEGED_SIDS)
    if private_sid:
        trusted.add(private_sid)
    if acl.get("owner") not in trusted or not acl.get("rules"):
        return False
    mask = PRIVATE_ACCESS if private_sid else WRITE_ACCESS
    for rule in acl["rules"]:
        if not isinstance(rule.get("rights"), int) or not rule.get("sid"):
            return False
        if rule.get("inherit_only") is True:
            continue
        if rule.get("type") == "Allow" and rule["sid"] not in trusted and rule["rights"] & mask:
            return False
        if rule.get("type") not in ("Allow", "Deny"):
            return False
    return True


def policy_is_valid(policy: Any) -> bool:
    if not isinstance(policy, dict):
        return False
    sid = policy.get("guard_sid", "")
    origin = policy.get("origin_sid", "")
    return (
        policy.get("schema_version") == POLICY_VERSION
        and policy.get("account_name") == ACCOUNT_NAME
        and isinstance(sid, str) and bool(LOCAL_USER_SID.fullmatch(sid))
        and isinstance(origin, str) and bool(LOCAL_USER_SID.fullmatch(origin))
        and sid != origin
        and isinstance(policy.get("guardcore_required", False), bool)
    )


def discord_signature_is_valid(info: dict[str, Any]) -> bool:
    return info.get("signature") == "Valid" and bool(re.search(
        r"(?:^|,\s*)O=Discord Inc\.(?:,|$)", info.get("signer", "")))


def hardening_checks(snapshot: dict[str, Any]) -> tuple[Check, ...]:
    """Non-blocking Windows status; identity and ACLs provide the targeted boundary."""
    status = snapshot.get("hardening", {})
    uac = status.get("uac", {})
    vbs = status.get("vbs", {})
    services = vbs.get("services_running", [])
    checks = (
        ("secure_boot", "Windows Güvenli Önyükleme durumu", status.get("secure_boot_registry") is True,
         "Windows durum kaydında Güvenli Önyükleme açık; bu uzaktan donanım doğrulaması değildir.",
         "Güvenli Önyükleme açık değil veya Windows durum kaydı okunamadı."),
        ("uac_secure", "Güvenli masaüstünde yönetici onayı", uac.get("enabled") is True
         and uac.get("secure_desktop") is True and uac.get("admin_prompt") in (1, 2, 5),
         "Yönetici yükseltmesi güvenli masaüstünde onay istiyor.",
         "UAC/güvenli masaüstü kapalı, sessiz yükseltme var veya durum doğrulanamadı."),
        ("memory_integrity", "Bellek bütünlüğü (HVCI)", vbs.get("status") == 2
         and isinstance(services, list) and 2 in services,
         "VBS ve HVCI şu anda çalışıyor; yalnızca yapılandırılmış olmasıyla yetinilmedi.",
         "HVCI şu anda çalışmıyor veya çalışan güvenlik hizmetleri okunamadı."),
        ("umci", "Windows kullanıcı modu uygulama denetimi", vbs.get("umci") == 2,
         "Windows UMCI uygulama modunda. İzin listesinin kapsamı ayrıca test edilmelidir.",
         "UMCI uygulama modunda değil. Kapalı, yalnızca denetim kaydında veya doğrulanamadı."),
        ("tamper", "Defender kurcalama koruması", status.get("tamper_protection") is True,
         "Defender kurcalama koruması açık.",
         "Defender kurcalama koruması kapalı veya doğrulanamadı."),
    )
    return tuple(Check(key, title, bool(passed), good if passed else bad)
                 for key, title, passed, good, bad in checks)


def decide(snapshot: dict[str, Any], *, require_profile: bool = True,
           require_client: bool = True, require_stopped: bool = True) -> Decision:
    checks: list[Check] = []

    def add(key: str, title: str, passed: bool, good: str, bad: str) -> None:
        checks.append(Check(key, title, bool(passed), good if passed else bad))

    add("windows", "Windows", snapshot.get("windows") is True,
        "Windows güvenlik kontrolleri kullanılabilir.", "Bu sürüm Windows 10/11 içindir.")
    policy = snapshot.get("policy")
    valid_policy = policy_is_valid(policy)
    native_required = valid_policy and policy.get("guardcore_required") is True
    add("installed", "Yönetilen kurulum", valid_policy,
        "Kurulum politikası bulundu.", "Yönetici onaylı kurulumu tamamlayın.")
    system_acls = snapshot.get("system_acls", {})
    trusted_install = bool(system_acls) and all(
        acl_is_safe(system_acls.get(key, {})) for key in
        (("program_parent", "program_dir", "app", "data_dir", "policy", "native_helper")
         if native_required else ("program_parent", "program_dir", "app", "data_dir", "policy")))
    add("policy_acl", "Başlatıcı ve politika izinleri", trusted_install,
        "Normal kullanıcılar başlatıcıyı ve politikayı değiştiremiyor.",
        "Kurulum dosyaları yok, yeniden yönlendirilmiş veya izinleri güvenilir değil.")
    guard_sid = policy.get("guard_sid") if valid_policy else None
    account = snapshot.get("account", {})
    account_ok = (
        guard_sid is not None and account.get("sid") == guard_sid
        and account.get("enabled") is True and account.get("admin_member") is False
        and account.get("description") == APP_MARKER
    )
    add("account", "Kısıtlı Windows hesabı", account_ok,
        "Korumalı hesap standart kullanıcı; yönetici üyesi değil.",
        "Korumalı hesap doğrulanamadı veya yönetici yetkisine sahip.")
    current = snapshot.get("current", {})
    identity_ok = guard_sid is not None and current.get("sid") == guard_sid
    add("identity", "Ayrı Windows oturumu", identity_ok and current.get("session_id", 0) > 0
        and current.get("session_sid") == guard_sid,
        "Korumalı hesabın kendi etkileşimli Windows oturumundasınız.",
        "Windows giriş ekranından DiscordGuard hesabına geçin. runas veya başka kullanıcının masaüstü kabul edilmez.")
    add("elevation", "Sınırlı süreç yetkisi", current.get("elevated") is False,
        "Discord yönetici yetkisiyle çalıştırılmayacak.", "Başlatıcıyı yönetici olarak çalıştırmayın.")
    add("switching", "Kullanıcı geçişi", snapshot.get("fast_switching_disabled") is False,
        "Windows ayrı kullanıcı oturumuna geçişe izin veriyor.",
        "Kullanıcı geçişi sistem politikasıyla kısıtlı veya doğrulanamadı.")
    defender = snapshot.get("defender", {})
    add("defender", "Windows Defender", defender.get("realtime") is True
        and defender.get("behavior") is True and defender.get("antivirus") is True,
        "Defender gerçek zamanlı ve davranış koruması açık.",
        "Defender koruması doğrulanamadı veya gerekli korumalar kapalı.")
    if require_stopped:
        add("client_process", "Discord süreç durumu", snapshot.get("client_running") is False,
            "Bu Windows oturumunda Discord kapalı; denetimli başlatma yapılabilir.",
            "Bu oturumda Discord zaten açık veya süreç bilgileri okunamadı. Önce Discord’u tamamen kapatın.")
    if native_required:
        native = snapshot.get("guardcore", {})
        native_ready = native.get("available") is True and native.get("error") == 0 \
            and native.get("configured") == 1 and native.get("connected") == 1 \
            and native.get("process_callbacks") == 1
        add("guardcore", "GuardCore sürücüsü ve SYSTEM hizmeti", native_ready,
            "SYSTEM hizmetinden yapılandırılmış sürücü ve süreç geri çağrısı durumu alındı. VM çalışma testi ayrıca gerekir.",
            "GuardCore zorunlu fakat sürücü/hizmet doğrulanamadı. Normal başlatmaya geri düşülmeyecek.")
    elif require_client:
        client = snapshot.get("client", {})
        add("client_signature", "Resmî Discord imzası", discord_signature_is_valid(client),
            "Discord Inc. dijital imzası doğrulandı.",
            "Korumalı hesapta geçerli imzalı Discord masaüstü kurulumu bulunamadı.")
        client_acls = client.get("acls", [])
        add("client_acl", "Discord kurulum izinleri", guard_sid is not None and bool(client_acls)
            and all(acl_is_safe(acl, private_sid=guard_sid) for acl in client_acls),
            "Discord kurulum dosyaları diğer normal kullanıcılara kapalı.",
            "Discord kurulumunda güvensiz izin, yönlendirme veya denetlenemeyen dosya var.")
        add("client_entry", "Discord başlangıç dosyaları", client.get("entry_clean") is True,
            "Standart masaüstü başlangıç noktası bulundu; bilinen ek yükleyici yapısı yok.",
            "Başlangıç noktası standart değil veya denetlenemedi. Resmî Discord kurulumunu kullanın.")
    if require_profile and not native_required:
        profile_acls = snapshot.get("profile_acls", [])
        add("profile_acl", "Oturum deposunun erişim sınırı", guard_sid is not None
            and len(profile_acls) >= 7
            and all(acl_is_safe(acl, private_sid=guard_sid) for acl in profile_acls),
            "Profil ve mevcut oturum depolarına yalnızca korumalı kullanıcı, SYSTEM ve yöneticiler erişebilir.",
            "Özel profil hazır değil veya dosya izinleri başka kullanıcılara erişim veriyor.")
    return Decision(tuple(checks), hardening_checks(snapshot))
