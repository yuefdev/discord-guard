# DiscordGuard — desktop isolation prototype

A small Windows launcher for the **normal, official Discord desktop application**.
Use your existing Discord account. Version 0.8 uses a **Windows-managed virtual
service identity on your current desktop**. The Turkish interface uses PySide6/Qt. Original code is
MIT-licensed; see `THIRD_PARTY_NOTICES.md` for dependency terms.

## Automatic setup on the same desktop (0.8, unpublished)

**Distribution blocked:** Windows Defender classified the local 0.8 launcher as
`Trojan:Win32/Bearfoos.B!ml`. A false positive has not been established. Do not
disable Defender or restore the quarantined file to run this preview. The 0.8
source is under development; there is no published 0.8 installer. Existing
[release assets](https://github.com/yuefdev/discord-guard/releases) use the older
account-switching flow.

Approve Windows UAC once. The installer registers a Windows-managed virtual
identity and a local broker. There is no new Windows password to enter and no
account switching. The broker downloads and verifies the official Discord
installer and opens Discord on the current desktop under its private identity.
Your first Discord sign-in remains yours; existing tokens are never copied.

Before launch, a harmless process under the private identity checks DPAPI, and
the caller must receive access denied when opening its dummy file and process
memory. Failure blocks launch. Service calls authenticate the installing SID,
actual WTS session owner, SCM configuration and pipe-server PID. Only fixed
status, fixture-test and verified Discord launch operations are exposed.

**Same desktop means shared input, screen and clipboard.** This layer targets
cross-identity file/process access, not keylogging, malicious Discord attachments
executed inside the private identity, or administrator/kernel attackers. It is
an unsigned preview; full Discord audio/video/update acceptance is still pending.
GuardCore remains a separate lab driver. Verified 0.7 launcher/policy directories
are backed up during automatic migration; the old account and its data remain.

Version 0.6.1 restores and raises the existing window when opened again. Each
Windows user/session keeps one main window; repeat launches no longer accumulate
background copies. Account setup uses a separate window channel.

## Legacy separate-account mode (0.7)

The following account-switching instructions apply to existing 0.7 installations.
New 0.8 installations use the automatic desktop service described above. See
[desktop service details](docs/DESKTOP-SERVICE.md) for setup, recovery and limits.

### Separate-session security boundary

The protected account has its own Windows SID, interactive session and Discord
profile. An ordinary process running as the original Windows user cannot read
that user's private profile or Discord process memory. DiscordGuard checks the
boundary before launching. It never reads, exports, encrypts or decrypts tokens.

Start from a **clean system**. Administrator/SYSTEM attackers, malware running as
the protected user and keyloggers active during setup are outside this model.
Passing checks verify configuration, not absence of malware. The account is not
an application allow-list: reserve it for Discord and run no untrusted software.

## Account setup

1. Resolve suspected infection first. Defender's **Offline scan** restarts Windows.
2. Run `DiscordGuard.exe` from the original Windows account.
3. Choose **Korumalı hesabı kur** and accept the Windows UAC prompt.
4. Choose a unique password of at least 14 characters. It goes to Windows over a
   local pipe, never through command-line arguments, logs, policy or files.
5. Setup creates the standard `DiscordGuard` account, installs the launcher and
   any `_internal` dependency directory in
    `Program Files\DiscordGuard`, and adds a common Start-menu shortcut.
6. Choose **Windows giriş ekranı**, then sign into `DiscordGuard`. Do not use
   `runas` on the original desktop.

Existing accounts/directories are refused rather than taken over.

## Install and use normal Discord

1. In the separate Windows account, open DiscordGuard from the Start menu.
2. In **Kurulum ve kullanım**, choose **Resmî Discord’u indir ve kur**.
3. The official Windows installer is downloaded from Discord's HTTPS download
   endpoint. Only official Discord hosts are accepted, and its **Discord Inc.**
   digital signature is verified before execution.
4. After installation, fully quit Discord, refresh checks, then choose **Discord’u aç**.
5. Sign into the normal desktop application with your existing Discord account.
6. Revoke old sessions through Discord's **Settings → Devices**. They are not migrated.

The installer may open Discord automatically; it remains inside the separate
Windows session. Enable checked startup as described below for daily use.

## Launch conditions

- Administrator-owned launcher/policy and the expected account SID.
- Current user is the enabled, standard `DiscordGuard` account.
- Actual WTS session owner matches the protected SID, user switching enabled,
  launcher not elevated. A matching process SID alone is insufficient.
- Defender antivirus, real-time and behaviour protection enabled.
- No Discord process already running in that Windows session.
- Discord executable has a valid **Discord Inc.** signature.
- Installation, profile ancestors and session-storage files have private ACLs
  and no reparse points; broad allows cannot be hidden by a deny.
- The desktop-core entry is the standard `core.asar` loader; no `resources\app`
  override. This is a limited injection check, not complete ASAR authenticity proof.

The launcher starts the installed `Discord.exe` without user-supplied switches.
Electron/Node environment overrides are removed from the child environment.
The official desktop updater remains functional; its downloaded code is trusted
as part of Discord's own supply chain.

## Automatic daily use

In the protected Windows account, choose **Otomatik kullanım → Denetimli otomatik
açılışı etkinleştir** once. At the next sign-in, DiscordGuard checks the isolated
account and client, launches normal Discord, then exits. Problems open the UI;
no unchecked fallback is used. An already running valid client is not duplicated.

Only this user's `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` entries
named `DiscordGuard` and standard `Discord` are managed. The previous Discord
setting is saved under `HKCU\Software\DiscordGuard\Startup`. Turning the feature
off restores it. Conflicting/user-modified entries are preserved rather than
overwritten. Other applications are untouched.

Windows sign-in and the first Discord login remain manual. Passwords and Windows
auto-logon credentials are not stored. Task Manager can independently disable a
registered startup app; re-enable DiscordGuard there if needed.

## Optional Windows status

Version 0.4 makes UMCI, HVCI, Secure Boot, secure-desktop UAC and Defender tamper
status **informational**. They appear in **Windows durumu** and the diagnostic
JSON's `advisories`, not in the blocking decision. Unknown state is not shown as
enabled. No App Control policy, UEFI change or global program allow-list is
required or applied. The actual boundary remains the separate SID/session and
private Discord ACLs. These optional readings do not establish administrator or
SYSTEM resistance.

## Files and privacy

| Location | Content |
| --- | --- |
| `Program Files\DiscordGuard` | Launcher and uninstall script; administrators write |
| `ProgramData\DiscordGuard\policy.json` | Account SID and metadata; no credentials |
| Protected user's `AppData\Roaming\discord` | Discord-managed session data |
| Protected user's `AppData\Local\Discord` | Normal Discord installation |
| Protected user's `AppData\Local\DiscordGuard\Installers` | Verified official installer |

No analytics, application-server or AI calls are made. Discord downloads/traffic
use the official service. Existing Discord installations in the original Windows
account remain outside this boundary. AI explanations and incident-message
recovery are later work; an AI score must never override Windows identity checks.

## GuardCore laboratory layer (0.5)

`native/` contains a separate experimental minifilter, process/thread handle
callbacks and LocalSystem launch broker. It is **not installed or enabled by the
ordinary application package**. VM installation explicitly selects the
`guardcore_required` policy. Then the UI shows real broker status, and launch is
delegated to the service without falling back if the driver is unavailable.

Source, build provenance, signing requirements, recovery and the unexecuted VM
acceptance matrix are in [native/README.md](native/README.md). The native artifacts
are unsigned; successful compilation/policy tests are not an actual RAT test or
proof of administrator-resistant protection.

## Remove the launcher

First turn off automatic startup in the protected account's DiscordGuard UI.
Switch back to the administrator without signing the protected user out, then
close DiscordGuard. In an elevated PowerShell window:

```powershell
& "$env:ProgramFiles\DiscordGuard\Uninstall.ps1"
```

Type `REMOVE`. Only launcher files, policy and shortcut are removed. The Windows
account, Discord installation and session data remain. Revoke that Discord
session before deleting its Windows account through **Settings → Accounts →
Other users**; Windows account removal can delete its files.

The uninstaller refuses removal while checked startup remains registered, so it
does not leave an orphaned startup command. If the protected profile is unloaded,
it asks you to sign into that account first instead of loading/editing its hive.

The initial web prototype, if installed, may also have a private `WebProfile`
directory in that account. Revoke its old Discord session. This version neither
opens that profile nor removes its data automatically.

## Develop and build

With Python 3.11+ and PyInstaller, from this directory:

```powershell
$env:PYTHONPATH = 'src'
$env:PYTHONDONTWRITEBYTECODE = '1'
python -m pip install -r requirements-build.txt
python -m discord_guard
python -m unittest discover -s tests -v
.\build.ps1
```

For Controlled Folder Access, choose a build output outside protected documents:

```powershell
.\build.ps1 -OutputRoot "$env:TEMP\DiscordGuardBuild"
```

The executable is under that output's `dist` folder. No Windows security setting
needs changing. Read-only `python -m discord_guard --diagnose` returns `2` when
launch conditions are unmet, `1` for inspection failure, `0` when all pass.
`--smoke-test` opens/closes the UI without setup, downloads or Discord launch.

## Verification and release status

Automated tests exercise fail-closed identity/ACL decisions, native Windows
access checks, desktop-only launch paths, official download host restrictions,
installer signature rejection and the packaged interface. PowerShell is parsed
and its native directory helper compiled without changing accounts.
Startup tests exercise restoration, write-failure rollback, user-change
preservation and silent success/error-UI behaviour. They use in-memory registry
fixtures; no real account's startup settings are changed by tests.

Interactive UAC provisioning, a complete official Discord installation and
cross-user sign-in need a disposable Windows VM/account; they have not been
performed by the automated suite. This is an unsigned prototype, not a deployed
protection or proof an infected machine is safe. Distribution requires a reviewed,
signed release and clean-machine end-to-end testing.

## Open source and Windows acceptance

CI and draft experimental-release workflows are in `.github/workflows`. They do
not contain signing keys or publish a stable protection claim. Use
`tools/sign-app.ps1` for a real publisher certificate, `tools/verify-driver.ps1`
for a Microsoft-returned kernel signature, and `tools/package_release.py` for
the source/licence/hash-bearing preview. Full prerequisites, external accounts,
cost-bearing certificates, HLK and remaining blockers: [docs/RELEASING.md](docs/RELEASING.md).
