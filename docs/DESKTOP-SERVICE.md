# Automatic desktop service (0.8)

**Status: unpublished, runtime verification blocked.** Defender classified the
local launcher as `Trojan:Win32/Bearfoos.B!ml`; the classification is not resolved.
SHA-256 of the flagged launcher:
`8a04ec2ad70302b8949fb26bda7156f38820a1e8de944fde62479b0a40a2ac6c`.
No exclusion, security-setting change or quarantine restoration was applied.
Use Microsoft's submission/review route: <https://www.microsoft.com/en-us/wdsi/filesubmission>.
The new build gate was exercised against the flagged artifact: Defender found
one threat, removed it, and the gate stopped publication as intended.

## Installation and use

The intended setup flow is one Windows UAC approval. Setup installs the
launcher and `DiscordGuardSession.exe` under `Program Files\DiscordGuard`, creates
two automatic-start Windows services, and returns to the original desktop app.
The first launch verifies an actual private-identity fixture, downloads the
official Discord installer over HTTPS, verifies its Discord Inc. signer and
runs it under the restricted virtual identity. Discord sign-in is manual.

No Windows password, existing Discord token, email credentials or browser session
is read or transferred. Windows SCM manages the virtual account credential and
profile. The original user's Discord installation is untouched.

## Services and trust

- `DiscordGuardIdentity`: `NT SERVICE\DiscordGuardIdentity`; Windows-managed
  profile, only `SeChangeNotifyPrivilege` requested. No desktop UI or command IPC.
- `DiscordGuardDesktop`: LocalSystem broker; depends on the identity service.
  Authenticates the installing user's SID and WTS session via a local-only pipe.
- Child tokens remove privileges and use medium integrity. The broker never runs
  Discord or its installer as SYSTEM. Only fixed official-install/launch and
  harmless fixture operations are supported; no caller-supplied executable/path.
- The client authenticates the service binary/configuration and live SCM PID
  against the named-pipe server. Admin-owned policy and helper ACLs are checked.
- Private roots and their files reject reparse paths and unrelated effective
  allow ACEs. Broker/profile failure refuses launch rather than using host Discord.

## What the fixture proves

The broker starts its fixed helper under the same restricted identity/session
used for Discord. The child encrypts/decrypts 32 dummy bytes using user DPAPI and
writes a private fixture. The original user must receive `ERROR_ACCESS_DENIED`
from both a read open on that file and a `PROCESS_VM_READ` process open. The probe
has no real session data. The fixture is deleted after acknowledgement; the
short-lived helper exits itself. A probe failure prevents Discord launch.

## Recovery and removal

Disable checked startup from DiscordGuard first, then close private Discord and
DiscordGuard. From elevated PowerShell run:

```powershell
& "$env:ProgramFiles\DiscordGuard\Uninstall.ps1"
```

Confirm `REMOVE`. The uninstaller verifies desktop policy, stops/removes only its
two services and removes the launcher/policy/shortcut. The virtual account's
profile and Discord data remain. Failed installation rolls back newly created
services/files but also retains any virtual profile. Verified 0.7 installations
belonging to the same origin SID are moved to admin-owned `.legacy-<id>` sibling
directories before replacement. Other installations are refused. Rollback attempts
to restore the old directories/shortcut; a failed restoration retains the backups
and reports that manual inspection is needed. The old Windows account/profile is
never removed. Backup paths are recorded in the new policy. Profile deletion is a
separate explicit action.

## Scope and outstanding acceptance

The current desktop is intentionally shared. Input hooks, screen/clipboard
capture and UI automation are not isolated. This is not administrator-resistant
protection or an application allow-list. Files opened by Discord may execute
under its private identity; do not run untrusted attachments there.

Full acceptance still needs Discord sign-in, persistent DPAPI across service/PC
restarts, Electron renderer/GPU/audio/video, links/attachments, screen sharing,
automatic Discord updates, sleep/resume, cancellation and recovery on clean VMs.
GuardCore's production signing and driver acceptance are separate work.

The first local migration attempt reached service registration, failed on the
`sc.exe` command-line boundary and restored the original 0.7 policy. Registration
now uses `CreateServiceW` directly. Compilation and automated gates passed before
the Defender block; successful desktop-service installation, the actual private
fixture probe and Discord launch have **not** been demonstrated yet.
