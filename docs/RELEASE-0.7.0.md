# DiscordGuard 0.7.0 — isolated-session preview

## Install

Download `DiscordGuard-0.7.0-Setup.exe` from this release and run it. The wizard
opens automatically. Approve Windows UAC and choose a unique password for the new
standard `DiscordGuard` Windows account. Finish setup, choose **Korumalı hesaba
geç**, and sign into that Windows account. Open DiscordGuard from Start, then use
**Discord’u indir ve kur**. Sign into the official Discord client normally.

The setup EXE contains the onedir application, replaceable Qt libraries,
licences and application source. `SHA256SUMS.txt` covers all published binaries
and archives. Neither the setup EXE nor the experimental driver is signed.
Existing accounts/installations are preserved and are not taken over.

## Changes

- Every launch now requires the isolated account; ordinary-user fallback removed.
- WTS verifies the actual interactive session owner. A protected-account process
  started with `runas` on another user's desktop cannot pass the launch gate.
- One primary button follows account setup, Windows sign-in, official Discord
  installation and checked launch. Startup registration is offered explicitly.
- PowerShell inspection uses a bounded bootstrap command, fixing Windows error
  206 when the encoded inspection script exceeds the CreateProcess command limit.
- The installer waits for elevated setup to finish before discarding extracted
  files, and checks the payload for missing, modified or unexpected files.
- Existing single-instance window activation improvements are included.

## Verification

Local Windows checks: 82 automated tests passed, including Windows AccessCheck
denial for a different user's private ACL and WTS owner resolution. The packaged
application opened and closed successfully. Native compilation and user-mode
policy checks passed. The release packager also requires the setup EXE to pass
its no-install smoke check before producing release hashes.

Interactive account creation, a complete isolated Discord login, audio/video and
cross-user attack fixtures still require a clean VM acceptance run. No live
malware test, kernel-driver load or general application allow-list is included.
GuardCore remains VM-only, with no production signature or updater support.

## Security scope

The release enforces a separate Windows identity/session and private filesystem
permissions against ordinary processes in the original user's account. It does
not establish protection against administrator/kernel attackers, pre-existing
infection, or code already running inside the protected account. Tokens are
never read or copied by DiscordGuard. Old Discord sessions remain separate;
revoke them through Discord's device/session settings when migrating.
