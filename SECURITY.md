# Security policy

DiscordGuard is an experimental security project. There is currently **no
production-supported release**, Microsoft-signed driver or completed driver VM
acceptance run. Do not treat compilation, a green test or a valid signature as
evidence of effectiveness against RATs.

## Reporting

Use the repository's private vulnerability-reporting facility when enabled.
Describe the affected commit, Windows version, harmless reproduction and expected
boundary. Do not attach live tokens, passwords, private signing keys or malware.
If private reporting is unavailable, ask the repository owner for a private
contact without posting exploit details publicly.

## Boundaries

- Version 0.8 uses a Windows-managed virtual service account and a LocalSystem
  broker. Discord itself runs with a restricted, medium-integrity virtual-account
  token on the original desktop. No user-managed password or account switch is
  required. Shared-desktop input/screen/clipboard and code already executing as
  that virtual identity remain outside the file/process-access boundary.
- Before launching, the client requires denial of a harmless fixture read and
  process-memory open, plus a successful DPAPI round-trip inside the private
  identity. These probes are not a complete Discord or malware acceptance test.
- Version 0.7 requires a Windows user/session/ACL boundary for every launch.
  WTS verifies the interactive session owner, including rejection of `runas` on
  another user's desktop. There is no ordinary-user launch fallback.
- The setup EXE installs the account-isolation launcher. It is unsigned and
  requires interactive UAC, a new account password and Windows sign-in.
- GuardCore is a separate unsigned laboratory driver. Administrator unload,
  kernel compromise, pre-existing mappings, raw-volume/offline reads and code
  executing inside trusted Discord are outside its demonstrated boundary.
- No production driver installer is supplied. The VM installer uses demand start
  and permits explicit removal; no stealth, resurrection or anti-uninstall layer.

Signing credentials belong in hardware-backed or managed signing services, not
the source tree, GitHub artifacts, this PC or release ZIPs. Untrusted pull
requests must never run on a signing runner. Require reviewed source, narrowly
scoped tokens and release-environment approval for real signing.
