# SignPath Foundation application reference

**Submission reported by the maintainer; approval pending.** No approval or
certificate has been obtained. This page retains the preparation text as a
reference, not a copy of the actual submission or provider confirmation. Do not
represent the project as already sponsored or production-ready.

## Public project details

- Project: DiscordGuard
- Repository and website: <https://github.com/yuefdev/discord-guard>
- Owner/maintainer GitHub profile: <https://github.com/yuefdev>
- Licence: MIT for original project code; third-party licence notices are shipped.
- Releases: <https://github.com/yuefdev/discord-guard/releases>
- Published version: 0.7.0 experimental, unsigned, separate-account flow.
- Candidate: 0.8.0 same-desktop service flow; not published or runtime-accepted.
- Code signing policy: [CODE-SIGNING.md](CODE-SIGNING.md)
- Security policy: [SECURITY.md](../SECURITY.md)

## Proposed description for provider review

DiscordGuard is an experimental Windows launcher for the official Discord desktop
application. It uses a Windows-managed virtual service account and a local broker
to run Discord on the user's desktop with a separate file/process identity.
Before launch it tests denial of access to its own harmless fixture file and
process, and checks a DPAPI round trip on dummy data. These are local boundary
probes, not network vulnerability scans or exploitation features. Please confirm
whether this functionality meets the Foundation's security-tool conditions.

The broker downloads Discord's official installer over HTTPS and verifies the
Discord Inc. publisher. It does not bundle Discord in our distribution. First
sign-in occurs through Discord's own UI. It does not extract, decrypt or migrate
existing Discord credentials. After private launch is confirmed, the origin
user's old stable client is removed using its official uninstaller, and standard
shortcuts are redirected. The installation/removal behaviour is documented.

Requested signing scope is our desktop launcher, native desktop-service helper
and setup executable, with consistent DiscordGuard product/version metadata.
Upstream Python/Qt binaries would be included under their respective licences,
without being signed as our own code. The experimental kernel driver is separate
and not part of this publisher-signing request.

## Outstanding disclosures and prerequisites

- Microsoft Defender classified a local 0.8 launcher as
  `Trojan:Win32/Bearfoos.B!ml`. The classification is unresolved; no false-positive
  determination is claimed. Recorded SHA-256:
  `8a04ec2ad70302b8949fb26bda7156f38820a1e8de944fde62479b0a40a2ac6c`.
- Current automated tests are not proof of malware resistance. Same-desktop
  input/screen/clipboard and administrator/kernel attackers are outside the
  boundary. Full Windows/Discord runtime acceptance is outstanding.
- The 0.8 distribution is not released yet; the provider's released-software
  requirement and project-reputation requirement remain to be evaluated.
- The maintainer must supply actual contact details, confirm roles and MFA,
  accept the provider terms and configure the approved build/signing integration.
  No certificate is issued by committing this draft.
