# Microsoft Defender detection review

**Status: not submitted, classification unresolved.** This is a submission draft,
not a Microsoft determination. Code signing does not resolve this classification.

## Evidence recorded locally

- Product: Microsoft Defender Antivirus; select the actual Windows edition in
  the submission portal.
- Detection: `Trojan:Win32/Bearfoos.B!ml`.
- Detected file: `DiscordGuard.exe` from the local 0.8 development build.
- Recorded SHA-256:
  `8a04ec2ad70302b8949fb26bda7156f38820a1e8de944fde62479b0a40a2ac6c`.
- Defender signature version at the last local check: `1.461.76.0`.
- Local detection history reports successful remediation. This does not establish
  whether the original file was correctly classified.

The source has changed since this artifact was built. Do not describe a newly
built executable as this exact sample or reuse this hash for different bytes.

## Submission

Open <https://www.microsoft.com/en-us/wdsi/filesubmission>, select **Software
developer**, the actual Defender product, and **Incorrectly detected as
malware/malicious** to request a suspected false-positive review. Supply the
specific detected sample and its actual hash, rather than the complete installer
or all dependencies. The portal requires the maintainer's account/contact details
and sample upload. Neither has been submitted by this tooling.

The recorded sample is quarantined. If it is unavailable, obtain Microsoft's
guidance for submitting the quarantined sample. No quarantine recovery or
execution is part of these release tools.

Suggested additional information (check against the uploaded sample):

```text
Please investigate a suspected false-positive classification of DiscordGuard.exe
as Trojan:Win32/Bearfoos.B!ml. We are not claiming that a false positive has been
confirmed. Recorded SHA-256:
8a04ec2ad70302b8949fb26bda7156f38820a1e8de944fde62479b0a40a2ac6c

DiscordGuard is an experimental MIT-licensed Windows launcher:
https://github.com/yuefdev/discord-guard
The affected file was a PyInstaller-packaged 0.8 development build. Its intended
function is to install a Windows-managed service identity and local broker for
the official Discord desktop client. It downloads Discord from official HTTPS
endpoints, checks its publisher signature, and uses dummy file/process-access
and DPAPI probes before launch. It does not migrate existing Discord credentials.

The source has changed since that local build; the current development branch
is not claimed to reproduce the exact uploaded bytes. The project has no trusted
publisher certificate or completed runtime acceptance. Distribution is blocked
while this classification is unresolved. Please provide your determination and
any specific behaviour that needs correction. Recorded Defender definitions:
1.461.76.0.
```

## After review

Record Microsoft's submission ID and determination. Apply any required source
corrections, update Defender security intelligence and scan the final candidate
application, helper and installer with protection enabled. A clean scan applies
to those bytes and definitions; it is not proof of resistance against RATs.

The latest source CI run, `39068623006`, passed 108 tests with one skipped on the
elevated runner and built the application. Its distribution gate then stopped
because enabled Defender protection was unavailable on that runner. This is an
environment blocker, separate from the unresolved local detection.
