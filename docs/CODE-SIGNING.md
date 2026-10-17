# Code signing policy

## Current status

DiscordGuard is open source under MIT. No trusted signing certificate or managed
signing subscription is currently configured, and no signed release is claimed.
SignPath Foundation is a possible free OSS route; no application has been
submitted or approved. Its acceptance decision belongs to the provider.

The 0.8 launcher has an unresolved Microsoft Defender detection. Application
signing does not clear that detection, certify protection against RATs, or supply
a Microsoft kernel-driver signature. Current releases remain experimental.
The factual Microsoft submission draft is in [DEFENDER-REVIEW.md](DEFENDER-REVIEW.md).

## Ownership and approval

- Repository owner and proposed signing maintainer: [yuefdev](https://github.com/yuefdev).
- The maintainer must confirm the signing requester, reviewer and approver roles
  when enrolling with a provider, and enable the provider's required MFA.
- Signing inputs must come from a reviewed version tag and its source build.
  Pull requests do not receive signing credentials. A signing request requires
  the configured release approval; provider credentials are never source files
  or downloadable artifacts.

## Files that may be signed

Only our `DiscordGuard.exe`, `DiscordGuardSession.exe` and
`DiscordGuard-<version>-Setup.exe` receive DiscordGuard publisher signatures.
They carry matching product/version metadata. Third-party Python/Qt libraries
retain their upstream identity and licence notices; they are not re-signed as
our code. The proprietary Discord installer/client is downloaded separately
from Discord, not distributed inside our signed payload.

The signer must be trusted by Windows, match the explicitly selected certificate
thumbprint and include a verified timestamp. Payload hashes are created after
payload signing; distribution hashes are created after installer signing.
`tools/verify-app.ps1` checks the final signature, metadata and hash. Defender
checks remain required before distribution. A signed application candidate still
records incomplete runtime acceptance and unsigned laboratory-driver status.

## Privacy and system changes

DiscordGuard has no analytics or application-server calls. Requested official
Discord downloads and Discord's own client traffic use Discord's services and
their privacy policy: <https://discord.com/privacy>. Tokens and Discord passwords
are not read or transferred by DiscordGuard. Sign-in uses Discord's own UI.

Installation adds the documented Windows services and launcher. After verified
private launch, the old stable client is removed with its official uninstaller
and recognised shortcuts are redirected. The desktop UI explains this before
installation. Removal is documented in [DESKTOP-SERVICE.md](DESKTOP-SERVICE.md).

## Provider application

The factual application draft is in [SIGNPATH-APPLICATION.md](SIGNPATH-APPLICATION.md).
SignPath's [conditions](https://signpath.org/terms) include OSS licensing,
verifiable builds, project reputation, release availability, approval and
restrictions on security tools. Eligibility must be confirmed, especially for
the harmless local access-denial probes. Provider sponsorship must only be
announced after acceptance.
