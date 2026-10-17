# GuardCore — unsigned laboratory prototype

This is a **compiled research layer**, not deployed protection or a tested RAT
blocker. Use a clean, disposable Windows 11 x64 VM with a snapshot. No driver was
loaded on the development computer, and its security settings were not changed.
The regular DiscordGuard account-isolation launcher remains independently usable.

## Implemented path

1. A LocalSystem broker verifies the configured protected user's profile, the
   Discord executable's Authenticode chain/publisher and standard core loader.
2. It connects to a SYSTEM-only Filter Manager port and configures immutable
   profile/installation roots. The driver verifies instances exist on both NTFS volumes.
3. The protected user requests launch through a local named pipe. The broker
   verifies the caller's SID/session and a non-administrator WTS token.
4. Discord is created suspended. The driver enrols its process object before
   execution resumes. Same-image children are enrolled using the actual creator,
   not the caller-supplied parent PID. Process objects, not reusable PIDs, are held.
5. New process/thread handle requests have documented modifiable write,
   injection, impersonation and termination access stripped. Duplicated
   handles are checked against their destination process as well as the source.
6. The minifilter denies untrusted user-mode access in the selected Discord roots.
   Stream-handle contexts, section creation, rename and hard-link destinations
   are considered. System/paging I/O is allowed.
7. Broker disconnection leaves the roots configured and denies new user-mode
   access. Reconnection requires an explicit driver unload/reload.

The pipe client checks the server PID against SCM, the LocalSystem service
configuration and the expected broker executable. The service verifies its own token.
There is no remote endpoint, arbitrary kernel memory operation, credential dump,
process hiding, patching, Defender bypass or automatic service resurrection.

## Important boundaries

- Administrators can stop the broker, unload the driver or replace installation
  files. This prototype is **not administrator-tamper-proof** or boot protection.
- Existing handles/mappings and memory copied before arming are not revoked.
- This version follows Microsoft's documented modifiable callback access rights.
  It does **not** claim to intercept all read-only process-memory/context access.
- Kernel callers, vulnerable drivers, raw-volume/offline reads and code executing
  inside an already trusted Discord process remain outside the boundary.
- Name-classification failures/high-IRQL I/O are counted, not represented as
  successfully blocked. Alternate pre-existing hard-link names are not a complete
  identity solution. NTFS only; ReFS, network and nonstandard profile mappings are refused.
- Authenticode covers the executable, not all ASAR/module contents. Core-loader
  checks are limited. A clean baseline and protected install are required.
- Only the selected version's `Discord.exe` and its same-image children are
  trusted. **Updater compatibility has not been implemented**. Unload the lab
  layer before updating, then select/verify the new executable and re-arm it.
- No generic script blocker or AI detector is claimed. Other applications are
  unaffected unless they try accessing these guarded files/processes.

## Build without installing a WDK

From the repository root, with Visual Studio 2022 C++ Build Tools, SDK 26100 and
Python installed:

```powershell
python -B native\build.py --output "$env:TEMP\GuardCoreBuild"
```

The builder downloads `Microsoft.Windows.WDK.x64` **10.0.26100.6584** into that
output directory. Its pinned SHA-512 comes from NuGet's package catalog. The
package is extracted for compilation only; no WDK installation or signing-mode
change occurs. Its Microsoft licence is in the extracted package. `--wdk PATH`
uses an already extracted matching package instead.

Outputs: `GuardCore.sys`, `GuardCoreCtl.exe`, native policy tests and
`GuardCore-lab.zip`. `/W4 /WX` applies to project code. Only the WDK header's
intentional alignment-padding diagnostic is locally suppressed. The driver uses
`/GS`, the kernel GS entry wrapper, NX/ASLR and `/INTEGRITYCHECK`. These flags are
not a substitute for Driver Verifier, signing or runtime tests.

## Prepare a separate test VM

1. Create a clean VM snapshot with a known recovery administrator and recovery media.
2. Install DiscordGuard 0.5 and normal Discord in its protected account. Close
   Discord fully; keep that protected Windows session signed in.
3. Build and **test-sign the embedded driver image** using the prepared VM's test
   certificate/toolchain. Prepare that VM's test-driver trust according to
   Microsoft's driver-testing guidance. This repository deliberately contains
   no script to disable Secure Boot or change signing mode on the host.
4. The unallocated altitude `385201.4242` is laboratory-only. Check for collisions
   in the VM. A production minifilter needs a Microsoft-assigned altitude and the
   appropriate Microsoft driver-signing route.

Microsoft references:
<https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option>
<https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-altitude-request>

## Arm inside the VM

From an elevated PowerShell **inside the disposable VM**:

```powershell
.\native\install-vm.ps1 -Artifacts 'C:\GuardCoreBuild' `
  -DiscordImage 'C:\Users\DiscordGuard\AppData\Local\Discord\app-1.0.9262\Discord.exe' `
  -DisposableVm
```

Replace the image path with that VM's actual version. The script refuses a
non-VM host, unsigned/untrusted driver, conflicting services or running Discord.
It installs two **demand-start** services and selects `guardcore_required` in the
admin-owned policy. It changes no general App Control policy. The launcher then
requires actual broker/driver status; there is no fallback to ordinary launch.

After arming, select **Discord’u aç** in the protected account's DiscordGuard.
The GuardCore tab shows configuration, connection, callbacks and counters. Those
counters are not a claim that no malware is present. Services must be started
manually in the lab after a reboot; they are not enabled at boot by this prototype.

## Required runtime acceptance — not yet executed

| Scenario in the disposable VM | Expected evidence |
| --- | --- |
| Official Discord login, renderer/GPU/audio children | Functional client, enrolled processes |
| Another ordinary or elevated user-mode process opens a guarded fixture file | Access denied, file counter increases |
| A new VM-write/thread-injection handle targets Discord | Documented dangerous rights stripped, handle counter increases |
| A trusted-source handle is duplicated into an untrusted process | Dangerous rights stripped |
| Broker is stopped during use | New user-mode file opens denied; no normal-launch fallback |
| Driver missing, port spoofed, wrong user/session or admin token | Launch rejected |
| Malformed messages, cancellation, repeated connect/disconnect, low resources | No crash or leak |
| Driver Verifier, HVCI, sleep/resume and repeated VM reboots | No bugchecks, deadlocks or resource leaks |
| Administrator explicitly unloads, then removes the layer | Successful documented recovery |

Use harmless fixture files and test processes, not live malware or real tokens.
Until this matrix passes, do not distribute the driver as protective software.

## Recovery/removal

Close Discord. In an elevated VM PowerShell:

```powershell
.\native\remove-vm.ps1
```

This stops the broker, unloads the minifilter, removes its two services and
restores ordinary isolated launching. Account and Discord data remain. If unload
fails, the required-driver policy remains set: revert the VM snapshot. Because
services are demand-start, rebooting also prevents automatic reloading, but
remove the lab configuration before resuming ordinary use.

## Verification actually performed

The driver and broker were compiled with Microsoft's x64 WDK/SDK and MSVC.
Native user-mode policy tests executed for scope boundaries, message ABI, broker
loss and duplicate-handle decisions. Python tests cover native-mode gating and
no-fallback behaviour. PowerShell is parsed without installing services.
**No driver load, VM runtime, real malware, updater or anti-tamper test has run.**
