param([Parameter(Mandatory=$true)][string]$ConfigBase64)
$ErrorActionPreference = 'Stop'
$config = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ConfigBase64)) | ConvertFrom-Json

function Get-AccessInfo([string]$Path) {
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return @{exists=$false} }
        $item = Get-Item -LiteralPath $Path -Force
        $acl = Get-Acl -LiteralPath $Path
        $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
            @{sid=$_.IdentityReference.Value;
              rights=[int]$_.FileSystemRights; type=$_.AccessControlType.ToString();
              inherit_only=[bool]($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)}
        })
        return @{exists=$true; owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;
            reparse=[bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint); rules=$rules}
    } catch { return @{exists=$false; error='ACL could not be verified'} }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$current = @{sid=$identity.User.Value;
    elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);
    session_id=(Get-Process -Id $PID).SessionId; session_sid=$null}
# A process token alone does not prove a separate desktop: runas retains the
# original user's session. Resolve the actual interactive session owner via WTS.
try {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class DiscordGuardSession {
    [DllImport("wtsapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool WTSQuerySessionInformationW(IntPtr server, int session,
        int info, out IntPtr buffer, out int bytes);
    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);
    public static string Query(int session, int info) {
        IntPtr buffer = IntPtr.Zero;
        int bytes;
        try {
            if (!WTSQuerySessionInformationW(IntPtr.Zero, session, info, out buffer, out bytes))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (buffer == IntPtr.Zero || bytes < 2) throw new InvalidOperationException("No session owner");
            return Marshal.PtrToStringUni(buffer);
        } finally { if (buffer != IntPtr.Zero) WTSFreeMemory(buffer); }
    }
}
'@
    $sessionUser = [DiscordGuardSession]::Query($current.session_id, 5)
    $sessionDomain = [DiscordGuardSession]::Query($current.session_id, 7)
    if (-not $sessionUser -or -not $sessionDomain) { throw 'Session owner is unavailable' }
    $sessionAccount = [Security.Principal.NTAccount]::new($sessionDomain, $sessionUser)
    $current.session_sid = $sessionAccount.Translate([Security.Principal.SecurityIdentifier]).Value
} catch {}
$result = @{windows=$true; current=$current; policy=$null; system_acls=@{};
    account=@{}; client=@{}; profile_acls=@(); client_running=$null;
    fast_switching_disabled=$null; defender=@{}; hardening=@{}}

$result.system_acls = @{
    program_parent=(Get-AccessInfo $config.program_parent)
    program_dir=(Get-AccessInfo $config.program_dir)
    app=(Get-AccessInfo $config.installed_exe)
    data_dir=(Get-AccessInfo $config.data_dir)
    policy=(Get-AccessInfo $config.policy_path)
}
try {
    if ((Get-Item -LiteralPath $config.policy_path).Length -gt 16384) { throw 'Policy too large' }
    $result.policy = Get-Content -LiteralPath $config.policy_path -Raw | ConvertFrom-Json
} catch {}
if ($result.policy -and $result.policy.guardcore_required -eq $true) {
    $result.system_acls.native_helper = Get-AccessInfo (Join-Path $config.program_dir 'GuardCoreCtl.exe')
}
if ($result.policy -and $result.policy.backend -eq 'desktop_service') {
    $result.system_acls.desktop_helper = Get-AccessInfo (Join-Path $config.program_dir 'DiscordGuardSession.exe')
}
try {
    $user = Get-LocalUser -Name 'DiscordGuard' -ErrorAction Stop
    $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
    $result.account = @{sid=$user.SID.Value; enabled=[bool]$user.Enabled;
        description=$user.Description;
        admin_member=[bool](@($admins | Where-Object {$_.SID.Value -eq $user.SID.Value}).Count)}
} catch {}
try {
    $switching = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
    $result.fast_switching_disabled = [bool]($switching.HideFastUserSwitching -eq 1)
} catch {}
try {
    $status = Get-MpComputerStatus -ErrorAction Stop
    $result.defender = @{realtime=[bool]$status.RealTimeProtectionEnabled;
        behavior=[bool]$status.BehaviorMonitorEnabled; antivirus=[bool]$status.AntivirusEnabled}
    $result.hardening.tamper_protection = [bool]$status.IsTamperProtected
} catch {}
try {
    $boot = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction Stop
    if ($null -ne $boot.UEFISecureBootEnabled) {
        $result.hardening.secure_boot_registry = [bool]($boot.UEFISecureBootEnabled -eq 1)
    }
} catch {}
try {
    $uac = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
    $result.hardening.uac = @{enabled=[bool]($uac.EnableLUA -eq 1);
        secure_desktop=[bool]($uac.PromptOnSecureDesktop -eq 1); admin_prompt=$uac.ConsentPromptBehaviorAdmin}
} catch {}
try {
    $guard = @(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop)
    if ($guard.Count -eq 1) {
        $result.hardening.vbs = @{status=[int]$guard[0].VirtualizationBasedSecurityStatus;
            services_running=@($guard[0].SecurityServicesRunning | ForEach-Object { [int]$_ });
            umci=[int]$guard[0].UsermodeCodeIntegrityPolicyEnforcementStatus;
            kernel_ci=[int]$guard[0].CodeIntegrityPolicyEnforcementStatus}
    }
} catch {}

try {
    $processes = @(Get-CimInstance Win32_Process -Filter "Name='Discord.exe'" -ErrorAction Stop)
    $result.client_running = [bool](@($processes | Where-Object {$_.SessionId -eq $current.session_id}).Count)
} catch {}

function Get-TreePaths([string]$Root, [int]$Limit=20000) {
    $paths = [Collections.Generic.List[string]]::new()
    $stack = [Collections.Generic.Stack[string]]::new()
    $paths.Add($Root)
    $rootItem = Get-Item -LiteralPath $Root -Force
    if (-not ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $stack.Push($Root) }
    while ($stack.Count) {
        foreach ($child in @(Get-ChildItem -LiteralPath $stack.Pop() -Force -ErrorAction Stop)) {
            $paths.Add($child.FullName)
            if ($paths.Count -gt $Limit) { throw 'Too many files for bounded ACL inspection' }
            if ($child.PSIsContainer -and -not ($child.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                $stack.Push($child.FullName)
            }
        }
    }
    return $paths.ToArray()
}

function Get-DesktopClient([string]$Root, [bool]$FullAcl) {
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return @{found=$false} }
    try {
        $versions = @(Get-ChildItem -LiteralPath $Root -Directory -Force | Where-Object {
            $_.Name -match '^app-\d+\.\d+\.\d+$'
        } | Sort-Object { [version]$_.Name.Substring(4) } -Descending)
        if (-not $versions.Count) { return @{found=$false} }
        $active=$versions[0].FullName
        $binary=Join-Path $active 'Discord.exe'
        $signature=Get-AuthenticodeSignature -LiteralPath $binary
        $clientPaths=@($Root,$active,$binary)
        if ($FullAcl) { $clientPaths=@($Root) + @(Get-TreePaths $active) }
        $updater=Join-Path $Root 'Update.exe'
        if (Test-Path -LiteralPath $updater) { $clientPaths+=$updater }
        $cores=@(Get-ChildItem -LiteralPath (Join-Path $active 'modules') -Directory | Where-Object {
            $_.Name -match '^discord_desktop_core-\d+$'
        })
        $entryClean=$false
        if ($cores.Count -eq 1 -and -not (Test-Path -LiteralPath (Join-Path $active 'resources\app'))) {
            $entry=Join-Path $cores[0].FullName 'discord_desktop_core\index.js'
            $archive=Join-Path $cores[0].FullName 'discord_desktop_core\core.asar'
            $appArchive=Join-Path $active 'resources\app.asar'
            if ((Get-Item -LiteralPath $entry).Length -lt 512 -and
                (Test-Path -LiteralPath $archive -PathType Leaf) -and
                (Test-Path -LiteralPath $appArchive -PathType Leaf)) {
                $entryClean=(Get-Content -LiteralPath $entry -Raw) -cmatch '^\s*module\.exports\s*=\s*require\(\s*[''"]\./core\.asar[''"]\s*\)\s*;?\s*$'
                $clientPaths+=@($entry,$archive,$appArchive,(Split-Path -Parent $entry),$cores[0].FullName,(Join-Path $active 'modules'),(Join-Path $active 'resources'))
            }
        }
        return @{found=$true; path=$binary; version=$versions[0].Name.Substring(4);
            signature=$signature.Status.ToString(); signer=$signature.SignerCertificate.Subject;
            entry_clean=[bool]$entryClean;
            acls=@($clientPaths | Sort-Object -Unique | ForEach-Object { Get-AccessInfo $_ })}
    } catch { return @{found=$true; error='Desktop client inspection failed'} }
}

if (-not ($result.policy -and $result.policy.guardcore_required)) {
    $result.installed_discord=Get-DesktopClient $config.discord_install_root $false
}

if ($result.policy -and $current.sid -eq $result.policy.guard_sid -and -not $result.policy.guardcore_required) {
    try {
        $registered = Get-ItemProperty -LiteralPath ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + $current.sid)
        $profile = [Environment]::ExpandEnvironmentVariables($registered.ProfileImagePath)
        $expected = Join-Path $profile 'AppData\Roaming\discord'
        $expectedInstall = Join-Path $profile 'AppData\Local\Discord'
        $expectedStaging = Join-Path $profile 'AppData\Local\DiscordGuard\Installers'
        if (-not [string]::Equals($expected, $config.discord_profile, [StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals($expectedInstall, $config.discord_install_root, [StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals($expectedStaging, $config.staging, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Profile path does not match the registered Windows profile'
        }
        $paths = @($profile, (Join-Path $profile 'AppData'), (Join-Path $profile 'AppData\Local'),
            (Join-Path $profile 'AppData\Roaming'), (Join-Path $profile 'AppData\Local\DiscordGuard'),
            $expectedStaging, $expected)
        foreach ($relative in @('Local State','settings.json')) {
            $candidate = Join-Path $expected $relative
            if (Test-Path -LiteralPath $candidate) { $paths += $candidate }
        }
        # Check individual storage files too. Private parent directories alone do
        # not override a permissive child ACL when traverse checking is bypassed.
        foreach ($relative in @('Local Storage','Session Storage','Network','Service Worker','IndexedDB')) {
            $store = Join-Path $expected $relative
            if (-not (Test-Path -LiteralPath $store)) { continue }
            $paths += Get-TreePaths $store 10000
        }
        $paths = @($paths | Sort-Object -Unique)
        $result.profile_acls = @($paths | ForEach-Object { Get-AccessInfo $_ })
        $result.registered_profile=$profile
        $result.client=Get-DesktopClient $expectedInstall $true
        $result.installed_discord=$result.client
    } catch { $result.profile_acls=@() }
}
$result | ConvertTo-Json -Depth 10 -Compress
