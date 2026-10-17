param([Parameter(Mandatory=$true)][string]$ConfigBase64)
$ErrorActionPreference = 'Stop'
$config = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ConfigBase64)) | ConvertFrom-Json
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
$createdProgram = $false
$createdData = $false
$createdRegistry = $false
$createdShortcut = $false
$createdServices = [Collections.Generic.List[string]]::new()
$backupProgram = $null
$backupData = $null
$savedShortcut = $null
$movedProgram = $false
$movedData = $false
$removedShortcut = $false

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class DiscordGuardServiceSetup {
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern IntPtr CreateServiceW(IntPtr manager, string name, string display,
        uint access, uint type, uint start, uint error, string command, string group,
        IntPtr tag, string dependencies, string account, string password);
    [DllImport("advapi32.dll")]
    private static extern bool CloseServiceHandle(IntPtr handle);
    public static void Create(string name, string display, string command, string account, string dependency) {
        IntPtr manager = OpenSCManagerW(null, null, 3);
        if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            IntPtr service = CreateServiceW(manager, name, display, 0xF01FF, 0x10, 2, 1,
                command, null, IntPtr.Zero, dependency == null ? null : dependency + "\0\0", account, null);
            if (service == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            CloseServiceHandle(service);
        } finally { CloseServiceHandle(manager); }
    }
}
'@

function Assert-NoReparse([string]$Path) {
    while ($Path) {
        if (Test-Path -LiteralPath $Path) {
            if ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Redirected installation paths are not accepted.'
            }
        }
        $parent = Split-Path -Parent $Path
        if (-not $parent -or $parent -eq $Path) { break }
        $Path = $parent
    }
}

function Invoke-ServiceCommand([string[]]$Arguments) {
    $output = & (Join-Path ([Environment]::SystemDirectory) 'sc.exe') @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Windows service configuration failed ($LASTEXITCODE)." }
}

function Assert-AdminOwned([string]$Path) {
    Assert-NoReparse $Path
    $acl = Get-Acl -LiteralPath $Path
    $trusted = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw 'Legacy installation owner is not trusted.' }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $trusted -and
            ([int64]$rule.FileSystemRights -band 0x500D0156)) { throw 'Legacy installation permits untrusted writes.' }
    }
}

try {
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Windows administrator consent is required.' }
    if ($config.origin_sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw 'Invalid originating identity.' }
    foreach ($path in @($config.program_dir, $config.data_dir, $config.shortcut_path)) { Assert-NoReparse $path }
    $legacy = $null
    if ((Test-Path -LiteralPath $config.program_dir) -or (Test-Path -LiteralPath $config.data_dir) -or
        (Test-Path -LiteralPath $config.shortcut_path)) {
        foreach ($path in @($config.program_parent, $config.program_dir, $config.data_dir, $config.policy_path, $config.installed_exe)) {
            Assert-AdminOwned $path
        }
        if ((Get-Item -LiteralPath $config.policy_path).Length -gt 16384) { throw 'Legacy policy is too large.' }
        $legacy = Get-Content -LiteralPath $config.policy_path -Raw | ConvertFrom-Json
        if ($legacy.schema_version -ne 1 -or $legacy.account_name -ne 'DiscordGuard' -or
            $legacy.origin_sid -ne $config.origin_sid -or $legacy.guardcore_required -eq $true) {
            throw 'Only a verified separate-account installation can be migrated automatically.'
        }
        $account = Get-LocalUser -Name DiscordGuard -ErrorAction Stop
        if ($account.SID.Value -ne $legacy.guard_sid -or $account.Description -ne 'DiscordGuard isolated Discord account v1') {
            throw 'Legacy account ownership is not verified.'
        }
        foreach ($root in @($config.program_dir, $config.data_dir)) {
            foreach ($item in @(Get-ChildItem -LiteralPath $root -Recurse -Force)) { Assert-AdminOwned $item.FullName }
        }
        foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name='DiscordGuard.exe'")) {
            if ($process.ExecutablePath -eq $config.installed_exe) { throw 'Close the installed old DiscordGuard window, then retry this setup.' }
        }
        if (Test-Path -LiteralPath $config.shortcut_path) {
            $shell = New-Object -ComObject WScript.Shell
            if ($shell.CreateShortcut($config.shortcut_path).TargetPath -ne $config.installed_exe) { throw 'Conflicting shortcut was preserved.' }
        }
    }
    $registry = 'HKLM:\SOFTWARE\DiscordGuard\Desktop'
    if (Test-Path -LiteralPath $registry) { throw 'A desktop service configuration already exists.' }
    foreach ($name in @('DiscordGuardIdentity','DiscordGuardDesktop')) {
        if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw 'A conflicting Windows service already exists.' }
    }
    foreach ($source in @($config.source_exe, $config.source_helper, $config.uninstall_source, $config.replacement_source)) {
        Assert-NoReparse $source
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'Setup payload is incomplete.' }
    }
    if ($legacy) {
        $suffix = '.legacy-' + [Guid]::NewGuid().ToString('N')
        $backupProgram = $config.program_dir + $suffix
        $backupData = $config.data_dir + $suffix
        Move-Item -LiteralPath $config.program_dir -Destination $backupProgram
        $movedProgram = $true
        Move-Item -LiteralPath $config.data_dir -Destination $backupData
        $movedData = $true
        if (Test-Path -LiteralPath $config.shortcut_path) {
            $savedShortcut = Join-Path $backupData ('shortcut-' + [Guid]::NewGuid().ToString('N') + '.lnk')
            Copy-Item -LiteralPath $config.shortcut_path -Destination $savedShortcut
            Remove-Item -LiteralPath $config.shortcut_path -Force
            $removedShortcut = $true
        }
    }
    # Reuse the atomic, admin-owned directory constructor from the account setup
    # without invoking any account-creation code.
    $definition = [IO.File]::ReadAllText($config.directory_helper_source)
    $match = [regex]::Match($definition, "(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@")
    if (-not $match.Success) { throw 'Atomic directory helper is unavailable.' }
    Add-Type -TypeDefinition $match.Groups[1].Value
    foreach ($path in @($config.program_dir, $config.data_dir)) {
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $security.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)')
        [DiscordGuardDirectory]::Create($path, $security.GetSecurityDescriptorBinaryForm())
        if ($path -eq $config.program_dir) { $createdProgram = $true } else { $createdData = $true }
    }
    Copy-Item -LiteralPath $config.source_exe -Destination $config.installed_exe
    $helper = Join-Path $config.program_dir 'DiscordGuardSession.exe'
    Copy-Item -LiteralPath $config.source_helper -Destination $helper
    if ($config.source_internal) {
        Assert-NoReparse $config.source_internal
        foreach ($item in @(Get-ChildItem -LiteralPath $config.source_internal -Force -Recurse)) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected dependency refused.' }
        }
        Copy-Item -LiteralPath $config.source_internal -Destination (Join-Path $config.program_dir '_internal') -Recurse
    }
    foreach ($source in @($config.source_legal)) {
        Assert-NoReparse $source
        $name = Split-Path -Leaf $source
        if ($name -notin @('LICENSE','THIRD_PARTY_NOTICES.md','SECURITY.md','source.zip','licences')) { throw 'Unexpected licence payload.' }
        Copy-Item -LiteralPath $source -Destination (Join-Path $config.program_dir $name) -Recurse
    }
    Copy-Item -LiteralPath $config.uninstall_source -Destination (Join-Path $config.program_dir 'Uninstall.ps1')
    Copy-Item -LiteralPath $config.replacement_source -Destination (Join-Path $config.program_dir 'ReplaceDiscord.ps1')
    New-Item -Path $registry -Force | Out-Null
    $createdRegistry = $true
    New-ItemProperty -LiteralPath $registry -Name OriginSid -Value $config.origin_sid -PropertyType String | Out-Null
    $policy = @{schema_version=2; backend='desktop_service'; origin_sid=$config.origin_sid;
        created_utc=[DateTime]::UtcNow.ToString('o')}
    if ($legacy) { $policy.legacy_backup_program = $backupProgram; $policy.legacy_backup_data = $backupData }
    [IO.File]::WriteAllText($config.policy_path, ($policy | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    [DiscordGuardServiceSetup]::Create('DiscordGuardIdentity','DiscordGuard private identity',
        ('"' + $helper + '" --identity-service'),'NT SERVICE\DiscordGuardIdentity',$null)
    $createdServices.Add('DiscordGuardIdentity')
    Invoke-ServiceCommand -Arguments @('privs','DiscordGuardIdentity','SeChangeNotifyPrivilege')
    [DiscordGuardServiceSetup]::Create('DiscordGuardDesktop','DiscordGuard desktop broker',
        ('"' + $helper + '" --broker-service'),'LocalSystem','DiscordGuardIdentity')
    $createdServices.Add('DiscordGuardDesktop')
    Start-Service -Name DiscordGuardIdentity
    (Get-Service -Name DiscordGuardIdentity).WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
    Start-Service -Name DiscordGuardDesktop
    (Get-Service -Name DiscordGuardDesktop).WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($config.shortcut_path)
    $shortcut.TargetPath = $config.installed_exe
    $shortcut.WorkingDirectory = $config.program_dir
    $shortcut.Description = 'DiscordGuard - automatic private Discord desktop'
    $shortcut.Save()
    $createdShortcut = $true
    @{ok=$true; backend='desktop_service'} | ConvertTo-Json -Compress
} catch {
    $message = $_.Exception.Message
    foreach ($name in @('DiscordGuardDesktop','DiscordGuardIdentity')) {
        if ($createdServices.Contains($name)) {
            Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
            & (Join-Path ([Environment]::SystemDirectory) 'sc.exe') delete $name | Out-Null
        }
    }
    if ($createdShortcut) { Remove-Item -LiteralPath $config.shortcut_path -Force -ErrorAction SilentlyContinue }
    if ($createdRegistry) { Remove-Item -LiteralPath $registry -Recurse -Force -ErrorAction SilentlyContinue }
    if ($createdData) { Remove-Item -LiteralPath $config.data_dir -Recurse -Force -ErrorAction SilentlyContinue }
    if ($createdProgram) { Remove-Item -LiteralPath $config.program_dir -Recurse -Force -ErrorAction SilentlyContinue }
    if ($removedShortcut -and $savedShortcut) { Copy-Item -LiteralPath $savedShortcut -Destination $config.shortcut_path -ErrorAction SilentlyContinue }
    if ($movedData -and -not (Test-Path -LiteralPath $config.data_dir)) {
        Move-Item -LiteralPath $backupData -Destination $config.data_dir -ErrorAction SilentlyContinue
    }
    if ($movedProgram -and -not (Test-Path -LiteralPath $config.program_dir)) {
        Move-Item -LiteralPath $backupProgram -Destination $config.program_dir -ErrorAction SilentlyContinue
    }
    if (($movedProgram -and (Test-Path -LiteralPath $backupProgram)) -or ($movedData -and (Test-Path -LiteralPath $backupData))) {
        $message += ' Previous installation backup was retained; automatic restoration needs inspection.'
    }
    # Virtual-account profiles may contain data; rollback never deletes profiles.
    @{ok=$false; error=$message} | ConvertTo-Json -Compress
    exit 1
}
