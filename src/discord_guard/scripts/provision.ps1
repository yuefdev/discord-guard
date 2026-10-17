param([Parameter(Mandatory=$true)][string]$ConfigBase64)
$ErrorActionPreference = 'Stop'
$config = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ConfigBase64)) | ConvertFrom-Json
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator consent is required.'
}
$inputData = [Console]::In.ReadToEnd() | ConvertFrom-Json
$createdAccount = $false
$newProgramDir = $false
$newDataDir = $false
$newShortcut = $false

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class DiscordGuardDirectory {
    [StructLayout(LayoutKind.Sequential)]
    private struct Attributes {
        public int Length;
        public IntPtr Descriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool Inherit;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool CreateDirectoryW(string path, ref Attributes attributes);
    public static void Create(string path, byte[] descriptor) {
        IntPtr memory = Marshal.AllocHGlobal(descriptor.Length);
        try {
            Marshal.Copy(descriptor, 0, memory, descriptor.Length);
            Attributes attributes = new Attributes {
                Length=Marshal.SizeOf(typeof(Attributes)), Descriptor=memory, Inherit=false
            };
            if (!CreateDirectoryW(path, ref attributes))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        } finally { Marshal.FreeHGlobal(memory); }
    }
}
'@

function Assert-NoReparse([string]$Path) {
    $current = $Path
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse points are not permitted.' }
        }
        $parent = Split-Path -Parent $current
        if (-not $parent -or $parent -eq $current) { break }
        $current = $parent
    }
}

function New-SystemDirectory([string]$Path) {
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $security.SetOwner($admins)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl',
            'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $security.AddAccessRule($rule)
    }
    $read = [Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'ReadAndExecute',
        'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $security.AddAccessRule($read)
    # Apply the ACL in the CreateDirectory syscall; no world-writable creation window.
    [DiscordGuardDirectory]::Create($Path, $security.GetSecurityDescriptorBinaryForm())
}

try {
    if ($inputData.origin_sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw 'Invalid originating account.' }
    foreach ($path in @($config.program_dir, $config.data_dir, $config.shortcut_path)) { Assert-NoReparse $path }
    if ((Test-Path -LiteralPath $config.program_dir) -or (Test-Path -LiteralPath $config.data_dir)) {
        throw 'An installation or conflicting directory already exists. Inspect it before reinstalling.'
    }
    if (Get-LocalUser -Name 'DiscordGuard' -ErrorAction SilentlyContinue) {
        throw 'The DiscordGuard account already exists. Existing accounts are never taken over.'
    }
    if (Test-Path -LiteralPath $config.shortcut_path) { throw 'A conflicting shortcut already exists.' }
    if (-not (Test-Path -LiteralPath $config.source_exe -PathType Leaf)) { throw 'Launcher executable missing.' }
    if ($inputData.password.Length -lt 14) { throw 'Use a password with at least 14 characters.' }
    if (-not (Test-Path -LiteralPath $config.program_parent -PathType Container)) { throw 'Program Files is missing.' }
    if (-not (Test-Path -LiteralPath (Split-Path -Parent $config.data_dir) -PathType Container)) { throw 'ProgramData is missing.' }
    if (-not (Test-Path -LiteralPath (Split-Path -Parent $config.shortcut_path) -PathType Container)) { throw 'Start Menu is missing.' }

    $password = ConvertTo-SecureString -String $inputData.password -AsPlainText -Force
    $inputData.password = $null
    $user = New-LocalUser -Name 'DiscordGuard' -Password $password -Description 'DiscordGuard isolated Discord account v1'
    $password.Dispose()
    $createdAccount = $true
    $members = @(Get-LocalGroupMember -SID 'S-1-5-32-545')
    if (-not @($members | Where-Object {$_.SID.Value -eq $user.SID.Value}).Count) {
        Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user
    }

    New-SystemDirectory $config.program_dir
    $newProgramDir = $true
    New-SystemDirectory $config.data_dir
    $newDataDir = $true

    Copy-Item -LiteralPath $config.source_exe -Destination $config.installed_exe
    if ($config.source_internal) {
        Assert-NoReparse $config.source_internal
        Copy-Item -LiteralPath $config.source_internal -Destination (Join-Path $config.program_dir '_internal') -Recurse
    }
    foreach ($source in @($config.source_legal)) {
        if (-not $source) { continue }
        Assert-NoReparse $source
        $name = Split-Path -Leaf $source
        if ($name -notin @('LICENSE','THIRD_PARTY_NOTICES.md','SECURITY.md','source.zip','licences')) {
            throw 'Unexpected licence payload.'
        }
        Copy-Item -LiteralPath $source -Destination (Join-Path $config.program_dir $name) -Recurse
    }
    $policy = @{schema_version=1; account_name='DiscordGuard'; guard_sid=$user.SID.Value;
        origin_sid=$inputData.origin_sid; created_utc=[DateTime]::UtcNow.ToString('o')}
    [IO.File]::WriteAllText($config.policy_path, ($policy | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    Copy-Item -LiteralPath $config.uninstall_source -Destination (Join-Path $config.program_dir 'Uninstall.ps1')

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($config.shortcut_path)
    $shortcut.TargetPath = $config.installed_exe
    $shortcut.WorkingDirectory = $config.program_dir
    $shortcut.Description = 'DiscordGuard - isolated Discord session'
    $shortcut.Save()
    $newShortcut = $true
    @{ok=$true; account_name='DiscordGuard'; guard_sid=$user.SID.Value} | ConvertTo-Json -Compress
} catch {
    # Roll back only objects created in this invocation. Never remove an existing profile.
    if ($newShortcut) { Remove-Item -LiteralPath $config.shortcut_path -Force -ErrorAction SilentlyContinue }
    if ($newDataDir) { Remove-Item -LiteralPath $config.data_dir -Recurse -Force -ErrorAction SilentlyContinue }
    if ($newProgramDir) { Remove-Item -LiteralPath $config.program_dir -Recurse -Force -ErrorAction SilentlyContinue }
    if ($createdAccount) { Remove-LocalUser -Name 'DiscordGuard' -ErrorAction SilentlyContinue }
    @{ok=$false; error=$_.Exception.Message} | ConvertTo-Json -Compress
    exit 1
} finally {
    $inputData = $null
    if ($password) { $password.Dispose() }
}
