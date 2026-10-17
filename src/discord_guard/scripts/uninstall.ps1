# Run from an elevated PowerShell window after closing DiscordGuard.
# This removes the launcher only. It never deletes the Windows account or Discord data.
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open PowerShell as administrator first.'
}
$programs = [Environment]::GetFolderPath('ProgramFiles')
$data = [Environment]::GetFolderPath('CommonApplicationData')
$start = [Environment]::GetFolderPath('CommonPrograms')
$install = Join-Path $programs 'DiscordGuard'
$policyDir = Join-Path $data 'DiscordGuard'
$shortcut = Join-Path $start 'DiscordGuard.lnk'
if (-not [string]::Equals($PSScriptRoot, $install, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Run the installed Uninstall.ps1 from Program Files\DiscordGuard.'
}
foreach ($path in @($install, $policyDir, $shortcut)) {
    if (Test-Path -LiteralPath $path) {
        $item = Get-Item -LiteralPath $path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unexpected reparse point.' }
    }
}
$policy = Get-Content -LiteralPath (Join-Path $policyDir 'policy.json') -Raw | ConvertFrom-Json
if ($policy.schema_version -ne 1 -or $policy.account_name -ne 'DiscordGuard') { throw 'Unknown installation.' }
if ($policy.guardcore_required) { throw 'Remove the GuardCore VM driver with native\remove-vm.ps1 before removing the launcher.' }
if ($policy.guard_sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw 'Invalid protected account SID.' }
$hive = 'Registry::HKEY_USERS\' + $policy.guard_sid
$profileKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $policy.guard_sid
if ((Test-Path -LiteralPath $profileKey) -and -not (Test-Path -LiteralPath $hive)) {
    throw 'Sign into the DiscordGuard Windows account first, turn off automatic startup in DiscordGuard, then switch back here without signing out.'
}
if (Test-Path -LiteralPath $hive) {
    $runKey = $hive + '\Software\Microsoft\Windows\CurrentVersion\Run'
    if (Test-Path -LiteralPath $runKey) {
        $run = Get-ItemProperty -LiteralPath $runKey
        if ($null -ne $run.DiscordGuard) {
            throw 'Turn off automatic startup from the DiscordGuard application before uninstalling. Its previous Discord setting will be restored.'
        }
    }
}
$answer = Read-Host 'Remove the launcher? The Windows account and Discord data will remain. Type REMOVE'
if ($answer -cne 'REMOVE') { return }
if (Test-Path -LiteralPath $shortcut) { Remove-Item -LiteralPath $shortcut -Force }
foreach ($name in @('DiscordGuard.exe', 'Uninstall.ps1')) {
    $path = Join-Path $install $name
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
}
$internal=Join-Path $install '_internal'
if (Test-Path -LiteralPath $internal) {
    if ((Get-Item -LiteralPath $internal -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unexpected library reparse point.' }
    Remove-Item -LiteralPath $internal -Recurse -Force
}
Remove-Item -LiteralPath (Join-Path $policyDir 'policy.json') -Force
Remove-Item -LiteralPath $policyDir
Remove-Item -LiteralPath $install
'Launcher removed. Manage the separate account through Windows Settings > Accounts > Other users.'
