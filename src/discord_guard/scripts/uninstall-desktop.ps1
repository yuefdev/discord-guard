# Removes only the desktop broker installation. Private Discord data is retained.
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run as administrator.' }
$program = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'DiscordGuard'
if ($PSScriptRoot -ne $program) { throw 'Run the installed uninstaller.' }
$data = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'DiscordGuard'
$policy = Get-Content -LiteralPath (Join-Path $data 'policy.json') -Raw | ConvertFrom-Json
if ($policy.schema_version -ne 2 -or $policy.backend -ne 'desktop_service') { throw 'Desktop installation not verified.' }
$run = 'Registry::HKEY_USERS\' + $policy.origin_sid + '\Software\Microsoft\Windows\CurrentVersion\Run'
$restore = 'Registry::HKEY_USERS\' + $policy.origin_sid + '\Software\DiscordGuard\Startup'
if (-not (Test-Path -LiteralPath ('Registry::HKEY_USERS\' + $policy.origin_sid))) { throw 'Sign into the installing user before removal.' }
if ((Get-ItemProperty -LiteralPath $run -Name DiscordGuard -ErrorAction SilentlyContinue) -or
    (Get-ItemProperty -LiteralPath $restore -Name RestoreState -ErrorAction SilentlyContinue)) {
    throw 'First disable checked startup in DiscordGuard. An uninstalled Discord startup entry is not restored.'
}
Write-Host 'Close private Discord and DiscordGuard first. Service removal retains Discord login data.'
if ((Read-Host 'Type REMOVE to remove the launcher and services') -cne 'REMOVE') { return }
$identity = [Security.Principal.NTAccount]::new('NT SERVICE','DiscordGuardIdentity').Translate([Security.Principal.SecurityIdentifier]).Value
foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name='Discord.exe'")) {
    $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
    if ($owner.Sid -eq $identity) { throw 'Close the private Discord process before uninstalling.' }
}
$replacementKey = 'Registry::HKEY_USERS\' + $policy.origin_sid + '\Software\DiscordGuard\Replacement'
if (Get-ItemProperty -LiteralPath $replacementKey -Name State -ErrorAction SilentlyContinue) {
    $cleanupScript = Join-Path $program 'ReplaceDiscord.ps1'
    $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{origin_sid=$policy.origin_sid} | ConvertTo-Json -Compress)))
    $cleanup = & $cleanupScript -ConfigBase64 $payload -RemoveShortcuts | ConvertFrom-Json
    if (-not $cleanup -or $cleanup.ok -ne $true) { throw 'Replacement shortcut cleanup failed; launcher and services were retained.' }
}
foreach ($name in @('DiscordGuardDesktop','DiscordGuardIdentity')) {
    $service = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($service) {
        Stop-Service -Name $name -ErrorAction Stop
        $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
        & (Join-Path ([Environment]::SystemDirectory) 'sc.exe') delete $name | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Service removal failed; installation retained.' }
    }
}
Remove-Item -LiteralPath 'HKLM:\SOFTWARE\DiscordGuard\Desktop' -Recurse -Force
$shortcut = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'DiscordGuard.lnk'
if (Test-Path -LiteralPath $shortcut) { Remove-Item -LiteralPath $shortcut -Force }
Remove-Item -LiteralPath $data -Recurse -Force
Remove-Item -LiteralPath $program -Recurse -Force
Write-Host 'Services and owned replacement shortcuts removed. Private Discord data was retained. The old application was not reinstalled.'
