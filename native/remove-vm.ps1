$ErrorActionPreference='Stop'
$admin=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator consent required.' }
if (Get-Process -Name Discord -ErrorAction SilentlyContinue) { throw 'Close Discord completely first.' }
$install=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'DiscordGuard'
$policyPath=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'DiscordGuard\policy.json'
$policy=Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
if ($policy.account_name -ne 'DiscordGuard' -or -not $policy.guardcore_required) { throw 'GuardCore managed configuration not found.' }
Stop-Service DiscordGuardBroker -ErrorAction SilentlyContinue
& "$env:WINDIR\System32\fltmc.exe" unload GuardCore
if ($LASTEXITCODE -ne 0) { throw 'Unload failed. The required-driver policy remains set. Use the VM snapshot for recovery.' }
foreach ($name in @('DiscordGuardBroker','GuardCore')) {
    & "$env:WINDIR\System32\sc.exe" delete $name
    if ($LASTEXITCODE -ne 0) { throw 'Service removal incomplete. Keep the VM snapshot available.' }
}
$policy.PSObject.Properties.Remove('guardcore_required')
[IO.File]::WriteAllText($policyPath, ($policy | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
foreach ($name in @('GuardCore.sys','GuardCoreCtl.exe')) {
    Remove-Item -LiteralPath (Join-Path $install $name) -Force
}
'VM driver removed. Account, Discord installation and session data were preserved.'
