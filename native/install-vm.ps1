param(
    [Parameter(Mandatory=$true)][string]$Artifacts,
    [Parameter(Mandatory=$true)][string]$DiscordImage,
    [Parameter(Mandatory=$true)][switch]$DisposableVm
)
$ErrorActionPreference = 'Stop'
$admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run inside the disposable VM as administrator.' }
$computer = Get-CimInstance Win32_ComputerSystem
if (-not $DisposableVm -or ("$($computer.Manufacturer) $($computer.Model)" -notmatch 'Virtual|VMware|QEMU|KVM|Xen|Parallels')) {
    throw 'This research installer is restricted to a disposable Windows VM.'
}
$install = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'DiscordGuard'
$policyPath = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'DiscordGuard\policy.json'
if (-not (Test-Path -LiteralPath $install -PathType Container)) { throw 'Install DiscordGuard in the VM first.' }
$policyText = Get-Content -LiteralPath $policyPath -Raw
$policy = $policyText | ConvertFrom-Json
if ($policy.account_name -ne 'DiscordGuard' -or $policy.guard_sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') {
    throw 'Managed isolated account not found.'
}
if ($policy.guardcore_required) { throw 'GuardCore is already selected. Remove its VM installation first.' }
if ((Get-Service -Name GuardCore,DiscordGuardBroker -ErrorAction SilentlyContinue)) { throw 'Conflicting driver/service already exists.' }
foreach ($name in @('GuardCore.sys','GuardCoreCtl.exe')) {
    if (-not (Test-Path -LiteralPath (Join-Path $Artifacts $name) -PathType Leaf)) { throw "Missing $name" }
    if (Test-Path -LiteralPath (Join-Path $install $name)) { throw "Existing $name is never overwritten." }
}
$driverSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $Artifacts 'GuardCore.sys')
if ($driverSignature.Status -ne 'Valid') { throw 'An embedded test-signed driver, trusted by the prepared VM, is required. This script changes no signing settings.' }
if ((Get-AuthenticodeSignature -LiteralPath $DiscordImage).Status -ne 'Valid') { throw 'Install official Discord inside the protected account first.' }
if (Get-Process -Name Discord -ErrorAction SilentlyContinue) { throw 'Close Discord completely before arming the VM driver.' }

function Invoke-ServiceControl([string[]]$Arguments) {
    & "$env:WINDIR\System32\sc.exe" @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'Windows service operation failed.' }
}
$createdDriver=$false; $createdBroker=$false; $policyChanged=$false; $copied=@()
try {
    foreach ($name in @('GuardCore.sys','GuardCoreCtl.exe')) {
        $target = Join-Path $install $name
        Copy-Item -LiteralPath (Join-Path $Artifacts $name) -Destination $target
        $copied += $target
    }
    $driver = Join-Path $install 'GuardCore.sys'
    Invoke-ServiceControl -Arguments @('create','GuardCore','type=','filesys','start=','demand','binPath=',('"'+$driver+'"'),'group=','FSFilter Activity Monitor','depend=','FltMgr')
    $createdDriver=$true
    # Laboratory altitude only. Production distribution requires Microsoft's allocation.
    $base='HKLM:\SYSTEM\CurrentControlSet\Services\GuardCore'
    foreach ($relative in @('Instances','Parameters\Instances')) {
        $key = Join-Path $base $relative
        New-Item -Path (Join-Path $key 'GuardCoreLab') -Force | Out-Null
        New-ItemProperty -LiteralPath $key -Name DefaultInstance -Value 'GuardCoreLab' -PropertyType String -Force | Out-Null
        New-ItemProperty -LiteralPath (Join-Path $key 'GuardCoreLab') -Name Altitude -Value '385201.4242' -PropertyType String -Force | Out-Null
        New-ItemProperty -LiteralPath (Join-Path $key 'GuardCoreLab') -Name Flags -Value 0 -PropertyType DWord -Force | Out-Null
    }
    $broker = Join-Path $install 'GuardCoreCtl.exe'
    if ($DiscordImage.Contains('"')) { throw 'Invalid image path.' }
    $command = '"'+$broker+'" --service --sid '+$policy.guard_sid+' --image "'+$DiscordImage+'"'
    Invoke-ServiceControl -Arguments @('create','DiscordGuardBroker','type=','own','start=','demand','binPath=',$command,'obj=','LocalSystem','depend=','GuardCore')
    $createdBroker=$true
    $policy | Add-Member -NotePropertyName guardcore_required -NotePropertyValue $true -Force
    [IO.File]::WriteAllText($policyPath, ($policy | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    $policyChanged=$true
    Start-Service GuardCore
    Start-Service DiscordGuardBroker
    & $broker --query
    if ($LASTEXITCODE -ne 0) { throw 'Broker did not report a live configured driver.' }
    'VM driver armed. In the isolated Windows account, launch through DiscordGuard. Both services use demand start.'
} catch {
    if ($createdBroker) { Stop-Service DiscordGuardBroker -ErrorAction SilentlyContinue; & "$env:WINDIR\System32\sc.exe" delete DiscordGuardBroker | Out-Null }
    if ($createdDriver) {
        & "$env:WINDIR\System32\fltmc.exe" unload GuardCore | Out-Null
        $unloaded = $LASTEXITCODE -eq 0 -or -not (Get-Service GuardCore -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'})
        if (-not $unloaded) { throw 'Rollback incomplete: driver still loaded. Keep the VM isolated and use its snapshot. The launcher remains fail-closed.' }
        & "$env:WINDIR\System32\sc.exe" delete GuardCore | Out-Null
    }
    if ($policyChanged) { [IO.File]::WriteAllText($policyPath, $policyText, [Text.UTF8Encoding]::new($false)) }
    foreach ($path in $copied) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
    throw
}
