param([Parameter(Mandatory=$true)][string]$Artifact)
$ErrorActionPreference = 'Stop'
$target = (Resolve-Path -LiteralPath $Artifact -ErrorAction Stop).Path
$status = Get-MpComputerStatus -ErrorAction Stop
if (-not $status.AntivirusEnabled -or -not $status.RealTimeProtectionEnabled) {
    throw 'Defender scan gate is unavailable. The build cannot be marked ready for distribution.'
}
$scanner = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Windows Defender\MpCmdRun.exe'
if (-not (Test-Path -LiteralPath $scanner -PathType Leaf)) { throw 'Microsoft Defender scanner is unavailable.' }
$started = (Get-Date).AddSeconds(-2)
& $scanner -Scan -ScanType 3 -File $target
if ($LASTEXITCODE -ne 0) { throw "Defender scan failed or reported a threat (exit $LASTEXITCODE)." }
$detections = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object {
    ($_.InitialDetectionTime -ge $started -or $_.LastThreatStatusChangeTime -ge $started) -and
    (($_.Resources -join ' ') -match 'DiscordGuard|discord-guard')
})
if ($detections.Count -or -not (Test-Path -LiteralPath $target)) {
    throw 'Defender detected or removed a DiscordGuard artifact. Publication stopped; review the detection with Microsoft.'
}
Write-Host 'Defender custom scan completed without a new DiscordGuard detection.'
