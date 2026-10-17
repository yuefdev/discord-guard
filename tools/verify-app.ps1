param(
    [Parameter(Mandatory=$true)][string]$Artifact,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$CertificateThumbprint,
    [Parameter(Mandatory=$true)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version
)
$ErrorActionPreference = 'Stop'
# A PowerShell 7 parent can pass its module path to Windows PowerShell 5.1.
# Resolve signature/hash commands from this host's modules, not the inherited path.
foreach ($name in @('Microsoft.PowerShell.Security','Microsoft.PowerShell.Utility')) {
    Import-Module -Name ([IO.Path]::Combine($PSHOME, "Modules\$name\$name.psd1")) -Force -ErrorAction Stop
}
if (-not (Test-Path -LiteralPath $Artifact -PathType Leaf)) { throw 'Signed artifact not found.' }
if ((Get-Item -LiteralPath $Artifact -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Redirected signed artifact refused.' }
$signature = Get-AuthenticodeSignature -LiteralPath $Artifact
if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or
    $signature.SignerCertificate.Thumbprint -ne $CertificateThumbprint) {
    throw 'Artifact is not trusted or was not signed by the expected certificate.'
}
if (-not $signature.TimeStamperCertificate) { throw 'A trusted timestamp is required.' }
$metadata = [Diagnostics.FileVersionInfo]::GetVersionInfo([IO.Path]::GetFullPath($Artifact))
if ($metadata.ProductName -cne 'DiscordGuard' -or $metadata.ProductVersion -cne $Version -or
    $metadata.FileVersion -cne $Version -or $metadata.OriginalFilename -cne [IO.Path]::GetFileName($Artifact)) {
    throw 'Signed artifact metadata does not match this DiscordGuard release.'
}
@{valid=$true; timestamped=$true; certificate_thumbprint=$signature.SignerCertificate.Thumbprint;
  product=$metadata.ProductName; version=$metadata.ProductVersion;
  sha256=(Get-FileHash -LiteralPath $Artifact -Algorithm SHA256).Hash.ToLowerInvariant()} | ConvertTo-Json -Compress
