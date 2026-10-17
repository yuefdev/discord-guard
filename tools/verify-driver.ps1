param([Parameter(Mandatory=$true)][string]$Driver,[Parameter(Mandatory=$true)][string]$SignTool)
$ErrorActionPreference='Stop'
if (-not (Test-Path -LiteralPath $Driver -PathType Leaf) -or -not (Test-Path -LiteralPath $SignTool -PathType Leaf)) { throw 'Driver/signing tool missing.' }
& $SignTool verify /kp /all /v $Driver
if ($LASTEXITCODE -ne 0) { throw 'Windows kernel-policy signature verification failed.' }
$signature=Get-AuthenticodeSignature -LiteralPath $Driver
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation(?:,|$)') {
    throw 'A valid Microsoft-returned embedded driver signature is required, not only a local test certificate.'
}
'Kernel-policy signature checks passed. Runtime, HVCI, HLK, package and recovery tests are still required.'
