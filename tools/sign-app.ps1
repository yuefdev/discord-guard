param(
    [Parameter(Mandatory=$true)][string]$Artifact,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$CertificateThumbprint,
    [Parameter(Mandatory=$true)][string]$SignTool,
    [ValidateSet('CurrentUser','LocalMachine')][string]$StoreLocation='CurrentUser',
    [string]$TimestampUrl='https://timestamp.digicert.com'
)
$ErrorActionPreference='Stop'
foreach ($name in @('Microsoft.PowerShell.Security','Microsoft.PowerShell.Utility')) {
    Import-Module -Name ([IO.Path]::Combine($PSHOME, "Modules\$name\$name.psd1")) -Force -ErrorAction Stop
}
if (-not (Test-Path -LiteralPath $Artifact -PathType Leaf)) { throw 'Artifact not found.' }
if (-not (Test-Path -LiteralPath $SignTool -PathType Leaf)) { throw 'Supply the SDK signtool.exe path.' }
if ([IO.Path]::GetExtension($Artifact) -notin @('.exe','.dll','.cab','.cat')) { throw 'Use Microsoft dashboard signing for the kernel SYS; this tool signs publisher artifacts only.' }
$uri=[uri]$TimestampUrl
if ($uri.Scheme -ne 'https' -or $uri.UserInfo) { throw 'Use an HTTPS RFC3161 timestamp endpoint.' }
$certificate=Get-Item -LiteralPath ("Cert:\$StoreLocation\My\$CertificateThumbprint")
if (-not $certificate.HasPrivateKey -or $certificate.NotAfter -lt (Get-Date)) { throw 'An unexpired signing certificate with an accessible private key is required.' }
if (-not @($certificate.EnhancedKeyUsageList | Where-Object {$_.ObjectId.Value -eq '1.3.6.1.5.5.7.3.3'}).Count) { throw 'Certificate is not enabled for code signing.' }
$arguments=@('sign','/sha1',$CertificateThumbprint,'/s','My','/fd','SHA256','/tr',$TimestampUrl,'/td','SHA256')
if ($StoreLocation -eq 'LocalMachine') { $arguments+='/sm' }
& $SignTool @arguments $Artifact
if ($LASTEXITCODE -ne 0) { throw 'Authenticode signing failed.' }
& $SignTool verify /pa /all /tw /v $Artifact
if ($LASTEXITCODE -ne 0) { throw 'Signature/timestamp verification failed.' }
'Publisher signature verified. This does not provide Microsoft kernel acceptance or guarantee SmartScreen reputation.'
