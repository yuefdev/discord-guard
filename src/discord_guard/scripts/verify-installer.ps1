param([Parameter(Mandatory=$true)][string]$ConfigBase64)
$ErrorActionPreference = 'Stop'
$config = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ConfigBase64)) | ConvertFrom-Json
$signature = Get-AuthenticodeSignature -LiteralPath $config.path
@{signature=$signature.Status.ToString(); signer=$signature.SignerCertificate.Subject} | ConvertTo-Json -Compress
