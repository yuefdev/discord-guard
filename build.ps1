param([string]$OutputRoot = $PSScriptRoot, [ValidateSet('onefile','onedir')][string]$Layout='onefile')
$ErrorActionPreference = 'Stop'
if ((Get-Location).Path -ne $PSScriptRoot) { throw 'Run this script from the discord-guard project directory.' }
$env:PYTHONDONTWRITEBYTECODE = '1'
python -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { throw 'Tests failed. Packaging stopped.' }
& (Join-Path $PSScriptRoot 'tools\build-app.ps1') -OutputRoot $OutputRoot -Layout $Layout
