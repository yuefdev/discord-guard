param([string]$OutputRoot = $PSScriptRoot, [ValidateSet('onefile','onedir')][string]$Layout='onefile')
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $PSScriptRoot -PathType Container)) { throw 'Project directory missing.' }
if ((Get-Location).Path -ne $PSScriptRoot) { throw 'Run this script from the discord-guard project directory.' }
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
if (-not (Test-Path -LiteralPath $OutputRoot -PathType Container)) {
    if (-not (Test-Path -LiteralPath (Split-Path -Parent $OutputRoot) -PathType Container)) { throw 'Output parent directory missing.' }
    New-Item -ItemType Directory -Path $OutputRoot | Out-Null
}
$env:PYTHONDONTWRITEBYTECODE = '1'
python -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { throw 'Tests failed. Packaging stopped.' }
$spec = Join-Path $OutputRoot 'spec'
$work = Join-Path $OutputRoot 'build'
$dist = Join-Path $OutputRoot 'dist'
python -m PyInstaller --noconfirm --clean "--$Layout" --windowed --name DiscordGuard --specpath $spec --workpath $work --distpath $dist --paths src --exclude-module tkinter --exclude-module PySide6.QtQml --exclude-module PySide6.QtQuick --exclude-module PySide6.QtWebEngineCore --add-data "$(Join-Path $PSScriptRoot 'src\discord_guard\scripts');discord_guard\scripts" (Join-Path $PSScriptRoot 'src\discord_guard\__main__.py')
if ($LASTEXITCODE -ne 0) { throw 'Packaging failed.' }
$artifact = Join-Path $dist 'DiscordGuard.exe'
if ($Layout -eq 'onedir') { $artifact=Join-Path $dist 'DiscordGuard\DiscordGuard.exe' }
$process = Start-Process -FilePath $artifact -ArgumentList '--smoke-test' -PassThru -Wait
if ($process.ExitCode -ne 0) { throw 'Packaged GUI smoke check failed.' }
"Built: $artifact"
