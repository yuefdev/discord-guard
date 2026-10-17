param([Parameter(Mandatory=$true)][string]$ConfigBase64, [switch]$RemoveShortcuts)
$ErrorActionPreference = 'Stop'

function Assert-NoReparse([string]$Path) {
    while ($Path) {
        if ((Test-Path -LiteralPath $Path) -and
            ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Redirected replacement paths are not accepted.'
        }
        $parent = Split-Path -Parent $Path
        if (-not $parent -or $parent -eq $Path) { break }
        $Path = $parent
    }
}

function Get-DiscordImages([string]$Root) {
    Assert-NoReparse $Root
    if (-not (Test-Path -LiteralPath $Root)) { return }
    foreach ($directory in @(Get-ChildItem -LiteralPath $Root -Directory -Force)) {
        if ($directory.Name -notmatch '^app-\d+\.\d+\.\d+$') { continue }
        $image = Join-Path $directory.FullName 'Discord.exe'
        Assert-NoReparse $image
        if (Test-Path -LiteralPath $image -PathType Leaf) { $image }
    }
}

function Assert-OfficialUpdater([string]$Updater) {
    Assert-NoReparse $Updater
    $signature = Get-AuthenticodeSignature -LiteralPath $Updater
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(?:^|,\s*)O="?Discord Inc\."?(?:,|$)') {
        throw 'The original Discord uninstaller does not have a valid Discord Inc. signature.'
    }
}

function Test-ReplaceableLink($Link, [string]$Root, [string]$Guard) {
    if (-not $Link.TargetPath -or -not [IO.Path]::IsPathRooted($Link.TargetPath)) { return $false }
    $target = [IO.Path]::GetFullPath($Link.TargetPath)
    $Root = [IO.Path]::GetFullPath($Root)
    $Guard = [IO.Path]::GetFullPath($Guard)
    if ($target -eq $Guard -and $Link.Arguments -eq '--autostart') { return $true }
    if ($target -eq (Join-Path $Root 'Update.exe')) {
        if ($Link.Arguments -notmatch '^\s*--processStart\s+Discord\.exe(?:\s+--process-start-args\s+"--start-(?:inactive|minimized)")?\s*$') {
            throw 'A customised Discord shortcut was preserved; replacement stopped.'
        }
        return $true
    }
    $pattern = '^' + [regex]::Escape($Root.TrimEnd('\')) + '\\app-\d+\.\d+\.\d+\\Discord\.exe$'
    if ($target -match $pattern) {
        if ($Link.Arguments -notmatch '^\s*(?:--start-(?:inactive|minimized))?\s*$') {
            throw 'A customised Discord shortcut was preserved; replacement stopped.'
        }
        return $true
    }
    return $false
}

function Set-GuardLink($Shell, [string]$Path, [string]$Root, [string]$Guard) {
    Assert-NoReparse $Path
    $link = $Shell.CreateShortcut($Path)
    if ((Test-Path -LiteralPath $Path) -and -not (Test-ReplaceableLink $link $Root $Guard)) {
        throw 'A conflicting shortcut was preserved; replacement stopped.'
    }
    $link.TargetPath = $Guard
    $link.Arguments = '--autostart'
    $link.WorkingDirectory = Split-Path -Parent $Guard
    $link.IconLocation = $Guard + ',0'
    $link.Description = 'Discord - checked launch through DiscordGuard'
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) { [void][IO.Directory]::CreateDirectory($parent) }
    $link.Save()
}

function Invoke-OfficialUninstall([string]$Updater) {
    # Deny replacement until Windows has mapped the verified updater image.
    $lock = [IO.File]::Open($Updater, 'Open', 'Read', 'Read')
    $process = [Diagnostics.Process]::new()
    try {
        Assert-OfficialUpdater $Updater
        $process.StartInfo.FileName = $Updater
        $process.StartInfo.Arguments = '--uninstall --silent'
        $process.StartInfo.WorkingDirectory = Split-Path -Parent $Updater
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        foreach ($name in @($process.StartInfo.EnvironmentVariables.Keys)) {
            if ($name -match '^(ELECTRON_|NODE_|CHROME_|CHROMIUM_)') { $process.StartInfo.EnvironmentVariables.Remove($name) }
        }
        if (-not $process.Start()) { throw 'The official Discord uninstaller could not start.' }
    } catch { $process.Dispose(); throw }
    finally { $lock.Dispose() }
    try {
        # Drain both streams asynchronously: updater logs must neither block a
        # full pipe nor contaminate the script's JSON result.
        $process.BeginOutputReadLine()
        $process.BeginErrorReadLine()
        if (-not $process.WaitForExit(300000)) { throw 'Discord uninstall is still running; retry replacement after it finishes.' }
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw 'The official Discord uninstaller did not complete successfully.' }
    } finally { $process.Dispose() }
}

function Get-ReplacementState([string]$Key, [string]$Guard) {
    $entry = Get-ItemProperty -LiteralPath $Key -Name State -ErrorAction SilentlyContinue
    if (-not $entry) { return $null }
    if ($entry.State -isnot [string] -or $entry.State.Length -gt 1048576) { throw 'Replacement record is invalid.' }
    $state = $entry.State | ConvertFrom-Json
    if ($state.version -ne 1 -or $state.launcher -isnot [string] -or
        [IO.Path]::GetFullPath($state.launcher) -ne [IO.Path]::GetFullPath($Guard) -or $state.root -isnot [string] -or
        $state.uninstall_completed -isnot [bool] -or $state.shortcuts -isnot [array] -or $state.shortcuts.Count -gt 1024) {
        throw 'Replacement record belongs to another installation or is invalid.'
    }
    foreach ($path in $state.shortcuts) {
        if ($path -isnot [string] -or -not [IO.Path]::IsPathRooted($path) -or [IO.Path]::GetExtension($path) -ne '.lnk') {
            throw 'Replacement shortcut record is invalid.'
        }
    }
    return $state
}

function Save-ReplacementState([string]$Key, $State) {
    if ($null -eq $State) {
        if (Test-Path -LiteralPath $Key) { Remove-ItemProperty -LiteralPath $Key -Name State -ErrorAction SilentlyContinue }
    } else {
        New-Item -Path $Key -Force | Out-Null
        New-ItemProperty -LiteralPath $Key -Name State -Value ($State | ConvertTo-Json -Depth 4 -Compress) -PropertyType String -Force | Out-Null
    }
}

function Remove-ReplacementLinks([string]$Key, [string]$Guard, [string]$Profile) {
    $state = Get-ReplacementState $Key $Guard
    if ($null -eq $state) { return }
    Assert-NoReparse $Profile
    $Guard = [IO.Path]::GetFullPath($Guard)
    $prefix = [IO.Path]::GetFullPath($Profile).TrimEnd('\') + '\'
    $paths = [Collections.Generic.List[string]]::new()
    # The record is per-user and untrusted. Elevated removal is restricted to
    # actual launcher links inside the administrator-registered origin profile.
    foreach ($path in $state.shortcuts) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        if (-not [IO.Path]::GetFullPath($path).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Replacement shortcut is outside the original Windows profile; remove it as that user before uninstalling.'
        }
        Assert-NoReparse $path
        $paths.Add($path)
    }
    $shell = New-Object -ComObject WScript.Shell
    foreach ($path in $paths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        Assert-NoReparse $path
        $link = $shell.CreateShortcut($path)
        if ($link.TargetPath -and [IO.Path]::GetFullPath($link.TargetPath) -eq $Guard -and $link.Arguments -eq '--autostart') {
            Remove-Item -LiteralPath $path -Force
        }
    }
    Save-ReplacementState $Key $null
}

function Invoke-DiscordReplacement([string]$Root, [string]$Guard, [string]$Programs, [string]$Desktop, [string]$Pinned, [string]$StateKey) {
    # Shell links expand 8.3 aliases. Compare canonical Windows paths so a link
    # created through a short temporary/profile path is still recognised later.
    $Root = [IO.Path]::GetFullPath($Root)
    $Guard = [IO.Path]::GetFullPath($Guard)
    $Programs = [IO.Path]::GetFullPath($Programs)
    if ($Desktop) { $Desktop = [IO.Path]::GetFullPath($Desktop) }
    if ($Pinned) { $Pinned = [IO.Path]::GetFullPath($Pinned) }
    Assert-NoReparse $Root
    Assert-NoReparse $Guard
    if (-not (Test-Path -LiteralPath $Guard -PathType Leaf)) { throw 'The installed DiscordGuard launcher is missing.' }
    $updater = Join-Path $Root 'Update.exe'
    $hasUpdater = Test-Path -LiteralPath $updater -PathType Leaf
    $previous = Get-ReplacementState $StateKey $Guard
    if ($previous -and $previous.root -ne $Root) { throw 'Replacement record has a different original client path.' }
    $images = @(Get-DiscordImages $Root)
    $needsUninstall = $hasUpdater -and ($images.Count -gt 0 -or -not $previous -or -not $previous.uninstall_completed)
    if ($needsUninstall) { Assert-OfficialUpdater $updater }
    elseif ($images.Count) { throw 'The old client has no official uninstaller; no application files were deleted.' }
    $shell = New-Object -ComObject WScript.Shell
    $links = @{}
    $hasStartLink = $false
    $count = 0
    foreach ($folder in @($Programs, (Join-Path $Programs 'Discord'), (Join-Path $Programs 'Discord Inc'), $Desktop, $Pinned)) {
        if (-not $folder -or -not (Test-Path -LiteralPath $folder)) { continue }
        Assert-NoReparse $folder
        foreach ($file in @(Get-ChildItem -LiteralPath $folder -Filter '*.lnk' -File -Force)) {
            if (++$count -gt 1024) { throw 'Too many shortcuts for bounded replacement.' }
            Assert-NoReparse $file.FullName
            if (Test-ReplaceableLink ($shell.CreateShortcut($file.FullName)) $Root $Guard) {
                $links[$file.FullName] = [IO.File]::ReadAllBytes($file.FullName)
                if ($folder -eq $Programs -or $folder -eq (Join-Path $Programs 'Discord') -or $folder -eq (Join-Path $Programs 'Discord Inc')) {
                    $hasStartLink = $true
                }
            }
        }
    }
    if (-not $hasStartLink) {
        $path = Join-Path $Programs 'Discord.lnk'
        Assert-NoReparse $path
        if (Test-Path -LiteralPath $path) { throw 'A conflicting Start menu shortcut was preserved.' }
        $links[$path] = $null
    }
    $state = [pscustomobject]@{version=1; launcher=$Guard; root=$Root; shortcuts=@($links.Keys);
        uninstall_completed=(-not $needsUninstall)}
    $uninstallStarted = $false
    try {
        Save-ReplacementState $StateKey $state
        # Establish the replacement entry points before uninstalling the old app.
        foreach ($path in @($links.Keys)) { Set-GuardLink $shell $path $Root $Guard }
        if ($needsUninstall) {
            $uninstallStarted = $true
            Invoke-OfficialUninstall $updater
            for ($attempt = 0; $attempt -lt 20 -and @(Get-DiscordImages $Root).Count; $attempt++) { Start-Sleep -Milliseconds 250 }
            if (@(Get-DiscordImages $Root).Count) { throw 'The old Discord executable is still installed.' }
            $state.uninstall_completed = $true
            Save-ReplacementState $StateKey $state
        }
        foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name='Discord.exe'")) {
            if ($process.ExecutablePath -and $process.ExecutablePath.StartsWith($Root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
                throw 'The old Discord process is still running.'
            }
        }
        # Squirrel may remove its shortcuts while uninstalling. Recreate only
        # the recognised ones, pointing to the installed, checked launcher.
        foreach ($path in @($links.Keys)) { Set-GuardLink $shell $path $Root $Guard }
    } catch {
        $message = $_.Exception.Message
        $keepGuardLinks = $uninstallStarted -and -not @(Get-DiscordImages $Root).Count
        foreach ($path in @($links.Keys)) {
            try {
                Assert-NoReparse $path
                if ((Test-Path -LiteralPath $path) -and -not (Test-ReplaceableLink ($shell.CreateShortcut($path)) $Root $Guard)) {
                    throw 'Shortcut changed during replacement.'
                }
                if ($keepGuardLinks) { Set-GuardLink $shell $path $Root $Guard }
                elseif ($null -ne $links[$path]) { [IO.File]::WriteAllBytes($path, $links[$path]) }
                elseif (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
            } catch { $message += ' A shortcut could not be restored; inspect its target before retrying.' }
        }
        try {
            if ($keepGuardLinks) {
                $state.uninstall_completed = $true
                Save-ReplacementState $StateKey $state
                $message += ' The old application was already removed; launcher links were retained. Retry to finish replacement.'
            } else { Save-ReplacementState $StateKey $previous }
        } catch { $message += ' The replacement record needs inspection.' }
        throw $message
    }
    return @{ok=$true; replaced=$true; uninstalled=[bool]$needsUninstall; shortcuts=$links.Count}
}

try {
    $config = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ConfigBase64)) | ConvertFrom-Json
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $guard = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'DiscordGuard\DiscordGuard.exe'
    if ($RemoveShortcuts) {
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
            $PSScriptRoot -ne (Split-Path -Parent $guard) -or $config.origin_sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') {
            throw 'Shortcut cleanup requires the installed administrator uninstaller.'
        }
        $registered = Get-ItemProperty -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $config.origin_sid)
        $profile = [Environment]::ExpandEnvironmentVariables($registered.ProfileImagePath)
        $key = 'Registry::HKEY_USERS\' + $config.origin_sid + '\Software\DiscordGuard\Replacement'
        Remove-ReplacementLinks $key $guard $profile
        @{ok=$true} | ConvertTo-Json -Compress
        return
    }
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or $identity.User.Value -ne $config.origin_sid) {
        throw 'Run replacement as the original, non-elevated desktop user.'
    }
    $root = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Discord'
    if ($config.discord_install_root -ne $root -or $config.installed_exe -ne $guard) { throw 'Replacement paths do not match the Windows known folders.' }
    $helper = Join-Path (Split-Path -Parent $guard) 'DiscordGuardSession.exe'
    Assert-NoReparse $helper
    $status = & $helper --query | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $status.available -ne $true -or $status.error -ne 0 -or $status.ready -ne 1 -or
        $status.installed -ne 1 -or $status.running -ne 1) { throw 'Private Discord must be installed and running before replacement.' }
    $programs = [Environment]::GetFolderPath('Programs')
    $desktop = [Environment]::GetFolderPath('DesktopDirectory')
    $pinned = Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar'
    Invoke-DiscordReplacement $root $guard $programs $desktop $pinned 'HKCU:\Software\DiscordGuard\Replacement' | ConvertTo-Json -Compress
} catch {
    @{ok=$false; error=$_.Exception.Message} | ConvertTo-Json -Compress
    exit 1
}
