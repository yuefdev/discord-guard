import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from discord_guard import startup, windows
from test_desktop_service import desktop_ready
from test_startup import COMMAND, DISCORD, Store, UPDATER


def running():
    state = desktop_ready()
    state["desktop_service"].update(installed=1, running=1)
    return state


class ReplacementTests(unittest.TestCase):
    def setUp(self):
        self.paths = windows.Paths(Path("C:/Program Files"), Path("C:/ProgramData"), Path("C:/Start"),
                                   Path("C:/Users/User/AppData/Local"), Path("C:/Users/User/AppData/Roaming"))

    def test_no_old_client_removal_before_live_private_install_and_launch(self):
        for change in (lambda s: s["desktop_service"].update(installed=0),
                       lambda s: s["desktop_service"].update(running=0),
                       lambda s: s["desktop_service"].update(available=False),
                       lambda s: s["current"].update(elevated=True),
                       lambda s: s["system_acls"]["desktop_helper"].update(reparse=True)):
            state = running()
            change(state)
            store = Store()
            with patch.object(sys, "frozen", True, create=True), patch.object(windows, "run_script") as script, \
                    self.assertRaises(windows.GuardError):
                windows.replace_discord(self.paths, inspector=lambda _: state, store=store)
            script.assert_not_called()
            self.assertEqual(store.writes, 0)

    def test_unrecognised_startup_stops_removal_before_any_changes(self):
        store = Store({(startup.RUN_KEY, "Discord"): startup.Entry("user-customised-command")})
        before = copy.deepcopy(store.values)
        with patch.object(sys, "frozen", True, create=True), patch.object(windows, "run_script") as script, \
                self.assertRaises(windows.GuardError):
            windows.replace_discord(self.paths, inspector=lambda _: running(), store=store)
        script.assert_not_called()
        self.assertEqual(store.values, before)

    def test_failed_uninstall_does_not_retire_startup(self):
        store = Store({(startup.RUN_KEY, "Discord"): DISCORD})
        before = copy.deepcopy(store.values)
        with patch.object(sys, "frozen", True, create=True), \
                patch.object(windows, "run_script", side_effect=windows.GuardError("Uninstall failed")), \
                self.assertRaises(windows.GuardError):
            windows.replace_discord(self.paths, inspector=lambda _: running(), store=store)
        self.assertEqual(store.values, before)

    def test_success_retires_only_the_original_clients_startup(self):
        updater = str(self.paths.discord_install_root / "Update.exe")
        unrelated = startup.Entry("leave-this-app-alone")
        store = Store({(startup.RUN_KEY, "Discord"): startup.Entry(f'"{updater}" --processStart Discord.exe'),
                       (startup.RUN_KEY, "OtherApp"): unrelated})

        def replace(name, config, **kwargs):
            self.assertEqual(name, "replace-discord")
            self.assertEqual(config["origin_sid"], running()["policy"]["origin_sid"])
            self.assertEqual(config["discord_install_root"], str(self.paths.discord_install_root))
            self.assertEqual(kwargs["timeout"], 360)
            self.assertIsNotNone(store.read(startup.RUN_KEY, "Discord"))
            return {"ok": True, "replaced": True}

        with patch.object(sys, "frozen", True, create=True), patch.object(windows, "run_script", side_effect=replace):
            self.assertTrue(windows.replace_discord(self.paths, inspector=lambda _: running(), store=store)["replaced"])
        self.assertEqual(store.values, {(startup.RUN_KEY, "OtherApp"): unrelated})

    def test_disabling_guard_startup_never_resurrects_an_uninstalled_updater(self):
        store = Store({(startup.RUN_KEY, "Discord"): DISCORD})
        startup.configure(store, COMMAND, UPDATER, enabled=True)
        before = copy.deepcopy(store.values)
        startup.retire_discord(store, COMMAND, UPDATER, validate_only=True)
        self.assertEqual(store.values, before)
        startup.retire_discord(store, COMMAND, UPDATER)
        self.assertEqual(store.read(startup.RUN_KEY, startup.GUARD_VALUE), startup.Entry(COMMAND))
        startup.configure(store, COMMAND, UPDATER, enabled=False)
        self.assertEqual(store.values, {})

    def test_failed_startup_retirement_restores_all_its_values(self):
        store = Store({(startup.RUN_KEY, "Discord"): DISCORD})
        startup.configure(store, COMMAND, UPDATER, enabled=True)
        store.values[(startup.RUN_KEY, "Discord")] = DISCORD
        before = copy.deepcopy(store.values)
        store.fail_at = store.writes + 2
        with self.assertRaises(startup.StartupError):
            startup.retire_discord(store, COMMAND, UPDATER)
        self.assertEqual(store.values, before)


@unittest.skipUnless(os.name == "nt", "Windows shell shortcut transaction")
class NativeReplacementTests(unittest.TestCase):
    def fixture(self, body):
        # Load function definitions only. The real entry point and official
        # uninstaller never run; all files/links are disposable test fixtures.
        bootstrap = r'''
$ErrorActionPreference = 'Stop'
$data = [Console]::In.ReadToEnd() | ConvertFrom-Json
$data.temporary = [IO.Path]::GetFullPath($data.temporary)
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($data.script, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Replacement script did not parse.' }
foreach ($node in $ast.EndBlock.Statements) {
    if ($node -is [Management.Automation.Language.FunctionDefinitionAst]) { . ([scriptblock]::Create($node.Extent.Text)) }
}
$realSignatureCheck = (Get-Command Assert-OfficialUpdater).ScriptBlock
$realUninstall = (Get-Command Invoke-OfficialUninstall).ScriptBlock
$profile = Join-Path $data.temporary 'Profile'
$root = Join-Path $profile 'AppData\Local\Discord'
$guard = Join-Path $data.temporary 'Guard\DiscordGuard.exe'
$programs = Join-Path $profile 'AppData\Roaming\Start\Programs'
$desktop = Join-Path $profile 'Desktop'
$pinned = Join-Path $profile 'Pinned'
$oldDirectory = Join-Path $root 'app-1.0.0'
$oldImage = Join-Path $oldDirectory 'Discord.exe'
$key = 'HKCU:\Software\DiscordGuard\Tests\' + [Guid]::NewGuid().ToString('N')
foreach ($path in @($oldDirectory, (Split-Path -Parent $guard), $programs, $desktop, $pinned, (Join-Path $programs 'Discord Inc'))) {
    [void][IO.Directory]::CreateDirectory($path)
}
$updater = Join-Path $root 'Update.exe'
foreach ($path in @($guard, $oldImage, $updater)) { [IO.File]::WriteAllText($path, 'inert test fixture, never executed') }
$profileData = Join-Path $profile 'old-profile-canary'
[IO.File]::WriteAllText($profileData, 'retain original data')
$shell = New-Object -ComObject WScript.Shell
$oldLink = Join-Path $desktop 'Discord.lnk'
$startLink = Join-Path $programs 'Discord Inc\Discord.lnk'
foreach ($path in @($oldLink, $startLink)) {
    $link = $shell.CreateShortcut($path); $link.TargetPath = $updater
    $link.Arguments = '--processStart Discord.exe'; $link.Save()
}
$unrelated = Join-Path $desktop 'OtherApp.lnk'
$link = $shell.CreateShortcut($unrelated); $link.TargetPath = Join-Path $data.temporary 'Other.exe'; $link.Save()
$unrelatedBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($unrelated))
$oldLinkBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($oldLink))
$script:uninstalls = 0; $script:badSignature = $false
$script:failBefore = $false; $script:failAfter = $false
function Assert-OfficialUpdater([string]$Updater) { if ($script:badSignature) { throw 'Synthetic invalid signature' } }
function Get-CimInstance { return @() }
function Invoke-OfficialUninstall([string]$Updater) {
    $script:uninstalls++
    if ($script:failBefore) { throw 'Synthetic uninstall failure before removal' }
    Remove-Item -LiteralPath $oldDirectory -Recurse -Force
    Remove-Item -LiteralPath (Join-Path $programs 'Discord Inc') -Recurse -Force
    if ($script:failAfter) { throw 'Synthetic uninstall failure after removal' }
}
try {
'''
        finish = r'''
} finally {
    if (Test-Path -LiteralPath $key) { Remove-Item -LiteralPath $key -Recurse -Force }
}
'''
        encoded = base64.b64encode((bootstrap + body + finish).encode("utf-16-le")).decode("ascii")
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run([str(windows.powershell_path()), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                input=json.dumps({"script": str(windows.script_path("replace-discord")), "temporary": temporary,
                                  "python": sys.executable}),
                capture_output=True, text=True, encoding="utf-8", timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_success_retry_and_cleanup_use_real_shortcuts_without_repeating_uninstall(self):
        result = self.fixture(r'''
$first = Invoke-DiscordReplacement $root $guard $programs $desktop $pinned $key
$target = $shell.CreateShortcut($startLink).TargetPath
$script:badSignature = $true
$again = Invoke-DiscordReplacement $root $guard $programs $desktop $pinned $key
$link = $shell.CreateShortcut($oldLink); $link.TargetPath = Join-Path $data.temporary 'UserChanged.exe'; $link.Save()
Remove-ReplacementLinks $key $guard $profile
@{replaced=$first.replaced; oldGone=(-not (Test-Path -LiteralPath $oldImage)); target=$target; guard=$guard;
  uninstalls=$script:uninstalls; repeatedUninstall=$again.uninstalled; cleaned=(-not (Test-Path -LiteralPath $startLink));
  userChangedRetained=(Test-Path -LiteralPath $oldLink); dataRetained=(Test-Path -LiteralPath $profileData);
  recordGone=($null -eq (Get-ReplacementState $key $guard));
  unrelated=($unrelatedBytes -eq [Convert]::ToBase64String([IO.File]::ReadAllBytes($unrelated)))} | ConvertTo-Json -Compress
''')
        self.assertTrue(result["replaced"] and result["oldGone"] and result["cleaned"])
        self.assertEqual(result["target"], result["guard"])
        self.assertEqual(result["uninstalls"], 1)
        self.assertFalse(result["repeatedUninstall"])
        self.assertTrue(all(result[key] for key in ("userChangedRetained", "dataRetained", "recordGone", "unrelated")))

    def test_uninstall_failure_restores_links_and_keeps_the_old_client(self):
        result = self.fixture(r'''
$script:failBefore = $true; $failed = $false
try { Invoke-DiscordReplacement $root $guard $programs $desktop $pinned $key | Out-Null } catch { $failed = $true }
@{failed=$failed; oldRetained=(Test-Path -LiteralPath $oldImage);
  linkRestored=($oldLinkBytes -eq [Convert]::ToBase64String([IO.File]::ReadAllBytes($oldLink)));
  recordGone=($null -eq (Get-ReplacementState $key $guard))} | ConvertTo-Json -Compress
''')
        self.assertTrue(all(result.values()))

    def test_partial_uninstall_keeps_working_guard_links_and_can_be_retried(self):
        result = self.fixture(r'''
$script:failAfter = $true; $failed = $false
try { Invoke-DiscordReplacement $root $guard $programs $desktop $pinned $key | Out-Null } catch { $failed = $true }
$kept = $shell.CreateShortcut($startLink).TargetPath -eq $guard
$script:badSignature = $true
$again = Invoke-DiscordReplacement $root $guard $programs $desktop $pinned $key
@{failed=$failed; kept=$kept; retried=$again.replaced; uninstalls=$script:uninstalls} | ConvertTo-Json -Compress
''')
        self.assertTrue(result["failed"] and result["kept"] and result["retried"])
        self.assertEqual(result["uninstalls"], 1)

    def test_invalid_signature_changes_no_shortcuts_and_runs_no_uninstaller(self):
        result = self.fixture(r'''
$script:badSignature = $true; $failed = $false
try { Invoke-DiscordReplacement $root $guard $programs $desktop $pinned $key | Out-Null } catch { $failed = $true }
$realSignatureRejected = $false
try { & $realSignatureCheck $updater } catch { $realSignatureRejected = $true }
@{failed=$failed; uninstalls=$script:uninstalls; oldRetained=(Test-Path -LiteralPath $oldImage);
  realSignatureRejected=$realSignatureRejected;
  linkRetained=($oldLinkBytes -eq [Convert]::ToBase64String([IO.File]::ReadAllBytes($oldLink)))} | ConvertTo-Json -Compress
''')
        self.assertTrue(result["failed"] and result["oldRetained"] and result["linkRetained"])
        self.assertTrue(result["realSignatureRejected"])
        self.assertEqual(result["uninstalls"], 0)

    def test_custom_shortcut_is_not_overwritten_or_used_to_uninstall(self):
        result = self.fixture(r'''
$link = $shell.CreateShortcut($oldLink); $link.Arguments = '--processStart Discord.exe --custom'; $link.Save()
$before = [Convert]::ToBase64String([IO.File]::ReadAllBytes($oldLink)); $failed = $false
try { Invoke-DiscordReplacement $root $guard $programs $desktop $pinned $key | Out-Null } catch { $failed = $true }
@{failed=$failed; oldRetained=(Test-Path -LiteralPath $oldImage); uninstalls=$script:uninstalls;
  customRetained=($before -eq [Convert]::ToBase64String([IO.File]::ReadAllBytes($oldLink)))} | ConvertTo-Json -Compress
''')
        self.assertTrue(result["failed"] and result["oldRetained"] and result["customRetained"])
        self.assertEqual(result["uninstalls"], 0)

    def test_missing_official_uninstaller_does_not_fall_back_to_recursive_deletion(self):
        result = self.fixture(r'''
Remove-Item -LiteralPath $updater -Force
$failed = $false
try { Invoke-DiscordReplacement $root $guard $programs $desktop $pinned $key | Out-Null } catch { $failed = $true }
@{failed=$failed; oldRetained=(Test-Path -LiteralPath $oldImage); uninstalls=$script:uninstalls;
  linkRetained=($oldLinkBytes -eq [Convert]::ToBase64String([IO.File]::ReadAllBytes($oldLink)))} | ConvertTo-Json -Compress
''')
        self.assertTrue(result["failed"] and result["oldRetained"] and result["linkRetained"])
        self.assertEqual(result["uninstalls"], 0)

    def test_reinstalled_old_client_is_detected_after_a_completed_replacement(self):
        result = self.fixture(r'''
Invoke-DiscordReplacement $root $guard $programs $desktop $pinned $key | Out-Null
[void][IO.Directory]::CreateDirectory($oldDirectory)
[IO.File]::WriteAllText($oldImage, 'inert reinstalled client fixture')
$again = Invoke-DiscordReplacement $root $guard $programs $desktop $pinned $key
@{replaced=$again.replaced; removedAgain=$again.uninstalled; uninstalls=$script:uninstalls;
  oldGone=(-not (Test-Path -LiteralPath $oldImage))} | ConvertTo-Json -Compress
''')
        self.assertTrue(result["replaced"] and result["removedAgain"] and result["oldGone"])
        self.assertEqual(result["uninstalls"], 2)

    def test_elevated_cleanup_rejects_recorded_paths_outside_the_original_profile(self):
        result = self.fixture(r'''
Invoke-DiscordReplacement $root $guard $programs $desktop $pinned $key | Out-Null
$outside = Join-Path $data.temporary 'Outside.lnk'
$link = $shell.CreateShortcut($outside); $link.TargetPath = $guard; $link.Arguments = '--autostart'; $link.Save()
$state = Get-ReplacementState $key $guard; $state.shortcuts += $outside; Save-ReplacementState $key $state
$failed = $false
try { Remove-ReplacementLinks $key $guard $profile } catch { $failed = $true }
$outsideRetained = Test-Path -LiteralPath $outside
$ownedRetained = Test-Path -LiteralPath $startLink
Remove-Item -LiteralPath $outside -Force
Remove-ReplacementLinks $key $guard $profile
@{failed=$failed; outsideRetained=$outsideRetained; ownedRetained=$ownedRetained;
  retried=(-not (Test-Path -LiteralPath $startLink))} | ConvertTo-Json -Compress
''')
        self.assertTrue(all(result.values()))

    def test_native_uninstaller_runner_drains_output_and_observes_a_failed_exit(self):
        result = self.fixture(r'''
# Exercise the native process wrapper with the known Python interpreter and an
# unsupported flag. No actual Discord uninstaller or fixture executable runs.
$message = ''
try { & $realUninstall $data.python } catch { $message = $_.Exception.Message }
@{failed=($message -eq 'The official Discord uninstaller did not complete successfully.');
  oldRetained=(Test-Path -LiteralPath $oldImage)} | ConvertTo-Json -Compress
''')
        self.assertTrue(all(result.values()))


if __name__ == "__main__":
    unittest.main()
