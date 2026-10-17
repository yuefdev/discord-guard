from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from discord_guard.core import APP_MARKER, acl_is_safe, decide, policy_is_valid
from discord_guard import windows


GUARD = "S-1-5-21-111-222-333-1002"
HOST = "S-1-5-21-111-222-333-1001"
ADMIN = "S-1-5-32-544"


def safe_acl(private=False):
    rules = [{"sid": "S-1-5-18", "rights": 0x1F01FF, "type": "Allow"},
             {"sid": ADMIN, "rights": 0x1F01FF, "type": "Allow"}]
    if private:
        rules.append({"sid": GUARD, "rights": 0x1F01FF, "type": "Allow"})
    else:
        rules.append({"sid": "S-1-5-32-545", "rights": 0x1200A9, "type": "Allow"})
    return {"exists": True, "owner": GUARD if private else ADMIN,
            "reparse": False, "rules": rules}


def ready():
    return {
        "windows": True,
        "policy": {"schema_version": 1, "account_name": "DiscordGuard", "guard_sid": GUARD, "origin_sid": HOST},
        "system_acls": {key: safe_acl() for key in
                        ("program_parent", "program_dir", "app", "data_dir", "policy")},
        "account": {"sid": GUARD, "enabled": True, "admin_member": False, "description": APP_MARKER},
        "current": {"sid": GUARD, "session_id": 2, "elevated": False},
        "fast_switching_disabled": False,
        "defender": {"realtime": True, "behavior": True, "antivirus": True},
        "hardening": {"secure_boot_registry": True, "tamper_protection": True,
                      "uac": {"enabled": True, "secure_desktop": True, "admin_prompt": 5},
                      "vbs": {"status": 2, "services_running": [2], "umci": 2, "kernel_ci": 2}},
        "client": {"signature": "Valid", "signer": "CN=Discord Inc., O=Discord Inc., C=US",
                   "path": str(Path("C:/Users/DiscordGuard/AppData/Local/Discord/app-1.0.1/Discord.exe")),
                   "entry_clean": True, "acls": [safe_acl(True) for _ in range(5)]},
        "client_running": False,
        "profile_acls": [safe_acl(True) for _ in range(7)],
    }


class DecisionTests(unittest.TestCase):
    def test_valid_boundary_can_launch(self):
        self.assertTrue(decide(ready()).allowed)

    def test_missing_evidence_is_not_a_pass(self):
        self.assertFalse(decide({}).allowed)

    def test_private_account_can_install_discord_before_a_client_exists(self):
        state = ready()
        state["client"] = {}
        self.assertFalse(decide(state).allowed)
        self.assertTrue(decide(state, require_client=False).allowed)

    def test_host_identity_cannot_launch(self):
        state = ready()
        state["current"]["sid"] = HOST
        self.assertFalse(decide(state).allowed)

    def test_no_identity_separation_is_rejected(self):
        state = ready()
        state["policy"]["origin_sid"] = GUARD
        self.assertFalse(decide(state).allowed)

    def test_elevated_or_admin_account_cannot_launch(self):
        for section, key in (("current", "elevated"), ("account", "admin_member")):
            with self.subTest(key=key):
                state = ready()
                state[section][key] = True
                self.assertFalse(decide(state).allowed)

    def test_valid_signature_from_another_publisher_is_rejected(self):
        state = ready()
        state["client"]["signer"] = "CN=Some other publisher"
        self.assertFalse(decide(state).allowed)

    def test_similarly_named_certificate_organisation_is_rejected(self):
        state = ready()
        state["client"]["signer"] = "CN=Other, O=Discord Inc. Impostor, C=US"
        self.assertFalse(decide(state).allowed)

    def test_each_required_condition_is_fail_closed(self):
        cases = [
            ("account", "enabled", False), ("account", "description", "unrelated account"),
            ("account", "sid", HOST), ("current", "session_id", 0),
            ("defender", "realtime", False), ("defender", "behavior", None),
            ("client", "signature", "HashMismatch"), ("client", "entry_clean", False),
        ]
        for section, key, value in cases:
            with self.subTest(section=section, key=key):
                state = ready()
                state[section][key] = value
                self.assertFalse(decide(state).allowed)
        for key, value in (("client_running", True), ("client_running", None),
                           ("fast_switching_disabled", True), ("profile_acls", [])):
            state = ready()
            state[key] = value
            self.assertFalse(decide(state).allowed)

    def test_tampered_policy_acl_is_rejected(self):
        state = ready()
        state["system_acls"]["policy"]["rules"].append(
            {"sid": HOST, "rights": 0x2, "type": "Allow"})
        self.assertFalse(decide(state).allowed)

    def test_one_public_child_storage_file_blocks_launch(self):
        state = ready()
        child = safe_acl(True)
        child["rules"].append({"sid": HOST, "rights": 0x1, "type": "Allow"})
        state["profile_acls"].append(child)
        self.assertFalse(decide(state).allowed)


class AclTests(unittest.TestCase):
    def test_private_owner_must_be_trusted(self):
        acl = safe_acl(True)
        acl["owner"] = HOST
        self.assertFalse(acl_is_safe(acl, private_sid=GUARD))

    def test_broad_allow_is_not_hidden_by_deny(self):
        acl = safe_acl(True)
        acl["rules"] += [{"sid": "S-1-1-0", "rights": 1, "type": "Deny"},
                         {"sid": "S-1-1-0", "rights": 1, "type": "Allow"}]
        self.assertFalse(acl_is_safe(acl, private_sid=GUARD))

    def test_generic_read_all_write_delete_and_acl_changes_are_not_missed(self):
        for rights in (0x80000000, -2147483648, 0x40000000, 0x10000000,
                       0x40, 0x10000, 0x40000, 0x80000):
            with self.subTest(rights=rights):
                acl = safe_acl(True)
                acl["rules"].append({"sid": HOST, "rights": rights, "type": "Allow"})
                self.assertFalse(acl_is_safe(acl, private_sid=GUARD))

    def test_reparse_points_are_always_rejected(self):
        acl = safe_acl(True)
        acl["reparse"] = True
        self.assertFalse(acl_is_safe(acl, private_sid=GUARD))

    def test_system_files_can_be_read_but_not_written_by_users(self):
        acl = safe_acl()
        self.assertTrue(acl_is_safe(acl))
        acl["rules"].append({"sid": HOST, "rights": 0x40000000, "type": "Allow"})
        self.assertFalse(acl_is_safe(acl))

    def test_trusted_installer_owner_is_supported(self):
        acl = safe_acl()
        acl["owner"] = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        self.assertTrue(acl_is_safe(acl))

    def test_inherit_only_ace_is_not_an_effective_grant_on_parent(self):
        acl = safe_acl()
        acl["rules"].append({"sid": "S-1-3-0", "rights": 0x1F01FF,
                             "type": "Allow", "inherit_only": True})
        self.assertTrue(acl_is_safe(acl))


class HardeningTests(unittest.TestCase):
    def advisory(self, state, key):
        return next(check for check in decide(state).advisories if check.key == key)

    def test_audit_umci_is_not_reported_as_enforced_but_does_not_block_discord(self):
        state = ready()
        state["hardening"]["vbs"]["umci"] = 1
        self.assertTrue(decide(state).allowed)
        self.assertFalse(self.advisory(state, "umci").passed)

    def test_kernel_only_integrity_is_reported_without_requiring_app_control(self):
        state = ready()
        state["hardening"]["vbs"].update(kernel_ci=2, umci=0)
        self.assertTrue(decide(state).allowed)
        self.assertFalse(self.advisory(state, "umci").passed)

    def test_hvci_must_be_running_not_merely_configured(self):
        for status, running in ((1, [2]), (2, []), (2, [1]), (2, "2")):
            with self.subTest(status=status, running=running):
                state = ready()
                state["hardening"]["vbs"].update(status=status, services_running=running)
                self.assertTrue(decide(state).allowed)
                self.assertFalse(self.advisory(state, "memory_integrity").passed)

    def test_unknown_optional_hardening_neither_claims_protection_nor_blocks(self):
        for key, value in (("secure_boot_registry", False), ("secure_boot_registry", None),
                           ("tamper_protection", False), ("tamper_protection", None)):
            with self.subTest(key=key, value=value):
                state = ready()
                state["hardening"][key] = value
                self.assertTrue(decide(state).allowed)
        state = ready()
        state.pop("hardening")
        self.assertTrue(decide(state).allowed)
        self.assertFalse(any(check.passed for check in decide(state).advisories))

    def test_unprotected_uac_is_advisory_not_a_global_policy_requirement(self):
        for key, value in (("admin_prompt", 0), ("secure_desktop", False), ("enabled", False)):
            state = ready()
            state["hardening"]["uac"][key] = value
            self.assertTrue(decide(state).allowed)
            self.assertFalse(self.advisory(state, "uac_secure").passed)

    def test_installer_does_not_require_app_control_but_still_requires_separate_identity(self):
        state = ready()
        state["hardening"]["vbs"]["umci"] = 0
        self.assertTrue(decide(state, require_client=False, require_profile=False).allowed)
        state["current"]["sid"] = HOST
        self.assertFalse(decide(state, require_client=False, require_profile=False).allowed)


class LaunchTests(unittest.TestCase):
    def paths(self, temporary):
        root = Path(temporary)
        return windows.Paths(root / "program", root / "data", root / "start", root / "local", root / "roaming")

    def test_wrong_account_creates_no_profile_and_starts_no_discord(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.paths(temporary)
            state = ready()
            state["current"]["sid"] = HOST
            start = Mock()
            with self.assertRaises(windows.GuardError):
                windows.launch(paths, inspector=lambda _: state, popen=start)
            self.assertFalse(paths.discord_profile.exists())
            start.assert_not_called()

    def test_second_permission_check_cannot_be_skipped(self):
        with tempfile.TemporaryDirectory() as temporary:
            states = [ready(), ready()]
            states[1]["profile_acls"][0]["reparse"] = True
            inspector = Mock(side_effect=states)
            start = Mock()
            with self.assertRaises(windows.GuardError):
                windows.launch(self.paths(temporary), inspector=inspector, popen=start)
            self.assertEqual(inspector.call_count, 2)
            start.assert_not_called()

    def test_disabled_umci_does_not_block_a_valid_discord_isolation_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            states = [ready(), ready()]
            states[1]["hardening"]["vbs"]["umci"] = 0
            paths = self.paths(temporary)
            for state in states:
                state["client"]["path"] = str(paths.discord_install_root / "app-1.0.1" / "Discord.exe")
            start = Mock()
            windows.launch(paths, inspector=Mock(side_effect=states), popen=start)
            start.assert_called_once()

    def test_autostart_does_not_duplicate_an_already_running_valid_client(self):
        state = ready()
        state["client_running"] = True
        start = Mock()
        with tempfile.TemporaryDirectory() as temporary:
            windows.run_autostart(self.paths(temporary), inspector=lambda _: state, popen=start)
            start.assert_not_called()
            state["current"]["sid"] = HOST
            with self.assertRaises(windows.GuardError):
                windows.run_autostart(self.paths(temporary), inspector=lambda _: state, popen=start)

    def test_success_starts_normal_discord_without_browser_or_debugging_switches(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = ready()
            start = Mock(return_value="started")
            paths = self.paths(temporary)
            binary = paths.discord_install_root / "app-1.0.1" / "Discord.exe"
            state["client"]["path"] = str(binary)
            self.assertEqual(windows.launch(paths, inspector=lambda _: state, popen=start), "started")
            args, kwargs = start.call_args
            self.assertEqual(args[0], [str(binary)])
            self.assertNotIn("shell", kwargs)
            self.assertEqual(kwargs["cwd"], str(binary.parent))

    def test_relative_paths_are_not_accepted(self):
        with self.assertRaises(windows.GuardError):
            windows.desktop_arguments(Path("Discord.exe"), Path("Discord"))

    def test_binary_from_another_account_or_arbitrary_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.paths(temporary)
            for binary in (Path(temporary) / "attacker" / "app-1.0.1" / "Discord.exe",
                           paths.discord_install_root / "app-custom" / "Discord.exe",
                           paths.discord_install_root / "app-1.0.1" / "other.exe"):
                with self.subTest(binary=str(binary)), self.assertRaises(windows.GuardError):
                    windows.desktop_arguments(binary, paths.discord_install_root)

    def test_electron_environment_injection_options_are_removed(self):
        with patch.dict(windows.os.environ, {"NODE_OPTIONS": "--require=bad.js",
                "ELECTRON_RUN_AS_NODE": "1", "CHROME_LOG_FILE": "private.txt", "SYSTEMROOT": "C:\\Windows"}, clear=True):
            self.assertEqual(windows.clean_client_environment(), {"SYSTEMROOT": "C:\\Windows"})

    def test_invalid_policy_is_not_accepted(self):
        for value in (None, {}, [], {"guard_sid": "S-1-5-18"}):
            self.assertFalse(policy_is_valid(value))

    @unittest.skipUnless(sys.platform == "win32", "Windows subprocess contract")
    def test_setup_password_is_only_in_stdin_not_arguments_or_environment(self):
        secret = "fixture-only-unique-password"
        result = Mock(returncode=0, stdout='{"ok":true}', stderr="")
        with patch.object(windows.subprocess, "run", return_value=result) as run:
            windows.run_script("provision", {"test": "non-secret"}, secret_input={"password": secret})
        positional, keywords = run.call_args
        self.assertNotIn(secret, repr(positional))
        self.assertNotIn("env", keywords)
        self.assertIn(secret, keywords["input"])


class InstallerTests(unittest.TestCase):
    def test_download_hosts_accept_only_official_https_domains(self):
        for url in ("https://discord.com/api/download?platform=win",
                    "https://stable.dl2.discordapp.net/distro/DiscordSetup.exe"):
            self.assertTrue(windows.download_url_is_official(url))
        for url in ("http://discord.com/x", "https://discord.com.evil.test/x", "https://evil-discord.com/x",
                    "https://evil.test@discord.com/x", "file:///DiscordSetup.exe", "https://discord.com:444/x"):
            self.assertFalse(windows.download_url_is_official(url))

    def test_redirect_cannot_escape_the_official_hosts(self):
        with self.assertRaises(windows.GuardError):
            windows.OfficialRedirects().redirect_request(None, None, 302, "", {}, "https://untrusted.test/a.exe")

    def test_bad_installer_signature_never_runs_and_download_is_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = windows.Paths(root / "program", root / "data", root / "start", root / "local", root / "roaming")
            paths.staging.mkdir(parents=True)
            response = MagicMock()
            response.__enter__.return_value = response
            response.geturl.return_value = "https://stable.dl2.discordapp.net/DiscordSetup.exe"
            response.read.side_effect = [b"MZ-synthetic-test-fixture", b""]
            opener = Mock()
            opener.open.return_value = response
            with patch.object(windows, "prepare_profile"), \
                    patch.object(windows, "inspect", return_value=ready()), \
                    patch.object(windows.request, "build_opener", return_value=opener), \
                    patch.object(windows, "run_script", return_value={"signature": "NotSigned"}), \
                    patch.object(windows.subprocess, "Popen") as start:
                with self.assertRaises(windows.GuardError):
                    windows.install_discord(paths)
                start.assert_not_called()
            self.assertEqual(list(paths.staging.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
