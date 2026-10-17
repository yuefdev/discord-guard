from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from discord_guard import experience, windows
from discord_guard.core import decide
from test_security import HOST, GUARD, ready, safe_acl


def desktop_ready():
    state = ready()
    state["policy"] = {"schema_version": 2, "backend": "desktop_service", "origin_sid": HOST}
    state["current"].update(sid=HOST, session_sid=HOST)
    state["system_acls"]["desktop_helper"] = safe_acl()
    state["desktop_service"] = {"available": True, "error": 0, "ready": 1, "installed": 0, "running": 0}
    return state


class DesktopServiceTests(unittest.TestCase):
    def test_origin_stays_on_own_desktop_without_a_local_guard_account(self):
        state = desktop_ready()
        state["account"] = {}
        state["profile_acls"] = []
        self.assertTrue(decide(state).allowed)
        self.assertEqual(experience.present(state).mode, "desktop")

    def test_broken_service_wrong_caller_or_unsafe_helper_cannot_launch(self):
        changes = (
            lambda s: s["desktop_service"].update(available=False),
            lambda s: s["desktop_service"].update(error=5),
            lambda s: s["desktop_service"].update(ready=0),
            lambda s: s["current"].update(sid=GUARD),
            lambda s: s["current"].update(session_sid=GUARD),
            lambda s: s["current"].update(elevated=True),
            lambda s: s["system_acls"]["desktop_helper"].update(owner=HOST),
            lambda s: s["policy"].update(schema_version=99),
        )
        for change in changes:
            state = desktop_ready()
            change(state)
            with patch.object(windows, "desktop_command") as command, self.assertRaises(windows.GuardError):
                windows.launch(paths=Mock(), inspector=lambda _: state, popen=Mock())
            command.assert_not_called()

    def test_real_access_denial_proof_is_required_before_discord_install_or_launch(self):
        state = desktop_ready()
        for bad in ({"available": False}, {"available": True, "error": 0, "file_denied": 1, "memory_denied": 0}):
            with patch.object(windows, "desktop_command", return_value=bad) as command, self.assertRaises(windows.GuardError):
                windows.launch(paths=Mock(), inspector=lambda _: state)
            self.assertEqual([call.args[1] for call in command.call_args_list], ["--verify-boundary"])

    def test_success_uses_only_authenticated_service_after_fixture_proof(self):
        state = desktop_ready()
        proof = {"available": True, "error": 0, "file_denied": 1, "memory_denied": 1}
        launched = {"available": True, "error": 0, "running": 1}
        start = Mock()
        with patch.object(windows, "desktop_command", side_effect=[proof, launched]) as command:
            self.assertEqual(windows.launch(paths=Mock(), inspector=lambda _: state, popen=start), launched)
        self.assertEqual([call.args[1] for call in command.call_args_list], ["--verify-boundary", "--launch"])
        start.assert_not_called()

    def test_an_existing_host_discord_never_satisfies_private_autostart(self):
        state = desktop_ready()
        state["client_running"] = True
        with patch.object(windows, "launch") as launch:
            windows.run_autostart(paths=Mock(), inspector=lambda _: state)
        launch.assert_called_once()

    def test_legacy_installer_cannot_install_into_the_host_profile(self):
        with patch.object(windows, "inspect", return_value=desktop_ready()), \
                patch.object(windows, "prepare_profile") as prepare, self.assertRaises(windows.GuardError):
            windows.install_discord(paths=Mock())
        prepare.assert_not_called()


if __name__ == "__main__":
    unittest.main()
