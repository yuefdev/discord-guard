from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from discord_guard import experience, windows
from test_security import ready, HOST, GUARD
from test_guardcore import kernel_ready


def ordinary():
    state = ready()
    state["policy"] = None
    state["current"]["sid"] = HOST
    state["current"]["session_sid"] = HOST
    state["system_acls"] = {}
    state["account"] = {}
    state["installed_discord"] = dict(state["client"], found=True, version="1.0.1")
    for acl in state["installed_discord"]["acls"]:
        acl["owner"] = HOST
        for rule in acl["rules"]:
            if rule["sid"].endswith("1002"):
                rule["sid"] = HOST
    return state


class ExperienceTests(unittest.TestCase):
    def test_normal_installed_client_requires_protected_account_setup(self):
        state = experience.present(ordinary())
        self.assertEqual(state.mode, "setup")
        self.assertFalse(state.launchable)

    def test_partial_installation_never_takes_over_an_existing_account(self):
        for key, value in (("account", {"sid": GUARD}),
                           ("system_acls", {"data_dir": {"exists": True}})):
            state = ordinary()
            state[key] = value
            self.assertEqual(experience.present(state).mode, "blocked")

    def test_host_or_runas_is_directed_to_actual_windows_sign_in(self):
        for sid, session in ((HOST, HOST), (GUARD, HOST), (GUARD, None)):
            state = ready()
            state["current"].update(sid=sid, session_sid=session)
            dashboard = experience.present(state)
            self.assertEqual(dashboard.mode, "upgrade" if sid == HOST and session == HOST else "switch")
            self.assertFalse(dashboard.launchable)

    def test_missing_client_offers_install_only_in_verified_guard_session(self):
        state = ready()
        state["client"] = {"found": False}
        state["profile_acls"] = []
        self.assertEqual(experience.present(state).mode, "install")
        state["defender"]["realtime"] = False
        self.assertEqual(experience.present(state).mode, "blocked")

    def test_corrupt_policy_and_unsafe_isolation_never_use_host_discord(self):
        for mutate in (lambda s: s.update(policy={"guard_sid": GUARD}),
                       lambda s: s["defender"].update(realtime=False),
                       lambda s: s["system_acls"]["policy"].update(reparse=True),
                       lambda s: s["profile_acls"][0].update(owner=HOST)):
            state = ready()
            state["installed_discord"] = ordinary()["installed_discord"]
            mutate(state)
            self.assertEqual(experience.present(state).mode, "blocked")

    def test_bad_signature_or_modified_entry_never_starts_installed_client(self):
        for key, value in (("signature", "NotSigned"), ("entry_clean", False)):
            state = ordinary()
            state["installed_discord"][key] = value
            start = Mock()
            paths = windows.Paths(Path("C:/Program Files"), Path("C:/ProgramData"), Path("C:/Start"),
                Path("C:/Users/User/AppData/Local"), Path("C:/Users/User/AppData/Roaming"))
            result = experience.one_click(paths, inspector=lambda _: state, popen=start)
            self.assertFalse(result["opened"])
            start.assert_not_called()

    def test_unsigned_absent_driver_never_falls_back_to_ordinary_open(self):
        state = kernel_ready()
        state["guardcore"]["connected"] = 0
        state["installed_discord"] = ordinary()["installed_discord"]
        start = Mock()
        self.assertEqual(experience.present(state).mode, "blocked")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = windows.Paths(root, root, root, root / "Local", root / "Roaming")
            self.assertFalse(experience.one_click(paths, inspector=lambda _: state, popen=start)["opened"])
        start.assert_not_called()

    def test_even_a_valid_host_discord_never_opens_or_registers_startup(self):
        state = ordinary()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = windows.Paths(root, root, root, root / "Local", root / "Roaming")
            binary = paths.discord_install_root / "app-1.0.1" / "Discord.exe"
            state["installed_discord"]["path"] = str(binary)
            start = Mock()
            with patch.object(windows, "set_autostart") as startup:
                result = experience.one_click(paths, inspector=lambda _: state, popen=start, enable_startup=True)
            self.assertFalse(result["opened"])
            self.assertEqual(result["state"].mode, "setup")
            start.assert_not_called()
            startup.assert_not_called()

    def test_missing_profile_is_prepared_only_through_the_launch_gate(self):
        state = ready()
        state["profile_acls"][-1] = {"exists": False}
        self.assertEqual(experience.present(state).mode, "prepare")
        with patch.object(windows, "launch", side_effect=windows.GuardError("ACL rejected")), \
                self.assertRaises(windows.GuardError):
            experience.one_click(paths=Mock(), inspector=lambda _: state)

    def test_isolated_launch_keeps_existing_security_gate(self):
        state = ready()
        self.assertEqual(experience.present(state).mode, "isolated")
        with patch.object(windows, "launch") as launch:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                paths = windows.Paths(root, root, root, root / "Local", root / "Roaming")
                experience.one_click(paths, inspector=lambda _: state)
            launch.assert_called_once()

    def test_existing_client_still_needs_all_checks_and_startup_consent(self):
        state = ready()
        state["client_running"] = True
        with patch.object(windows, "launch") as launch, patch.object(windows, "set_autostart") as startup:
            result = experience.one_click(paths=Mock(), inspector=lambda _: state, enable_startup=True)
            self.assertTrue(result["opened"])
            launch.assert_not_called()
            startup.assert_called_once()
        state["current"]["session_sid"] = HOST
        with patch.object(windows, "set_autostart") as startup:
            self.assertFalse(experience.one_click(paths=Mock(), inspector=lambda _: state, enable_startup=True)["opened"])
            startup.assert_not_called()


class GuiFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PySide6.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication([])

    def test_primary_button_routes_setup_switch_and_install_without_launch(self):
        from discord_guard.gui import GuardWindow
        window = GuardWindow(auto_refresh=False)
        host = ready()
        host["current"].update(sid=GUARD, session_sid=HOST)
        missing = ready()
        missing["client"] = {"found": False}
        try:
            for snapshot, method in ((ordinary(), "setup"), (host, "switch"), (missing, "install_discord")):
                window.render(snapshot)
                with patch.object(window, method) as action, patch.object(windows, "launch") as launch:
                    window.activate()
                    action.assert_called_once()
                    launch.assert_not_called()
        finally:
            window.close()
            window.deleteLater()

    def test_finished_worker_can_chain_the_next_onboarding_operation(self):
        from PySide6.QtCore import QEventLoop, QTimer
        from discord_guard.gui import GuardWindow
        window = GuardWindow(auto_refresh=False)
        loop = QEventLoop()
        results = []

        def second(value):
            results.append(value)
            loop.quit()

        def first(value):
            results.append(value)
            window.begin(lambda: "installed", second)

        timer = QTimer()
        timer.setSingleShot(True)
        timer.timeout.connect(loop.quit)
        try:
            window.begin(lambda: "inspected", first)
            timer.start(5000)
            loop.exec()
            self.assertEqual(results, ["inspected", "installed"])
            self.assertIsNone(window.task)
        finally:
            timer.stop()
            if window.task:
                window.task.wait(5000)
            window.close()
            window.deleteLater()


if __name__ == "__main__":
    unittest.main()
