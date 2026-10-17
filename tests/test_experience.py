from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from discord_guard import experience, windows
from test_security import ready, HOST
from test_guardcore import kernel_ready


def ordinary():
    state = ready()
    state["policy"] = None
    state["current"]["sid"] = HOST
    state["installed_discord"] = dict(state["client"], found=True, version="1.0.1")
    for acl in state["installed_discord"]["acls"]:
        acl["owner"] = HOST
        for rule in acl["rules"]:
            if rule["sid"].endswith("1002"):
                rule["sid"] = HOST
    return state


class ExperienceTests(unittest.TestCase):
    def test_normal_installed_client_never_claims_live_protection(self):
        state = experience.present(ordinary())
        self.assertEqual(state.mode, "checked")
        self.assertIn("KAPALI", state.badge)
        self.assertIn("engellemez", state.detail)

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

    def test_ordinary_one_click_opens_only_the_fixed_discord_binary(self):
        state = ordinary()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = windows.Paths(root, root, root, root / "Local", root / "Roaming")
            binary = paths.discord_install_root / "app-1.0.1" / "Discord.exe"
            state["installed_discord"]["path"] = str(binary)
            start = Mock()
            result = experience.one_click(paths, inspector=lambda _: state, popen=start)
            self.assertTrue(result["opened"])
            self.assertEqual(result["state"].mode, "checked")
            self.assertEqual(start.call_args.args[0], [str(binary)])

    def test_isolated_launch_keeps_existing_security_gate(self):
        state = ready()
        self.assertEqual(experience.present(state).mode, "isolated")
        with patch.object(windows, "launch") as launch:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                paths = windows.Paths(root, root, root, root / "Local", root / "Roaming")
                experience.one_click(paths, inspector=lambda _: state)
            launch.assert_called_once()


if __name__ == "__main__":
    unittest.main()
