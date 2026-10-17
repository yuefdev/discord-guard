from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from discord_guard.core import decide
from discord_guard import windows
from test_security import ready, safe_acl, HOST


def kernel_ready():
    state = ready()
    state["policy"]["guardcore_required"] = True
    state["system_acls"]["native_helper"] = safe_acl()
    state["guardcore"] = {"available": True, "error": 0, "configured": 1,
                          "connected": 1, "process_callbacks": 1}
    # These stores are intentionally inaccessible to the ordinary launcher.
    state["client"] = {}
    state["profile_acls"] = []
    return state


class GuardCoreGateTests(unittest.TestCase):
    def test_native_mode_uses_the_authenticated_broker_not_direct_profile_reads(self):
        self.assertTrue(decide(kernel_ready()).allowed)

    def test_missing_driver_or_disconnected_callbacks_are_not_reported_as_protected(self):
        for key, value in (("available", False), ("configured", 0), ("connected", 0),
                           ("process_callbacks", 0), ("error", 5)):
            state = kernel_ready()
            state["guardcore"][key] = value
            self.assertFalse(decide(state).allowed)
        state = kernel_ready()
        state.pop("guardcore")
        self.assertFalse(decide(state).allowed)

    def test_native_mode_still_requires_the_separate_standard_identity(self):
        state = kernel_ready()
        state["current"]["sid"] = HOST
        self.assertFalse(decide(state).allowed)
        state = kernel_ready()
        state["account"]["admin_member"] = True
        self.assertFalse(decide(state).allowed)

    def test_native_helper_with_a_public_write_acl_is_never_executed(self):
        state = kernel_ready()
        state["system_acls"]["native_helper"]["rules"].append({"sid": HOST, "rights": 2, "type": "Allow"})
        self.assertFalse(decide(state).allowed)
        with patch.object(windows, "run_script", return_value=state), \
                patch.object(windows, "guardcore_command") as helper:
            windows.inspect(windows.Paths(Path("C:/Program Files"), Path("C:/ProgramData"),
                Path("C:/Start"), Path("C:/Users/Guard/AppData/Local"), Path("C:/Users/Guard/AppData/Roaming")))
            helper.assert_not_called()

    def test_broker_rejection_never_falls_back_to_unprotected_discord(self):
        state = kernel_ready()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = windows.Paths(root / "program", root / "data", root / "start", root / "local", root / "roaming")
            direct = Mock()
            with patch.object(windows, "guardcore_command", return_value={"available": False}):
                with self.assertRaises(windows.GuardError):
                    windows.launch(paths, inspector=lambda _: state, popen=direct)
                direct.assert_not_called()
            self.assertFalse(paths.discord_profile.exists())

    def test_success_is_delegated_to_service_instead_of_popen(self):
        state = kernel_ready()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = windows.Paths(root / "program", root / "data", root / "start", root / "local", root / "roaming")
            direct = Mock()
            with patch.object(windows, "guardcore_command", return_value={"available": True, "error": 0}) as helper:
                windows.launch(paths, inspector=lambda _: state, popen=direct)
                helper.assert_called_once_with(paths, "--launch")
                direct.assert_not_called()


if __name__ == "__main__":
    unittest.main()
