import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from discord_guard import startup, windows
from discord_guard.__main__ import main
from test_security import ready, HOST


COMMAND = r'"C:\Program Files\DiscordGuard\DiscordGuard.exe" --autostart'
UPDATER = r'C:\Users\DiscordGuard\AppData\Local\Discord\Update.exe'
DISCORD = startup.Entry(f'"{UPDATER}" --processStart Discord.exe --process-start-args "--start-inactive"')


class Store:
    def __init__(self, values=None, fail_at=0):
        self.values = dict(values or {})
        self.fail_at = fail_at
        self.writes = 0

    def read(self, key, name):
        return self.values.get((key, name))

    def write(self, key, name, entry):
        self.writes += 1
        if self.writes == self.fail_at:
            raise OSError("Synthetic registry write failure")
        if entry is None:
            self.values.pop((key, name), None)
        else:
            self.values[(key, name)] = entry


class StartupTransactionTests(unittest.TestCase):
    def test_enable_disable_restores_discord_and_preserves_unrelated_apps(self):
        original = {(startup.RUN_KEY, "Discord"): DISCORD,
                    (startup.RUN_KEY, "UserApplication"): startup.Entry("leave-this-command-alone")}
        store = Store(original)
        startup.configure(store, COMMAND, UPDATER, enabled=True)
        self.assertEqual(store.read(startup.RUN_KEY, startup.GUARD_VALUE), startup.Entry(COMMAND))
        self.assertIsNone(store.read(startup.RUN_KEY, "Discord"))
        startup.configure(store, COMMAND, UPDATER, enabled=False)
        self.assertEqual(store.values, original)

    def test_disabling_does_not_create_a_previously_absent_discord_entry(self):
        store = Store()
        startup.configure(store, COMMAND, UPDATER, enabled=True)
        startup.configure(store, COMMAND, UPDATER, enabled=False)
        self.assertEqual(store.values, {})

    def test_repeated_enable_preserves_the_original_restore_record(self):
        store = Store({(startup.RUN_KEY, "Discord"): DISCORD})
        startup.configure(store, COMMAND, UPDATER, enabled=True)
        saved = store.read(startup.STATE_KEY, startup.STATE_VALUE)
        startup.configure(store, COMMAND, UPDATER, enabled=True)
        self.assertEqual(store.read(startup.STATE_KEY, startup.STATE_VALUE), saved)
        startup.configure(store, COMMAND, UPDATER, enabled=False)
        self.assertEqual(store.read(startup.RUN_KEY, "Discord"), DISCORD)

    def test_unknown_discord_command_is_never_taken_over(self):
        original = {(startup.RUN_KEY, "Discord"): startup.Entry('"C:\\Somewhere\\custom.exe" --user-setting')}
        store = Store(original)
        with self.assertRaises(startup.StartupError):
            startup.configure(store, COMMAND, UPDATER, enabled=True)
        self.assertEqual(store.values, original)
        self.assertEqual(store.writes, 0)

    def test_new_user_changes_are_preserved_when_disabling(self):
        store = Store({(startup.RUN_KEY, "Discord"): DISCORD})
        startup.configure(store, COMMAND, UPDATER, enabled=True)
        store.values[(startup.RUN_KEY, "Discord")] = startup.Entry("user-changed-startup")
        before = copy.deepcopy(store.values)
        with self.assertRaises(startup.StartupError):
            startup.configure(store, COMMAND, UPDATER, enabled=False)
        self.assertEqual(store.values, before)

    def test_failed_handover_rolls_back_all_our_values(self):
        original = {(startup.RUN_KEY, "Discord"): DISCORD,
                    (startup.RUN_KEY, "UserApplication"): startup.Entry("unrelated")}
        store = Store(original, fail_at=3)
        with self.assertRaises(startup.StartupError):
            startup.configure(store, COMMAND, UPDATER, enabled=True)
        self.assertEqual(store.values, original)

    def test_conflicting_guard_entry_or_corrupt_backup_is_untouched(self):
        for key, entry in (((startup.RUN_KEY, startup.GUARD_VALUE), startup.Entry("different-launcher")),
                           ((startup.STATE_KEY, startup.STATE_VALUE), startup.Entry("not-json"))):
            store = Store({key: entry})
            with self.assertRaises(startup.StartupError):
                startup.configure(store, COMMAND, UPDATER, enabled=True)
            self.assertEqual(store.writes, 0)

    def test_wrong_windows_account_cannot_configure_startup(self):
        state = ready()
        state["current"]["sid"] = HOST
        store = Store()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = windows.Paths(root / "program", root / "data", root / "start", root / "local", root / "roaming")
            with self.assertRaises(windows.GuardError):
                windows.set_autostart(True, paths, inspector=lambda _: state, store=store)
        self.assertEqual(store.writes, 0)


class AutoEntrypointTests(unittest.TestCase):
    def test_successful_auto_start_is_quiet(self):
        with patch.object(windows, "run_autostart") as run, patch("discord_guard.gui.show") as show:
            self.assertEqual(main(["--autostart"]), 0)
            run.assert_called_once_with()
            show.assert_not_called()

    def test_failed_auto_start_opens_the_explanation_ui_without_a_bypass(self):
        with patch.object(windows, "run_autostart", side_effect=windows.GuardError("private ACL failed")) as run, \
                patch("discord_guard.gui.show") as show:
            self.assertEqual(main(["--autostart"]), 0)
            run.assert_called_once_with()
            self.assertEqual(show.call_args.kwargs["startup_error"], "private ACL failed")


if __name__ == "__main__":
    unittest.main()
