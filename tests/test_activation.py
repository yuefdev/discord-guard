import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from discord_guard import activation


class ActivationTests(unittest.TestCase):
    def test_a_minimised_existing_window_is_restored_and_activated(self):
        window = Mock()
        window.isMinimized.return_value = True
        with patch.object(activation.os, "name", "posix"):
            activation.foreground(window)
        window.showNormal.assert_called_once()
        window.raise_.assert_called_once()
        window.activateWindow.assert_called_once()

    def test_visible_window_is_raised_without_resetting_its_size(self):
        window = Mock()
        window.isMinimized.return_value = False
        with patch.object(activation.os, "name", "posix"):
            activation.foreground(window)
        window.show.assert_called_once()
        window.showNormal.assert_not_called()
        window.raise_.assert_called_once()
        window.activateWindow.assert_called_once()

    def test_setup_and_main_windows_use_different_user_session_channels(self):
        self.assertEqual(activation.instance_name(), activation.instance_name())
        self.assertNotEqual(activation.instance_name(), activation.instance_name(setup=True))
        self.assertNotEqual(activation.instance_name(), activation.instance_name(onboard=True))
        self.assertNotEqual(activation.instance_name(setup=True), activation.instance_name(onboard=True))

    def test_second_process_activates_the_first_instead_of_claiming_another_window(self):
        name = "DiscordGuard-test-" + uuid.uuid4().hex
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        server_code = """
from PySide6.QtCore import QCoreApplication, QTimer
from discord_guard.activation import SingleInstance
import sys
app = QCoreApplication([])
def activate():
    print('activated', flush=True)
    QTimer.singleShot(100, app.quit)
server = SingleInstance(sys.argv[1], activate, app)
assert server.claim()
print('ready', flush=True)
QTimer.singleShot(8000, app.quit)
app.exec()
server.close()
"""
        client_code = """
from PySide6.QtCore import QCoreApplication
from discord_guard.activation import SingleInstance
import sys
app = QCoreApplication([])
client = SingleInstance(sys.argv[1], lambda: None, app)
print(client.claim())
client.close()
"""
        server = subprocess.Popen([sys.executable, "-B", "-u", "-c", server_code, name],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
        try:
            self.assertEqual(server.stdout.readline().strip(), "ready")
            client = subprocess.run([sys.executable, "-B", "-c", client_code, name],
                                    capture_output=True, text=True, env=environment, timeout=8)
            self.assertEqual(client.returncode, 0, client.stderr)
            self.assertEqual(client.stdout.strip(), "False")
            remaining, errors = server.communicate(timeout=10)
            self.assertEqual(server.returncode, 0, errors)
            self.assertIn("activated", remaining)
        finally:
            if server.poll() is None:
                server.kill()
                server.communicate()


if __name__ == "__main__":
    unittest.main()
