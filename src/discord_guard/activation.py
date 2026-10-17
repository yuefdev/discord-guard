"""Bring the existing user/session window forward instead of opening hidden copies."""

import ctypes
from ctypes import wintypes
import getpass
import hashlib
import os

from PySide6.QtCore import QObject
from PySide6.QtNetwork import QLocalServer, QLocalSocket

from .windows import GuardError
from . import __version__


def instance_name(*, setup=False, onboard=False):
    session = 0
    if os.name == "nt":
        value = wintypes.DWORD()
        if ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(value)):
            session = value.value
    channel = f"setup-{__version__}" if setup else f"onboard-{__version__}" if onboard else "main"
    identity = f"{getpass.getuser()}:{session}:{channel}"
    return "DiscordGuard-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]


def foreground(window):
    if window.isMinimized():
        window.showNormal()
    else:
        window.show()
    window.raise_()
    window.activateWindow()
    if os.name == "nt":
        user = ctypes.WinDLL("user32", use_last_error=True)
        user.SetForegroundWindow.argtypes = [wintypes.HWND]
        user.SetForegroundWindow.restype = wintypes.BOOL
        user.SetForegroundWindow(int(window.winId()))


class SingleInstance(QObject):
    def __init__(self, name, activate, parent=None):
        super().__init__(parent)
        self.name = name
        self.activate = activate
        self.server = QLocalServer(self)
        self.server.setSocketOptions(QLocalServer.UserAccessOption)
        self.server.newConnection.connect(self.accept)
        self.connections = set()

    def notify_existing(self):
        client = QLocalSocket()
        client.connectToServer(self.name)
        if not client.waitForConnected(200):
            return False
        if not client.bytesAvailable() and not client.waitForReadyRead(1500):
            raise GuardError("Açık DiscordGuard penceresi yanıt vermiyor. Görev çubuğundan pencereye geçin.")
        owner = bytes(client.readLine()).strip()
        if not owner.isdigit():
            raise GuardError("DiscordGuard pencere bağlantısı doğrulanamadı.")
        if os.name == "nt":
            # A user-started second instance can grant foreground permission to the first.
            ctypes.windll.user32.AllowSetForegroundWindow(int(owner))
        client.write(b"activate\n")
        client.waitForBytesWritten(500)
        if (not client.bytesAvailable() and not client.waitForReadyRead(1500)) \
                or bytes(client.readAll()).strip() != b"shown":
            raise GuardError("Açık pencere öne getirilemedi. Görev çubuğundaki DiscordGuard’ı seçin.")
        client.disconnectFromServer()
        return True

    def claim(self):
        if self.notify_existing():
            return False
        if self.server.listen(self.name):
            return True
        # Another launch may have claimed the pipe between the connect/listen calls.
        if self.notify_existing():
            return False
        raise GuardError("DiscordGuard pencere kanalı açılamadı; yeni bir gizli kopya başlatılmadı.")

    def accept(self):
        while self.server.hasPendingConnections():
            client = self.server.nextPendingConnection()
            self.connections.add(client)
            client.write(str(os.getpid()).encode("ascii") + b"\n")
            client.flush()
            client.readyRead.connect(lambda client=client: self.receive(client))
            client.disconnected.connect(lambda client=client: self.release(client))
            if client.bytesAvailable():
                self.receive(client)

    def receive(self, client):
        if client.bytesAvailable() > 64:
            client.disconnectFromServer()
            return
        if not client.canReadLine():
            return
        if bytes(client.readLine()).strip() == b"activate":
            self.activate()
            client.write(b"shown\n")
            client.flush()
        client.disconnectFromServer()

    def release(self, client):
        self.connections.discard(client)
        client.deleteLater()

    def close(self):
        for client in tuple(self.connections):
            client.abort()
        self.server.close()
