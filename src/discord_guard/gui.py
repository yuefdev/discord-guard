"""Liquid-glass dashboard. UI never upgrades a check into a protection claim."""

import math
from pathlib import Path
import sys

from PySide6.QtCore import Qt, QThread, QTimer
from PySide6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen, QRadialGradient
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QDialog, QFormLayout, QFrame, QGraphicsDropShadowEffect,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton,
    QScrollArea, QVBoxLayout, QWidget,
)

from . import __version__, experience, windows
from .activation import SingleInstance, foreground, instance_name
from .core import LOCAL_USER_SID, decide


STYLE = """
QWidget { color: #edf0ff; font-family: 'Segoe UI'; font-size: 14px; }
QMainWindow, QDialog { background: #090b15; }
QFrame#glass { background: rgba(27,32,57,190); border: 1px solid rgba(176,191,255,36); border-radius: 28px; }
QFrame#metric { background: rgba(36,42,70,150); border: 1px solid rgba(184,196,255,28); border-radius: 20px; }
QLabel { background: transparent; border: none; }
QLabel#brand { font-size: 23px; font-weight: 700; letter-spacing: -1px; }
QLabel#muted { color: #a3accb; }
QLabel#eyebrow { color: #a8b9f7; font-size: 12px; font-weight: 700; letter-spacing: 2px; }
QLabel#heading { font-size: 43px; font-weight: 700; letter-spacing: -2px; }
QLabel#badge { background: rgba(235,180,94,22); color: #edca8e; border: 1px solid rgba(235,180,94,60); border-radius: 13px; padding: 7px 12px; font-size: 11px; font-weight: 700; }
QLabel#value { font-size: 18px; font-weight: 600; }
QPushButton { background: rgba(117,137,209,15); border: 1px solid rgba(178,194,255,38); border-radius: 13px; padding: 10px 17px; color: #dce3ff; }
QPushButton:hover { background: rgba(125,151,245,32); border-color: rgba(172,195,255,100); }
QPushButton:pressed { background: rgba(125,151,245,50); }
QPushButton:disabled { color: #737c9d; border-color: rgba(178,194,255,15); }
QPushButton#primary { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #9eadff,stop:0.55 #b3a5ff,stop:1 #d3b6fb); color: #14172d; border: 1px solid #d2d8ff; font-size: 16px; font-weight: 700; padding: 17px 24px; border-radius: 17px; }
QPushButton#primary:hover { background: #c9c6ff; }
QPushButton#primary:disabled { background: #3c4262; border-color: #4a5278; color: #a7afca; }
QPushButton#link { background: transparent; border: none; color: #aebbdc; padding: 7px; }
QLineEdit { background: #171d32; border: 1px solid #3c476e; border-radius: 10px; padding: 11px; }
QLineEdit:focus { border-color: #a4b1ff; }
QCheckBox { spacing: 10px; }
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical { background: transparent; width: 9px; }
QScrollBar::handle:vertical { background: #424f78; border-radius: 4px; min-height: 30px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
"""


def label(text="", name="", *, wrap=False):
    result = QLabel(text)
    if name:
        result.setObjectName(name)
    result.setWordWrap(wrap)
    return result


class Ambient(QWidget):
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor("#090b15"))
        for x, y, radius, colour in ((0.05, 0.10, 620, "#242958"), (0.92, 0.45, 540, "#372448"),
                                     (0.4, 1.0, 480, "#142d42")):
            gradient = QRadialGradient(self.width() * x, self.height() * y, radius)
            gradient.setColorAt(0, QColor(colour))
            gradient.setColorAt(1, QColor(9, 11, 21, 0))
            painter.fillRect(self.rect(), gradient)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(QPen(QColor(180, 194, 255, 10), 1))
        for offset in range(3):
            painter.drawEllipse(int(self.width() * 0.6) - offset * 75, -280 - offset * 50, 760, 760)


class Shield(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(245, 265)
        self.phase = 0.0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(60)

    def tick(self):
        self.phase += 0.045
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        glow = QRadialGradient(122, 130, 121)
        glow.setColorAt(0, QColor(150, 155, 255, 64))
        glow.setColorAt(1, QColor(100, 100, 255, 0))
        painter.fillRect(self.rect(), glow)
        painter.setPen(QPen(QColor(186, 201, 255, 35), 1))
        painter.setBrush(QColor(173, 187, 255, 9))
        painter.drawEllipse(24, 31, 197, 197)
        painter.setPen(QPen(QColor(207, 218, 255, 80 + int(18 * math.sin(self.phase))), 1.2))
        painter.drawEllipse(41, 48, 163, 163)
        path = QPainterPath()
        path.moveTo(122, 66)
        path.cubicTo(142, 79, 163, 83, 169, 85)
        path.lineTo(166, 133)
        path.cubicTo(163, 160, 145, 180, 122, 191)
        path.cubicTo(99, 180, 81, 160, 78, 133)
        path.lineTo(75, 85)
        path.cubicTo(94, 82, 109, 75, 122, 66)
        gradient = QLinearGradient(75, 66, 170, 190)
        gradient.setColorAt(0, QColor(215, 227, 255, 155))
        gradient.setColorAt(0.5, QColor(150, 151, 250, 95))
        gradient.setColorAt(1, QColor(215, 163, 255, 150))
        painter.setBrush(gradient)
        painter.setPen(QPen(QColor(222, 231, 255, 200), 1.4))
        painter.drawPath(path)
        painter.setPen(QPen(QColor(237, 239, 255, 215), 3, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        painter.setBrush(Qt.NoBrush)
        painter.drawRoundedRect(106, 118, 32, 30, 7, 7)
        painter.drawArc(111, 99, 22, 30, 0, 180 * 16)
        painter.drawLine(122, 129, 122, 138)
        painter.setPen(QColor("#9cacca"))
        painter.setFont(QFont("Segoe UI", 9))
        painter.drawText(0, 233, 245, 24, Qt.AlignCenter, "Y E R E L   ·   Ş E F F A F")


class Task(QThread):
    def __init__(self, operation, parent):
        super().__init__(parent)
        self.operation = operation
        self.value = None
        self.error = None

    def run(self):
        try:
            self.value = self.operation()
        except Exception as error:
            self.error = str(error) if isinstance(error, windows.GuardError) else "İşlem tamamlanamadı. Kontrolleri yenile."


class WorkMixin:
    def begin(self, operation, callback):
        if getattr(self, "task", None) and self.task.isRunning():
            return
        for button in self.action_buttons:
            button.setEnabled(False)
        task = Task(operation, self)
        self.task = task

        def completed():
            self.task = None
            for button in self.action_buttons:
                button.setEnabled(True)
            if task.error:
                self.set_message(task.error)
            else:
                callback(task.value)

        # The next onboarding action may start another worker immediately. Wait
        # for actual thread completion before enabling buttons/calling back.
        task.finished.connect(completed)
        task.finished.connect(task.deleteLater)
        task.start()

    def closeEvent(self, event):
        if getattr(self, "task", None) and self.task.isRunning():
            self.set_message("Kontrol tamamlanırken lütfen bekle.")
            event.ignore()
        else:
            event.accept()


class Metric(QFrame):
    def __init__(self, title, parent):
        super().__init__(parent)
        self.setObjectName("metric")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(7)
        layout.addWidget(label(title, "muted"))
        self.value = label("Kontrol ediliyor", "value")
        self.caption = label("…", "muted", wrap=True)
        layout.addWidget(self.value)
        layout.addWidget(self.caption)

    def render(self, value, caption):
        self.value.setText(value)
        self.caption.setText(caption)


class GuardWindow(QMainWindow, WorkMixin):
    def __init__(self, *, auto_refresh=True, onboard=False):
        super().__init__()
        self.setWindowTitle(f"DiscordGuard {__version__}")
        self.resize(1010, 760)
        self.setMinimumSize(920, 720)
        self.snapshot = {}
        self.onboard = onboard
        self.setCentralWidget(Ambient())
        outer = QVBoxLayout(self.centralWidget())
        outer.setContentsMargins(38, 24, 38, 24)
        outer.setSpacing(22)
        header = QHBoxLayout()
        header.addWidget(label("◈", "brand"))
        header.addWidget(label("discordguard", "brand"))
        header.addStretch()
        header.addWidget(label(f"v{__version__}  /  prototip", "muted"))
        self.refresh_button = QPushButton("↻  Yenile")
        self.refresh_button.clicked.connect(self.refresh)
        header.addWidget(self.refresh_button)
        outer.addLayout(header)
        panel = QFrame()
        panel.setObjectName("glass")
        shadow = QGraphicsDropShadowEffect(panel)
        shadow.setColor(QColor(0, 0, 0, 80))
        shadow.setBlurRadius(45)
        shadow.setOffset(0, 15)
        panel.setGraphicsEffect(shadow)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(35, 30, 35, 26)
        layout.setSpacing(14)
        layout.addWidget(label("DISCORD İÇİN TEK MERKEZ", "eyebrow"))
        hero = QHBoxLayout()
        hero.setSpacing(10)
        copy = QVBoxLayout()
        copy.setSpacing(11)
        self.badge = label("DURUM KONTROL EDİLİYOR", "badge")
        badge_line = QHBoxLayout()
        badge_line.addWidget(self.badge)
        badge_line.addStretch()
        copy.addLayout(badge_line)
        self.heading = label("Korumalı\nDiscord alanı.", "heading", wrap=True)
        copy.addWidget(self.heading)
        self.description = label("Ayrı Windows oturumu ve erişim izinleri doğrulanıyor.", "muted", wrap=True)
        self.description.setMinimumHeight(52)
        copy.addWidget(self.description)
        copy.addStretch()
        hero.addLayout(copy, 3)
        hero.addWidget(Shield(), 1)
        layout.addLayout(hero)
        metrics = QHBoxLayout()
        metrics.setSpacing(12)
        self.discord_metric = Metric("DISCORD MASAÜSTÜ", panel)
        self.defender_metric = Metric("WINDOWS DEFENDER", panel)
        self.kernel_metric = Metric("GUARDCORE", panel)
        for metric in (self.discord_metric, self.defender_metric, self.kernel_metric):
            metrics.addWidget(metric, 1)
        layout.addLayout(metrics)
        layout.addSpacing(5)
        self.primary = QPushButton("Discord’u kontrol et")
        self.primary.setObjectName("primary")
        self.primary.setMinimumHeight(58)
        self.primary.clicked.connect(self.activate)
        layout.addWidget(self.primary)
        self.startup_choice = QCheckBox("Bu hesapta her Windows girişinde denetimli açılışı etkinleştir")
        self.startup_choice.setChecked(True)
        self.startup_choice.hide()
        layout.addWidget(self.startup_choice)
        self.note = label("Kontrol tamamlandığında yapılabilecek işlem burada görünecek.", "muted", wrap=True)
        self.note.setAlignment(Qt.AlignCenter)
        self.note.setMinimumHeight(38)
        layout.addWidget(self.note)
        outer.addWidget(panel, 1)
        footer = QHBoxLayout()
        footer.addWidget(label("●  Yerel çalışır  ·  Açık kaynak  ·  Token okumaz", "muted"))
        footer.addStretch()
        self.details_button = QPushButton("Ayrıntılar ve kurulum  ↗")
        self.details_button.setObjectName("link")
        self.details_button.clicked.connect(self.details)
        footer.addWidget(self.details_button)
        outer.addLayout(footer)
        self.action_buttons = [self.primary, self.refresh_button, self.details_button]
        if auto_refresh:
            QTimer.singleShot(100, self.refresh)

    def closeEvent(self, event):
        WorkMixin.closeEvent(self, event)

    def set_message(self, text):
        self.note.setText(text)

    def refresh(self):
        self.set_message("Discord ve Windows kontrolleri çalışıyor…")
        self.begin(windows.inspect, self.render)

    def render(self, snapshot):
        self.snapshot = snapshot
        state = experience.present(snapshot)
        self.badge.setText(state.badge)
        self.heading.setText(state.heading.replace(". ", ".\n", 1))
        self.description.setText(state.description)
        self.primary.setText(state.button)
        self.startup_choice.setVisible(state.mode in ("isolated", "kernel", "prepare", "install"))
        self.note.setText(state.detail)
        client = snapshot.get("installed_discord") or snapshot.get("client") or {}
        self.discord_metric.render("Yüklü" if client.get("found") else "Bulunamadı",
                                   f"Sürüm {client.get('version', '—')}" if client.get("found") else "Bu Windows hesabında")
        defender = snapshot.get("defender", {})
        active = all(defender.get(key) is True for key in ("realtime", "behavior", "antivirus"))
        self.defender_metric.render("Etkin" if active else "Doğrulanamadı", "Windows’un mevcut koruması")
        native = snapshot.get("guardcore", {})
        live = native.get("available") is True and native.get("configured") == 1 and native.get("connected") == 1
        self.kernel_metric.render("Deneysel bağlantı" if live else "Etkin değil",
                                  "VM çalışma testi gerekli" if live else "İmzalı sürücü kurulu değil")
        if self.onboard:
            self.onboard = False
            if state.mode == "setup":
                QTimer.singleShot(0, self.setup)

    def activate(self):
        state = experience.present(self.snapshot)
        if state.mode == "setup":
            self.setup()
            return
        if state.mode == "switch":
            self.switch()
            return
        if state.mode == "install":
            self.install_discord()
            return
        if not state.launchable:
            self.refresh()
            return
        self.set_message("Korumalı Discord açılışı doğrulanıyor…")

        def complete(result):
            self.render(result["snapshot"])
            if result["opened"]:
                self.set_message("Discord korumalı Windows oturumunda açıldı. Erişim sınırı Windows tarafından uygulanıyor.")

        enable_startup = self.startup_choice.isChecked()
        self.begin(lambda: experience.one_click(enable_startup=enable_startup), complete)

    def details(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("DiscordGuard · Ayrıntılar")
        dialog.resize(760, 650)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(24, 24, 24, 24)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        items = QVBoxLayout(body)
        items.setSpacing(14)
        items.addWidget(label("Gerçek koruma durumu", "brand"))
        items.addWidget(label(experience.present(self.snapshot).detail, "muted", wrap=True))
        client = self.snapshot.get("installed_discord") or {}
        if client.get("path"):
            path = label(client["path"], "muted", wrap=True)
            path.setTextInteractionFlags(Qt.TextSelectableByMouse)
            items.addWidget(path)
        for title, passed in experience.installed_checks(self.snapshot):
            items.addWidget(label(("✓  " if passed else "·  ") + title))
        items.addWidget(label("Ayrı Windows hesabıyla erişim sınırı", "value"))
        items.addWidget(label("Ana hesaptaki normal yetkili programlardan oturum dosyalarını ayırır. İlk kurulum ve "
                              "Windows kullanıcı geçişi gerekir; otomatik giriş parolası saklanmaz.", "muted", wrap=True))
        buttons = QHBoxLayout()
        for text, action in (("Korumalı hesabı kur", self.setup), ("Windows giriş ekranı", self.switch),
                             ("Resmî Discord’u kur", self.install_discord)):
            button = QPushButton(text)
            button.clicked.connect(lambda _=False, operation=action: (dialog.accept(), operation()))
            buttons.addWidget(button)
        items.addLayout(buttons)
        auto = QHBoxLayout()
        for text, enabled in (("Denetimli otomatik açılış: aç", True), ("Kapat ve önceki ayarı yükle", False)):
            button = QPushButton(text)
            button.clicked.connect(lambda _=False, value=enabled: (dialog.accept(), self.set_autostart(value)))
            auto.addWidget(button)
        items.addLayout(auto)
        items.addWidget(label("Sürücü ve yayın", "value"))
        items.addWidget(label("GuardCore derlenmiş bir araştırma prototipidir. Microsoft imzası ve VM çalışma testi henüz yok. "
                              "Bu paket sürücü yüklemez. Yönetici/SYSTEM yetkili saldırgana dayanım garantisi verilmez.", "muted", wrap=True))
        items.addWidget(label("Başlatma denetimleri", "value"))
        for check in decide(self.snapshot, require_stopped=False).checks:
            items.addWidget(label(("✓ " if check.passed else "· ") + check.title + "\n" + check.detail, "muted", wrap=True))
        for check in decide(self.snapshot).advisories:
            items.addWidget(label(f"{check.title}: {'etkinlik doğrulandı' if check.passed else 'kapalı / okunamadı'}", "muted"))
        items.addStretch()
        scroll.setWidget(body)
        layout.addWidget(scroll)
        close = QPushButton("Tamam")
        close.clicked.connect(dialog.accept)
        layout.addWidget(close)
        dialog.exec()

    def setup(self):
        def operation():
            snapshot = windows.inspect()
            if experience.present(snapshot).mode != "setup":
                return snapshot
            sid = snapshot.get("current", {}).get("sid", "")
            if not LOCAL_USER_SID.fullmatch(sid):
                raise windows.GuardError("Windows hesabının kimliği doğrulanamadı.")
            windows.request_setup(sid)
            return windows.inspect()

        self.set_message("Windows onayını ve açılan kurulum penceresini tamamla…")
        self.begin(operation, self.render)

    def switch(self):
        if QMessageBox.question(self, "Windows giriş ekranı", "Windows oturumu kilitlenecek. Devam edilsin mi?") == QMessageBox.Yes:
            try:
                windows.lock_for_user_switch()
            except windows.GuardError as error:
                self.set_message(str(error))

    def install_discord(self):
        if QMessageBox.question(self, "Discord kurulumu", "Resmî Discord kurucusu indirilsin, imzası doğrulansın ve açılsın mı?") == QMessageBox.Yes:
            self.set_message("Resmî Discord indiriliyor. Açılan kurulum penceresini tamamla…")
            enable_startup = self.startup_choice.isChecked()

            def operation():
                process = windows.install_discord()
                try:
                    code = process.wait(timeout=300)
                except windows.subprocess.TimeoutExpired as error:
                    raise windows.GuardError("Discord kurucusu hâlâ açık. Kurulumu tamamlayıp Yenile’ye bas.") from error
                if code != 0:
                    raise windows.GuardError("Discord kurucusu başarı bildirmedi. Kontrolleri yenileyip tekrar dene.")
                snapshot = windows.inspect()
                if enable_startup and experience.present(snapshot).launchable:
                    windows.set_autostart(True)
                return snapshot

            self.begin(operation, self.render)

    def set_autostart(self, enabled):
        self.begin(lambda: windows.set_autostart(enabled), lambda _: self.set_message(
            "Otomatik açılış etkin." if enabled else "Önceki başlangıç ayarı geri yüklendi."))


class SetupWindow(QDialog, WorkMixin):
    def __init__(self, origin_sid):
        super().__init__()
        self.origin_sid = origin_sid
        self.setWindowTitle("DiscordGuard · Kurulum")
        self.resize(580, 510)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(18)
        layout.addWidget(label("Korumalı alanını hazırla.", "brand"))
        layout.addWidget(label("Windows’ta standart DiscordGuard hesabı oluşturulacak. En az 14 karakterlik, "
                              "başka yerde kullanmadığın bir parola seç. Bu parola kaydedilmez.", "muted", wrap=True))
        form = QFormLayout()
        self.password, self.confirmation = QLineEdit(), QLineEdit()
        for field in (self.password, self.confirmation):
            field.setEchoMode(QLineEdit.Password)
        form.addRow("Yeni hesap parolası", self.password)
        form.addRow("Parola tekrarı", self.confirmation)
        layout.addLayout(form)
        self.agree = QCheckBox("Ayrı Windows hesabı oluşturulmasını onaylıyorum.")
        layout.addWidget(self.agree)
        self.status = label("Mevcut bir hesabın üzerine yazılmaz. Windows kullanıcı geçişi gerekecek.", "muted", wrap=True)
        layout.addWidget(self.status)
        self.install_button = QPushButton("Korumalı hesabı oluştur")
        self.install_button.setObjectName("primary")
        self.install_button.clicked.connect(self.install)
        layout.addWidget(self.install_button)
        self.action_buttons = [self.install_button]

    def closeEvent(self, event):
        WorkMixin.closeEvent(self, event)

    def set_message(self, text):
        self.status.setText(text)

    def install(self):
        password = self.password.text()
        if len(password) < 14 or password != self.confirmation.text() or not self.agree.isChecked():
            self.set_message("Parolalar aynı ve en az 14 karakter olmalı. Onayı işaretle.")
            return
        self.password.clear()
        self.confirmation.clear()
        self.set_message("Hesap ve özel dosya izinleri hazırlanıyor…")

        def complete(_):
            self.install_button.setText("Tamam, kurulumu bitir")
            self.install_button.clicked.disconnect()
            self.install_button.clicked.connect(self.accept)
            self.set_message("Kurulum tamam. Tamam’a bas; ana ekrandaki Korumalı hesaba geç düğmesiyle DiscordGuard hesabına giriş yap. Başlat menüsünden DiscordGuard’ı aç.")

        self.begin(lambda: windows.provision(password, self.origin_sid), complete)


def show(*, setup_origin_sid=None, smoke_test=False, startup_error=None, screenshot=None, onboard=False):
    application = QApplication.instance() or QApplication(sys.argv[:1])
    application.setApplicationName("DiscordGuard")
    application.setOrganizationName("DiscordGuard")
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("DiscordGuard.Desktop")
    application.setStyleSheet(STYLE)
    application.setFont(QFont("Segoe UI", 10))
    holder = {}
    gate = None
    if not smoke_test and not screenshot:
        gate = SingleInstance(instance_name(setup=bool(setup_origin_sid), onboard=onboard),
                              lambda: foreground(holder["window"]), application)
        try:
            if not gate.claim():
                return 0
        except windows.GuardError as error:
            QMessageBox.warning(None, "DiscordGuard açılışı", str(error))
            return 1
    window = SetupWindow(setup_origin_sid) if setup_origin_sid else GuardWindow(auto_refresh=not smoke_test, onboard=onboard)
    holder["window"] = window
    window.show()
    if not smoke_test and not screenshot:
        QTimer.singleShot(0, lambda: foreground(window))
    if startup_error:
        window.set_message(startup_error)
    if screenshot:
        def capture():
            window.grab().save(str(Path(screenshot)))
            application.quit()
        QTimer.singleShot(700, capture)
    elif smoke_test:
        QTimer.singleShot(250, application.quit)
    try:
        return application.exec()
    finally:
        if gate:
            gate.close()
