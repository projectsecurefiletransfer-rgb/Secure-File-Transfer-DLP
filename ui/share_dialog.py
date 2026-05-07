"""
ui/share_dialog.py - Secure File Sharing Dialog
Member 2 (Frontend Developer) | CET334 - Secure File Transfer & DLP System

Fixed:
- Accepts file_path from MainWindow
- Calls sharing.create_share_link() to save link + expiry to SQLite
- Falls back gracefully if sharing.py not yet ready (generates local UUID)
- Copy link button copies to clipboard
- Logs SHARE event to audit database via log_event()
- DLP BLOCKED files cannot be shared
"""

import os
import uuid
from datetime import datetime, timezone, timedelta

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QSpinBox, QApplication, QMessageBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui  import QFont

from database import log_event, EVENT_SHARE


class ShareDialog(QDialog):

    def __init__(self, file_path: str = "", dlp_decision: str = "ALLOW"):
        """
        Args:
            file_path:     Full path to the file to be shared.
            dlp_decision:  DLP decision string — "ALLOW", "BLOCK", or "WARN".
                           Blocked files cannot generate a share link.
        """
        super().__init__()
        self.file_path     = file_path
        self.dlp_decision  = dlp_decision
        self.current_link  = ""

        self.setWindowTitle("Secure Share Link — CET334")
        self.resize(440, 300)
        self._build_ui()

        # Disable creation immediately if DLP blocked
        if self.dlp_decision == "BLOCK":
            self.create_button.setEnabled(False)
            self.link_label.setText("⛔  Sharing blocked — DLP policy violation")
            self.link_label.setStyleSheet(
                "background: #f8d7da; border: 1px solid #f5c6cb; "
                "border-radius: 6px; padding: 8px; color: #721c24; font-size: 11px;"
            )

    # ── UI ───────────────────────────────
    def _build_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        title = QLabel("Create Secure Share Link")
        title.setFont(QFont("Arial", 13, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)

        # File info
        filename = os.path.basename(self.file_path) if self.file_path else "No file"
        self.file_label = QLabel(f"File: {filename}")
        self.file_label.setStyleSheet("color: #555; font-size: 12px;")

        # Expiry selector
        exp_row = QHBoxLayout()
        exp_row.addWidget(QLabel("Expiration:"))
        self.hours_box = QSpinBox()
        self.hours_box.setRange(1, 168)   # 1 hour → 7 days
        self.hours_box.setValue(24)
        self.hours_box.setSuffix(" hours")
        exp_row.addWidget(self.hours_box)
        exp_row.addStretch()

        # Generated link display
        self.link_label = QLabel("No link generated yet")
        self.link_label.setWordWrap(True)
        self.link_label.setStyleSheet(
            "background: #f8f9fa; border: 1px solid #dee2e6; "
            "border-radius: 6px; padding: 8px; font-family: monospace; font-size: 11px;"
        )
        self.link_label.setTextInteractionFlags(Qt.TextSelectableByMouse)

        # Expiry info
        self.expiry_label = QLabel("")
        self.expiry_label.setStyleSheet("color: gray; font-size: 11px;")

        # Buttons
        btn_row = QHBoxLayout()
        self.create_button = QPushButton("🔗  Create Link")
        self.copy_button   = QPushButton("📋  Copy Link")
        self.copy_button.setEnabled(False)
        self.create_button.setMinimumHeight(36)
        self.copy_button.setMinimumHeight(36)
        btn_row.addWidget(self.create_button)
        btn_row.addWidget(self.copy_button)

        layout.addWidget(title)
        layout.addWidget(self.file_label)
        layout.addLayout(exp_row)
        layout.addWidget(self.link_label)
        layout.addWidget(self.expiry_label)
        layout.addLayout(btn_row)
        self.setLayout(layout)

        self.create_button.clicked.connect(self.create_link)
        self.copy_button.clicked.connect(self.copy_link)

    # ── Create Link ──────────────────────
    def create_link(self):
        if not self.file_path:
            QMessageBox.warning(self, "Error", "No file selected.")
            return

        hours = self.hours_box.value()

        # Try sharing.py (Member 3) — fallback to local UUID
        try:
            from sharing import create_share_link
            link = create_share_link(self.file_path, hours)

        except ImportError:
            # sharing.py not yet ready — generate UUID locally
            link = f"secure-share://{uuid.uuid4()}"

        self.current_link = link
        self.link_label.setText(link)
        self.link_label.setStyleSheet(
            "background: #f8f9fa; border: 1px solid #dee2e6; "
            "border-radius: 6px; padding: 8px; font-family: monospace; font-size: 11px;"
        )
        self.copy_button.setEnabled(True)

        # Show expiry time
        expiry = datetime.now(timezone.utc) + timedelta(hours=hours)
        self.expiry_label.setText(
            f"⏱  Expires at: {expiry.strftime('%Y-%m-%d %H:%M UTC')}"
        )

        # Log SHARE event to audit
        try:
            log_event(
                EVENT_SHARE,
                os.path.basename(self.file_path),
                "user",
                {"link": link, "expires_hours": hours}
            )
        except Exception:
            pass   # audit logging is non-critical — don't crash sharing

    # ── Copy to Clipboard ────────────────
    def copy_link(self):
        if self.current_link:
            QApplication.clipboard().setText(self.current_link)
            self.copy_button.setText("✅  Copied!")
            from PyQt5.QtCore import QTimer
            QTimer.singleShot(2000, lambda: self.copy_button.setText("📋  Copy Link"))