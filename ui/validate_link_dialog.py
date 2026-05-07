"""
ui/validate_link_dialog.py - Validate & Access Secure Share Link
CET334 - Secure File Transfer & DLP System

Allows a user to paste a "secure-share://<uuid>" link and:
- Validates it against the SQLite database (not expired, not revoked)
- Shows file info + expiry time if valid
- Offers to decrypt the file directly (password prompt)
- Logs ACCESS event to audit log
"""

import os
from datetime import datetime, timezone

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QMessageBox, QFrame,
    QInputDialog
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui  import QFont

from database import log_event, EVENT_ACCESS


class ValidateLinkDialog(QDialog):

    def __init__(self, prefill_link: str = ""):
        super().__init__()
        self.setWindowTitle("Validate Share Link — CET334")
        self.resize(480, 320)
        self._build_ui()

        if prefill_link:
            self.link_input.setText(prefill_link)
            self._validate()

    # ── UI ───────────────────────────────
    def _build_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(22, 22, 22, 22)
        layout.setSpacing(12)

        # Title
        title = QLabel("🔗  Validate Secure Share Link")
        title.setFont(QFont("Arial", 13, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)

        # Divider
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("color: #cccccc;")

        # Link input row
        input_row = QHBoxLayout()
        self.link_input = QLineEdit()
        self.link_input.setPlaceholderText("Paste link here:  secure-share://xxxxxxxx-...")
        self.link_input.setMinimumHeight(34)
        self.link_input.setStyleSheet(
            "font-family: monospace; font-size: 11px; padding: 4px 8px; "
            "border: 1px solid #ced4da; border-radius: 4px;"
        )
        self.validate_btn = QPushButton("🔍  Validate")
        self.validate_btn.setMinimumHeight(34)
        self.validate_btn.setMinimumWidth(100)
        input_row.addWidget(self.link_input)
        input_row.addWidget(self.validate_btn)

        # Status badge
        self.status_label = QLabel("Enter a link above and click Validate.")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setWordWrap(True)
        self.status_label.setStyleSheet(
            "color: gray; background: #f0f0f0; font-size: 12px; "
            "padding: 8px; border-radius: 6px;"
        )

        # File info area
        self.info_label = QLabel("")
        self.info_label.setAlignment(Qt.AlignCenter)
        self.info_label.setStyleSheet("color: #444; font-size: 11px;")
        self.info_label.setWordWrap(True)

        # Action buttons
        btn_row = QHBoxLayout()
        self.decrypt_btn = QPushButton("🔓  Decrypt File")
        self.decrypt_btn.setMinimumHeight(36)
        self.decrypt_btn.setEnabled(False)
        self.decrypt_btn.setStyleSheet(
            "QPushButton:enabled { background: #0d6efd; color: white; "
            "border-radius: 5px; font-weight: bold; }"
            "QPushButton:disabled { background: #e0e0e0; color: #aaa; border-radius: 5px; }"
        )
        self.close_btn = QPushButton("Close")
        self.close_btn.setMinimumHeight(36)
        btn_row.addWidget(self.decrypt_btn)
        btn_row.addWidget(self.close_btn)

        layout.addWidget(title)
        layout.addWidget(line)
        layout.addLayout(input_row)
        layout.addWidget(self.status_label)
        layout.addWidget(self.info_label)
        layout.addStretch()
        layout.addLayout(btn_row)
        self.setLayout(layout)

        self.validate_btn.clicked.connect(self._validate)
        self.decrypt_btn.clicked.connect(self._decrypt_file)
        self.close_btn.clicked.connect(self.close)
        self.link_input.returnPressed.connect(self._validate)

        # Store validated file path
        self._valid_file_path = ""

    # ── Validate ─────────────────────────
    def _validate(self):
        link = self.link_input.text().strip()
        if not link:
            QMessageBox.warning(self, "Error", "Please paste a share link first.")
            return

        try:
            from sharing import validate_share_link
            result = validate_share_link(link)
        except ImportError:
            QMessageBox.critical(
                self, "Error",
                "sharing.py not found. Make sure it's in the project root."
            )
            return
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Validation error: {e}")
            return

        if result["valid"]:
            self._valid_file_path = result["file_path"]

            # Compute time remaining
            expires_dt = datetime.fromisoformat(result["expires_at"])
            now        = datetime.now(timezone.utc)
            remaining  = expires_dt - now
            hours_left = int(remaining.total_seconds() // 3600)
            mins_left  = int((remaining.total_seconds() % 3600) // 60)

            self.status_label.setText("✅  Link is VALID — Access Granted")
            self.status_label.setStyleSheet(
                "color:#155724; background:#d4edda; font-size:13px; "
                "font-weight:bold; padding:8px; border-radius:6px;"
            )
            self.info_label.setText(
                f"📄  File: {result['file_name']}\n"
                f"⏱  Expires in: {hours_left}h {mins_left}m   "
                f"({result['expires_at'][:19]} UTC)"
            )
            self.decrypt_btn.setEnabled(True)

        else:
            self._valid_file_path = ""
            self.status_label.setText(f"🚫  INVALID — {result['reason']}")
            self.status_label.setStyleSheet(
                "color:#721c24; background:#f8d7da; font-size:13px; "
                "font-weight:bold; padding:8px; border-radius:6px;"
            )
            self.info_label.setText(
                f"File: {result.get('file_name', 'N/A')}   "
                f"Expired at: {result.get('expires_at', 'N/A')[:19]}"
                if result.get("file_name") else ""
            )
            self.decrypt_btn.setEnabled(False)

    # ── Decrypt after validation ─────────
    def _decrypt_file(self):
        if not self._valid_file_path:
            QMessageBox.warning(self, "Error", "No valid file to decrypt.")
            return

        if not os.path.isfile(self._valid_file_path):
            QMessageBox.critical(
                self, "File Not Found",
                f"The file no longer exists at:\n{self._valid_file_path}"
            )
            return

        # Ask for password
        dlg = QInputDialog(self)
        dlg.setWindowTitle("Decryption Password")
        dlg.setLabelText("Enter password to decrypt:")
        dlg.setTextEchoMode(QLineEdit.Password)
        if not dlg.exec_():
            return
        password = dlg.textValue()
        if not password:
            return

        # Output path
        if self._valid_file_path.endswith(".enc"):
            output_path = self._valid_file_path[:-4] + ".dec"
        else:
            output_path = self._valid_file_path + ".dec"

        try:
            from crypto import decrypt_file
            decrypt_file(self._valid_file_path, output_path, password)

            # Log ACCESS event
            try:
                log_event(
                    EVENT_ACCESS,
                    os.path.basename(self._valid_file_path),
                    "user",
                    {"action": "decrypted_via_share_link", "output": output_path}
                )
            except Exception:
                pass

            QMessageBox.information(
                self, "Success",
                f"✅  File decrypted successfully:\n{output_path}"
            )

        except ValueError as e:
            QMessageBox.critical(
                self, "Decryption Failed",
                f"❌  Wrong password or file tampered.\n\n{e}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"❌  {e}")