"""
ui/main_window.py - Main Application Window
Member 2 (Frontend Developer) | CET334 - Secure File Transfer & DLP System

Updates:
- Password input uses PasswordEchoOnEdit (hidden characters)
- Progress bar shows action label during crypto
- Consistent EVENT_* constants from database.py
- QThread prevents GUI freeze during encrypt/decrypt
- log_event() called after every operation
- DLP check calls dlp.check_file_policy() with fallback
- NONCE_SIZE fix: compiled against crypto.py with NONCE_SIZE=12 (NIST standard)
"""

import os
from PyQt5.QtWidgets import (
    QWidget, QPushButton, QLabel, QFileDialog,
    QVBoxLayout, QHBoxLayout, QMessageBox, QInputDialog,
    QProgressBar, QFrame, QLineEdit, QApplication
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui  import QFont

from crypto   import encrypt_file, decrypt_file
from database import (
    log_event, init_db,
    EVENT_ENCRYPT, EVENT_DECRYPT,
    EVENT_DLP_BLOCK, EVENT_DLP_ALLOW
)

from ui.share_dialog          import ShareDialog
from ui.audit_viewer          import AuditViewer
from ui.dlp_report            import DLPReport
from ui.validate_link_dialog  import ValidateLinkDialog


# ─────────────────────────────────────────
#  Background Worker — prevents GUI freeze
# ─────────────────────────────────────────
class CryptoWorker(QThread):
    """Runs encrypt/decrypt in a background thread using QThread."""

    finished = pyqtSignal(str)   # emits output_path on success
    error    = pyqtSignal(str)   # emits error message on failure

    def __init__(self, mode: str, input_path: str,
                 output_path: str, password: str):
        super().__init__()
        self.mode        = mode          # "encrypt" or "decrypt"
        self.input_path  = input_path
        self.output_path = output_path
        self.password    = password

    def run(self):
        try:
            if self.mode == "encrypt":
                encrypt_file(self.input_path, self.output_path, self.password)
            else:
                decrypt_file(self.input_path, self.output_path, self.password)
            self.finished.emit(self.output_path)
        except Exception as e:
            self.error.emit(str(e))


# ─────────────────────────────────────────
#  Main Window
# ─────────────────────────────────────────
class MainWindow(QWidget):

    def __init__(self):
        super().__init__()

        # Ensure DB tables exist
        init_db()

        self.selected_file = ""
        self.dlp_result    = {}
        self.worker        = None   # keep reference — prevents GC during thread

        self._build_ui()
        self._connect_signals()

    # ── UI Construction ──────────────────
    def _build_ui(self):
        self.setWindowTitle("Secure File Transfer & DLP System — CET334")
        self.resize(520, 460)

        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("Secure File Transfer & DLP System")
        title.setFont(QFont("Arial", 15, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)

        # Divider
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("color: #cccccc;")

        # File info
        self.file_label = QLabel("No file selected")
        self.file_label.setWordWrap(True)
        self.file_label.setStyleSheet("color: #555555; font-size: 12px;")

        # DLP status badge
        self.dlp_label = QLabel("DLP Status: Not Checked")
        self.dlp_label.setAlignment(Qt.AlignCenter)
        self.dlp_label.setStyleSheet(
            "color: gray; font-weight: bold; font-size: 13px; "
            "padding: 6px; border-radius: 6px; background: #f0f0f0;"
        )

        # Progress bar — shown during crypto operations
        self.progress       = QProgressBar()
        self.progress_label = QLabel("")
        self.progress.setRange(0, 0)   # indeterminate spinner
        self.progress.setVisible(False)
        self.progress_label.setVisible(False)
        self.progress_label.setAlignment(Qt.AlignCenter)
        self.progress_label.setStyleSheet("color: #555; font-size: 12px;")
        self.progress.setStyleSheet("QProgressBar { border-radius: 4px; }")

        # Buttons — row 1
        row1 = QHBoxLayout()
        self.select_button  = QPushButton("📂  Select File")
        self.encrypt_button = QPushButton("🔒  Encrypt")
        self.decrypt_button = QPushButton("🔓  Decrypt")
        for btn in [self.select_button, self.encrypt_button, self.decrypt_button]:
            btn.setMinimumHeight(38)
            row1.addWidget(btn)

        # Buttons — row 2
        row2 = QHBoxLayout()
        self.share_button      = QPushButton("🔗  Share File")
        self.audit_button      = QPushButton("📋  Audit Logs")
        self.dlp_report_button = QPushButton("🛡  DLP Report")
        for btn in [self.share_button, self.audit_button, self.dlp_report_button]:
            btn.setMinimumHeight(38)
            row2.addWidget(btn)

        # Buttons — row 3 (Validate Link)
        row3 = QHBoxLayout()
        self.validate_link_button = QPushButton("🔍  Validate & Open Link")
        self.validate_link_button.setMinimumHeight(38)
        self.validate_link_button.setToolTip(
            "Paste a secure-share:// link to validate and decrypt a shared file"
        )
        self.validate_link_button.setStyleSheet(
            "QPushButton { background: #e8f4fd; border: 1px solid #90caf9; "
            "border-radius: 5px; color: #0d47a1; font-weight: bold; }"
            "QPushButton:hover { background: #bbdefb; }"
        )
        row3.addWidget(self.validate_link_button)
        row3.addStretch()

        layout.addWidget(title)
        layout.addWidget(line)
        layout.addWidget(self.file_label)
        layout.addWidget(self.dlp_label)
        layout.addWidget(self.progress_label)
        layout.addWidget(self.progress)
        layout.addLayout(row1)
        layout.addLayout(row2)
        layout.addLayout(row3)
        self.setLayout(layout)

    def _connect_signals(self):
        self.select_button.clicked.connect(self.select_file)
        self.encrypt_button.clicked.connect(self.encrypt_selected_file)
        self.decrypt_button.clicked.connect(self.decrypt_selected_file)
        self.share_button.clicked.connect(self.open_share_dialog)
        self.audit_button.clicked.connect(self.open_audit_logs)
        self.dlp_report_button.clicked.connect(self.open_dlp_report)
        self.validate_link_button.clicked.connect(self.open_validate_link)

    # ── File Selection + DLP Check ───────
    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if not file_path:
            return

        self.selected_file = file_path
        self.file_label.setText(f"Selected: {file_path}")

        # DLP check — uses dlp.py (Member 3) with extension fallback
        try:
            from dlp import check_file_policy
            self.dlp_result = check_file_policy(file_path)
            decision = self.dlp_result.get("decision", "ALLOW")

        except ImportError:
            blocked_ext = [".exe", ".bat", ".dll", ".sh", ".cmd", ".vbs"]
            decision    = "BLOCK" if any(
                file_path.lower().endswith(e) for e in blocked_ext
            ) else "ALLOW"
            self.dlp_result = {
                "decision": decision,
                "file":     file_path,
                "matches":  [],
                "note":     "dlp.py not available — extension check only",
            }

        # Update DLP badge
        styles = {
            "ALLOW": ("DLP Status: ✅  SAFE",
                      "color:#1a6b1a; background:#d4edda; font-weight:bold; "
                      "font-size:13px; padding:6px; border-radius:6px;"),
            "BLOCK": ("DLP Status: 🚫  BLOCKED",
                      "color:#721c24; background:#f8d7da; font-weight:bold; "
                      "font-size:13px; padding:6px; border-radius:6px;"),
            "WARN":  ("DLP Status: ⚠️  WARNING",
                      "color:#856404; background:#fff3cd; font-weight:bold; "
                      "font-size:13px; padding:6px; border-radius:6px;"),
        }
        text, style = styles.get(decision, styles["ALLOW"])
        self.dlp_label.setText(text)
        self.dlp_label.setStyleSheet(style)

        # Log DLP result to audit
        event = EVENT_DLP_BLOCK if decision == "BLOCK" else EVENT_DLP_ALLOW
        log_event(event, os.path.basename(file_path), "user",
                  {"decision": decision})

    # ── Password prompt (hidden input) ───
    def _ask_password(self, title: str) -> str | None:
        """Show password dialog with hidden characters. Returns None if cancelled."""
        dlg = QInputDialog(self)
        dlg.setWindowTitle(title)
        dlg.setLabelText("Enter password:")
        dlg.setTextEchoMode(QLineEdit.Password)   # hidden characters ✅
        if dlg.exec_():
            return dlg.textValue() or None
        return None

    # ── Encrypt ──────────────────────────
    def encrypt_selected_file(self):
        if not self.selected_file:
            QMessageBox.warning(self, "Error", "Please select a file first.")
            return

        if "BLOCKED" in self.dlp_label.text():
            QMessageBox.critical(
                self, "DLP Blocked",
                "This file is blocked by DLP policy and cannot be encrypted."
            )
            return

        password = self._ask_password("Encryption Password")
        if not password:
            return

        output_path = self.selected_file + ".enc"
        self._run_crypto("encrypt", self.selected_file, output_path, password)

    # ── Decrypt ──────────────────────────
    def decrypt_selected_file(self):
        if not self.selected_file:
            QMessageBox.warning(self, "Error", "Please select a file first.")
            return

        password = self._ask_password("Decryption Password")
        if not password:
            return

        if self.selected_file.endswith(".enc"):
            output_path = self.selected_file[:-4] + ".dec"
        else:
            output_path = self.selected_file + ".dec"

        self._run_crypto("decrypt", self.selected_file, output_path, password)

    # ── QThread runner ───────────────────
    def _run_crypto(self, mode, input_path, output_path, password):
        """Launch CryptoWorker thread — keeps GUI responsive."""
        self._set_buttons_enabled(False)

        label = "🔒  Encrypting..." if mode == "encrypt" else "🔓  Decrypting..."
        self.progress_label.setText(label)
        self.progress_label.setVisible(True)
        self.progress.setVisible(True)

        self.worker = CryptoWorker(mode, input_path, output_path, password)
        self.worker.finished.connect(
            lambda path: self._on_crypto_done(mode, input_path, path)
        )
        self.worker.error.connect(self._on_crypto_error)
        self.worker.start()

    def _on_crypto_done(self, mode: str, input_path: str, output_path: str):
        self.progress.setVisible(False)
        self.progress_label.setVisible(False)
        self._set_buttons_enabled(True)

        # Log to audit
        event = EVENT_ENCRYPT if mode == "encrypt" else EVENT_DECRYPT
        log_event(event, os.path.basename(input_path), "user",
                  {"output": output_path,
                   "size":   os.path.getsize(output_path)})

        action = "Encrypted" if mode == "encrypt" else "Decrypted"
        QMessageBox.information(
            self, "Success",
            f"✅  File {action} successfully:\n{output_path}"
        )

    def _on_crypto_error(self, message: str):
        self.progress.setVisible(False)
        self.progress_label.setVisible(False)
        self._set_buttons_enabled(True)
        QMessageBox.critical(self, "Error", f"❌  {message}")

    def _set_buttons_enabled(self, enabled: bool):
        for btn in [self.encrypt_button, self.decrypt_button,
                    self.select_button, self.share_button]:
            btn.setEnabled(enabled)

    # ── Sub-windows ──────────────────────
    def open_validate_link(self):
        # Try to pre-fill from clipboard if it looks like a share link
        clipboard_text = QApplication.clipboard().text().strip()
        prefill = clipboard_text if clipboard_text.startswith("secure-share://") else ""
        self.validate_window = ValidateLinkDialog(prefill_link=prefill)
        self.validate_window.exec_()

    def open_share_dialog(self):
        if not self.selected_file:
            QMessageBox.warning(self, "Error", "Please select a file first.")
            return
        dialog = ShareDialog(self.selected_file)
        dialog.exec_()

    def open_audit_logs(self):
        self.audit_window = AuditViewer()
        self.audit_window.show()

    def open_dlp_report(self):
        self.report_window = DLPReport(self.dlp_result)
        self.report_window.show()