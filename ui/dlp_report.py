"""
ui/dlp_report.py - DLP Scan Result Viewer
Member 2 (Frontend Developer) | CET334 - Secure File Transfer & DLP System

Fixed:
- Accepts dict from dlp.check_file_policy() instead of raw string
- Shows structured ALLOW / BLOCK / WARN with color coding
- Lists matched patterns (credit cards, SSN, magic number violations, etc.)
- Falls back gracefully if passed a plain string
- Shows magic number detection details if present
- Resize to fit content dynamically
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui  import QFont, QColor


# Decision color map
DECISION_STYLE = {
    "ALLOW": ("✅  ALLOW — File is Safe",
               "color:#155724; background:#d4edda; font-size:14px; "
               "font-weight:bold; padding:10px; border-radius:8px;"),
    "BLOCK": ("🚫  BLOCK — File Rejected by DLP Policy",
               "color:#721c24; background:#f8d7da; font-size:14px; "
               "font-weight:bold; padding:10px; border-radius:8px;"),
    "WARN":  ("⚠️  WARN — Sensitive Content Detected",
               "color:#856404; background:#fff3cd; font-size:14px; "
               "font-weight:bold; padding:10px; border-radius:8px;"),
}


class DLPReport(QWidget):

    def __init__(self, report_data):
        """
        Args:
            report_data: dict from dlp.check_file_policy()
                         OR plain string (fallback)
        """
        super().__init__()
        self.setWindowTitle("DLP Scan Report — CET334")
        self.resize(560, 440)

        # Normalize input — accept dict or plain string
        if isinstance(report_data, dict):
            self.data = report_data
        else:
            text = str(report_data)
            decision = "BLOCK" if "BLOCKED" in text else "ALLOW"
            self.data = {"decision": decision, "file": "", "matches": [], "note": text}

        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        # Title
        title = QLabel("DLP Scan Result")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)

        # Decision badge
        decision = self.data.get("decision", "ALLOW")
        badge_text, badge_style = DECISION_STYLE.get(decision, DECISION_STYLE["ALLOW"])
        self.decision_label = QLabel(badge_text)
        self.decision_label.setAlignment(Qt.AlignCenter)
        self.decision_label.setStyleSheet(badge_style)
        self.decision_label.setWordWrap(True)

        # File info
        file_path = self.data.get("file", "")
        if file_path:
            file_label = QLabel(f"File: {file_path}")
            file_label.setStyleSheet("color: #555; font-size: 12px;")
            file_label.setWordWrap(True)
        else:
            file_label = QLabel("")

        # Magic number result (if present)
        magic = self.data.get("magic_number", "")
        if magic:
            magic_label = QLabel(f"Magic Number Check: {magic}")
            magic_label.setStyleSheet(
                "color: #004085; background: #cce5ff; font-size: 11px; "
                "padding: 4px 8px; border-radius: 4px;"
            )
            magic_label.setWordWrap(True)
        else:
            magic_label = QLabel("")

        # Matches table
        matches = self.data.get("matches", [])
        matches_title = QLabel(f"Detected Patterns ({len(matches)} found):")
        matches_title.setFont(QFont("Arial", 11, QFont.Bold))

        self.matches_table = QTableWidget()
        self.matches_table.setColumnCount(2)
        self.matches_table.setHorizontalHeaderLabels(["Pattern Type", "Details"])
        self.matches_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.matches_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.matches_table.setMaximumHeight(180)

        if matches:
            self.matches_table.setRowCount(len(matches))
            for row, match in enumerate(matches):
                if isinstance(match, dict):
                    type_val   = str(match.get("type", ""))
                    detail_val = str(match.get("value", ""))
                else:
                    type_val   = "match"
                    detail_val = str(match)

                type_item   = QTableWidgetItem(type_val)
                detail_item = QTableWidgetItem(detail_val)
                type_item.setBackground(QColor("#f8d7da"))
                self.matches_table.setItem(row, 0, type_item)
                self.matches_table.setItem(row, 1, detail_item)
        else:
            self.matches_table.setRowCount(1)
            ok_item = QTableWidgetItem("No sensitive patterns detected")
            ok_item.setBackground(QColor("#d4edda"))
            self.matches_table.setItem(0, 0, ok_item)
            self.matches_table.setItem(0, 1, QTableWidgetItem(""))

        # Extra note
        note = self.data.get("note", "")
        note_label = QLabel(note) if note else QLabel("")
        note_label.setStyleSheet("color: gray; font-size: 11px;")
        note_label.setWordWrap(True)

        layout.addWidget(title)
        layout.addWidget(self.decision_label)
        layout.addWidget(file_label)
        layout.addWidget(magic_label)
        layout.addWidget(matches_title)
        layout.addWidget(self.matches_table)
        layout.addWidget(note_label)
        self.setLayout(layout)