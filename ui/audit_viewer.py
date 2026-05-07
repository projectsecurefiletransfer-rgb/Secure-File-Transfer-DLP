"""
ui/audit_viewer.py - Tamper-Evident Audit Log Viewer
Member 2 (Frontend Developer) | CET334 - Secure File Transfer & DLP System

Fixed:
- Reads real data from database.get_all_logs()
- Shows all 6 columns: ID, Timestamp, Event, File, User, Details
- Verify Chain button calls database.verify_chain()
- Color-coded event rows (BLOCK=red, ENCRYPT=green, etc.)
- Export to CSV feature added
- Handles empty log gracefully
"""

import json
import csv
import os
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QPushButton,
    QMessageBox, QHeaderView, QFileDialog
)
from PyQt5.QtCore  import Qt
from PyQt5.QtGui   import QColor, QFont

from database import get_all_logs, verify_chain


# ─────────────────────────────────────────
#  Event color coding
# ─────────────────────────────────────────
EVENT_COLORS = {
    "ENCRYPT":   "#d4edda",   # green
    "DECRYPT":   "#cce5ff",   # blue
    "DLP_BLOCK": "#f8d7da",   # red
    "DLP_ALLOW": "#d4edda",   # green
    "SHARE":     "#fff3cd",   # yellow
    "ACCESS":    "#e2e3e5",   # gray
}


class AuditViewer(QWidget):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Audit Log Viewer — CET334")
        self.resize(860, 520)
        self._build_ui()
        self.load_logs()

    # ── UI ───────────────────────────────
    def _build_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        # Header row
        header_row = QHBoxLayout()
        title = QLabel("System Audit Log")
        title.setFont(QFont("Arial", 14, QFont.Bold))

        self.chain_label = QLabel("Chain: Not Verified")
        self.chain_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.chain_label.setStyleSheet(
            "color: gray; font-size: 12px; font-weight: bold;"
        )

        header_row.addWidget(title)
        header_row.addStretch()
        header_row.addWidget(self.chain_label)

        # Buttons
        btn_row = QHBoxLayout()
        self.refresh_button = QPushButton("🔄  Refresh")
        self.verify_button  = QPushButton("🔐  Verify Chain Integrity")
        self.export_button  = QPushButton("💾  Export CSV")
        for btn in [self.refresh_button, self.verify_button, self.export_button]:
            btn.setMinimumHeight(34)
            btn_row.addWidget(btn)
        btn_row.addStretch()

        # Record count label
        self.count_label = QLabel("0 records")
        self.count_label.setStyleSheet("color: #888; font-size: 11px;")
        self.count_label.setAlignment(Qt.AlignRight)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            ["ID", "Timestamp", "Event", "File", "User", "Details"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setWordWrap(False)

        layout.addLayout(header_row)
        layout.addLayout(btn_row)
        layout.addWidget(self.count_label)
        layout.addWidget(self.table)
        self.setLayout(layout)

        self.refresh_button.clicked.connect(self.load_logs)
        self.verify_button.clicked.connect(self.verify_integrity)
        self.export_button.clicked.connect(self.export_csv)

    # ── Load Real Data ───────────────────
    def load_logs(self):
        """Read all records from database and populate table."""
        logs = get_all_logs()

        self.table.setRowCount(len(logs))
        self.count_label.setText(f"{len(logs)} record{'s' if len(logs) != 1 else ''}")

        for row, log in enumerate(logs):
            # Parse details JSON for display
            try:
                details_dict = json.loads(log.get("details", "{}"))
                details_str  = ", ".join(f"{k}:{v}" for k, v in details_dict.items())
            except Exception:
                details_str = log.get("details", "")

            values = [
                str(log["id"]),
                log["timestamp"][:19].replace("T", " "),  # trim microseconds
                log["event"],
                log["file_name"],
                log["user"],
                details_str,
            ]

            row_color = EVENT_COLORS.get(log["event"], "#ffffff")

            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setBackground(QColor(row_color))
                if col == 2:   # Event column — bold
                    font = QFont()
                    font.setBold(True)
                    item.setFont(font)
                self.table.setItem(row, col, item)

        self.table.resizeColumnsToContents()

    # ── Verify Chain ─────────────────────
    def verify_integrity(self):
        """Call database.verify_chain() and show result."""
        result = verify_chain()

        if result["valid"]:
            self.chain_label.setText(
                f"✅  Chain Intact ({result['total_records']} records)"
            )
            self.chain_label.setStyleSheet(
                "color: #155724; font-size: 12px; font-weight: bold;"
            )
            QMessageBox.information(
                self, "Chain Integrity",
                f"✅ {result['message']}"
            )
        else:
            self.chain_label.setText("🚫  Chain BROKEN!")
            self.chain_label.setStyleSheet(
                "color: #721c24; font-size: 12px; font-weight: bold;"
            )
            QMessageBox.critical(
                self, "Chain Integrity",
                f"🚫 {result['message']}\n\n"
                f"Record #{result.get('broken_at_id', '?')} has been tampered with."
            )

    # ── Export CSV ───────────────────────
    def export_csv(self):
        """Export current logs to a CSV file."""
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Audit Log", "audit_log.csv", "CSV Files (*.csv)"
        )
        if not path:
            return

        try:
            headers = ["ID", "Timestamp", "Event", "File", "User", "Details"]
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                for row in range(self.table.rowCount()):
                    row_data = [
                        self.table.item(row, col).text() if self.table.item(row, col) else ""
                        for col in range(self.table.columnCount())
                    ]
                    writer.writerow(row_data)

            QMessageBox.information(
                self, "Export Successful",
                f"✅  Audit log exported to:\n{path}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"❌  {e}")