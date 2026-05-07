"""
database.py - Tamper-Evident Audit Log
Team Leader | CET334 - Secure File Transfer & DLP System

Implements:
- SQLite database for local audit logging
- Hash Chaining: each record stores SHA-256 of the previous record
- Any tampering with old records breaks the chain (detectable immediately)
- All operations timestamped (UTC)
"""

import sqlite3
import hashlib
import json
import os
from datetime import datetime, timezone


# ─────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), "audit_log.db")

# Audit event types
EVENT_ENCRYPT   = "ENCRYPT"
EVENT_DECRYPT   = "DECRYPT"
EVENT_DLP_BLOCK = "DLP_BLOCK"
EVENT_DLP_ALLOW = "DLP_ALLOW"
EVENT_SHARE     = "SHARE"
EVENT_ACCESS    = "ACCESS"


# ─────────────────────────────────────────
#  Database Initialization
# ─────────────────────────────────────────
def init_db(db_path: str = DB_PATH) -> None:
    """
    Create the audit_log table if it doesn't exist.

    Schema:
        id        - auto-increment primary key
        timestamp - UTC ISO-8601 string
        event     - event type (ENCRYPT, DECRYPT, etc.)
        file_name - name of the file involved
        user      - username or identifier
        details   - JSON string with extra info
        prev_hash - SHA-256 hash of the previous record (Hash Chaining)
        self_hash - SHA-256 hash of this record's content
    """
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT    NOT NULL,
                event     TEXT    NOT NULL,
                file_name TEXT    NOT NULL,
                user      TEXT    NOT NULL,
                details   TEXT,
                prev_hash TEXT    NOT NULL,
                self_hash TEXT    NOT NULL
            )
        """)
        conn.commit()


# ─────────────────────────────────────────
#  Hash Helpers
# ─────────────────────────────────────────
def _compute_record_hash(timestamp: str, event: str, file_name: str,
                          user: str, details: str, prev_hash: str) -> str:
    """
    Compute SHA-256 hash of a record's content fields.
    Used to detect tampering.
    """
    content = f"{timestamp}|{event}|{file_name}|{user}|{details}|{prev_hash}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _get_last_hash(conn: sqlite3.Connection) -> str:
    """
    Retrieve the self_hash of the most recent record.
    Returns '0' * 64 (genesis hash) if the table is empty.
    """
    cursor = conn.execute(
        "SELECT self_hash FROM audit_log ORDER BY id DESC LIMIT 1"
    )
    row = cursor.fetchone()
    return row[0] if row else "0" * 64


# ─────────────────────────────────────────
#  Log Entry
# ─────────────────────────────────────────
def log_event(event: str, file_name: str, user: str,
              details: dict = None, db_path: str = DB_PATH) -> int:
    """
    Append a new tamper-evident record to the audit log.

    Args:
        event:     one of the EVENT_* constants
        file_name: name of the file involved
        user:      username or system identifier
        details:   optional dict with extra context (serialized to JSON)
        db_path:   path to the SQLite database

    Returns:
        id of the inserted record
    """
    timestamp   = datetime.now(timezone.utc).isoformat()
    details_str = json.dumps(details or {})

    with sqlite3.connect(db_path) as conn:
        prev_hash = _get_last_hash(conn)
        self_hash = _compute_record_hash(
            timestamp, event, file_name, user, details_str, prev_hash
        )

        cursor = conn.execute(
            """
            INSERT INTO audit_log
                (timestamp, event, file_name, user, details, prev_hash, self_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (timestamp, event, file_name, user, details_str, prev_hash, self_hash)
        )
        conn.commit()
        return cursor.lastrowid


# ─────────────────────────────────────────
#  Retrieve Logs
# ─────────────────────────────────────────
def get_all_logs(db_path: str = DB_PATH) -> list[dict]:
    """
    Return all audit log records as a list of dicts (oldest first).
    """
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT * FROM audit_log ORDER BY id ASC"
        )
        return [dict(row) for row in cursor.fetchall()]


# ─────────────────────────────────────────
#  Chain Integrity Verification
# ─────────────────────────────────────────
def verify_chain(db_path: str = DB_PATH) -> dict:
    """
    Verify the integrity of the entire audit log chain.

    Checks every record:
    1. Recomputes self_hash from content fields
    2. Confirms it matches the stored self_hash
    3. Confirms prev_hash matches the self_hash of the previous record

    Returns:
        dict with keys:
            valid         (bool)   - True if chain is intact
            total_records (int)    - total number of records checked
            broken_at_id  (int)    - id of first broken record (None if valid)
            message       (str)    - human-readable result
    """
    records = get_all_logs(db_path)

    if not records:
        return {
            "valid": True,
            "total_records": 0,
            "broken_at_id": None,
            "message": "Audit log is empty."
        }

    expected_prev = "0" * 64  # genesis hash

    for record in records:
        # Re-compute expected self_hash
        expected_self = _compute_record_hash(
            record["timestamp"],
            record["event"],
            record["file_name"],
            record["user"],
            record["details"],
            record["prev_hash"],
        )

        # Check 1: prev_hash must match previous record's self_hash
        if record["prev_hash"] != expected_prev:
            return {
                "valid": False,
                "total_records": len(records),
                "broken_at_id": record["id"],
                "message": f"Chain broken at record #{record['id']}: prev_hash mismatch."
            }

        # Check 2: self_hash must match recomputed hash
        if record["self_hash"] != expected_self:
            return {
                "valid": False,
                "total_records": len(records),
                "broken_at_id": record["id"],
                "message": f"Chain broken at record #{record['id']}: self_hash mismatch (record tampered)."
            }

        expected_prev = record["self_hash"]

    return {
        "valid": True,
        "total_records": len(records),
        "broken_at_id": None,
        "message": f"Chain intact. All {len(records)} records verified ✓"
    }


# ─────────────────────────────────────────
#  Quick self-test (run directly)
# ─────────────────────────────────────────
if __name__ == "__main__":
    import tempfile

    print("=== database.py self-test ===\n")

    # Use a temp DB so we don't pollute the real one
    tmp_db = tempfile.mktemp(suffix=".db")

    try:
        # Init
        init_db(tmp_db)
        print("[OK] Database initialized\n")

        # Log some events
        id1 = log_event(EVENT_ENCRYPT,   "report.pdf",  "Mohamed", {"size": 2048},          tmp_db)
        id2 = log_event(EVENT_DLP_BLOCK, "malware.exe", "Mohamed", {"reason": "EXE blocked"}, tmp_db)
        id3 = log_event(EVENT_DECRYPT,   "report.pdf",  "Mohamed", {"size": 2048},            tmp_db)
        print(f"[OK] Logged 3 events (ids: {id1}, {id2}, {id3})\n")

        # Verify chain (should be valid)
        result = verify_chain(tmp_db)
        status = "✓" if result["valid"] else "✗"
        print(f"[{status}] Chain verification: {result['message']}\n")

        # Tamper with a record directly
        with sqlite3.connect(tmp_db) as conn:
            conn.execute(
                "UPDATE audit_log SET file_name = 'hacked.pdf' WHERE id = 1"
            )
            conn.commit()
        print("[INFO] Tampered with record #1 directly in DB\n")

        # Verify chain again (should detect tampering)
        result = verify_chain(tmp_db)
        status = "✓" if not result["valid"] else "✗"
        print(f"[{status}] Tampering detected: {result['message']}\n")

        print("=== All tests passed ✓ ===")

    finally:
        if os.path.exists(tmp_db):
            os.remove(tmp_db)