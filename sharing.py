"""
sharing.py - Secure File Sharing with Expiration Links
Member 3 (Security & Docs) | CET334 - Secure File Transfer & DLP System

Implements:
- UUID-based secure share links (secure-share://<uuid>)
- Expiration time stored in SQLite (same audit_log.db)
- Validate link before allowing access (expired = denied)
- Revoke links manually
- All operations logged to audit log
"""

import os
import uuid
import sqlite3
import json
from datetime import datetime, timezone, timedelta

from database import DB_PATH, log_event, EVENT_SHARE, EVENT_ACCESS


# ─────────────────────────────────────────
#  Shared Links Table Setup
# ─────────────────────────────────────────
def _init_shares_table(db_path: str = DB_PATH) -> None:
    """
    Create the shared_links table if it doesn't exist.

    Schema:
        id         - auto-increment primary key
        link_id    - UUID string (unique)
        file_path  - absolute path to the encrypted file
        file_name  - basename for display
        created_at - UTC ISO-8601 creation time
        expires_at - UTC ISO-8601 expiration time
        is_revoked - 0/1 flag
    """
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS shared_links (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                link_id    TEXT    NOT NULL UNIQUE,
                file_path  TEXT    NOT NULL,
                file_name  TEXT    NOT NULL,
                created_at TEXT    NOT NULL,
                expires_at TEXT    NOT NULL,
                is_revoked INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.commit()


# ─────────────────────────────────────────
#  Create Share Link
# ─────────────────────────────────────────
def create_share_link(file_path: str, expires_in_hours: int = 24,
                      db_path: str = DB_PATH) -> str:
    """
    Generate a UUID share link for a file and store it with expiry.

    Args:
        file_path:         absolute path to the file (should be .enc)
        expires_in_hours:  how many hours until the link expires (default 24)
        db_path:           SQLite database path

    Returns:
        link string: "secure-share://<uuid>"

    Raises:
        FileNotFoundError: if the file doesn't exist
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    _init_shares_table(db_path)

    link_id    = str(uuid.uuid4())
    file_name  = os.path.basename(file_path)
    created_at = datetime.now(timezone.utc).isoformat()
    expires_at = (
        datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)
    ).isoformat()

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO shared_links
                (link_id, file_path, file_name, created_at, expires_at, is_revoked)
            VALUES (?, ?, ?, ?, ?, 0)
            """,
            (link_id, file_path, file_name, created_at, expires_at)
        )
        conn.commit()

    # Log the share event to audit log
    try:
        log_event(
            EVENT_SHARE,
            file_name,
            "user",
            {
                "link_id":       link_id,
                "expires_hours": expires_in_hours,
                "expires_at":    expires_at,
            }
        )
    except Exception:
        pass  # Audit log is non-critical

    return f"secure-share://{link_id}"


# ─────────────────────────────────────────
#  Validate Link
# ─────────────────────────────────────────
def validate_share_link(link: str, db_path: str = DB_PATH) -> dict:
    """
    Check if a share link is valid (exists, not expired, not revoked).

    Args:
        link:    "secure-share://<uuid>" string
        db_path: SQLite database path

    Returns:
        dict:
            valid      (bool)  - True if link can be used
            file_path  (str)   - path to the file (if valid)
            file_name  (str)   - filename for display
            expires_at (str)   - expiration timestamp
            reason     (str)   - why it's invalid (if not valid)
    """
    _init_shares_table(db_path)

    # Extract UUID from link string
    if link.startswith("secure-share://"):
        link_id = link[len("secure-share://"):]
    else:
        link_id = link

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT * FROM shared_links WHERE link_id = ?", (link_id,)
        )
        row = cursor.fetchone()

    if not row:
        return {
            "valid":      False,
            "file_path":  "",
            "file_name":  "",
            "expires_at": "",
            "reason":     "Link not found.",
        }

    if row["is_revoked"]:
        return {
            "valid":      False,
            "file_path":  row["file_path"],
            "file_name":  row["file_name"],
            "expires_at": row["expires_at"],
            "reason":     "Link has been revoked.",
        }

    # Check expiration
    expires_at = datetime.fromisoformat(row["expires_at"])
    if datetime.now(timezone.utc) > expires_at:
        return {
            "valid":      False,
            "file_path":  row["file_path"],
            "file_name":  row["file_name"],
            "expires_at": row["expires_at"],
            "reason":     f"Link expired at {row['expires_at'][:19]} UTC.",
        }

    # Log ACCESS event
    try:
        log_event(
            EVENT_ACCESS,
            row["file_name"],
            "user",
            {"link_id": link_id, "action": "link_validated"}
        )
    except Exception:
        pass

    return {
        "valid":      True,
        "file_path":  row["file_path"],
        "file_name":  row["file_name"],
        "expires_at": row["expires_at"],
        "reason":     "",
    }


# ─────────────────────────────────────────
#  Revoke Link
# ─────────────────────────────────────────
def revoke_share_link(link: str, db_path: str = DB_PATH) -> bool:
    """
    Revoke a share link so it can no longer be used.

    Args:
        link:    "secure-share://<uuid>" or raw UUID
        db_path: SQLite database path

    Returns:
        True if revoked successfully, False if link not found
    """
    _init_shares_table(db_path)

    link_id = link[len("secure-share://"):] if link.startswith("secure-share://") else link

    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute(
            "UPDATE shared_links SET is_revoked = 1 WHERE link_id = ?", (link_id,)
        )
        conn.commit()
        return cursor.rowcount > 0


# ─────────────────────────────────────────
#  Get All Links (for admin view)
# ─────────────────────────────────────────
def get_all_links(db_path: str = DB_PATH) -> list[dict]:
    """
    Return all share links (for audit/admin display).

    Returns:
        List of dicts with all fields + status string
    """
    _init_shares_table(db_path)

    now = datetime.now(timezone.utc)

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT * FROM shared_links ORDER BY id DESC"
        )
        rows = cursor.fetchall()

    results = []
    for row in rows:
        d = dict(row)
        if d["is_revoked"]:
            d["status"] = "REVOKED"
        elif datetime.fromisoformat(d["expires_at"]) < now:
            d["status"] = "EXPIRED"
        else:
            d["status"] = "ACTIVE"
        results.append(d)

    return results


# ─────────────────────────────────────────
#  Quick self-test (run directly)
# ─────────────────────────────────────────
if __name__ == "__main__":
    import tempfile, os as _os

    print("=== sharing.py self-test ===\n")

    tmp_db = tempfile.mktemp(suffix=".db")

    # Create a dummy file to share
    with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as f:
        f.write(b"fake encrypted content")
        dummy_file = f.name

    try:
        # 1. Create link
        link = create_share_link(dummy_file, expires_in_hours=1, db_path=tmp_db)
        print(f"[OK] Link created : {link}\n")

        # 2. Validate link — should be valid
        result = validate_share_link(link, db_path=tmp_db)
        status = "✓" if result["valid"] else "✗"
        print(f"[{status}] Valid link  : {result['valid']}")
        print(f"     File      : {result['file_name']}")
        print(f"     Expires   : {result['expires_at'][:19]} UTC\n")

        # 3. Revoke link
        revoked = revoke_share_link(link, db_path=tmp_db)
        print(f"[OK] Revoked : {revoked}")

        result = validate_share_link(link, db_path=tmp_db)
        assert not result["valid"], "Should be invalid after revoke!"
        print(f"[✓]  Revoked link correctly rejected: {result['reason']}\n")

        # 4. Create expired link (using negative hours hack for testing)
        link2 = create_share_link(dummy_file, expires_in_hours=24, db_path=tmp_db)
        # Manually expire it
        link_id = link2[len("secure-share://"):]
        with sqlite3.connect(tmp_db) as conn:
            conn.execute(
                "UPDATE shared_links SET expires_at = '2000-01-01T00:00:00+00:00' WHERE link_id = ?",
                (link_id,)
            )
            conn.commit()

        result = validate_share_link(link2, db_path=tmp_db)
        assert not result["valid"]
        print(f"[✓]  Expired link correctly rejected: {result['reason']}\n")

        # 5. Get all links
        all_links = get_all_links(db_path=tmp_db)
        print(f"[OK] All links ({len(all_links)} total):")
        for lnk in all_links:
            print(f"     {lnk['link_id'][:8]}... | {lnk['status']} | {lnk['file_name']}")

        print("\n=== All tests passed ✓ ===")

    finally:
        _os.remove(dummy_file)
        if _os.path.exists(tmp_db):
            _os.remove(tmp_db)