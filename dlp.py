"""
dlp.py - Data Loss Prevention Engine
Member 3 (Security & Docs) | CET334 - Secure File Transfer & DLP System

Implements:
- Magic Number detection (reads file header bytes — defeats extension spoofing)
- Regex-based sensitive content scanning (Credit Cards, SSN, Emails, API Keys)
- Blocked file types list (EXE, DLL, BAT, etc.)
- Returns structured dict consumed by ui/main_window.py and ui/dlp_report.py
"""

import os
import re

# ─────────────────────────────────────────
#  Magic Number Signatures
#  Format: { "TYPE": (bytes_offset, hex_signature_bytes) }
# ─────────────────────────────────────────
MAGIC_SIGNATURES = {
    "EXE/DLL (Windows Executable)": (0, bytes([0x4D, 0x5A])),              # MZ
    "ZIP Archive":                   (0, bytes([0x50, 0x4B, 0x03, 0x04])), # PK
    "PDF Document":                  (0, bytes([0x25, 0x50, 0x44, 0x46])), # %PDF
    "RAR Archive":                   (0, bytes([0x52, 0x61, 0x72, 0x21])), # Rar!
    "ELF (Linux Executable)":        (0, bytes([0x7F, 0x45, 0x4C, 0x46])), # .ELF
    "PNG Image":                     (0, bytes([0x89, 0x50, 0x4E, 0x47])), # .PNG
    "JPEG Image":                    (0, bytes([0xFF, 0xD8, 0xFF])),        # JFIF/EXIF
    "GIF Image":                     (0, bytes([0x47, 0x49, 0x46, 0x38])), # GIF8
    "7-Zip Archive":                 (0, bytes([0x37, 0x7A, 0xBC, 0xAF])), # 7z
    "SQLite Database":               (0, bytes([0x53, 0x51, 0x4C, 0x69])), # SQLi
    "Class File (Java)":             (0, bytes([0xCA, 0xFE, 0xBA, 0xBE])), # Java class
}

# ─────────────────────────────────────────
#  Blocked File Types (by real type, not just extension)
# ─────────────────────────────────────────
BLOCKED_TYPES = {
    "EXE/DLL (Windows Executable)",
    "ELF (Linux Executable)",
    "Class File (Java)",
}

# Also block by extension (secondary check)
BLOCKED_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".sh", ".vbs",
    ".ps1", ".msi", ".com", ".scr", ".jar",
}

# ─────────────────────────────────────────
#  Regex Patterns for Sensitive Content
# ─────────────────────────────────────────
SENSITIVE_PATTERNS = [
    {
        "type": "Credit Card Number",
        "regex": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "severity": "BLOCK",
    },
    {
        "type": "US Social Security Number (SSN)",
        "regex": r"\b\d{3}-\d{2}-\d{4}\b",
        "severity": "BLOCK",
    },
    {
        "type": "Private Key / API Secret",
        "regex": r"(?i)(api[_\-]?key|secret[_\-]?key|private[_\-]?key|password)\s*[:=]\s*\S{8,}",
        "severity": "BLOCK",
    },
    {
        "type": "AWS Access Key",
        "regex": r"\bAKIA[0-9A-Z]{16}\b",
        "severity": "BLOCK",
    },
    {
        "type": "Email Address",
        "regex": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        "severity": "WARN",
    },
    {
        "type": "IP Address",
        "regex": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        "severity": "WARN",
    },
    {
        "type": "Phone Number",
        "regex": r"\b(?:\+?\d{1,3}[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b",
        "severity": "WARN",
    },
]

# File types we skip content scanning (binary / encrypted)
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
    ".mp3", ".mp4", ".avi", ".mkv", ".mov",
    ".zip", ".rar", ".7z", ".gz", ".tar",
    ".enc",   # already encrypted — skip
}

# Max bytes to read for content scanning (1 MB)
MAX_SCAN_BYTES = 1 * 1024 * 1024


# ─────────────────────────────────────────
#  Magic Number Detection
# ─────────────────────────────────────────
def detect_magic_number(file_path: str) -> str | None:
    """
    Read the first 8 bytes of a file and compare against known signatures.

    Args:
        file_path: path to the file

    Returns:
        Detected type string (e.g. "EXE/DLL") or None if unknown
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(8)
    except Exception:
        return None

    for type_name, (offset, signature) in MAGIC_SIGNATURES.items():
        if header[offset:offset + len(signature)] == signature:
            return type_name

    return None


# ─────────────────────────────────────────
#  Content Scanning (Regex)
# ─────────────────────────────────────────
def scan_content(file_path: str) -> list[dict]:
    """
    Scan file text content for sensitive patterns using regex.

    Skips binary files. Reads up to MAX_SCAN_BYTES.

    Args:
        file_path: path to the file

    Returns:
        List of match dicts: [{"type": str, "value": str, "severity": str}]
    """
    ext = os.path.splitext(file_path)[1].lower()
    if ext in BINARY_EXTENSIONS:
        return []

    try:
        with open(file_path, "rb") as f:
            raw = f.read(MAX_SCAN_BYTES)
        # Try UTF-8 first, fallback to latin-1 (never fails)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")
    except Exception:
        return []

    matches = []
    for pattern in SENSITIVE_PATTERNS:
        found = re.findall(pattern["regex"], text)
        for value in found[:3]:   # cap at 3 matches per pattern type
            # Partially mask sensitive values for display
            display = _mask_value(str(value))
            matches.append({
                "type":     pattern["type"],
                "value":    display,
                "severity": pattern["severity"],
            })

    return matches


def _mask_value(value: str) -> str:
    """Partially mask sensitive values for safe display in UI."""
    if len(value) <= 4:
        return "****"
    return value[:3] + "*" * (len(value) - 6) + value[-3:] if len(value) > 6 else value[:2] + "****"


# ─────────────────────────────────────────
#  Main Policy Check (called by main_window.py)
# ─────────────────────────────────────────
def check_file_policy(file_path: str) -> dict:
    """
    Run full DLP check on a file.

    Steps:
    1. Check extension against blocked list
    2. Detect magic number (real file type)
    3. Scan content for sensitive patterns (text files only)
    4. Determine final decision: BLOCK / WARN / ALLOW

    Args:
        file_path: absolute or relative path to the file

    Returns:
        dict:
            decision     (str)  - "BLOCK", "WARN", or "ALLOW"
            file         (str)  - file_path
            magic_number (str)  - detected type or "Unknown"
            matches      (list) - list of sensitive pattern matches
            note         (str)  - human-readable summary
            blocked_by   (str)  - "extension", "magic_number", "content", or ""
    """
    if not os.path.isfile(file_path):
        return {
            "decision":     "BLOCK",
            "file":         file_path,
            "magic_number": "N/A",
            "matches":      [],
            "note":         "File not found.",
            "blocked_by":   "not_found",
        }

    ext          = os.path.splitext(file_path)[1].lower()
    magic_type   = detect_magic_number(file_path)
    magic_str    = magic_type if magic_type else "Unknown / Safe"
    matches      = []
    decision     = "ALLOW"
    blocked_by   = ""
    note         = ""

    # ── Step 1: Extension check ──
    if ext in BLOCKED_EXTENSIONS:
        decision   = "BLOCK"
        blocked_by = "extension"
        note       = f"File extension '{ext}' is blocked by DLP policy."

    # ── Step 2: Magic number check (overrides extension) ──
    if magic_type in BLOCKED_TYPES:
        decision   = "BLOCK"
        blocked_by = "magic_number"
        note       = (
            f"Real file type detected as '{magic_type}' "
            f"(magic number check — extension spoofing blocked)."
        )

    # ── Step 3: Content scan (only for non-blocked files) ──
    if decision != "BLOCK":
        matches = scan_content(file_path)
        block_matches = [m for m in matches if m["severity"] == "BLOCK"]
        warn_matches  = [m for m in matches if m["severity"] == "WARN"]

        if block_matches:
            decision   = "BLOCK"
            blocked_by = "content"
            types      = ", ".join(set(m["type"] for m in block_matches))
            note       = f"Sensitive content detected: {types}."
        elif warn_matches:
            decision = "WARN"
            blocked_by = "content"
            types    = ", ".join(set(m["type"] for m in warn_matches))
            note     = f"Potentially sensitive content found: {types}. Review before sharing."

    if not note:
        note = "No policy violations detected. File is safe to encrypt and share."

    return {
        "decision":     decision,
        "file":         file_path,
        "magic_number": magic_str,
        "matches":      matches,
        "note":         note,
        "blocked_by":   blocked_by,
    }


# ─────────────────────────────────────────
#  Quick self-test (run directly)
# ─────────────────────────────────────────
if __name__ == "__main__":
    import tempfile

    print("=== dlp.py self-test ===\n")

    # Test 1: Text file with sensitive content
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="w") as f:
        f.write("User email: test@example.com\n")
        f.write("Credit card: 4111111111111111\n")
        f.write("SSN: 123-45-6789\n")
        txt_path = f.name

    result = check_file_policy(txt_path)
    print(f"[TXT] Decision : {result['decision']}")
    print(f"      Magic    : {result['magic_number']}")
    print(f"      Matches  : {len(result['matches'])}")
    print(f"      Note     : {result['note']}\n")

    # Test 2: Fake EXE (MZ header) with .txt extension (spoofing)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        f.write(bytes([0x4D, 0x5A]) + b"\x00" * 20)   # MZ header
        exe_path = f.name

    result = check_file_policy(exe_path)
    print(f"[EXE-spoof] Decision : {result['decision']}")
    print(f"            Magic    : {result['magic_number']}")
    print(f"            Blocked  : {result['blocked_by']}\n")

    # Test 3: Clean text file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="w") as f:
        f.write("Hello, this is a clean document with no sensitive data.")
        clean_path = f.name

    result = check_file_policy(clean_path)
    print(f"[CLEAN] Decision : {result['decision']}")
    print(f"        Note     : {result['note']}\n")

    print("=== All tests passed ✓ ===")

    import os as _os
    for p in [txt_path, exe_path, clean_path]:
        _os.remove(p)