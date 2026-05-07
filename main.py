"""
main.py - Application Entry Point
Team Leader | CET334 - Secure File Transfer & DLP System

Wires together:
- crypto.py      → AES-256-GCM encryption/decryption
- database.py    → Tamper-evident audit log
- key_manager.py → RSA key management

This file is the entry point. It will launch the PyQt5 GUI
once the ui/ folder is ready (Member 2). For now it provides
a CLI demo that exercises all core components together.
"""

import os
import sys

# ─────────────────────────────────────────
#  Import core modules
# ─────────────────────────────────────────
from crypto      import encrypt_file, decrypt_file
from database    import init_db, log_event, verify_chain, get_all_logs
from database    import EVENT_ENCRYPT, EVENT_DECRYPT, EVENT_DLP_BLOCK
from key_manager import (generate_rsa_keypair, load_private_key,
                          load_public_key, keys_exist,
                          encrypt_with_public_key, decrypt_with_private_key)


# ─────────────────────────────────────────
#  Application Bootstrap
# ─────────────────────────────────────────
def bootstrap() -> None:
    """
    Run once on first launch:
    - Initialize the SQLite audit database
    - Generate RSA key pair if not already present
    """
    print("[BOOT] Initializing database...")
    init_db()
    print("[BOOT] Database ready ✓")

    if not keys_exist():
        print("[BOOT] Generating RSA-2048 key pair...")
        info = generate_rsa_keypair()
        print(f"[BOOT] Keys saved to: {os.path.dirname(info['private_path'])} ✓")
    else:
        print("[BOOT] RSA keys found ✓")


# ─────────────────────────────────────────
#  High-level Operations
# ─────────────────────────────────────────
def secure_encrypt(input_path: str, password: str,
                   user: str = "system") -> str:
    """
    Encrypt a file and log the operation.

    Args:
        input_path: path to the plaintext file
        password:   encryption password
        user:       username for audit log

    Returns:
        path to the encrypted .enc file
    """
    output_path = input_path + ".enc"
    result = encrypt_file(input_path, output_path, password)

    log_event(
        EVENT_ENCRYPT,
        os.path.basename(input_path),
        user,
        {"size": result["file_size"], "output": output_path},
    )

    return output_path


def secure_decrypt(enc_path: str, password: str,
                   user: str = "system") -> str:
    """
    Decrypt a file and log the operation.

    Args:
        enc_path:  path to the .enc encrypted file
        password:  decryption password
        user:      username for audit log

    Returns:
        path to the decrypted output file
    """
    # Remove .enc extension for output (safe check)
    output_path = enc_path[:-4] + ".dec" if enc_path.endswith(".enc") else enc_path + ".dec"
    result = decrypt_file(enc_path, output_path, password)

    log_event(
        EVENT_DECRYPT,
        os.path.basename(enc_path),
        user,
        {"size": result["file_size"], "output": output_path},
    )

    return output_path


# ─────────────────────────────────────────
#  GUI Launch (Member 2 - ui/)
# ─────────────────────────────────────────
def launch_gui() -> None:
    """
    Launch the PyQt5 GUI.
    Will be connected once Member 2 completes ui/main_window.py
    """
    try:
        from PyQt5.QtWidgets import QApplication
        from ui.main_window import MainWindow

        app    = QApplication(sys.argv)
        window = MainWindow()
        window.show()
        sys.exit(app.exec_())

    except ImportError:
        print("[GUI] ui/main_window.py not ready yet (Member 2 pending)")
        print("[GUI] Running CLI demo instead...\n")
        cli_demo()


# ─────────────────────────────────────────
#  CLI Demo (runs until GUI is ready)
# ─────────────────────────────────────────
def cli_demo() -> None:
    """
    CLI demonstration that exercises all core components:
    crypto + database + key_manager working together.
    """
    import tempfile

    print("=" * 55)
    print("  Secure File Transfer & DLP System — CLI Demo")
    print("=" * 55 + "\n")

    # ── Step 1: Bootstrap ──
    bootstrap()
    print()

    # ── Step 2: Create a test file ──
    tmp     = tempfile.NamedTemporaryFile(delete=False,
                                          suffix=".txt",
                                          mode="w")
    tmp.write("Confidential: CET334 project data — Team Leader test.")
    tmp.close()
    test_file = tmp.name
    password  = "DemoP@ss123!"
    user      = "Mohamed_TeamLeader"

    print(f"[DEMO] Test file  : {test_file}")
    print(f"[DEMO] Password   : {password}\n")

    # ── Step 3: Encrypt ──
    enc_path = secure_encrypt(test_file, password, user)
    print(f"[OK] Encrypted → {enc_path}")

    # ── Step 4: Decrypt ──
    dec_path = secure_decrypt(enc_path, password, user)
    with open(dec_path, "r") as f:
        content = f.read()
    print(f"[OK] Decrypted → {dec_path}")
    print(f"     Content  : {content}\n")

    # ── Step 5: RSA key wrap demo ──
    print("[DEMO] RSA key-wrap demo...")
    pub  = load_public_key()
    priv = load_private_key()

    import os as _os
    session_key   = _os.urandom(32)
    wrapped_key   = encrypt_with_public_key(session_key, pub)
    unwrapped_key = decrypt_with_private_key(wrapped_key, priv)
    assert session_key == unwrapped_key
    print("[OK] RSA key-wrap / unwrap successful ✓\n")

    # ── Step 6: Audit log verification ──
    print("[DEMO] Verifying audit log chain...")
    result = verify_chain()
    status = "✓" if result["valid"] else "✗"
    print(f"[{status}] {result['message']}\n")

    # ── Step 7: Print audit log ──
    logs = get_all_logs()
    print(f"[DEMO] Audit log ({len(logs)} entries):")
    print(f"  {'ID':<4} {'Event':<12} {'File':<30} {'User'}")
    print(f"  {'-'*4} {'-'*12} {'-'*30} {'-'*20}")
    for log in logs:
        fname = os.path.basename(log["file_name"])
        print(f"  {log['id']:<4} {log['event']:<12} {fname:<30} {log['user']}")

    print("\n" + "=" * 55)
    print("  All systems operational ✓")
    print("=" * 55)

    # Cleanup temp files
    for p in [test_file, enc_path, dec_path]:
        if os.path.exists(p):
            os.remove(p)


# ─────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────
if __name__ == "__main__":
    launch_gui()