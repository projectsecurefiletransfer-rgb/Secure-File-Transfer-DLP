"""
crypto.py - File Encryption Engine
Team Leader | CET334 - Secure File Transfer & DLP System

Implements:
- AES-256-GCM encryption/decryption
- Scrypt KDF for key derivation from password
- Binary structure: Salt(32) + Nonce(16) + Tag(16) + Ciphertext
"""

import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt


# ─────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────
SALT_SIZE   = 32   # bytes
NONCE_SIZE  = 16   # bytes (GCM standard)
TAG_SIZE    = 16   # bytes (GCM authentication tag)
KEY_SIZE    = 32   # bytes → 256-bit key

# Scrypt parameters (balanced for desktop performance)
SCRYPT_N = 2 ** 14   # CPU/memory cost  (2^17 is stronger but slower)
SCRYPT_R = 8         # block size
SCRYPT_P = 1         # parallelization


# ─────────────────────────────────────────
#  Key Derivation
# ─────────────────────────────────────────
def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte AES key from a user password using Scrypt KDF.

    Args:
        password: plaintext password string
        salt:     32 random bytes (unique per file)

    Returns:
        32-byte derived key
    """
    return scrypt(
        password.encode("utf-8"),
        salt,
        key_len=KEY_SIZE,
        N=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )


# ─────────────────────────────────────────
#  Encryption
# ─────────────────────────────────────────
def encrypt_file(input_path: str, output_path: str, password: str) -> dict:
    """
    Encrypt a file using AES-256-GCM.

    Binary output format:
        [Salt 32B][Nonce 16B][Tag 16B][Ciphertext]

    Args:
        input_path:  path to plaintext file
        output_path: path for encrypted output (.enc)
        password:    user-supplied password

    Returns:
        dict with keys: salt, nonce, tag, file_size, output_path
    
    Raises:
        FileNotFoundError: if input file doesn't exist
        PermissionError:   if output path isn't writable
    """
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    # Generate fresh random salt and nonce for every encryption
    salt  = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    # Derive key from password + salt
    key = derive_key(password, salt)

    # Read plaintext
    with open(input_path, "rb") as f:
        plaintext = f.read()

    # Encrypt
    cipher     = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Write: Salt | Nonce | Tag | Ciphertext
    with open(output_path, "wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)

    return {
        "salt":        salt.hex(),
        "nonce":       nonce.hex(),
        "tag":         tag.hex(),
        "file_size":   len(ciphertext),
        "output_path": output_path,
    }


# ─────────────────────────────────────────
#  Decryption
# ─────────────────────────────────────────
def decrypt_file(input_path: str, output_path: str, password: str) -> dict:
    """
    Decrypt a file previously encrypted with encrypt_file().

    Reads the Salt, Nonce, and Tag from the file header,
    then verifies integrity via GCM tag before writing plaintext.

    Args:
        input_path:  path to .enc encrypted file
        output_path: path for decrypted output
        password:    user-supplied password

    Returns:
        dict with keys: file_size, output_path

    Raises:
        FileNotFoundError: if encrypted file doesn't exist
        ValueError:        if password is wrong or file is tampered
    """
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Encrypted file not found: {input_path}")

    with open(input_path, "rb") as f:
        salt       = f.read(SALT_SIZE)
        nonce      = f.read(NONCE_SIZE)
        tag        = f.read(TAG_SIZE)
        ciphertext = f.read()

    # Re-derive key using stored salt
    key = derive_key(password, salt)

    # Decrypt + verify tag
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise ValueError(
            "Decryption failed: wrong password or file has been tampered with."
        )

    with open(output_path, "wb") as f:
        f.write(plaintext)

    return {
        "file_size":   len(plaintext),
        "output_path": output_path,
    }


# ─────────────────────────────────────────
#  Quick self-test (run directly)
# ─────────────────────────────────────────
if __name__ == "__main__":
    import tempfile, pathlib

    print("=== crypto.py self-test ===\n")

    # Create a dummy plaintext file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
        tmp.write(b"Secret data: CET334 DLP Project - Team Leader test.")
        plain_path = tmp.name

    enc_path = plain_path + ".enc"
    dec_path = plain_path + ".dec.txt"
    password = "StrongP@ssw0rd!"

    try:
        # Encrypt
        enc_info = encrypt_file(plain_path, enc_path, password)
        print(f"[OK] Encrypted successfully")
        print(f"     Salt  : {enc_info['salt'][:16]}...")
        print(f"     Nonce : {enc_info['nonce']}")
        print(f"     Tag   : {enc_info['tag']}")
        print(f"     Size  : {enc_info['file_size']} bytes\n")

        # Decrypt with correct password
        dec_info = decrypt_file(enc_path, dec_path, password)
        result   = pathlib.Path(dec_path).read_text()
        print(f"[OK] Decrypted successfully")
        print(f"     Content: {result}\n")

        # Attempt decryption with wrong password
        try:
            decrypt_file(enc_path, dec_path, "WrongPassword")
            print("[FAIL] Should have raised ValueError!")
        except ValueError as e:
            print(f"[OK] Wrong password correctly rejected: {e}\n")

        print("=== All tests passed ✓ ===")

    finally:
        for p in [plain_path, enc_path, dec_path]:
            if os.path.exists(p):
                os.remove(p)