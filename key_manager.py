"""
key_manager.py - RSA Key Management
Team Leader | CET334 - Secure File Transfer & DLP System

Implements:
- RSA-2048 key pair generation
- Save/load keys in PEM format (OpenSSL compatible)
- Encrypt/decrypt AES session keys using RSA-OAEP
- Key stored locally (no cloud dependency)
"""

import os
from OpenSSL import crypto


# ─────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────
KEY_DIR      = os.path.join(os.path.dirname(__file__), "keys")
PRIVATE_KEY  = os.path.join(KEY_DIR, "private_key.pem")
PUBLIC_KEY   = os.path.join(KEY_DIR, "public_key.pem")
RSA_BITS     = 2048


# ─────────────────────────────────────────
#  Key Generation
# ─────────────────────────────────────────
def generate_rsa_keypair(private_path: str = PRIVATE_KEY,
                          public_path: str  = PUBLIC_KEY) -> dict:
    """
    Generate a new RSA-2048 key pair and save as PEM files.

    Args:
        private_path: path to save private key (.pem)
        public_path:  path to save public key (.pem)

    Returns:
        dict with keys: private_path, public_path, bits
    """
    os.makedirs(os.path.dirname(private_path), exist_ok=True)
    os.makedirs(os.path.dirname(public_path),  exist_ok=True)

    # Generate RSA key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, RSA_BITS)

    # Serialize private key to PEM
    private_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
    with open(private_path, "wb") as f:
        f.write(private_pem)

    # Serialize public key to PEM
    public_pem = crypto.dump_publickey(crypto.FILETYPE_PEM, key)
    with open(public_path, "wb") as f:
        f.write(public_pem)

    # Restrict private key file permissions (owner read-only)
    try:
        os.chmod(private_path, 0o600)
    except Exception:
        pass  # Windows may not support Unix permissions

    return {
        "private_path": private_path,
        "public_path":  public_path,
        "bits":         RSA_BITS,
    }


# ─────────────────────────────────────────
#  Load Keys
# ─────────────────────────────────────────
def load_private_key(path: str = PRIVATE_KEY) -> crypto.PKey:
    """
    Load a private key from a PEM file.

    Args:
        path: path to the private key PEM file

    Returns:
        OpenSSL PKey object

    Raises:
        FileNotFoundError: if PEM file doesn't exist
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Private key not found: {path}")

    with open(path, "rb") as f:
        return crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())


def load_public_key(path: str = PUBLIC_KEY) -> crypto.PKey:
    """
    Load a public key from a PEM file.

    Args:
        path: path to the public key PEM file

    Returns:
        OpenSSL PKey object

    Raises:
        FileNotFoundError: if PEM file doesn't exist
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Public key not found: {path}")

    with open(path, "rb") as f:
        return crypto.load_publickey(crypto.FILETYPE_PEM, f.read())


# ─────────────────────────────────────────
#  Encrypt / Decrypt with RSA-OAEP
# ─────────────────────────────────────────
def encrypt_with_public_key(data: bytes, public_key: crypto.PKey) -> bytes:
    """
    Encrypt small data (e.g. AES session key) using RSA public key + OAEP padding.

    Args:
        data:       bytes to encrypt (max ~214 bytes for RSA-2048)
        public_key: OpenSSL PKey object (public)

    Returns:
        encrypted bytes (256 bytes for RSA-2048)
    """
    from OpenSSL.crypto import _lib, _ffi
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes

    # Convert OpenSSL PKey to cryptography library key for OAEP
    pub = public_key.to_cryptography_key()
    return pub.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )


def decrypt_with_private_key(encrypted_data: bytes,
                              private_key: crypto.PKey) -> bytes:
    """
    Decrypt data encrypted with the matching public key using RSA-OAEP.

    Args:
        encrypted_data: bytes to decrypt
        private_key:    OpenSSL PKey object (private)

    Returns:
        original plaintext bytes

    Raises:
        ValueError: if decryption fails (wrong key or corrupted data)
    """
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes

    priv = private_key.to_cryptography_key()
    try:
        return priv.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )
    except Exception as e:
        raise ValueError(f"RSA decryption failed: {e}")


# ─────────────────────────────────────────
#  Key Existence Check
# ─────────────────────────────────────────
def keys_exist(private_path: str = PRIVATE_KEY,
               public_path:  str = PUBLIC_KEY) -> bool:
    """
    Check whether both key files already exist on disk.

    Returns:
        True if both PEM files exist, False otherwise
    """
    return os.path.isfile(private_path) and os.path.isfile(public_path)


def get_public_key_pem(path: str = PUBLIC_KEY) -> str:
    """
    Read and return the public key as a PEM string (for sharing).

    Returns:
        PEM string of the public key
    """
    with open(path, "r") as f:
        return f.read()


# ─────────────────────────────────────────
#  Quick self-test (run directly)
# ─────────────────────────────────────────
if __name__ == "__main__":
    import tempfile, shutil

    print("=== key_manager.py self-test ===\n")

    # Use temp directory
    tmp_dir  = tempfile.mkdtemp()
    priv_pem = os.path.join(tmp_dir, "private_key.pem")
    pub_pem  = os.path.join(tmp_dir, "public_key.pem")

    try:
        # Generate key pair
        info = generate_rsa_keypair(priv_pem, pub_pem)
        print(f"[OK] RSA-{info['bits']} key pair generated")
        print(f"     Private: {info['private_path']}")
        print(f"     Public : {info['public_path']}\n")

        # Load keys
        priv = load_private_key(priv_pem)
        pub  = load_public_key(pub_pem)
        print("[OK] Keys loaded from PEM files\n")

        # Encrypt an AES key (32 bytes) with public key
        fake_aes_key = os.urandom(32)
        encrypted    = encrypt_with_public_key(fake_aes_key, pub)
        print(f"[OK] AES key encrypted with RSA public key")
        print(f"     Encrypted size: {len(encrypted)} bytes\n")

        # Decrypt with private key
        decrypted = decrypt_with_private_key(encrypted, priv)
        assert decrypted == fake_aes_key, "Decrypted key doesn't match!"
        print("[OK] AES key decrypted with RSA private key — matches original ✓\n")

        # Test wrong key detection
        wrong_info = generate_rsa_keypair(
            os.path.join(tmp_dir, "wrong_priv.pem"),
            os.path.join(tmp_dir, "wrong_pub.pem"),
        )
        wrong_priv = load_private_key(os.path.join(tmp_dir, "wrong_priv.pem"))
        try:
            decrypt_with_private_key(encrypted, wrong_priv)
            print("[FAIL] Should have raised ValueError!")
        except ValueError as e:
            print(f"[OK] Wrong key correctly rejected ✓\n")

        # Check keys_exist()
        assert keys_exist(priv_pem, pub_pem)
        print("[OK] keys_exist() works correctly ✓\n")

        print("=== All tests passed ✓ ===")

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
