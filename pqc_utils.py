# pqc_utils.py
import base64
import os
from kyber_py.kyber import Kyber512  # Using Kyber512 from kyber-py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- PQC Key Generation ---
def generate_kyber_keys():
    """Generates Kyber512 public and private keys."""
    try:
        # Returns (public_key, private_key)
        pk, sk = Kyber512.keygen()
        return pk, sk
    except Exception as e:
        print(f"Error generating Kyber keys: {e}")
        return None, None

# --- Hybrid Encryption (Kyber KEM + AES-GCM) ---
def encrypt_message(pk_bytes: bytes, message_string: str):
    """
    Encrypts a message using hybrid encryption:
    1. Kyber KEM (encapsulation) to establish a shared secret.
    2. AES-GCM to encrypt the message using the shared secret.
    Returns: (kem_ciphertext, nonce, aes_ciphertext, tag) or (None, None, None, None) on error.
    """
    if not isinstance(message_string, str):
        raise TypeError("Message must be a string")
    if not pk_bytes or not isinstance(pk_bytes, (bytes, bytearray)):
        raise ValueError("Public key must be non-empty bytes")

    message_bytes = message_string.encode('utf-8')

    try:
        # 1. Kyber KEM Encapsulation
        # Kyber512.encaps returns (shared_secret, kem_ciphertext)
        shared_secret, kem_ciphertext = Kyber512.encaps(pk_bytes)

        # 2. AES-GCM Encryption
        # Use the Kyber shared secret (32 bytes) as the AES key (256 bits)
        aesgcm = AESGCM(shared_secret)
        nonce = os.urandom(12)  # Standard 12-byte nonce for AES-GCM
        ciphertext_with_tag = aesgcm.encrypt(nonce, message_bytes, None)

        # AESGCM.encrypt returns ciphertext || tag (tag is last 16 bytes)
        aes_ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]

        return kem_ciphertext, nonce, aes_ciphertext, tag

    except Exception as e:
        print(f"Error during encryption: {e}")
        return None, None, None, None

# --- Hybrid Decryption (Kyber KEM + AES-GCM) ---
def decrypt_message(sk_bytes: bytes, kem_ciphertext: bytes, nonce: bytes, aes_ciphertext: bytes, tag: bytes):
    """
    Decrypts a message using hybrid decryption:
    1. Kyber KEM decapsulation to recover the shared secret.
    2. AES-GCM to decrypt the ciphertext using the shared secret.
    Returns the original message string or None on error.
    """
    # Validate inputs
    for name, arg in [('sk_bytes', sk_bytes), ('kem_ciphertext', kem_ciphertext),
                      ('nonce', nonce), ('aes_ciphertext', aes_ciphertext), ('tag', tag)]:
        if not arg or not isinstance(arg, (bytes, bytearray)):
            raise ValueError(f"{name} must be non-empty bytes for decryption")

    try:
        # 1. Kyber KEM Decapsulation
        shared_secret = Kyber512.decaps(sk_bytes, kem_ciphertext)

        # 2. AES-GCM Decryption
        aesgcm = AESGCM(shared_secret)
        ciphertext_with_tag = aes_ciphertext + tag
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)

        return plaintext_bytes.decode('utf-8')

    except Exception as e:
        # Includes InvalidTag if authentication fails
        print(f"Error during decryption: {e}")
        return None

# --- Helper for Base64 Encoding/Decoding ---
def bytes_to_base64(data: bytes) -> str:
    """Encodes bytes to a Base64 string."""
    return base64.b64encode(data).decode('utf-8') if data else ""

def base64_to_bytes(b64_string: str) -> bytes | None:
    """Decodes a Base64 string to bytes. Returns None on error."""
    if not b64_string:
        return None
    try:
        return base64.b64decode(b64_string.encode('utf-8'))
    except Exception as e:
        print(f"Error decoding Base64 string: {e}")
        return None
