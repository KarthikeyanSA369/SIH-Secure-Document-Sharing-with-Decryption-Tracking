import os
import hashlib
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def calculate_sha256(data: bytes) -> str:
    """Calculate SHA-256 hex digest of given bytes."""
    return hashlib.sha256(data).hexdigest()

def generate_aes_key() -> bytes:
    """Generate a secure random 256-bit (32 bytes) AES key."""
    return os.urandom(32)

def encrypt_document_aes_gcm(key: bytes, plaintext: bytes, associated_data: bytes = None) -> bytes:
    """
    Encrypt plaintext bytes using AES-256-GCM.
    Returns: 12-byte nonce prepended to (ciphertext + 16-byte tag).
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # Standard 96-bit GCM nonce
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext_and_tag

def decrypt_document_aes_gcm(key: bytes, encrypted_payload: bytes, associated_data: bytes = None) -> bytes:
    """
    Decrypt payload encrypted with AES-256-GCM.
    Expects: 12-byte nonce prepended to (ciphertext + 16-byte tag).
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")
    if len(encrypted_payload) < 28: # 12 bytes nonce + 16 bytes tag minimum
        raise ValueError("Encrypted payload is too short.")
    
    nonce = encrypted_payload[:12]
    ciphertext_and_tag = encrypted_payload[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data)

def derive_key_from_shared_secret(shared_secret: bytes, salt: bytes = b"SecureShare-ML-KEM-v1", info: bytes = b"aes-key-wrap") -> bytes:
    """
    Derive a 256-bit encryption key from ML-KEM shared secret using HKDF-SHA256.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info
    )
    return hkdf.derive(shared_secret)

def wrap_key(kek: bytes, key_to_wrap: bytes) -> bytes:
    """Encrypt/wrap a 256-bit AES key using a Key Encryption Key (KEK) via AES-GCM."""
    return encrypt_document_aes_gcm(kek, key_to_wrap)

def unwrap_key(kek: bytes, wrapped_key: bytes) -> bytes:
    """Decrypt/unwrap a 256-bit AES key using a Key Encryption Key (KEK) via AES-GCM."""
    return decrypt_document_aes_gcm(kek, wrapped_key)
