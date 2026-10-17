import base64
from typing import Tuple
from kyber_py.kyber import Kyber768

def generate_ml_kem_keypair() -> Tuple[str, str]:
    """
    Generate ML-KEM-768 (Kyber768) public and secret key pair.
    Returns:
        Tuple of (public_key_b64, secret_key_b64)
    """
    pk_bytes, sk_bytes = Kyber768.keygen()
    pk_b64 = base64.b64encode(pk_bytes).decode("utf-8")
    sk_b64 = base64.b64encode(sk_bytes).decode("utf-8")
    return pk_b64, sk_b64

def encapsulate_ml_kem(public_key_b64: str) -> Tuple[bytes, str]:
    """
    Perform ML-KEM-768 encapsulation using the recipient's public key.
    Args:
        public_key_b64: Base64-encoded ML-KEM-768 public key.
    Returns:
        Tuple of (shared_secret_bytes, ciphertext_b64)
    """
    pk_bytes = base64.b64decode(public_key_b64.encode("utf-8"))
    shared_secret, ct_bytes = Kyber768.encaps(pk_bytes)
    ct_b64 = base64.b64encode(ct_bytes).decode("utf-8")
    return shared_secret, ct_b64

def decapsulate_ml_kem(secret_key_b64: str, ciphertext_b64: str) -> bytes:
    """
    Perform ML-KEM-768 decapsulation using the recipient's secret key.
    Args:
        secret_key_b64: Base64-encoded ML-KEM-768 secret key.
        ciphertext_b64: Base64-encoded KEM ciphertext.
    Returns:
        Recovered 32-byte shared secret.
    """
    sk_bytes = base64.b64decode(secret_key_b64.encode("utf-8"))
    ct_bytes = base64.b64decode(ciphertext_b64.encode("utf-8"))
    shared_secret = Kyber768.decaps(sk_bytes, ct_bytes)
    return shared_secret
