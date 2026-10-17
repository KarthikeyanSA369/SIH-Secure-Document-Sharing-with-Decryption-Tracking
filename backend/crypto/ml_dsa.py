import base64
from typing import Tuple
from dilithium_py.dilithium import Dilithium3  # Dilithium3 corresponds to NIST ML-DSA-65

def generate_ml_dsa_keypair() -> Tuple[str, str]:
    """
    Generate ML-DSA-65 (Dilithium3) public and secret key pair.
    Returns:
        Tuple of (public_key_b64, secret_key_b64)
    """
    pk_bytes, sk_bytes = Dilithium3.keygen()
    pk_b64 = base64.b64encode(pk_bytes).decode("utf-8")
    sk_b64 = base64.b64encode(sk_bytes).decode("utf-8")
    return pk_b64, sk_b64

def sign_access_event_ml_dsa(secret_key_b64: str, message_bytes: bytes) -> str:
    """
    Sign canonical message bytes using ML-DSA-65 secret key.
    Args:
        secret_key_b64: Base64-encoded ML-DSA-65 secret key.
        message_bytes: Raw bytes of canonical message/event to sign.
    Returns:
        Base64-encoded ML-DSA-65 digital signature.
    """
    sk_bytes = base64.b64decode(secret_key_b64.encode("utf-8"))
    sig_bytes = Dilithium3.sign(sk_bytes, message_bytes)
    return base64.b64encode(sig_bytes).decode("utf-8")

def verify_signature_ml_dsa(public_key_b64: str, message_bytes: bytes, signature_b64: str) -> bool:
    """
    Verify an ML-DSA-65 signature against canonical message bytes.
    Args:
        public_key_b64: Base64-encoded ML-DSA-65 public key.
        message_bytes: Raw bytes of canonical message/event.
        signature_b64: Base64-encoded digital signature.
    Returns:
        True if valid, False otherwise.
    """
    try:
        pk_bytes = base64.b64decode(public_key_b64.encode("utf-8"))
        sig_bytes = base64.b64decode(signature_b64.encode("utf-8"))
        return Dilithium3.verify(pk_bytes, message_bytes, sig_bytes)
    except Exception:
        return False
