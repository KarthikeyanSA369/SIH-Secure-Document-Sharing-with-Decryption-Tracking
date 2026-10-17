"""
SecureShare Cryptographic Package
Provides:
- AES-256-GCM symmetric document encryption
- ML-KEM-768 (NIST FIPS 203) post-quantum key encapsulation
- ML-DSA-65 (NIST FIPS 204) post-quantum digital signatures
- OpenCV + NumPy imperceptible watermark embedding
- Server-side secure keystore
"""

from .aes_gcm import (
    generate_aes_key,
    encrypt_document_aes_gcm,
    decrypt_document_aes_gcm,
    calculate_sha256,
    derive_key_from_shared_secret
)
from .ml_kem import (
    generate_ml_kem_keypair,
    encapsulate_ml_kem,
    decapsulate_ml_kem
)
from .ml_dsa import (
    generate_ml_dsa_keypair,
    sign_access_event_ml_dsa,
    verify_signature_ml_dsa
)
from .watermark import embed_invisible_watermark
from .keystore import KeyStore
