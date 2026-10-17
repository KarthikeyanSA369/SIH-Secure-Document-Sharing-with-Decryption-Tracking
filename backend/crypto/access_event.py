import json
import hashlib
from typing import Dict, Any

def canonicalize_access_event(
    document_id: str,
    recipient_id: str,
    recipient_key_id: str,
    session_id: str,
    watermark_id: str,
    document_hash: str,
    timestamp_iso: str
) -> bytes:
    """
    Produce a deterministic, canonical representation of an access event for
    both ML-DSA-65 signing and signature verification.
    
    Ensures identical key ordering, strict separators, and UTC ISO-8601 timestamps.
    """
    canonical_dict = {
        "document_hash": str(document_hash).strip(),
        "document_id": str(document_id).strip(),
        "recipient_id": str(recipient_id).strip(),
        "recipient_key_id": str(recipient_key_id).strip(),
        "session_id": str(session_id).strip(),
        "timestamp": str(timestamp_iso).strip(),
        "watermark_id": str(watermark_id).strip()
    }
    # Deterministic JSON serialization with sorted keys
    return json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")

def compute_event_hash(canonical_bytes: bytes) -> str:
    """Compute the SHA-256 digest of the canonical event bytes."""
    return hashlib.sha256(canonical_bytes).hexdigest()
