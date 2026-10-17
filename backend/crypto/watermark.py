"""
Cryptographic Invisible Watermark Module
Delegates to backend.services.watermark_service
"""
from services.watermark_service import (
    generate_watermark_id,
    embed_watermark as embed_invisible_watermark,
    extract_watermark
)
