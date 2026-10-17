import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel

class LoginRequest(BaseModel):
    username: str
    password: str
    role: Optional[str] = None

class UserOut(BaseModel):
    id: str
    username: str
    name: str
    role: str
    ml_kem_public_key: Optional[str] = None
    ml_dsa_public_key: Optional[str] = None

    class Config:
        from_attributes = True

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut

class RecipientOption(BaseModel):
    id: str
    username: str
    name: str

class SendDocumentRequest(BaseModel):
    recipient_id: str

class SendDocumentResponse(BaseModel):
    success: bool
    message: str
    document_id: str
    filename: str
    recipient_name: str
    recipient_username: str

class DocumentItem(BaseModel):
    id: str
    filename: str
    created_at: datetime.datetime
    status: str
    shared_by: str

    class Config:
        from_attributes = True

class AdminStatsResponse(BaseModel):
    documents_count: int
    recipients_count: int
    access_events_count: int
    protected_copies_count: int

# --- Recipient Document Preparation Schemas ---

class PrepareDocumentResponse(BaseModel):
    job_id: str
    status: str

class PrepareStatusResponse(BaseModel):
    job_id: str
    status: str  # 'PROCESSING', 'COMPLETED', 'FAILED'
    current_step: Optional[str] = None
    completed_steps: List[str] = []
    error: Optional[str] = None
    watermark_id: Optional[str] = None
    session_id: Optional[str] = None
    document_id: Optional[str] = None
    filename: Optional[str] = None


# --- Investigation Schemas ---

class InvestigationStage(BaseModel):
    id: int
    name: str
    status: str  # 'COMPLETED', 'PROCESSING', 'PENDING', 'FAILED'
    detail: Optional[str] = None

class TechnicalEvidence(BaseModel):
    document_sha256: str
    watermark_id: Optional[str] = None
    session_id: Optional[str] = None
    event_id: Optional[str] = None
    event_hash: Optional[str] = None
    signature_algorithm: str = "ML-DSA-65 (NIST FIPS 204 / Dilithium3)"
    signature_preview: Optional[str] = None
    key_identifier: Optional[str] = None
    timestamp: Optional[str] = None
    ledger_status: str = "NOT_IMPLEMENTED"
    ledger_message: str = "Ledger verification pending"

class InvestigationResultResponse(BaseModel):
    investigation_id: Optional[str] = None
    status: str  # 'MATCH_FOUND', 'NO_WATERMARK', 'EVENT_NOT_FOUND', 'SIGNATURE_FAILED'
    title: str
    status_label: str
    document_filename: Optional[str] = None
    watermark_id: Optional[str] = None
    access_event_id: Optional[str] = None
    recipient_identity: Optional[str] = None
    session_id: Optional[str] = None
    access_timestamp: Optional[str] = None
    forensic_statement: str
    attribution_disclaimer: str
    verification_checks: List[Dict[str, Any]]
    technical_evidence: Optional[TechnicalEvidence] = None
    stages: List[InvestigationStage]
    explanations: Optional[List[str]] = None

class InvestigationHistoryItem(BaseModel):
    investigation_id: str
    document_name: str
    status: str
    status_label: str
    recipient_identity: Optional[str] = None
    verification_status: str
    timestamp: str

class ReportRequest(BaseModel):
    investigation_id: str
    status: str
    status_label: str
    document_filename: Optional[str] = None
    document_sha256: Optional[str] = None
    watermark_id: Optional[str] = None
    access_event_id: Optional[str] = None
    session_id: Optional[str] = None
    recipient_identity: Optional[str] = None
    access_timestamp: Optional[str] = None
    technical_evidence: Optional[Dict[str, Any]] = None

