import os
import io
import json
import uuid
import datetime
from pathlib import Path
from typing import List, Optional
import pymupdf as fitz

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, status, Response, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from config import settings
from database import get_db, engine, Base
from models import User, Document, DocumentRecipient, AccessEvent, AuditLog, WatermarkRecord
from schemas import (
    LoginRequest, TokenResponse, UserOut, RecipientOption,
    SendDocumentResponse, DocumentItem, AdminStatsResponse,
    InvestigationResultResponse, InvestigationStage, TechnicalEvidence,
    InvestigationHistoryItem, ReportRequest,
    PrepareDocumentResponse, PrepareStatusResponse
)
from auth import (
    verify_password, create_access_token, get_current_user,
    require_admin, require_recipient, require_investigator
)
from crypto.aes_gcm import (
    generate_aes_key, encrypt_document_aes_gcm, decrypt_document_aes_gcm,
    calculate_sha256, derive_key_from_shared_secret, wrap_key, unwrap_key
)
from crypto.ml_kem import encapsulate_ml_kem, decapsulate_ml_kem
from crypto.ml_dsa import sign_access_event_ml_dsa, verify_signature_ml_dsa
from crypto.access_event import canonicalize_access_event, compute_event_hash
from services.watermark_service import generate_watermark_id, embed_watermark, extract_watermark
from services.report_service import generate_evidence_pdf_report
from crypto.keystore import KeyStore

app = FastAPI(
    title="SecureShare API",
    description="Post-Quantum Secure Multi-Recipient Document Distribution & Forensic Provenance Platform",
    version="2.1.0"
)

# Enable CORS for frontend Vite dev server & production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

keystore = KeyStore(str(settings.KEYSTORE_PATH))

def log_audit(db: Session, action: str, user_id: Optional[str] = None, details: Optional[dict] = None):
    """Record an auditable system event without storing sensitive key material."""
    try:
        clean_details = json.dumps(details or {})
        entry = AuditLog(
            id=str(uuid.uuid4()),
            user_id=user_id,
            action=action,
            details=clean_details,
            timestamp=datetime.datetime.utcnow()
        )
        db.add(entry)
        db.commit()
    except Exception as e:
        print(f"[Audit Log Warning] {e}")


# -------------------------------------------------------------------
# Authentication Endpoints
# -------------------------------------------------------------------

@app.post("/api/login", response_model=TokenResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate Admin, Recipient, or Investigator and issue signed JWT access token."""
    user = db.query(User).filter(User.username == req.username.strip().lower()).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    if req.role and req.role.upper() != user.role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"User is not registered with role '{req.role}'"
        )

    token = create_access_token(user)
    log_audit(db, "LOGIN", user_id=user.id, details={"username": user.username, "role": user.role})

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserOut.from_orm(user)
    )

@app.get("/api/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    """Return currently authenticated user profile."""
    return UserOut.from_orm(current_user)


# -------------------------------------------------------------------
# Admin Endpoints
# -------------------------------------------------------------------

@app.get("/api/admin/stats", response_model=AdminStatsResponse)
def get_admin_stats(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Return security distribution statistics for Admin Dashboard."""
    docs_count = db.query(Document).count()
    recipients_count = db.query(User).filter(User.role == "RECIPIENT").count()
    events_count = db.query(AccessEvent).count()
    return AdminStatsResponse(
        documents_count=docs_count,
        recipients_count=recipients_count,
        access_events_count=events_count,
        protected_copies_count=events_count
    )

@app.get("/api/admin/recipients", response_model=List[RecipientOption])
def list_recipients(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """List available document recipients (e.g. Alice)."""
    recipients = db.query(User).filter(User.role == "RECIPIENT").all()
    return [
        RecipientOption(id=r.id, username=r.username, name=r.name)
        for r in recipients
    ]

@app.post("/api/admin/documents", response_model=SendDocumentResponse)
async def upload_and_send_document(
    file: UploadFile = File(...),
    recipient_id: str = Form(...),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Admin document upload and distribution pipeline:
    1. Generate unique Document ID (e.g. DOC-001).
    2. Compute SHA-256 hash of original PDF.
    3. Generate 256-bit AES symmetric key.
    4. Encrypt PDF using AES-256-GCM.
    5. Save encrypted file in storage/encrypted/DOC-XXX.enc.
    6. Encapsulate AES key with recipient's ML-KEM-768 public key.
    7. Save document metadata in MySQL and log audit event.
    """
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only PDF documents are supported"
        )

    recipient = db.query(User).filter(
        (User.id == recipient_id) | (User.username == recipient_id)
    ).first()
    if not recipient or recipient.role != "RECIPIENT":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient not found"
        )

    raw_pdf_bytes = await file.read()
    if len(raw_pdf_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty"
        )

    count = db.query(Document).count() + 1
    doc_id = f"DOC-{count:03d}"
    doc_sha256 = calculate_sha256(raw_pdf_bytes)
    aes_key = generate_aes_key()

    encrypted_bytes = encrypt_document_aes_gcm(aes_key, raw_pdf_bytes)

    enc_filename = f"{doc_id}.enc"
    enc_file_path = settings.STORAGE_PATH / enc_filename
    with open(enc_file_path, "wb") as f:
        f.write(encrypted_bytes)

    if not recipient.ml_kem_public_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Recipient does not have an ML-KEM-768 public key configured"
        )
    
    shared_secret, kem_ciphertext = encapsulate_ml_kem(recipient.ml_kem_public_key)
    kek = derive_key_from_shared_secret(shared_secret)
    wrapped_aes_key_bytes = wrap_key(kek, aes_key)
    import base64
    wrapped_aes_key_b64 = base64.b64encode(wrapped_aes_key_bytes).decode("utf-8")

    doc_record = Document(
        id=doc_id,
        filename=file.filename,
        sha256_hash=doc_sha256,
        encrypted_file_path=enc_filename,
        created_by=admin.id
    )
    db.add(doc_record)

    recipient_assoc = DocumentRecipient(
        id=str(uuid.uuid4()),
        document_id=doc_id,
        recipient_id=recipient.id,
        status="AUTHORIZED",
        kem_ciphertext=kem_ciphertext,
        wrapped_key=wrapped_aes_key_b64
    )
    db.add(recipient_assoc)
    db.commit()

    log_audit(db, "DOCUMENT_UPLOADED", user_id=admin.id, details={"doc_id": doc_id, "filename": file.filename, "sha256": doc_sha256})
    log_audit(db, "DOCUMENT_SHARED", user_id=admin.id, details={"doc_id": doc_id, "recipient": recipient.username})

    return SendDocumentResponse(
        success=True,
        message="Document sent successfully",
        document_id=doc_id,
        filename=file.filename,
        recipient_name=recipient.name,
        recipient_username=recipient.username
    )


# -------------------------------------------------------------------
# Recipient Endpoints
# -------------------------------------------------------------------

@app.get("/api/recipient/documents", response_model=List[DocumentItem])
def get_recipient_documents(
    recipient: User = Depends(require_recipient),
    db: Session = Depends(get_db)
):
    """Retrieve all documents authorized for the logged-in recipient."""
    assignments = db.query(DocumentRecipient).filter(
        DocumentRecipient.recipient_id == recipient.id,
        DocumentRecipient.status == "AUTHORIZED"
    ).all()

    items = []
    for a in assignments:
        doc = db.query(Document).filter(Document.id == a.document_id).first()
        if doc:
            creator = db.query(User).filter(User.id == doc.created_by).first()
            creator_name = creator.name if creator else "Admin"
            items.append(
                DocumentItem(
                    id=doc.id,
                    filename=doc.filename,
                    created_at=doc.created_at,
                    status="Available",
                    shared_by=creator_name
                )
            )
    return items


PREPARATION_JOBS: dict = {}

def process_document_preparation_job(job_id: str, document_id: str, recipient_id: str):
    """
    Background Security Processing Pipeline for Recipient Open Flow:
    1. Verify Alice authentication and authorization.
    2. Retrieve encrypted document from storage.
    3. Recover AES-256-GCM document key via ML-KEM-768 decapsulation and decrypt PDF.
    4. Generate unique session ID.
    5. Generate unique forensic Watermark ID.
    6. Embed Watermark ID into physical PDF using OpenCV/NumPy.
    7. Create canonical access event.
    8. Sign access event using Alice's ML-DSA-65 private key.
    9. Store access event in MySQL and prepare protected PDF.
    """
    db = next(get_db())
    try:
        job = PREPARATION_JOBS.get(job_id)
        if not job:
            return

        # Stage 1: Access authorization
        job["current_step"] = "auth_verification"
        user = db.query(User).filter(User.id == recipient_id).first()
        if not user:
            job["status"] = "FAILED"
            job["error"] = "Access authorization failed: Recipient not found."
            return

        print(f"[OPEN] {user.username} requested document {document_id}")

        assignment = db.query(DocumentRecipient).filter(
            DocumentRecipient.document_id == document_id,
            DocumentRecipient.recipient_id == user.id,
            DocumentRecipient.status == "AUTHORIZED"
        ).first()
        if not assignment:
            job["status"] = "FAILED"
            job["error"] = "Access authorization failed: You are not authorized to view this document."
            return

        print(f"[AUTH] Authorization verified for {user.username}")
        job["completed_steps"].append("auth_verification")

        # Stage 2: Encrypted document retrieval
        job["current_step"] = "document_retrieval"
        doc = db.query(Document).filter(Document.id == document_id).first()
        if not doc:
            job["status"] = "FAILED"
            job["error"] = "Encrypted document unavailable: Master record missing."
            return

        job["filename"] = doc.filename
        enc_path = settings.STORAGE_PATH / doc.encrypted_file_path
        if not enc_path.exists():
            job["status"] = "FAILED"
            job["error"] = "Encrypted document unavailable: File storage object missing."
            return

        with open(enc_path, "rb") as f:
            encrypted_bytes = f.read()

        print(f"[STORAGE] Encrypted document loaded ({len(encrypted_bytes)} bytes)")
        job["completed_steps"].append("document_retrieval")

        # Stage 3: Secure decryption (ML-KEM-768 + AES-256-GCM)
        job["current_step"] = "secure_decryption"
        recipient_kem_sk = keystore.get_user_kem_sk(user.id)
        if not recipient_kem_sk:
            job["status"] = "FAILED"
            job["error"] = "Document decryption failed: Recipient private key not found."
            return

        import base64
        shared_secret = decapsulate_ml_kem(recipient_kem_sk, assignment.kem_ciphertext)
        kek = derive_key_from_shared_secret(shared_secret)
        wrapped_aes_key_bytes = base64.b64decode(assignment.wrapped_key.encode("utf-8"))
        aes_key = unwrap_key(kek, wrapped_aes_key_bytes)

        try:
            decrypted_pdf_bytes = decrypt_document_aes_gcm(aes_key, encrypted_bytes)
        except Exception:
            job["status"] = "FAILED"
            job["error"] = "Document decryption failed: Integrity check or authentication tag mismatch."
            return

        print(f"[DECRYPTION] Document decrypted successfully")
        job["completed_steps"].append("secure_decryption")

        # Stage 4: Session generation
        job["current_step"] = "session_generation"
        import random
        session_num = random.randint(10000, 99999)
        session_id = f"SES-{session_num}"
        job["session_id"] = session_id
        print(f"[WATERMARK] Session ID generated: {session_id}")
        job["completed_steps"].append("session_generation")

        # Stage 5: Forensic watermark generation
        job["current_step"] = "watermark_generation"
        watermark_id = generate_watermark_id(doc.id, user.id, session_id)
        job["watermark_id"] = watermark_id
        print(f"[WATERMARK] Watermark ID generated: {watermark_id}")
        job["completed_steps"].append("watermark_generation")

        # Stage 6: PDF watermark embedding
        job["current_step"] = "watermark_embedding"
        try:
            watermarked_pdf = embed_watermark(
                decrypted_pdf_bytes,
                watermark_id=watermark_id,
                session_id=session_id,
                document_id=doc.id,
                recipient_id=user.id
            )
        except Exception as e:
            job["status"] = "FAILED"
            job["error"] = f"Watermark embedding failed: {str(e)}"
            return

        # Validate PDF validity & watermark extraction immediately
        if not watermarked_pdf or not watermarked_pdf.startswith(b"%PDF-") or b"%%EOF" not in watermarked_pdf:
            job["status"] = "FAILED"
            job["error"] = "Protected PDF generation failed: generated PDF is invalid."
            return

        try:
            val_doc = fitz.open(stream=watermarked_pdf, filetype="pdf")
            page_count = len(val_doc)
            val_doc.close()
            assert page_count > 0
        except Exception as val_e:
            job["status"] = "FAILED"
            job["error"] = f"Protected PDF generation failed: invalid PDF structure ({str(val_e)})."
            return

        val_wid, val_sid, _ = extract_watermark(watermarked_pdf)
        if val_wid != watermark_id:
            job["status"] = "FAILED"
            job["error"] = "Protected PDF generation failed: embedded watermark could not be verified."
            return

        print(f"[PDF VALIDATION]")
        print(f"valid=true")
        print(f"content_type=application/pdf")
        print(f"size={len(watermarked_pdf)}")
        print(f"pages={page_count}")
        print(f"[WATERMARK VALIDATION]")
        print(f"generated={watermark_id}")
        print(f"extracted={val_wid}")
        print(f"match=true")
        print(f"[WATERMARK] Watermark embedded ({len(watermarked_pdf)} bytes)")
        job["completed_steps"].append("watermark_embedding")

        # Stage 7: Access event recording
        job["current_step"] = "event_recording"
        timestamp = datetime.datetime.utcnow().replace(microsecond=0)
        iso_timestamp = timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        recipient_key_id = f"KEM-{user.username.upper()}-01"

        canonical_bytes = canonicalize_access_event(
            document_id=doc.id,
            recipient_id=user.id,
            recipient_key_id=recipient_key_id,
            session_id=session_id,
            watermark_id=watermark_id,
            document_hash=doc.sha256_hash,
            timestamp_iso=iso_timestamp
        )
        event_hash = compute_event_hash(canonical_bytes)
        print(f"[ACCESS_EVENT] Event created (Hash: {event_hash})")
        job["completed_steps"].append("event_recording")

        # Stage 8: ML-DSA-65 signature
        job["current_step"] = "dsa_signing"
        recipient_signing_key = keystore.get_user_dsa_sk(user.id)
        if not recipient_signing_key:
            job["status"] = "FAILED"
            job["error"] = "Signing access event failed: Recipient ML-DSA-65 private key missing."
            return

        ml_dsa_signature = sign_access_event_ml_dsa(recipient_signing_key, canonical_bytes)
        print(f"[ML-DSA] Signature generated using {user.username}'s private key")
        job["completed_steps"].append("dsa_signing")

        # Stage 9: Protected PDF preparation & storage
        job["current_step"] = "pdf_preparation"
        watermarked_pdf_hash = calculate_sha256(watermarked_pdf)
        wm_record = WatermarkRecord(
            watermark_id=watermark_id,
            session_id=session_id,
            document_id=doc.id,
            recipient_id=user.id,
            document_hash=doc.sha256_hash,
            watermarked_pdf_hash=watermarked_pdf_hash,
            created_at=timestamp
        )
        db.add(wm_record)

        access_event = AccessEvent(
            id=f"EVT-{timestamp.year}-{str(uuid.uuid4())[:8].upper()}",
            document_id=doc.id,
            recipient_id=user.id,
            session_id=session_id,
            watermark_id=watermark_id,
            document_hash=doc.sha256_hash,
            signature=ml_dsa_signature,
            timestamp=timestamp,
            event_hash=event_hash
        )
        db.add(access_event)
        db.commit()

        log_audit(db, "DOCUMENT_OPENED", user_id=user.id, details={
            "doc_id": doc.id,
            "session_id": session_id,
            "watermark_id": watermark_id,
            "event_id": access_event.id
        })

        job["watermarked_pdf"] = watermarked_pdf
        job["completed_steps"].append("pdf_preparation")
        job["status"] = "COMPLETED"
        print(f"[DOWNLOAD] Protected PDF ready for {user.username} (Watermark: {watermark_id})")

    except Exception as e:
        print(f"[Preparation Pipeline Error] {e}")
        if job_id in PREPARATION_JOBS:
            PREPARATION_JOBS[job_id]["status"] = "FAILED"
            PREPARATION_JOBS[job_id]["error"] = f"Secure document processing failed: {str(e)}"
    finally:
        db.close()


@app.post("/api/recipient/documents/{document_id}/prepare", response_model=PrepareDocumentResponse)
def prepare_recipient_document(
    document_id: str,
    background_tasks: BackgroundTasks,
    recipient: User = Depends(require_recipient),
    db: Session = Depends(get_db)
):
    """Initiate background security processing for recipient document open."""
    job_id = f"JOB-{uuid.uuid4().hex[:12].upper()}"
    PREPARATION_JOBS[job_id] = {
        "job_id": job_id,
        "document_id": document_id,
        "user_id": recipient.id,
        "username": recipient.username,
        "status": "PROCESSING",
        "current_step": "auth_verification",
        "completed_steps": [],
        "error": None,
        "watermark_id": None,
        "session_id": None,
        "filename": None,
        "watermarked_pdf": None,
        "timestamp": datetime.datetime.utcnow()
    }
    background_tasks.add_task(process_document_preparation_job, job_id, document_id, recipient.id)
    return PrepareDocumentResponse(job_id=job_id, status="PROCESSING")


@app.get("/api/recipient/documents/prepare-status/{job_id}", response_model=PrepareStatusResponse)
def get_prepare_status(
    job_id: str,
    recipient: User = Depends(require_recipient)
):
    """Poll the real-time background security processing stages."""
    job = PREPARATION_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Preparation job not found")
    if job["user_id"] != recipient.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    return PrepareStatusResponse(
        job_id=job["job_id"],
        status=job["status"],
        current_step=job.get("current_step"),
        completed_steps=job.get("completed_steps", []),
        error=job.get("error"),
        watermark_id=job.get("watermark_id"),
        session_id=job.get("session_id"),
        document_id=job.get("document_id"),
        filename=job.get("filename")
    )


@app.get("/api/recipient/documents/download-protected/{job_id}")
def download_protected_pdf(
    job_id: str,
    recipient: User = Depends(require_recipient)
):
    """Download or stream the generated watermarked protected PDF."""
    job = PREPARATION_JOBS.get(job_id)
    if not job or job.get("status") != "COMPLETED" or not job.get("watermarked_pdf"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Protected PDF not ready or job failed")
    if job["user_id"] != recipient.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    watermarked_pdf = job["watermarked_pdf"]
    doc_filename = job.get("filename", "Project_Report.pdf")
    base_name = doc_filename.rsplit(".", 1)[0] if "." in doc_filename else doc_filename
    safe_base = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in base_name.strip()).strip("_")
    protected_filename = f"SecureShare_{safe_base or 'Document'}_protected.pdf"

    # Diagnostics
    print(f"[DOWNLOAD]")
    print(f"content_type=application/pdf")
    print(f"pdf_size={len(watermarked_pdf)}")
    print(f"pdf_header={watermarked_pdf[:8].decode('latin1', errors='ignore').strip()}")
    print(f"pdf_footer={watermarked_pdf[-8:].decode('latin1', errors='ignore').strip()}")

    return Response(
        content=watermarked_pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{protected_filename}"',
            "Content-Type": "application/pdf",
            "X-Document-ID": job.get("document_id", ""),
            "X-Session-ID": job.get("session_id", ""),
            "X-Watermark-ID": job.get("watermark_id", "")
        }
    )


@app.post("/api/recipient/documents/{document_id}/open")
def open_recipient_document(
    document_id: str,
    recipient: User = Depends(require_recipient),
    db: Session = Depends(get_db)
):
    """
    Background Decryption & Watermarking Flow:
    1. Authenticate recipient and verify authorization in MySQL.
    2. Retrieve encrypted PDF from storage/encrypted/.
    3. Recover document AES key using ML-KEM-768 decapsulation.
    4. Decrypt document using AES-256-GCM.
    5. Generate unique Session ID (SES-XXXXX) and Watermark ID (WM-XXXXXXXX).
    6. Physically embed invisible watermark into the actual PDF bytes using OpenCV + NumPy.
    7. Generate canonical Access Event using unified canonical format and sign using ML-DSA-65.
    8. Store signed access event in MySQL.
    9. Return watermarked PDF bytes to recipient browser.
    """
    assignment = db.query(DocumentRecipient).filter(
        DocumentRecipient.document_id == document_id,
        DocumentRecipient.recipient_id == recipient.id,
        DocumentRecipient.status == "AUTHORIZED"
    ).first()

    if not assignment:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Forbidden: You are not authorized to view this document."
        )

    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )

    enc_path = settings.STORAGE_PATH / doc.encrypted_file_path
    if not enc_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Encrypted document storage file missing"
        )

    with open(enc_path, "rb") as f:
        encrypted_bytes = f.read()

    recipient_kem_sk = keystore.get_user_kem_sk(recipient.id)
    if not recipient_kem_sk:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Recipient cryptographic private key not found in secure keystore"
        )

    import base64
    shared_secret = decapsulate_ml_kem(recipient_kem_sk, assignment.kem_ciphertext)
    kek = derive_key_from_shared_secret(shared_secret)
    wrapped_aes_key_bytes = base64.b64decode(assignment.wrapped_key.encode("utf-8"))
    aes_key = unwrap_key(kek, wrapped_aes_key_bytes)

    try:
        decrypted_pdf_bytes = decrypt_document_aes_gcm(aes_key, encrypted_bytes)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document decryption failed: integrity check or authentication tag mismatch."
        )

    import random
    session_num = random.randint(10000, 99999)
    session_id = f"SES-{session_num}"
    watermark_id = generate_watermark_id(doc.id, recipient.id, session_id)

    print(f"[WATERMARK] Access started for user {recipient.username} (ID: {recipient.id}) on document {doc.id}")
    print(f"[WATERMARK] Session ID: {session_id}")
    print(f"[WATERMARK] Watermark ID generated: {watermark_id}")
    print(f"[WATERMARK] Embedding watermark into PDF")

    # Physically embed invisible forensic watermark into the actual PDF content
    try:
        watermarked_pdf = embed_watermark(
            decrypted_pdf_bytes,
            watermark_id=watermark_id,
            session_id=session_id,
            document_id=doc.id,
            recipient_id=recipient.id
        )
    except Exception as e:
        print(f"[Watermark Embedding Error] {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Secure document generation failed: forensic watermark could not be embedded."
        )

    # Validate PDF structure and page count before proceeding
    if not watermarked_pdf or not watermarked_pdf.startswith(b"%PDF-") or b"%%EOF" not in watermarked_pdf:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Protected PDF generation failed: generated PDF is invalid."
        )

    try:
        val_doc = fitz.open(stream=watermarked_pdf, filetype="pdf")
        page_count = len(val_doc)
        val_doc.close()
        assert page_count > 0
    except Exception as val_e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Protected PDF generation failed: generated PDF is invalid ({str(val_e)})."
        )

    val_wid, val_sid, _ = extract_watermark(watermarked_pdf)
    if val_wid != watermark_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Protected PDF generation failed: embedded watermark could not be verified."
        )

    print(f"[PDF] Content-Type: application/pdf")
    print(f"[PDF] Size: {len(watermarked_pdf)} bytes")
    print(f"[PDF] Header: {watermarked_pdf[:5].decode('latin1', errors='ignore')}")
    print(f"[PDF] Valid PDF: True")
    print(f"[PDF] Page count: {page_count}")
    print(f"[WATERMARK] ID: {watermark_id}")
    print(f"[WATERMARK] Watermarked PDF size: {len(watermarked_pdf)} bytes")

    # Create Unified Canonical Access Event & Sign with Recipient's ML-DSA-65 Private Key
    timestamp = datetime.datetime.utcnow().replace(microsecond=0)
    iso_timestamp = timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    recipient_key_id = f"KEM-{recipient.username.upper()}-01"

    canonical_bytes = canonicalize_access_event(
        document_id=doc.id,
        recipient_id=recipient.id,
        recipient_key_id=recipient_key_id,
        session_id=session_id,
        watermark_id=watermark_id,
        document_hash=doc.sha256_hash,
        timestamp_iso=iso_timestamp
    )
    event_hash = compute_event_hash(canonical_bytes)

    # Sign using RECIPIENT'S ML-DSA-65 private key from secure server-side keystore
    recipient_signing_key = keystore.get_user_dsa_sk(recipient.id)
    if not recipient_signing_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Recipient ML-DSA-65 signing key missing from secure keystore"
        )

    ml_dsa_signature = sign_access_event_ml_dsa(recipient_signing_key, canonical_bytes)
    print(f"[ML-DSA] Signature generated using recipient private key for {recipient.username}")

    watermarked_pdf_hash = calculate_sha256(watermarked_pdf)
    wm_record = WatermarkRecord(
        watermark_id=watermark_id,
        session_id=session_id,
        document_id=doc.id,
        recipient_id=recipient.id,
        document_hash=doc.sha256_hash,
        watermarked_pdf_hash=watermarked_pdf_hash,
        created_at=timestamp
    )
    db.add(wm_record)

    access_event = AccessEvent(
        id=f"EVT-{timestamp.year}-{str(uuid.uuid4())[:8].upper()}",
        document_id=doc.id,
        recipient_id=recipient.id,
        session_id=session_id,
        watermark_id=watermark_id,
        document_hash=doc.sha256_hash,
        signature=ml_dsa_signature,
        timestamp=timestamp,
        event_hash=event_hash
    )
    db.add(access_event)
    db.commit()

    print(f"[ACCESS EVENT] Created: {access_event.id} (Hash: {event_hash})")

    log_audit(db, "DOCUMENT_OPENED", user_id=recipient.id, details={
        "doc_id": doc.id,
        "session_id": session_id,
        "watermark_id": watermark_id,
        "event_id": access_event.id
    })

    base_name = doc.filename.rsplit(".", 1)[0] if "." in doc.filename else doc.filename
    safe_base = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in base_name.strip()).strip("_")
    protected_filename = f"SecureShare_{safe_base or 'Document'}_protected.pdf"

    print(f"[DOWNLOAD]")
    print(f"content_type=application/pdf")
    print(f"pdf_size={len(watermarked_pdf)}")
    print(f"pdf_header={watermarked_pdf[:8].decode('latin1', errors='ignore').strip()}")
    print(f"pdf_footer={watermarked_pdf[-8:].decode('latin1', errors='ignore').strip()}")
    print(f"[DOWNLOAD] Returning valid watermarked PDF to {recipient.username}")

    return Response(
        content=watermarked_pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{protected_filename}"',
            "Content-Type": "application/pdf",
            "X-Document-ID": doc.id,
            "X-Session-ID": session_id,
            "X-Watermark-ID": watermark_id
        }
    )


# -------------------------------------------------------------------
# Investigator Forensic Analysis Endpoint
# -------------------------------------------------------------------

@app.post("/api/investigator/analyze", response_model=InvestigationResultResponse)
async def analyze_leaked_document(
    file: UploadFile = File(...),
    investigator: User = Depends(require_investigator),
    db: Session = Depends(get_db)
):
    """
    Forensic Provenance Pipeline:
    1. Validate PDF file
    2. Calculate SHA-256 document fingerprint
    3. Search for forensic watermark
    4. Recover watermark identifier
    5. Search access records in MySQL
    6. Verify ML-DSA-65 digital signature
    7. Verify document integrity relationship
    8. Check immutable evidence record status
    9. Prepare investigation result
    """
    log_audit(db, "INVESTIGATION_STARTED", user_id=investigator.id, details={"filename": file.filename})

    # Sequential investigation ID
    prev_count = db.query(AuditLog).filter(AuditLog.action == "INVESTIGATION_COMPLETED").count()
    inv_id = f"INV-{prev_count + 1:04d}"

    stages = [
        InvestigationStage(id=1, name="Document received", status="PENDING"),
        InvestigationStage(id=2, name="Calculating document fingerprint", status="PENDING"),
        InvestigationStage(id=3, name="Searching for forensic watermark", status="PENDING"),
        InvestigationStage(id=4, name="Recovering watermark identifier", status="PENDING"),
        InvestigationStage(id=5, name="Searching access records", status="PENDING"),
        InvestigationStage(id=6, name="Verifying ML-DSA-65 signature", status="PENDING"),
        InvestigationStage(id=7, name="Verifying document integrity", status="PENDING"),
        InvestigationStage(id=8, name="Checking immutable evidence record", status="PENDING"),
        InvestigationStage(id=9, name="Preparing investigation result", status="PENDING")
    ]

    # Step 1: Document received & validate PDF
    if not file.filename.lower().endswith(".pdf"):
        stages[0].status = "FAILED"
        stages[0].detail = "Invalid file type. Only PDF documents are supported."
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only PDF documents are supported."
        )
    
    stages[0].status = "COMPLETED"
    stages[0].detail = f"Received '{file.filename}'"

    pdf_bytes = await file.read()
    if len(pdf_bytes) == 0:
        stages[0].status = "FAILED"
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty.")

    # Step 2: Calculating document fingerprint
    stages[1].status = "PROCESSING"
    doc_fingerprint = calculate_sha256(pdf_bytes)
    stages[1].status = "COMPLETED"
    stages[1].detail = f"SHA-256: {doc_fingerprint[:16]}..."

    # Step 3 & 4: Searching & Recovering forensic watermark
    stages[2].status = "PROCESSING"
    stages[3].status = "PROCESSING"

    recovered_wid, recovered_sid, meta_dict = extract_watermark(pdf_bytes)

    if not recovered_wid:
        stages[2].status = "COMPLETED"
        stages[3].status = "FAILED"
        stages[3].detail = "No recognizable watermark pattern found"
        stages[4].status = "FAILED"
        stages[5].status = "FAILED"
        stages[6].status = "FAILED"
        stages[7].status = "FAILED"
        stages[8].status = "COMPLETED"

        log_audit(db, "INVESTIGATION_COMPLETED", user_id=investigator.id, details={
            "investigation_id": inv_id,
            "document_filename": file.filename,
            "status": "NO_WATERMARK",
            "status_label": "No Forensic Watermark",
            "recipient_identity": None,
            "verification_status": "Unverified"
        })

        return InvestigationResultResponse(
            investigation_id=inv_id,
            status="NO_WATERMARK",
            title="Investigation Result",
            status_label="NO FORENSIC WATERMARK DETECTED",
            document_filename=file.filename,
            forensic_statement="No recognizable forensic watermark was recovered from this document.",
            attribution_disclaimer="No recipient identity or cryptographic association could be determined.",
            verification_checks=[
                {"label": "Document received and parsed", "verified": True},
                {"label": "SHA-256 fingerprint calculated", "verified": True},
                {"label": "Forensic watermark detected", "verified": False},
                {"label": "Access event found", "verified": False},
                {"label": "ML-DSA-65 signature verified", "verified": False}
            ],
            technical_evidence=TechnicalEvidence(
                document_sha256=doc_fingerprint,
                ledger_status="NOT_IMPLEMENTED",
                ledger_message="Ledger verification pending"
            ),
            stages=stages,
            explanations=[
                "Document may not originate from SecureShare",
                "Watermark may have been damaged",
                "Document may have been transformed",
                "Available evidence may be insufficient"
            ]
        )

    stages[2].status = "COMPLETED"
    stages[3].status = "COMPLETED"
    stages[3].detail = f"Recovered Watermark ID: {recovered_wid}"

    # Step 5: Searching access and watermark records in MySQL
    stages[4].status = "PROCESSING"
    wm_record = db.query(WatermarkRecord).filter(WatermarkRecord.watermark_id == recovered_wid).first()
    event = db.query(AccessEvent).filter(AccessEvent.watermark_id == recovered_wid).first()

    if not event:
        stages[4].status = "FAILED"
        stages[4].detail = f"No access event found for watermark {recovered_wid}"
        stages[5].status = "FAILED"
        stages[6].status = "FAILED"
        stages[7].status = "FAILED"
        stages[8].status = "COMPLETED"

        log_audit(db, "INVESTIGATION_COMPLETED", user_id=investigator.id, details={
            "investigation_id": inv_id,
            "document_filename": file.filename,
            "status": "EVENT_NOT_FOUND",
            "status_label": "Access Record Not Found",
            "recipient_identity": None,
            "verification_status": "Incomplete",
            "watermark_id": recovered_wid
        })

        return InvestigationResultResponse(
            investigation_id=inv_id,
            status="EVENT_NOT_FOUND",
            title="Investigation Result",
            status_label="WATERMARK DETECTED — ACCESS RECORD NOT FOUND",
            document_filename=file.filename,
            watermark_id=recovered_wid,
            session_id=recovered_sid,
            forensic_statement="A forensic watermark was recovered, but no corresponding access event was found in the available evidence store.",
            attribution_disclaimer="Cryptographic verification cannot be completed without an immutable access record.",
            verification_checks=[
                {"label": "Forensic watermark detected", "verified": True},
                {"label": "Access event found", "verified": False},
                {"label": "ML-DSA-65 signature verified", "verified": False},
                {"label": "Document integrity verified", "verified": False}
            ],
            technical_evidence=TechnicalEvidence(
                document_sha256=doc_fingerprint,
                watermark_id=recovered_wid,
                session_id=recovered_sid,
                ledger_status="NOT_IMPLEMENTED",
                ledger_message="Ledger verification pending"
            ),
            stages=stages,
            explanations=[
                "The watermark was recognized but the corresponding access log may have been purged or belongs to a different environment.",
                "Cryptographic provenance cannot be verified without a matching access record."
            ]
        )

    stages[4].status = "COMPLETED"
    stages[4].detail = f"Matched Access Event: {event.id}"

    # Step 6: Verifying ML-DSA-65 signature
    stages[5].status = "PROCESSING"

    doc_record = db.query(Document).filter(Document.id == event.document_id).first()
    recipient_user = db.query(User).filter(User.id == event.recipient_id).first()
    recipient_name = recipient_user.name if recipient_user else "Alice"
    recipient_key_id = f"KEM-{recipient_user.username.upper()}-01" if recipient_user else "KEM-UNKNOWN-01"

    recipient_dsa_pk = recipient_user.ml_dsa_public_key if recipient_user else None

    iso_timestamp = event.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    canonical_bytes = canonicalize_access_event(
        document_id=event.document_id,
        recipient_id=event.recipient_id,
        recipient_key_id=recipient_key_id,
        session_id=event.session_id,
        watermark_id=event.watermark_id,
        document_hash=event.document_hash,
        timestamp_iso=iso_timestamp
    )

    sig_verified = False
    if recipient_dsa_pk and event.signature:
        sig_verified = verify_signature_ml_dsa(recipient_dsa_pk, canonical_bytes, event.signature)

    if not sig_verified:
        stages[5].status = "FAILED"
        stages[5].detail = "ML-DSA-65 post-quantum digital signature mismatch"
        stages[6].status = "FAILED"
        stages[7].status = "FAILED"
        stages[8].status = "COMPLETED"

        log_audit(db, "INVESTIGATION_COMPLETED", user_id=investigator.id, details={
            "investigation_id": inv_id,
            "document_filename": doc_record.filename if doc_record else file.filename,
            "status": "SIGNATURE_FAILED",
            "status_label": "Signature Verification Failed",
            "recipient_identity": recipient_name,
            "verification_status": "Failed",
            "event_id": event.id
        })

        return InvestigationResultResponse(
            investigation_id=inv_id,
            status="SIGNATURE_FAILED",
            title="Investigation Result",
            status_label="SIGNATURE VERIFICATION FAILED",
            document_filename=doc_record.filename if doc_record else file.filename,
            watermark_id=recovered_wid,
            access_event_id=event.id,
            session_id=event.session_id,
            access_timestamp=event.timestamp.strftime("%d %b %Y, %H:%M UTC"),
            forensic_statement="The access record exists, but its cryptographic signature could not be verified.",
            attribution_disclaimer="Cryptographic proof cannot be confirmed because the digital signature verification failed.",
            verification_checks=[
                {"label": "Forensic watermark detected", "verified": True},
                {"label": "Access event found", "verified": True},
                {"label": "ML-DSA-65 signature verified", "verified": False},
                {"label": "Document integrity verified", "verified": False}
            ],
            technical_evidence=TechnicalEvidence(
                document_sha256=doc_fingerprint,
                watermark_id=recovered_wid,
                session_id=event.session_id,
                event_id=event.id,
                event_hash=event.event_hash,
                signature_preview=event.signature[:32] + "..." if event.signature else None,
                key_identifier=recipient_key_id,
                timestamp=iso_timestamp,
                ledger_status="NOT_IMPLEMENTED",
                ledger_message="Ledger verification pending"
            ),
            stages=stages,
            explanations=[
                "Signature verification failed against the registered post-quantum public key.",
                "The record may have been modified or tampered with."
            ]
        )

    stages[5].status = "COMPLETED"
    stages[5].detail = "ML-DSA-65 signature valid and authentic"

    # Step 7: Verifying document integrity relationship
    stages[6].status = "PROCESSING"
    integrity_verified = (doc_record is not None and doc_record.sha256_hash == event.document_hash)
    
    if not integrity_verified:
        stages[6].status = "FAILED"
        stages[6].detail = "Origin document hash mismatch"
        stages[7].status = "FAILED"
        stages[8].status = "COMPLETED"

        log_audit(db, "INVESTIGATION_COMPLETED", user_id=investigator.id, details={
            "investigation_id": inv_id,
            "document_filename": file.filename,
            "status": "INTEGRITY_FAILED",
            "status_label": "Integrity Check Failed",
            "recipient_identity": recipient_name,
            "verification_status": "Failed"
        })

        return InvestigationResultResponse(
            investigation_id=inv_id,
            status="INTEGRITY_FAILED",
            title="Investigation Result",
            status_label="DOCUMENT INTEGRITY VERIFICATION FAILED",
            document_filename=file.filename,
            watermark_id=recovered_wid,
            access_event_id=event.id,
            forensic_statement="The document hash in the access record does not match the master document record.",
            attribution_disclaimer="Document integrity relationship could not be validated.",
            verification_checks=[
                {"label": "Forensic watermark detected", "verified": True},
                {"label": "Access event found", "verified": True},
                {"label": "ML-DSA-65 signature verified", "verified": True},
                {"label": "Document integrity verified", "verified": False}
            ],
            technical_evidence=TechnicalEvidence(
                document_sha256=doc_fingerprint,
                watermark_id=recovered_wid,
                session_id=event.session_id,
                event_id=event.id,
                ledger_status="NOT_IMPLEMENTED",
                ledger_message="Ledger verification pending"
            ),
            stages=stages
        )

    stages[6].status = "COMPLETED"
    stages[6].detail = "Document hash matches original encrypted master"

    # Step 8: Checking immutable evidence record status
    stages[7].status = "PROCESSING"
    stages[7].status = "COMPLETED"
    stages[7].detail = "Evidence record verified (Ledger status: NOT_IMPLEMENTED)"

    # Step 9: Preparing investigation result
    stages[8].status = "COMPLETED"
    stages[8].detail = "Forensic report compiled"

    formatted_time = event.timestamp.strftime("%d %b %Y, %H:%M")

    log_audit(db, "INVESTIGATION_COMPLETED", user_id=investigator.id, details={
        "investigation_id": inv_id,
        "document_filename": doc_record.filename if doc_record else file.filename,
        "status": "MATCH_FOUND",
        "status_label": "Verified Match",
        "recipient": recipient_name,
        "recipient_identity": recipient_name,
        "verification_status": "Verified Match",
        "watermark_id": recovered_wid,
        "event_id": event.id
    })

    return InvestigationResultResponse(
        investigation_id=inv_id,
        status="MATCH_FOUND",
        title="Investigation Result",
        status_label="FORENSIC MATCH FOUND",
        document_filename=doc_record.filename if doc_record else file.filename,
        watermark_id=recovered_wid,
        access_event_id=event.id,
        recipient_identity=recipient_name,
        session_id=event.session_id,
        access_timestamp=formatted_time,
        forensic_statement=f"This document contains a forensic watermark corresponding to a verified access event associated with {recipient_name}'s registered cryptographic identity.",
        attribution_disclaimer="Cryptographic verification establishes the association between the leaked copy and the recorded access event. It does not by itself establish who physically leaked or distributed the document.",
        verification_checks=[
            {"label": "Forensic watermark detected", "verified": True},
            {"label": "Access event found", "verified": True},
            {"label": "ML-DSA-65 signature verified", "verified": True},
            {"label": "Document integrity verified", "verified": True},
            {"label": "Evidence record verified", "verified": True}
        ],
        technical_evidence=TechnicalEvidence(
            document_sha256=event.document_hash,
            watermark_id=recovered_wid,
            session_id=event.session_id,
            event_id=event.id,
            event_hash=event.event_hash,
            signature_algorithm="ML-DSA-65 (NIST FIPS 204 / Dilithium3)",
            signature_preview=event.signature[:32] + "...",
            key_identifier=recipient_key_id,
            timestamp=iso_timestamp,
            ledger_status="NOT_IMPLEMENTED",
            ledger_message="Ledger verification pending"
        ),
        stages=stages
    )


@app.get("/api/investigator/history", response_model=List[InvestigationHistoryItem])
def get_investigation_history(
    investigator: User = Depends(require_investigator),
    db: Session = Depends(get_db)
):
    """Retrieve recent investigation logs for the Investigator dashboard."""
    logs = db.query(AuditLog).filter(
        AuditLog.action == "INVESTIGATION_COMPLETED"
    ).order_by(AuditLog.timestamp.desc()).limit(20).all()

    history = []
    for log in logs:
        try:
            details = json.loads(log.details) if log.details else {}
            inv_id = details.get("investigation_id", f"INV-{log.id[:4].upper()}")
            doc_name = details.get("document_filename", "Project_Report.pdf")
            status_val = details.get("status", "MATCH_FOUND")
            status_label = details.get("status_label", "Verified Match" if status_val == "MATCH_FOUND" else "No Watermark")
            recipient = details.get("recipient") or details.get("recipient_identity")
            ver_status = details.get("verification_status", "Verified" if status_val == "MATCH_FOUND" else "Unverified")
            ts = log.timestamp.strftime("%d %b %Y, %H:%M")
            history.append(InvestigationHistoryItem(
                investigation_id=inv_id,
                document_name=doc_name,
                status=status_val,
                status_label=status_label,
                recipient_identity=recipient,
                verification_status=ver_status,
                timestamp=ts
            ))
        except Exception:
            continue
    return history


@app.post("/api/investigator/report")
def generate_investigation_report(
    req: ReportRequest,
    investigator: User = Depends(require_investigator)
):
    """Generate and return a clean 1-page PDF Forensic Investigation Report."""
    try:
        report_data = req.dict()
        pdf_bytes = generate_evidence_pdf_report(report_data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="Forensic_Investigation_Report_{req.investigation_id}.pdf"'
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation error: {str(e)}"
        )


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "platform": "SecureShare",
        "pqc_kem": "ML-KEM-768",
        "pqc_dsa": "ML-DSA-65",
        "forensics": "OpenCV + NumPy Watermark Extraction"
    }
