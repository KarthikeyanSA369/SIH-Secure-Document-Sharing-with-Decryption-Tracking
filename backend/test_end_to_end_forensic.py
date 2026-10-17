import io
import json
import uuid
import datetime
import pymupdf as fitz
from fastapi.testclient import TestClient
from main import app
from database import SessionLocal
from seed import ensure_seed_users
from models import AccessEvent, Document, DocumentRecipient, User, AuditLog
from services.watermark_service import extract_watermark, embed_watermark, generate_watermark_id
from crypto.ml_dsa import sign_access_event_ml_dsa, generate_ml_dsa_keypair
from crypto.access_event import canonicalize_access_event

client = TestClient(app)

def create_test_pdf(title: str = "CONFIDENTIAL PROJECT REPORT") -> bytes:
    """Generate a clean test PDF."""
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)
    page.insert_text((50, 80), title, fontsize=18, color=(0.1, 0.2, 0.5))
    page.insert_text((50, 120), "Author: SecureShare Engineering Team", fontsize=11)
    page.insert_text((50, 150), "This document is confidential and subject to forensic distribution controls.", fontsize=10)
    buf = io.BytesIO()
    doc.save(buf)
    doc.close()
    return buf.getvalue()

def test_full_forensic_lifecycle():
    print("\n=======================================================")
    print("RUNNING COMPREHENSIVE END-TO-END FORENSIC AUDIT & TESTS")
    print("=======================================================")

    db = SessionLocal()
    ensure_seed_users()

    # -------------------------------------------------------------
    # 1. Admin Login & Upload
    # -------------------------------------------------------------
    print("\n[Step 1] Admin Authentication")
    res = client.post("/api/login", json={"username": "admin", "password": "admin123"})
    assert res.status_code == 200, f"Admin login failed: {res.text}"
    admin_token = res.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    print("  [OK] Admin logged in successfully")

    print("\n[Step 2] Admin Uploads & Encrypts PDF (AES-256-GCM + ML-KEM-768 for Alice)")
    pdf_bytes = create_test_pdf("FINANCIAL PROJECTIONS Q4")
    files = {"file": ("Project_Report.pdf", pdf_bytes, "application/pdf")}
    data = {"recipient_id": "alice"}
    res = client.post("/api/admin/documents", files=files, data=data, headers=admin_headers)
    assert res.status_code == 200, f"Document upload failed: {res.text}"
    doc_id = res.json()["document_id"]
    print(f"  [OK] Document created & encrypted: {doc_id} -> Recipient: Alice")

    # -------------------------------------------------------------
    # 2. Recipient Login & Opening (Decapsulation + Decryption + Watermarking)
    # -------------------------------------------------------------
    print("\n[Step 3] Alice Authentication")
    res = client.post("/api/login", json={"username": "alice", "password": "alice123"})
    assert res.status_code == 200, f"Alice login failed: {res.text}"
    alice_token = res.json()["access_token"]
    alice_headers = {"Authorization": f"Bearer {alice_token}"}
    print("  [OK] Alice logged in successfully")

    print("\n[Step 4] Alice Opens Document (ML-KEM Decapsulation + AES Decryption + Watermark)")
    res = client.post(f"/api/recipient/documents/{doc_id}/open", headers=alice_headers)
    assert res.status_code == 200, f"Open document failed: {res.text}"
    assert res.headers["content-type"] == "application/pdf"
    watermarked_pdf_bytes_1 = res.content
    wid_1 = res.headers.get("X-Watermark-ID")
    sid_1 = res.headers.get("X-Session-ID")
    assert wid_1 is not None and wid_1.startswith("WM-")
    assert sid_1 is not None and sid_1.startswith("SES-")
    print(f"  [OK] Watermarked PDF generated and streamed ({len(watermarked_pdf_bytes_1)} bytes)")
    print(f"    • Session ID:   {sid_1}")
    print(f"    • Watermark ID: {wid_1}")

    # -------------------------------------------------------------
    # 3. Direct Watermark Extraction Verification from PDF Bytes
    # -------------------------------------------------------------
    print("\n[Step 5] Direct Verification: Extracting Watermark from Received PDF Bytes")
    extracted_wid, extracted_sid, meta_dict = extract_watermark(watermarked_pdf_bytes_1)
    assert extracted_wid == wid_1, f"Extracted watermark ({extracted_wid}) != Generated ({wid_1})"
    assert extracted_sid == sid_1, f"Extracted session ({extracted_sid}) != Generated ({sid_1})"
    print(f"  [OK] Exact watermark extraction match confirmed: {extracted_wid} == {wid_1}")

    # -------------------------------------------------------------
    # 4. Session Uniqueness: Same Document + Same Recipient -> Different Watermark
    # -------------------------------------------------------------
    print("\n[Step 6] Verifying Session Uniqueness (Second Access by Alice)")
    res2 = client.post(f"/api/recipient/documents/{doc_id}/open", headers=alice_headers)
    assert res2.status_code == 200
    wid_2 = res2.headers.get("X-Watermark-ID")
    sid_2 = res2.headers.get("X-Session-ID")
    assert wid_1 != wid_2, f"Watermark IDs must be unique per session: {wid_1} == {wid_2}"
    assert sid_1 != sid_2, f"Session IDs must be unique: {sid_1} == {sid_2}"
    print(f"  [OK] Session uniqueness verified: Session 1 ({wid_1}) != Session 2 ({wid_2})")

    # -------------------------------------------------------------
    # 5. Investigator Login & Leaked Document Analysis
    # -------------------------------------------------------------
    print("\n[Step 7] Investigator Authentication")
    res = client.post("/api/login", json={"username": "investigator", "password": "investigator123", "role": "INVESTIGATOR"})
    assert res.status_code == 200
    inv_token = res.json()["access_token"]
    inv_headers = {"Authorization": f"Bearer {inv_token}"}
    print("  [OK] Investigator logged in successfully")

    print("\n[Step 8] Investigator Analyzes Leaked Watermarked PDF")
    leaked_file = {"file": ("Leaked_Project_Report.pdf", watermarked_pdf_bytes_1, "application/pdf")}
    res = client.post("/api/investigator/analyze", files=leaked_file, headers=inv_headers)
    assert res.status_code == 200, f"Analyze endpoint failed: {res.text}"
    inv_result = res.json()

    print(f"  [OK] Status:              {inv_result['status_label']}")
    print(f"  [OK] Matched Recipient:   {inv_result['recipient_identity']}")
    print(f"  [OK] Watermark ID:        {inv_result['watermark_id']}")
    print(f"  [OK] Access Event ID:     {inv_result['access_event_id']}")
    print(f"  [OK] Signature Algorithm: {inv_result['technical_evidence']['signature_algorithm']}")
    print(f"  [OK] Ledger Status:       {inv_result['technical_evidence']['ledger_status']} ({inv_result['technical_evidence']['ledger_message']})")

    assert inv_result["status"] == "MATCH_FOUND"
    assert inv_result["status_label"] == "FORENSIC MATCH FOUND"
    assert inv_result["recipient_identity"] == "Alice"
    assert inv_result["watermark_id"] == wid_1
    assert inv_result["technical_evidence"]["ledger_status"] == "NOT_IMPLEMENTED"

    # -------------------------------------------------------------
    # 6. Negative Tests
    # -------------------------------------------------------------
    print("\n[Step 9] Negative Test A: Clean Unwatermarked Document")
    clean_file = {"file": ("Clean_External_Doc.pdf", pdf_bytes, "application/pdf")}
    res = client.post("/api/investigator/analyze", files=clean_file, headers=inv_headers)
    assert res.status_code == 200
    assert res.json()["status"] == "NO_WATERMARK"
    print("  [OK] Returned status: NO_WATERMARK as expected")

    print("\n[Step 10] Negative Test B: Watermark Not Found in Access Events")
    # Embed an arbitrary unregistered watermark
    unregistered_wid = "WM-FA999999"
    unregistered_pdf = embed_watermark(pdf_bytes, watermark_id=unregistered_wid, session_id="SES-00000")
    fake_file = {"file": ("Unregistered_WM.pdf", unregistered_pdf, "application/pdf")}
    res = client.post("/api/investigator/analyze", files=fake_file, headers=inv_headers)
    assert res.status_code == 200
    assert res.json()["status"] == "EVENT_NOT_FOUND"
    print("  [OK] Returned status: EVENT_NOT_FOUND as expected")

    print("\n[Step 11] Negative Test C: Modified / Tampered ML-DSA-65 Signature")
    # Temporarily tamper the signature in database for wid_1
    event_record = db.query(AccessEvent).filter(AccessEvent.watermark_id == wid_1).first()
    original_sig = event_record.signature
    event_record.signature = "TAMPERED_INVALID_BASE64_SIGNATURE_PAYLOAD_XX=="
    db.commit()

    res = client.post("/api/investigator/analyze", files=leaked_file, headers=inv_headers)
    assert res.status_code == 200
    assert res.json()["status"] == "SIGNATURE_FAILED"
    print("  [OK] Returned status: SIGNATURE_FAILED as expected upon signature tampering")

    # Restore signature
    event_record.signature = original_sig
    db.commit()

    print("\n[Step 12] Negative Test D: Role & Access Control Verification")
    # Non-investigator tries to call analyze endpoint
    res = client.post("/api/investigator/analyze", files=leaked_file, headers=alice_headers)
    assert res.status_code == 403
    print("  [OK] Recipient denied access to /api/investigator/analyze (403 Forbidden)")

    # Investigator tries to call recipient endpoint
    res = client.post(f"/api/recipient/documents/{doc_id}/open", headers=inv_headers)
    assert res.status_code == 403
    print("  [OK] Investigator denied access to /api/recipient/documents/.../open (403 Forbidden)")

    # -------------------------------------------------------------
    # 7. Audit Logging Verification
    # -------------------------------------------------------------
    print("\n[Step 13] Verifying System Audit Logs")
    logs = db.query(AuditLog).all()
    actions = [l.action for l in logs]
    assert "LOGIN" in actions
    assert "DOCUMENT_UPLOADED" in actions
    assert "DOCUMENT_SHARED" in actions
    assert "DOCUMENT_OPENED" in actions
    assert "INVESTIGATION_STARTED" in actions
    assert "INVESTIGATION_COMPLETED" in actions
    print(f"  [OK] System recorded {len(logs)} audit entries covering all expected actions")

    db.close()
    print("\n=======================================================")
    print("ALL POSITIVE & NEGATIVE FORENSIC PROVENANCE TESTS PASSED!")
    print("=======================================================")

if __name__ == "__main__":
    test_full_forensic_lifecycle()
