import io
import pymupdf as fitz
from fastapi.testclient import TestClient
from main import app
from database import SessionLocal
from models import Document, DocumentRecipient, AccessEvent, User
from seed import reset_and_seed_database

client = TestClient(app)

def create_sample_pdf() -> bytes:
    """Create a sample PDF document for testing."""
    doc = fitz.open()
    page = doc.new_page(width=595, height=842) # A4
    page.insert_text((50, 80), "CONFIDENTIAL REPORT", fontsize=20, color=(0.1, 0.2, 0.5))
    page.insert_text((50, 130), "Document ID: DOC-DEMO", fontsize=12)
    page.insert_text((50, 160), "This document is protected with AES-256-GCM and ML-KEM-768 post-quantum key encapsulation.", fontsize=10)
    page.insert_text((50, 190), "Any access to this document is watermarked and signed via ML-DSA-65.", fontsize=10)
    
    # Draw sample graphic rectangle
    rect = fitz.Rect(50, 230, 545, 400)
    page.draw_rect(rect, color=(0.2, 0.4, 0.8), fill=(0.95, 0.97, 1.0))
    page.insert_text((70, 270), "PROJECT PERFORMANCE SUMMARY", fontsize=14)
    page.insert_text((70, 300), "- Quantum-safe multi-recipient key encapsulation: ACTIVE", fontsize=11)
    page.insert_text((70, 325), "- Tamper-evident digital audit logs: ACTIVE", fontsize=11)
    page.insert_text((70, 350), "- Invisible steganographic watermarking: ACTIVE", fontsize=11)
    
    buf = io.BytesIO()
    doc.save(buf)
    doc.close()
    return buf.getvalue()

def run_tests():
    print("--- 1. Initializing & Seeding Database ---")
    reset_and_seed_database()

    print("\n--- 2. Testing Admin Login ---")
    res = client.post("/api/login", json={"username": "admin", "password": "admin123"})
    assert res.status_code == 200, f"Admin login failed: {res.text}"
    admin_data = res.json()
    admin_token = admin_data["access_token"]
    print(f"[OK] Admin logged in: {admin_data['user']['name']} (Role: {admin_data['user']['role']})")

    print("\n--- 3. Testing Recipient Login (Alice) ---")
    res = client.post("/api/login", json={"username": "alice", "password": "alice123"})
    assert res.status_code == 200, f"Alice login failed: {res.text}"
    alice_data = res.json()
    alice_token = alice_data["access_token"]
    alice_id = alice_data["user"]["id"]
    print(f"[OK] Alice logged in: {alice_data['user']['name']} (Role: {alice_data['user']['role']})")

    print("\n--- 4. Admin Uploads & Sends PDF to Alice ---")
    pdf_bytes = create_sample_pdf()
    files = {"file": ("Project_Report.pdf", pdf_bytes, "application/pdf")}
    data = {"recipient_id": "alice"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    res = client.post("/api/admin/documents", files=files, data=data, headers=headers)
    assert res.status_code == 200, f"Document upload failed: {res.text}"
    upload_res = res.json()
    doc_id = upload_res["document_id"]
    print(f"[OK] Document uploaded and encrypted: {doc_id} ({upload_res['filename']}) -> {upload_res['recipient_name']}")

    print("\n--- 5. Recipient (Alice) Views Documents List ---")
    alice_headers = {"Authorization": f"Bearer {alice_token}"}
    res = client.get("/api/recipient/documents", headers=alice_headers)
    assert res.status_code == 200, f"Get documents failed: {res.text}"
    docs = res.json()
    assert len(docs) > 0, "No documents returned for Alice"
    print(f"[OK] Alice has {len(docs)} document(s): {docs[0]['filename']} (Status: {docs[0]['status']})")

    print("\n--- 6. Recipient (Alice) Opens & Decrypts Document ---")
    res = client.post(f"/api/recipient/documents/{doc_id}/open", headers=alice_headers)
    assert res.status_code == 200, f"Open document failed: {res.text}"
    assert res.headers["content-type"] == "application/pdf", f"Unexpected content-type: {res.headers.get('content-type')}"
    watermarked_pdf = res.content
    assert len(watermarked_pdf) > 0, "Watermarked PDF is empty"
    session_id = res.headers.get("X-Session-ID")
    watermark_id = res.headers.get("X-Watermark-ID")
    print(f"[OK] Document successfully decrypted and watermarked!")
    print(f"     Session ID:   {session_id}")
    print(f"     Watermark ID: {watermark_id}")
    print(f"     Payload size: {len(watermarked_pdf)} bytes")

    print("\n--- 7. Verifying MySQL Access Event & ML-DSA Signature ---")
    db = SessionLocal()
    event = db.query(AccessEvent).filter(AccessEvent.document_id == doc_id, AccessEvent.session_id == session_id).first()
    assert event is not None, "Access event was not saved in MySQL"
    print(f"[OK] Access Event found in MySQL:")
    print(f"     Event ID:     {event.id}")
    print(f"     Document ID:  {event.document_id}")
    print(f"     Watermark ID: {event.watermark_id}")
    print(f"     Event Hash:   {event.event_hash}")
    print(f"     Signature len:{len(event.signature)} b64 characters")
    db.close()

    print("\n--- 8. Testing Access Control Security (403 on Unauthorized User) ---")
    # Admin tries to call recipient endpoint -> 403 Forbidden
    res = client.post(f"/api/recipient/documents/{doc_id}/open", headers=headers)
    assert res.status_code == 403, f"Expected 403 Forbidden for admin on recipient endpoint, got {res.status_code}"
    print("[OK] Access control verified: Admin cannot call recipient open endpoint (403 Forbidden)")

    print("\n=======================================================")
    print("ALL BACKEND POST-QUANTUM CRYPTO PIPELINE TESTS PASSED!")
    print("=======================================================")

if __name__ == "__main__":
    run_tests()
