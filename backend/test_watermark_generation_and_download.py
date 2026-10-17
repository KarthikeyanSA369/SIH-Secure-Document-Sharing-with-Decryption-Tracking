import os
import io
import time
import hashlib
import pymupdf as fitz
from fastapi.testclient import TestClient
from main import app
from database import SessionLocal
from models import Document, DocumentRecipient, AccessEvent, User
from seed import reset_and_seed_database
from services.watermark_service import extract_watermark, generate_watermark_id, embed_watermark
from crypto.ml_dsa import verify_signature_ml_dsa
from crypto.access_event import canonicalize_access_event

client = TestClient(app)

def create_sample_pdf() -> bytes:
    """Create a sample PDF document for testing."""
    doc = fitz.open()
    page = doc.new_page(width=595, height=842) # A4
    page.insert_text((50, 80), "CONFIDENTIAL PROJECT REPORT", fontsize=18, color=(0.1, 0.2, 0.5))
    page.insert_text((50, 110), "Classification: RESTRICTED DISTRIBUTION", fontsize=11, color=(0.8, 0.1, 0.1))
    page.draw_line((50, 125), (545, 125), color=(0.7, 0.7, 0.7), width=1)
    
    rect = fitz.Rect(50, 140, 545, 260)
    page.draw_rect(rect, color=(0.2, 0.4, 0.8), fill=(0.95, 0.97, 1.0))
    page.insert_text((70, 170), "SECURE FORENSIC PROVENANCE SYSTEM", fontsize=13)
    page.insert_text((70, 195), "- Symmetric Protection: AES-256-GCM authenticated encryption", fontsize=10)
    page.insert_text((70, 215), "- Post-Quantum Key Exchange: ML-KEM-768 (Kyber768)", fontsize=10)
    page.insert_text((70, 235), "- Post-Quantum Authentication: ML-DSA-65 (Dilithium3)", fontsize=10)
    page.insert_text((70, 255), "- Steganographic Watermark: OpenCV/NumPy imperceptible raster embedding", fontsize=10)
    
    buf = io.BytesIO()
    doc.save(buf)
    doc.close()
    return buf.getvalue()

def run_tests():
    print("=" * 70)
    print("RUNNING COMPREHENSIVE FORENSIC WATERMARK & DOWNLOAD TEST SUITE")
    print("=" * 70)

    # 1. Reset and Seed Database
    print("\n[Setup] Initializing & Seeding Database with PQ Keypairs...")
    reset_and_seed_database()

    # 2. Authenticate
    admin_login = client.post("/api/login", json={"username": "admin", "password": "admin123"}).json()
    admin_token = admin_login["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    alice_login = client.post("/api/login", json={"username": "alice", "password": "alice123"}).json()
    alice_token = alice_login["access_token"]
    alice_headers = {"Authorization": f"Bearer {alice_token}"}
    alice_id = alice_login["user"]["id"]
    alice_dsa_pk = alice_login["user"]["ml_dsa_public_key"]

    inv_login = client.post("/api/login", json={"username": "investigator", "password": "investigator123"}).json()
    inv_token = inv_login["access_token"]
    inv_headers = {"Authorization": f"Bearer {inv_token}"}

    # 3. Admin Uploads Document
    raw_pdf = create_sample_pdf()
    files = {"file": ("Project_Report.pdf", raw_pdf, "application/pdf")}
    data = {"recipient_id": "alice"}
    upload_res = client.post("/api/admin/documents", files=files, data=data, headers=admin_headers).json()
    doc_id = upload_res["document_id"]
    print(f"[Setup] Admin created and encrypted {doc_id} for Alice")

    # -------------------------------------------------------------
    # TEST 1 — REAL WATERMARKED DOWNLOAD
    # -------------------------------------------------------------
    print("\n" + "-" * 70)
    print("TEST 1: Real Watermarked Download & Cryptographic Provenance")
    print("-" * 70)

    # Alice opens/downloads document through real API
    open_res = client.post(f"/api/recipient/documents/{doc_id}/open", headers=alice_headers)
    assert open_res.status_code == 200, f"Open failed: {open_res.text}"
    assert open_res.headers["content-type"] == "application/pdf"
    
    downloaded_bytes = open_res.content
    assert len(downloaded_bytes) > 0, "Downloaded PDF bytes are empty"
    
    header_sid = open_res.headers.get("X-Session-ID")
    header_wid = open_res.headers.get("X-Watermark-ID")
    assert header_sid is not None and header_wid is not None
    assert header_wid.startswith("WM-"), f"Invalid watermark format: {header_wid}"
    assert header_sid.startswith("SES-"), f"Invalid session format: {header_sid}"

    # Save exact response bytes to downloaded_alice.pdf
    with open("downloaded_alice.pdf", "wb") as f:
        f.write(downloaded_bytes)
    print(f"[TEST 1] Saved exact response bytes ({len(downloaded_bytes)} bytes) to 'downloaded_alice.pdf'")

    # Extract watermark from downloaded_alice.pdf
    with open("downloaded_alice.pdf", "rb") as f:
        saved_file_bytes = f.read()

    extracted_wid, extracted_sid, meta = extract_watermark(saved_file_bytes)
    print(f"[TEST 1] Extracted Watermark ID: {extracted_wid}")
    print(f"[TEST 1] Extracted Session ID:   {extracted_sid}")
    
    assert extracted_wid is not None, "Watermark extraction failed from downloaded_alice.pdf"
    assert extracted_wid == header_wid, f"Extracted {extracted_wid} != header {header_wid}"
    assert extracted_sid == header_sid, f"Extracted {extracted_sid} != header {header_sid}"
    print("[TEST 1] [PASS] Watermark extraction from exact saved PDF succeeded!")

    # Verify Access Event exists in MySQL and ML-DSA signature verifies
    db = SessionLocal()
    event = db.query(AccessEvent).filter(AccessEvent.watermark_id == extracted_wid).first()
    assert event is not None, f"Access event for watermark {extracted_wid} not found in MySQL"
    print(f"[TEST 1] Found Access Event in MySQL: {event.id}")
    print(f"[TEST 1] Access Event Hash: {event.event_hash}")

    # Verify ML-DSA signature with Alice's public key
    iso_ts = event.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    canonical_bytes = canonicalize_access_event(
        document_id=event.document_id,
        recipient_id=event.recipient_id,
        recipient_key_id=f"KEM-ALICE-01",
        session_id=event.session_id,
        watermark_id=event.watermark_id,
        document_hash=event.document_hash,
        timestamp_iso=iso_ts
    )
    sig_valid = verify_signature_ml_dsa(alice_dsa_pk, canonical_bytes, event.signature)
    assert sig_valid is True, "ML-DSA signature verification failed with Alice's public key"
    print("[TEST 1] [PASS] ML-DSA-65 digital signature verified against Alice's public key!")
    db.close()

    # -------------------------------------------------------------
    # TEST 2 — MULTIPLE ALICE OPENS (Distinct Watermarks)
    # -------------------------------------------------------------
    print("\n" + "-" * 70)
    print("TEST 2: Multiple Alice Opens (Distinct Forensic Copies)")
    print("-" * 70)

    # First access (already done in TEST 1)
    wid_1 = extracted_wid
    sid_1 = extracted_sid

    time.sleep(1)
    # Second access
    open_res_2 = client.post(f"/api/recipient/documents/{doc_id}/open", headers=alice_headers)
    assert open_res_2.status_code == 200
    copy2_bytes = open_res_2.content
    wid_2 = open_res_2.headers.get("X-Watermark-ID")
    sid_2 = open_res_2.headers.get("X-Session-ID")

    with open("alice_copy_2.pdf", "wb") as f:
        f.write(copy2_bytes)

    extracted_wid_2, extracted_sid_2, _ = extract_watermark(copy2_bytes)
    print(f"[TEST 2] Access 1: Watermark={wid_1}, Session={sid_1}")
    print(f"[TEST 2] Access 2: Watermark={wid_2}, Session={sid_2}")

    assert wid_1 != wid_2, f"Watermark IDs must be unique! {wid_1} == {wid_2}"
    assert sid_1 != sid_2, f"Session IDs must be unique! {sid_1} == {sid_2}"
    assert extracted_wid_2 == wid_2, "Extracted watermark 2 mismatch"
    print("[TEST 2] [PASS] Multiple accesses produced distinct, extractable watermarks and sessions!")

    # -------------------------------------------------------------
    # TEST 3 — INVESTIGATOR FLOW (Upload downloaded_alice.pdf)
    # -------------------------------------------------------------
    print("\n" + "-" * 70)
    print("TEST 3: Investigator Flow on Downloaded PDF")
    print("-" * 70)

    with open("downloaded_alice.pdf", "rb") as f:
        upload_leaked = f.read()

    files_inv = {"file": ("Project_Report_SECURE_COPY.pdf", upload_leaked, "application/pdf")}
    inv_res = client.post("/api/investigator/analyze", files=files_inv, headers=inv_headers).json()

    print(f"[TEST 3] Status:             {inv_res['status']} ({inv_res['status_label']})")
    print(f"[TEST 3] Recipient Identity: {inv_res.get('recipient_identity')}")
    print(f"[TEST 3] Watermark ID:       {inv_res.get('watermark_id')}")
    print(f"[TEST 3] Access Event ID:    {inv_res.get('access_event_id')}")

    assert inv_res["status"] == "MATCH_FOUND", f"Expected MATCH_FOUND, got {inv_res['status']}"
    assert inv_res["recipient_identity"] == "Alice", f"Expected Alice, got {inv_res.get('recipient_identity')}"
    assert inv_res["watermark_id"] == wid_1
    
    dsa_chk = next((c for c in inv_res["verification_checks"] if "ML-DSA-65" in c["label"]), None)
    assert dsa_chk is not None and dsa_chk["verified"] is True
    print("[TEST 3] [PASS] Forensic match verified: Alice identified via registered ML-DSA-65 identity!")

    # -------------------------------------------------------------
    # TEST 4 — CLEAN UNWATERMARKED PDF
    # -------------------------------------------------------------
    print("\n" + "-" * 70)
    print("TEST 4: Clean Unwatermarked PDF to Investigator")
    print("-" * 70)

    clean_files = {"file": ("Clean_Original.pdf", raw_pdf, "application/pdf")}
    clean_res = client.post("/api/investigator/analyze", files=clean_files, headers=inv_headers).json()

    print(f"[TEST 4] Status: {clean_res['status']} ({clean_res['status_label']})")
    assert clean_res["status"] == "NO_WATERMARK"
    assert clean_res.get("recipient_identity") is None
    print("[TEST 4] [PASS] Clean PDF correctly returned NO_WATERMARK without identifying any recipient!")

    # -------------------------------------------------------------
    # TEST 5 — UNKNOWN / UNREGISTERED WATERMARK
    # -------------------------------------------------------------
    print("\n" + "-" * 70)
    print("TEST 5: Unregistered Watermark (Watermark Exists, No Access Event)")
    print("-" * 70)

    unknown_wid = "WM-UNKNOWN99"
    unknown_sid = "SES-99999"
    unknown_wm_pdf = embed_watermark(raw_pdf, unknown_wid, unknown_sid, "DOC-999", "USER-UNKNOWN")

    unregistered_files = {"file": ("Unknown_WM.pdf", unknown_wm_pdf, "application/pdf")}
    unreg_res = client.post("/api/investigator/analyze", files=unregistered_files, headers=inv_headers).json()

    print(f"[TEST 5] Status: {unreg_res['status']} ({unreg_res['status_label']})")
    assert unreg_res["status"] == "EVENT_NOT_FOUND"
    assert unreg_res["watermark_id"] == unknown_wid
    print("[TEST 5] [PASS] Unregistered watermark correctly returned EVENT_NOT_FOUND!")

    # -------------------------------------------------------------
    # TEST 6 — TAMPERED ML-DSA-65 SIGNATURE
    # -------------------------------------------------------------
    print("\n" + "-" * 70)
    print("TEST 6: Tampered ML-DSA-65 Signature Detection")
    print("-" * 70)

    db = SessionLocal()
    target_event = db.query(AccessEvent).filter(AccessEvent.watermark_id == wid_1).first()
    assert target_event is not None
    original_signature = target_event.signature
    
    # Tamper the signature by flipping characters
    tampered_sig = ("AAAA" if not original_signature.startswith("AAAA") else "BBBB") + original_signature[4:]
    target_event.signature = tampered_sig
    db.commit()
    db.close()
    print("[TEST 6] Modified signature in MySQL access_events")

    # Analyze again with Investigator
    files_tamper = {"file": ("Tampered_Signature.pdf", upload_leaked, "application/pdf")}
    tamper_res = client.post("/api/investigator/analyze", files=files_tamper, headers=inv_headers).json()

    print(f"[TEST 6] Status: {tamper_res['status']} ({tamper_res['status_label']})")
    assert tamper_res["status"] == "SIGNATURE_FAILED"
    
    sig_check = next((c for c in tamper_res["verification_checks"] if "ML-DSA-65" in c["label"]), None)
    assert sig_check is not None and sig_check["verified"] is False
    print("[TEST 6] [PASS] Tampered signature detected: SIGNATURE_FAILED returned!")

    # Restore signature
    db = SessionLocal()
    target_event = db.query(AccessEvent).filter(AccessEvent.watermark_id == wid_1).first()
    target_event.signature = original_signature
    db.commit()
    db.close()

    print("\n" + "=" * 70)
    print("ALL 6 CRITICAL TESTS PASSED 100% SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()
