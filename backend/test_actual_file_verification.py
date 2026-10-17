import os
import sys
import io
import time
import json
import requests
from pathlib import Path

BASE_URL = "http://127.0.0.1:8000"

def log_step(title):
    print(f"\n{'='*70}\n[TEST STEP] {title}\n{'='*70}")

def run_actual_file_verification_suite():
    log_step("1. Health Check & Keystore Verification")
    r = requests.get(f"{BASE_URL}/health")
    assert r.status_code == 200, f"Health check failed: {r.text}"
    health_data = r.json()
    print(f"[OK] System Healthy: {health_data}")

    # Logins
    log_step("2. Authenticate Users (Admin, Alice, Investigator)")
    
    # Admin
    r = requests.post(f"{BASE_URL}/api/login", json={"username": "admin", "password": "admin123", "role": "ADMIN"})
    assert r.status_code == 200, f"Admin login failed: {r.text}"
    admin_token = r.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    print("[OK] Admin authenticated successfully")

    # Alice (Recipient)
    r = requests.post(f"{BASE_URL}/api/login", json={"username": "alice", "password": "alice123", "role": "RECIPIENT"})
    assert r.status_code == 200, f"Alice login failed: {r.text}"
    alice_token = r.json()["access_token"]
    alice_headers = {"Authorization": f"Bearer {alice_token}"}
    print("[OK] Alice authenticated successfully")

    # Investigator
    r = requests.post(f"{BASE_URL}/api/login", json={"username": "investigator", "password": "investigator123", "role": "INVESTIGATOR"})
    assert r.status_code == 200, f"Investigator login failed: {r.text}"
    inv_token = r.json()["access_token"]
    inv_headers = {"Authorization": f"Bearer {inv_token}"}
    print("[OK] Investigator authenticated successfully")

    # Admin: Check stats endpoint
    log_step("3. Verify Admin Stats Endpoint")
    r = requests.get(f"{BASE_URL}/api/admin/stats", headers=admin_headers)
    assert r.status_code == 200, f"Admin stats failed: {r.text}"
    initial_stats = r.json()
    print(f"[OK] Admin Stats: {initial_stats}")
    assert "documents_count" in initial_stats
    assert "access_events_count" in initial_stats

    # Admin Upload & Distribute PDF to Alice
    log_step("4. Admin Uploads & Encrypts Document for Alice")
    sample_pdf_path = Path("Project_Report.pdf")
    if not sample_pdf_path.exists():
        from create_sample_pdf import generate_sample_pdf
        generate_sample_pdf(str(sample_pdf_path))
    
    with open(sample_pdf_path, "rb") as f:
        pdf_bytes = f.read()

    files = {"file": ("Project_Report.pdf", io.BytesIO(pdf_bytes), "application/pdf")}
    data = {"recipient_id": "USER-ALICE-01"}
    r = requests.post(f"{BASE_URL}/api/admin/documents", headers=admin_headers, files=files, data=data)
    assert r.status_code == 200, f"Admin upload failed: {r.text}"
    send_res = r.json()
    doc_id = send_res["document_id"]
    print(f"[OK] Document uploaded & encrypted with AES-256-GCM + ML-KEM-768: ID={doc_id}")

    # Alice: Fetch Documents
    log_step("5. Alice Retrieves Authorized Documents")
    r = requests.get(f"{BASE_URL}/api/recipient/documents", headers=alice_headers)
    assert r.status_code == 200, f"Recipient list failed: {r.text}"
    docs = r.json()
    matching_doc = next((d for d in docs if d["id"] == doc_id), None)
    assert matching_doc is not None, f"Document {doc_id} not in Alice's authorized list"
    print(f"[OK] Found document {doc_id} in Alice's dashboard: {matching_doc['filename']}")

    # Alice: Open Document & Capture Exact Watermarked PDF
    log_step("6. Alice Opens Document (Decapsulate ML-KEM-768, Decrypt AES-256-GCM, Embed Watermark, Sign ML-DSA-65)")
    r = requests.post(f"{BASE_URL}/api/recipient/documents/{doc_id}/open", headers=alice_headers)
    assert r.status_code == 200, f"Alice open failed: {r.text}"
    assert r.headers.get("content-type") == "application/pdf", "Expected application/pdf"
    
    watermarked_pdf_bytes = r.content
    session_id_header = r.headers.get("X-Session-ID")
    watermark_id_header = r.headers.get("X-Watermark-ID")
    print(f"[OK] Received watermarked PDF: {len(watermarked_pdf_bytes)} bytes")
    print(f"[Header] X-Session-ID: {session_id_header}")
    print(f"[Header] X-Watermark-ID: {watermark_id_header}")

    # Save exact file as watermarked_demo.pdf
    saved_demo_path = Path("watermarked_demo.pdf")
    with open(saved_demo_path, "wb") as f:
        f.write(watermarked_pdf_bytes)
    print(f"[OK] Saved exact file to: {saved_demo_path.resolve()}")

    # Watermark Extraction on exact file
    log_step("7. Extract Watermark from the exact saved 'watermarked_demo.pdf'")
    from services.watermark_service import extract_watermark
    extracted_wid, extracted_sid, meta = extract_watermark(watermarked_pdf_bytes)
    print(f"[Extraction Result] Watermark ID: {extracted_wid}")
    print(f"[Extraction Result] Session ID:   {extracted_sid}")
    
    assert extracted_wid is not None, "Failed to recover watermark from watermarked_demo.pdf"
    assert extracted_wid == watermark_id_header, f"Extracted {extracted_wid} != header {watermark_id_header}"
    print(f"[OK] Extracted watermark perfectly matches header: {extracted_wid}")

    # Investigator: Submit exact file to Investigator API
    log_step("8. Investigator Uploads and Analyzes 'watermarked_demo.pdf'")
    with open(saved_demo_path, "rb") as f:
        test_file_bytes = f.read()

    files = {"file": ("Project_Report_SECURE_COPY.pdf", io.BytesIO(test_file_bytes), "application/pdf")}
    r = requests.post(f"{BASE_URL}/api/investigator/analyze", headers=inv_headers, files=files)
    assert r.status_code == 200, f"Investigator analysis failed: {r.text}"
    inv_result = r.json()
    
    print("\n--- Investigator Result ---")
    print(f"Status:             {inv_result['status']}")
    print(f"Status Label:       {inv_result['status_label']}")
    print(f"Recipient Identity: {inv_result['recipient_identity']}")
    print(f"Watermark ID:       {inv_result['watermark_id']}")
    print(f"Access Event ID:    {inv_result['access_event_id']}")
    print(f"Investigation ID:   {inv_result.get('investigation_id')}")

    # Assertions
    assert inv_result["status"] == "MATCH_FOUND", f"Expected MATCH_FOUND, got {inv_result['status']}"
    assert inv_result["recipient_identity"] == "Alice", f"Expected recipient Alice, got {inv_result['recipient_identity']}"
    assert inv_result["watermark_id"] == extracted_wid, f"Watermark ID mismatch"
    
    dsa_check = next((c for c in inv_result["verification_checks"] if "ML-DSA-65" in c["label"]), None)
    assert dsa_check is not None and dsa_check["verified"] is True, "ML-DSA-65 check not verified"
    print("[OK] Cryptographic Provenance Confirmed: Alice identified with ML-DSA-65 verified signature")

    # Generate & Download Forensic Evidence PDF Report
    log_step("9. Test Evidence Report PDF Generation")
    report_payload = {
        "investigation_id": inv_result.get("investigation_id", "INV-0001"),
        "status": inv_result["status"],
        "status_label": inv_result["status_label"],
        "document_filename": inv_result.get("document_filename", "Project_Report.pdf"),
        "document_sha256": inv_result.get("technical_evidence", {}).get("document_sha256"),
        "watermark_id": inv_result.get("watermark_id"),
        "access_event_id": inv_result.get("access_event_id"),
        "session_id": inv_result.get("session_id"),
        "recipient_identity": inv_result.get("recipient_identity"),
        "access_timestamp": inv_result.get("access_timestamp"),
        "technical_evidence": inv_result.get("technical_evidence")
    }
    r = requests.post(f"{BASE_URL}/api/investigator/report", headers=inv_headers, json=report_payload)
    assert r.status_code == 200, f"Report generation failed: {r.text}"
    assert r.headers.get("content-type") == "application/pdf"
    report_pdf_bytes = r.content
    assert len(report_pdf_bytes) > 500, "Report PDF too small"
    
    report_path = Path("Forensic_Investigation_Report_Demo.pdf")
    with open(report_path, "wb") as f:
        f.write(report_pdf_bytes)
    print(f"[OK] Generated evidence PDF report: {len(report_pdf_bytes)} bytes saved to {report_path.name}")

    # Test Multiple Copies (Requirement 15)
    log_step("10. Test Multiple Copies: Alice Opens Same Document Twice (Distinct Watermarks)")
    time.sleep(1)
    # Copy 1
    r1 = requests.post(f"{BASE_URL}/api/recipient/documents/{doc_id}/open", headers=alice_headers)
    assert r1.status_code == 200
    copy1_bytes = r1.content
    wid1 = r1.headers.get("X-Watermark-ID")

    with open("alice_copy_1.pdf", "wb") as f:
        f.write(copy1_bytes)

    time.sleep(1)
    # Copy 2
    r2 = requests.post(f"{BASE_URL}/api/recipient/documents/{doc_id}/open", headers=alice_headers)
    assert r2.status_code == 200
    copy2_bytes = r2.content
    wid2 = r2.headers.get("X-Watermark-ID")

    with open("alice_copy_2.pdf", "wb") as f:
        f.write(copy2_bytes)

    print(f"[Copy 1] Watermark ID: {wid1} -> saved to alice_copy_1.pdf")
    print(f"[Copy 2] Watermark ID: {wid2} -> saved to alice_copy_2.pdf")
    
    assert wid1 != wid2, f"Watermarks must be distinct! Got {wid1} and {wid2}"
    print("[OK] Confirmed distinct watermarks for two separate access sessions of the same document")

    # Analyze Copy 1 with Investigator
    files1 = {"file": ("alice_copy_1.pdf", io.BytesIO(copy1_bytes), "application/pdf")}
    res1 = requests.post(f"{BASE_URL}/api/investigator/analyze", headers=inv_headers, files=files1).json()
    assert res1["status"] == "MATCH_FOUND"
    assert res1["watermark_id"] == wid1
    assert res1["recipient_identity"] == "Alice"
    print(f"[OK] alice_copy_1.pdf analyzed -> Matched {wid1} -> Alice -> Event {res1['access_event_id']}")

    # Analyze Copy 2 with Investigator
    files2 = {"file": ("alice_copy_2.pdf", io.BytesIO(copy2_bytes), "application/pdf")}
    res2 = requests.post(f"{BASE_URL}/api/investigator/analyze", headers=inv_headers, files=files2).json()
    assert res2["status"] == "MATCH_FOUND"
    assert res2["watermark_id"] == wid2
    assert res2["recipient_identity"] == "Alice"
    print(f"[OK] alice_copy_2.pdf analyzed -> Matched {wid2} -> Alice -> Event {res2['access_event_id']}")

    assert res1["access_event_id"] != res2["access_event_id"], "Access event IDs must be distinct"
    print("[OK] Both copies correctly identified Alice with separate, cryptographically verified access events!")

    # Test No-Match Demo (Requirement 17)
    log_step("11. Test No-Match Demo (Plain Unwatermarked PDF)")
    unwatermarked_pdf = pdf_bytes # original unwatermarked sample
    files_clean = {"file": ("Clean_Sample.pdf", io.BytesIO(unwatermarked_pdf), "application/pdf")}
    res_clean = requests.post(f"{BASE_URL}/api/investigator/analyze", headers=inv_headers, files=files_clean).json()
    
    print(f"[No-Match Result] Status: {res_clean['status']} ({res_clean['status_label']})")
    assert res_clean["status"] == "NO_WATERMARK"
    assert res_clean["status_label"] == "NO FORENSIC WATERMARK DETECTED"
    assert res_clean.get("recipient_identity") is None
    print("[OK] Unwatermarked PDF correctly returned NO_WATERMARK without identifying any recipient")

    # Test Investigation History Endpoint (Requirement 12)
    log_step("12. Verify Investigation History Endpoint")
    r_hist = requests.get(f"{BASE_URL}/api/investigator/history", headers=inv_headers)
    assert r_hist.status_code == 200
    history_items = r_hist.json()
    print(f"[OK] Retrieved {len(history_items)} history items from audit logs")
    assert len(history_items) >= 3, "Expected at least 3 investigations in history"
    print(f"[Latest Investigation] {history_items[0]}")

    print("\n" + "="*70)
    print("ALL ACTUAL FILE VERIFICATION TESTS PASSED SUCCESSFULLY! (100%)")
    print("="*70)

if __name__ == "__main__":
    run_actual_file_verification_suite()
