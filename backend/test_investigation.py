import io
import pymupdf as fitz
from fastapi.testclient import TestClient
from main import app
from database import SessionLocal
from seed import ensure_seed_users
from models import AccessEvent

client = TestClient(app)

def create_raw_sample_pdf() -> bytes:
    """Create a sample unwatermarked PDF."""
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)
    page.insert_text((50, 80), "PLAIN TEST DOCUMENT", fontsize=18)
    page.insert_text((50, 120), "This is an unwatermarked outside document.", fontsize=11)
    buf = io.BytesIO()
    doc.save(buf)
    doc.close()
    return buf.getvalue()

def run_investigation_tests():
    print("--- 1. Ensuring Seed Users Exist ---")
    ensure_seed_users()

    print("\n--- 2. Admin Logs in & Sends Document to Alice ---")
    res = client.post("/api/login", json={"username": "admin", "password": "admin123"})
    assert res.status_code == 200
    admin_token = res.json()["access_token"]

    pdf_bytes = create_raw_sample_pdf()
    files = {"file": ("Project_Report.pdf", pdf_bytes, "application/pdf")}
    data = {"recipient_id": "alice"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    res = client.post("/api/admin/documents", files=files, data=data, headers=headers)
    assert res.status_code == 200
    doc_id = res.json()["document_id"]
    print(f"[OK] Document uploaded: {doc_id}")

    print("\n--- 3. Alice Logs in & Opens Document (Generates Watermarked PDF) ---")
    res = client.post("/api/login", json={"username": "alice", "password": "alice123"})
    assert res.status_code == 200
    alice_token = res.json()["access_token"]
    alice_headers = {"Authorization": f"Bearer {alice_token}"}

    res = client.post(f"/api/recipient/documents/{doc_id}/open", headers=alice_headers)
    assert res.status_code == 200
    watermarked_pdf_bytes = res.content
    expected_wid = res.headers.get("X-Watermark-ID")
    expected_sid = res.headers.get("X-Session-ID")
    print(f"[OK] Alice received watermarked PDF ({len(watermarked_pdf_bytes)} bytes)")
    print(f"     Watermark ID: {expected_wid}")
    print(f"     Session ID:   {expected_sid}")

    print("\n--- 4. Investigator Logs in ---")
    res = client.post("/api/login", json={"username": "investigator", "password": "investigator123", "role": "INVESTIGATOR"})
    assert res.status_code == 200
    inv_data = res.json()
    inv_token = inv_data["access_token"]
    print(f"[OK] Investigator logged in: {inv_data['user']['name']} (Role: {inv_data['user']['role']})")
    inv_headers = {"Authorization": f"Bearer {inv_token}"}

    print("\n--- 5. Investigator Analyzes Leaked Watermarked PDF ---")
    leaked_file = {"file": ("Leaked_Project_Report.pdf", watermarked_pdf_bytes, "application/pdf")}
    res = client.post("/api/investigator/analyze", files=leaked_file, headers=inv_headers)
    assert res.status_code == 200, f"Analyze failed: {res.text}"
    result = res.json()

    print(f"[OK] Investigation Result Status: {result['status_label']}")
    print(f"     Matched Recipient:          {result['recipient_identity']}")
    print(f"     Recovered Watermark ID:     {result['watermark_id']}")
    print(f"     Access Event ID:            {result['access_event_id']}")
    print(f"     Session ID:                 {result['session_id']}")
    print(f"     Forensic Statement:         {result['forensic_statement']}")
    print(f"     Ledger Status:              {result['technical_evidence']['ledger_status']} ({result['technical_evidence']['ledger_message']})")

    assert result["status"] == "MATCH_FOUND"
    assert result["recipient_identity"] == "Alice"
    assert result["watermark_id"] == expected_wid
    assert result["technical_evidence"]["ledger_status"] == "NOT_IMPLEMENTED"

    print("\n--- 6. Investigator Analyzes Unwatermarked Clean PDF ---")
    clean_file = {"file": ("Random_Clean.pdf", pdf_bytes, "application/pdf")}
    res = client.post("/api/investigator/analyze", files=clean_file, headers=inv_headers)
    assert res.status_code == 200
    clean_result = res.json()
    print(f"[OK] Clean Document Result: {clean_result['status_label']}")
    assert clean_result["status"] == "NO_WATERMARK"

    print("\n--- 7. Access Control: Non-Investigator Denied Access (403) ---")
    res = client.post("/api/investigator/analyze", files=leaked_file, headers=alice_headers)
    assert res.status_code == 403
    print("[OK] Recipient cannot call investigator endpoint (403 Forbidden)")

    print("\n=======================================================")
    print("ALL FORENSIC INVESTIGATION BACKEND TESTS PASSED!")
    print("=======================================================")

if __name__ == "__main__":
    run_investigation_tests()
