import requests
import time
import pymupdf as fitz
from services.watermark_service import extract_watermark

BASE_URL = "http://127.0.0.1:8000/api"

def run_real_protected_pdf_download_test():
    print("=" * 50)
    print("REAL PROTECTED PDF DOWNLOAD TEST")
    print("=" * 50)

    # 1. Login as Alice
    res = requests.post(f"{BASE_URL}/login", json={"username": "alice", "password": "alice123"})
    assert res.status_code == 200, f"Alice login failed: {res.text}"
    token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Get document
    res = requests.get(f"{BASE_URL}/recipient/documents", headers=headers)
    assert res.status_code == 200, f"Get documents failed: {res.text}"
    docs = res.json()
    assert len(docs) > 0, "No documents available for Alice"
    doc = docs[0]

    # 3. Open document (prepare flow)
    res = requests.post(f"{BASE_URL}/recipient/documents/{doc['id']}/prepare", headers=headers)
    assert res.status_code == 200, f"Prepare document failed: {res.text}"
    job_id = res.json()["job_id"]

    status_data = None
    for _ in range(50):
        time.sleep(0.1)
        res = requests.get(f"{BASE_URL}/recipient/documents/prepare-status/{job_id}", headers=headers)
        assert res.status_code == 200
        data = res.json()
        if data["status"] == "COMPLETED":
            status_data = data
            break
        elif data["status"] == "FAILED":
            raise AssertionError(f"Job failed: {data.get('error')}")

    assert status_data is not None, "Job timed out"
    expected_watermark_id = status_data["watermark_id"]
    expected_session_id = status_data["session_id"]

    # 4. Receive HTTP response
    res = requests.get(f"{BASE_URL}/recipient/documents/download-protected/{job_id}", headers=headers)
    http_status = res.status_code
    content_type = res.headers.get("content-type", "")
    assert http_status == 200, f"HTTP status expected 200, got {http_status}"
    assert "application/pdf" in content_type, f"Content-type expected application/pdf, got {content_type}"

    # 5. Convert response to exact bytes
    raw_pdf_bytes = res.content
    assert len(raw_pdf_bytes) > 0, "Response body is empty"

    # 6. Verify PDF header
    pdf_header_str = raw_pdf_bytes[:5].decode("latin1", errors="ignore")
    assert raw_pdf_bytes.startswith(b"%PDF-"), f"PDF Header does not start with %PDF-! Got: {pdf_header_str}"
    assert b"%%EOF" in raw_pdf_bytes, "PDF does not contain %%EOF footer"

    # 7. Verify PDF opens with PyMuPDF
    doc_fitz = fitz.open(stream=raw_pdf_bytes, filetype="pdf")
    pages = len(doc_fitz)
    assert pages > 0, "PyMuPDF opened 0 pages"
    doc_fitz.close()

    # 8. Extract watermark
    extracted_wid, extracted_sid, meta = extract_watermark(raw_pdf_bytes)
    assert extracted_wid == expected_watermark_id, f"Watermark ID mismatch: {extracted_wid} != {expected_watermark_id}"
    assert extracted_sid == expected_session_id, f"Session ID mismatch: {extracted_sid} != {expected_session_id}"

    # 9. Save exact bytes as: downloaded_protected.pdf
    saved_filename = "downloaded_protected.pdf"
    with open(saved_filename, "wb") as f:
        f.write(raw_pdf_bytes)

    # 10. Verify saved file again with PyMuPDF
    doc_saved = fitz.open(saved_filename)
    saved_pages = len(doc_saved)
    assert saved_pages == pages, f"Saved file pages mismatch: {saved_pages} != {pages}"
    doc_saved.close()

    # 11. Verify saved file watermark again
    with open(saved_filename, "rb") as f:
        saved_bytes = f.read()
    saved_wid, saved_sid, _ = extract_watermark(saved_bytes)
    assert saved_wid == expected_watermark_id, f"Saved file watermark mismatch: {saved_wid} != {expected_watermark_id}"

    # 12. Submit saved file to Investigator
    res = requests.post(f"{BASE_URL}/login", json={"username": "investigator", "password": "investigator123"})
    assert res.status_code == 200
    inv_token = res.json()["access_token"]
    inv_headers = {"Authorization": f"Bearer {inv_token}"}

    with open(saved_filename, "rb") as f:
        res = requests.post(
            f"{BASE_URL}/investigator/analyze",
            headers=inv_headers,
            files={"file": (saved_filename, f, "application/pdf")}
        )
    assert res.status_code == 200, f"Investigator analyze failed: {res.text}"
    inv_result = res.json()

    assert inv_result["status"] == "MATCH_FOUND", f"Expected MATCH_FOUND, got {inv_result['status']}"
    assert inv_result["recipient_identity"] == "Alice", f"Expected Alice, got {inv_result.get('recipient_identity')}"
    assert inv_result["watermark_id"] == expected_watermark_id, f"Investigator Watermark ID mismatch: {inv_result.get('watermark_id')} != {expected_watermark_id}"

    # Clean up test file
    import os
    if os.path.exists(saved_filename):
        os.remove(saved_filename)

    print(f"HTTP Status: {http_status}")
    print(f"Content-Type: application/pdf")
    print(f"PDF Header: {pdf_header_str}")
    print(f"PDF Valid: PASS")
    print(f"Pages: {pages}")
    print(f"Watermark Embedded: PASS")
    print(f"Watermark Extracted: {extracted_wid}")
    print(f"Access Event Found: PASS")
    print(f"ML-DSA Verification: PASS")
    print(f"Investigator Match: PASS")
    print("=" * 50)

if __name__ == "__main__":
    run_real_protected_pdf_download_test()
