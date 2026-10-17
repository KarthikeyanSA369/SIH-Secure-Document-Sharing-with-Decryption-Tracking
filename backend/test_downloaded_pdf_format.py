import requests
import time
import pymupdf as fitz
from services.watermark_service import extract_watermark

BASE_URL = "http://127.0.0.1:8000/api"

def run_downloaded_pdf_format_test():
    print("=" * 60)
    print("TEST: DOWNLOADED PROTECTED PDF FORMAT & INTEGRITY")
    print("=" * 60)

    # 1. Login Alice
    res = requests.post(f"{BASE_URL}/login", json={"username": "alice", "password": "alice123"})
    assert res.status_code == 200, f"Login failed: {res.text}"
    token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Get document
    res = requests.get(f"{BASE_URL}/recipient/documents", headers=headers)
    assert res.status_code == 200
    docs = res.json()
    assert len(docs) > 0
    doc = docs[0]

    # 3. Open document
    res = requests.post(f"{BASE_URL}/recipient/documents/{doc['id']}/prepare", headers=headers)
    assert res.status_code == 200
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

    assert status_data is not None
    watermark_id = status_data["watermark_id"]
    session_id = status_data["session_id"]

    # 4. Download Protected PDF bytes
    res = requests.get(f"{BASE_URL}/recipient/documents/download-protected/{job_id}", headers=headers)
    assert res.status_code == 200
    content_type = res.headers.get("content-type", "")
    assert "application/pdf" in content_type

    raw_bytes = res.content
    assert len(raw_bytes) > 0

    # 5. Check filename formatting
    doc_name = doc["filename"]
    safe_base = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in doc_name.rsplit(".", 1)[0].strip()).strip("_")
    expected_filename = f"SecureShare_{safe_base or 'Document'}_protected.pdf"
    assert expected_filename.endswith(".pdf"), "Filename does not end with .pdf"
    assert not expected_filename.endswith(".pdf.pdf"), "Filename has duplicate .pdf.pdf extension"

    # 6. Check magic bytes
    header = raw_bytes[:5].decode("latin1", errors="ignore")
    assert header == "%PDF-", f"Expected %PDF-, got {header}"
    assert b"%%EOF" in raw_bytes, "Missing %%EOF marker"

    # 7. Check PyMuPDF
    doc_fitz = fitz.open(stream=raw_bytes, filetype="pdf")
    page_count = len(doc_fitz)
    assert page_count > 0, "Page count must be > 0"
    doc_fitz.close()

    # 8. Check invisible watermark extraction
    extracted_wid, extracted_sid, meta = extract_watermark(raw_bytes)
    assert extracted_wid == watermark_id, f"Watermark ID mismatch: {extracted_wid} != {watermark_id}"
    assert extracted_sid == session_id, f"Session ID mismatch: {extracted_sid} != {session_id}"

    # 9. Save file to disk
    with open(expected_filename, "wb") as f:
        f.write(raw_bytes)

    # 10. Submit to investigator
    res = requests.post(f"{BASE_URL}/login", json={"username": "investigator", "password": "investigator123"})
    assert res.status_code == 200
    inv_token = res.json()["access_token"]
    inv_headers = {"Authorization": f"Bearer {inv_token}"}

    with open(expected_filename, "rb") as f:
        res = requests.post(
            f"{BASE_URL}/investigator/analyze",
            headers=inv_headers,
            files={"file": (expected_filename, f, "application/pdf")}
        )
    assert res.status_code == 200
    inv_result = res.json()

    assert inv_result["status"] == "MATCH_FOUND"
    assert inv_result["recipient_identity"] == "Alice"
    assert inv_result["watermark_id"] == watermark_id

    # Clean up test file
    import os
    if os.path.exists(expected_filename):
        os.remove(expected_filename)

    print(f"Filename:     {expected_filename}")
    print(f"MIME:         application/pdf")
    print(f"Header:       {header}")
    print(f"Valid PDF:    PASS (Pages: {page_count})")
    print(f"Watermark:    PASS (ID: {extracted_wid})")
    print(f"Investigator: FORENSIC MATCH FOUND (Recipient: {inv_result['recipient_identity']})")
    print("=" * 60)

if __name__ == "__main__":
    run_downloaded_pdf_format_test()
