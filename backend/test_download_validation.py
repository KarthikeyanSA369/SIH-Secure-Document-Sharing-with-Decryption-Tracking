import requests
import time
import pymupdf as fitz
from services.watermark_service import extract_watermark

BASE_URL = "http://127.0.0.1:8000/api"

def test_download_and_pdf_validity():
    print("=" * 70)
    print("RUNNING COMPREHENSIVE PROTECTED PDF DOWNLOAD & VALIDITY TEST")
    print("=" * 70)

    # 1. Login Alice
    res = requests.post(f"{BASE_URL}/login", json={"username": "alice", "password": "alice123"})
    assert res.status_code == 200, f"Alice login failed: {res.text}"
    token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("[1] Alice authenticated successfully")

    # 2. Retrieve Alice documents
    res = requests.get(f"{BASE_URL}/recipient/documents", headers=headers)
    assert res.status_code == 200, f"Get documents failed: {res.text}"
    docs = res.json()
    assert len(docs) > 0, "No documents found for Alice"
    doc = docs[0]
    print(f"[2] Document to open: {doc['id']} ('{doc['filename']}')")

    # 3. Trigger prepare
    res = requests.post(f"{BASE_URL}/recipient/documents/{doc['id']}/prepare", headers=headers)
    assert res.status_code == 200, f"Prepare failed: {res.text}"
    job_id = res.json()["job_id"]
    print(f"[3] Background preparation job started: {job_id}")

    # 4. Poll status
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
    watermark_id = status_data["watermark_id"]
    session_id = status_data["session_id"]
    print(f"[4] Job COMPLETED. Watermark ID: {watermark_id}, Session ID: {session_id}")

    # 5. Download Protected PDF bytes
    res = requests.get(f"{BASE_URL}/recipient/documents/download-protected/{job_id}", headers=headers)
    assert res.status_code == 200, f"Download failed: {res.text}"
    
    # Check headers
    content_type = res.headers.get("content-type", "")
    content_disp = res.headers.get("content-disposition", "")
    print(f"[5] Download Headers:")
    print(f"    - Content-Type:        {content_type}")
    print(f"    - Content-Disposition: {content_disp}")
    assert "application/pdf" in content_type, f"Invalid Content-Type: {content_type}"
    assert "attachment" in content_disp or "inline" in content_disp

    pdf_bytes = res.content
    print(f"[6] Downloaded PDF size: {len(pdf_bytes)} bytes")
    assert len(pdf_bytes) > 0, "Downloaded PDF is 0 bytes!"

    # 6. Verify PDF Magic bytes & EOF
    assert pdf_bytes.startswith(b"%PDF-"), f"Downloaded bytes do not start with %PDF-! Starts with: {pdf_bytes[:20]}"
    assert b"%%EOF" in pdf_bytes, "Downloaded bytes do not contain %%EOF!"
    print(f"[7] PDF Magic Bytes & EOF Check: PASSED (%PDF- header & %%EOF footer verified)")

    # 7. Verify opening in PyMuPDF (fitz)
    doc_opened = fitz.open(stream=pdf_bytes, filetype="pdf")
    page_count = len(doc_opened)
    print(f"[8] PyMuPDF Reader Verification: PASSED (Readable PDF with {page_count} page(s))")
    assert page_count > 0, "PDF has 0 pages"
    doc_opened.close()

    # 8. Save to disk as exact protected filename
    download_filename = f"SecureShare_{doc['filename'].rsplit('.', 1)[0]}_protected.pdf"
    with open(download_filename, "wb") as f:
        f.write(pdf_bytes)
    print(f"[9] Saved file to disk: '{download_filename}'")

    # 9. Read back from disk and verify
    with open(download_filename, "rb") as f:
        disk_bytes = f.read()
    assert len(disk_bytes) == len(pdf_bytes), "File size on disk does not match downloaded bytes!"
    doc_disk = fitz.open(download_filename)
    assert len(doc_disk) == page_count, "Disk PDF page count mismatch!"
    doc_disk.close()
    print(f"[10] Disk read & validation: PASSED")

    # 10. Extract watermark from the saved PDF file
    extracted_wid, extracted_sid, meta = extract_watermark(disk_bytes)
    print(f"[11] Watermark Extraction from saved PDF:")
    print(f"     - Expected Watermark ID: {watermark_id}")
    print(f"     - Extracted Watermark ID: {extracted_wid}")
    print(f"     - Expected Session ID:   {session_id}")
    print(f"     - Extracted Session ID:   {extracted_sid}")
    assert extracted_wid == watermark_id, f"Watermark ID mismatch! Expected {watermark_id}, got {extracted_wid}"
    assert extracted_sid == session_id, f"Session ID mismatch! Expected {session_id}, got {extracted_sid}"
    print(f"[12] Watermark Extraction: PASSED 100%")

    # 11. Investigator Flow on the EXACT downloaded file
    res = requests.post(f"{BASE_URL}/login", json={"username": "investigator", "password": "investigator123"})
    assert res.status_code == 200
    inv_token = res.json()["access_token"]
    inv_headers = {"Authorization": f"Bearer {inv_token}"}

    with open(download_filename, "rb") as f:
        res = requests.post(
            f"{BASE_URL}/investigator/analyze",
            headers=inv_headers,
            files={"file": (download_filename, f, "application/pdf")}
        )
    assert res.status_code == 200, f"Investigation failed: {res.text}"
    inv_result = res.json()

    print(f"[13] Investigator Forensic Analysis Result:")
    print(f"     - Status:             {inv_result['status']} ({inv_result['status_label']})")
    print(f"     - Recipient Identity: {inv_result.get('recipient_identity')}")
    print(f"     - Watermark ID:       {inv_result.get('watermark_id')}")
    print(f"     - Access Event ID:    {inv_result.get('access_event_id')}")
    print(f"     - Signature:          {inv_result.get('technical_evidence', {}).get('signature_algorithm')}")

    assert inv_result["status"] == "MATCH_FOUND"
    assert inv_result["recipient_identity"] == "Alice"
    assert inv_result["watermark_id"] == watermark_id

    # Clean up test file
    import os
    if os.path.exists(download_filename):
        os.remove(download_filename)

    print("=" * 70)
    print("DOWNLOADED FILE FULLY VERIFIED AS VALID PDF WITH EXTRACTABLE FORENSIC WATERMARK!")
    print("=" * 70)

if __name__ == "__main__":
    test_download_and_pdf_validity()
