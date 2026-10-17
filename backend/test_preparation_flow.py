import requests
import time
import sys

BASE_URL = "http://127.0.0.1:8000/api"

def run_test():
    print("=" * 70)
    print("TESTING ASYNC BACKGROUND SECURITY PROCESSING FLOW")
    print("=" * 70)

    # 1. Login Alice
    res = requests.post(f"{BASE_URL}/login", json={"username": "alice", "password": "alice123"})
    assert res.status_code == 200, f"Alice login failed: {res.text}"
    token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("[1] Alice logged in successfully")

    # 2. Get Alice's documents
    res = requests.get(f"{BASE_URL}/recipient/documents", headers=headers)
    assert res.status_code == 200, f"Get documents failed: {res.text}"
    docs = res.json()
    assert len(docs) > 0, "No documents available for Alice"
    doc_id = docs[0]["id"]
    print(f"[2] Found document {doc_id} ('{docs[0]['filename']}')")

    # 3. Trigger /prepare endpoint
    res = requests.post(f"{BASE_URL}/recipient/documents/{doc_id}/prepare", headers=headers)
    assert res.status_code == 200, f"Prepare failed: {res.text}"
    prep_data = res.json()
    job_id = prep_data["job_id"]
    print(f"[3] Initiated background preparation job: {job_id}")

    # 4. Poll /prepare-status/{job_id} until COMPLETED
    completed = False
    stages_seen = set()
    for _ in range(50):
        time.sleep(0.1)
        res = requests.get(f"{BASE_URL}/recipient/documents/prepare-status/{job_id}", headers=headers)
        assert res.status_code == 200, f"Status poll failed: {res.text}"
        status_data = res.json()
        
        cur_step = status_data.get("current_step")
        if cur_step:
            stages_seen.add(cur_step)
        for s in status_data.get("completed_steps", []):
            stages_seen.add(s)

        if status_data["status"] == "COMPLETED":
            completed = True
            print(f"[4] Job completed! Stages tracked: {sorted(list(stages_seen))}")
            print(f"    - Watermark ID: {status_data.get('watermark_id')}")
            print(f"    - Session ID:   {status_data.get('session_id')}")
            print(f"    - All 9 steps completed: {len(status_data.get('completed_steps', []))} steps")
            break
        elif status_data["status"] == "FAILED":
            print(f"[ERROR] Job failed: {status_data.get('error')}")
            sys.exit(1)

    assert completed, "Job did not complete within timeout"

    # 5. Download protected PDF from /download-protected/{job_id}
    res = requests.get(f"{BASE_URL}/recipient/documents/download-protected/{job_id}", headers=headers)
    assert res.status_code == 200, f"Download failed: {res.text}"
    assert res.headers.get("content-type") == "application/pdf"
    pdf_bytes = res.content
    print(f"[5] Successfully downloaded protected PDF ({len(pdf_bytes)} bytes)")
    
    # Save protected PDF
    test_pdf_path = "SecureShare_test_protected.pdf"
    with open(test_pdf_path, "wb") as f:
        f.write(pdf_bytes)
    print(f"[6] Saved to {test_pdf_path}")

    # 6. Investigator Analysis of this downloaded PDF
    res = requests.post(f"{BASE_URL}/login", json={"username": "investigator", "password": "investigator123"})
    assert res.status_code == 200
    inv_token = res.json()["access_token"]
    inv_headers = {"Authorization": f"Bearer {inv_token}"}

    with open(test_pdf_path, "rb") as f:
        res = requests.post(
            f"{BASE_URL}/investigator/analyze",
            headers=inv_headers,
            files={"file": ("SecureShare_test_protected.pdf", f, "application/pdf")}
        )
    assert res.status_code == 200, f"Investigation failed: {res.text}"
    inv_result = res.json()
    print(f"[7] Investigator analysis result:")
    print(f"    - Status:             {inv_result['status']} ({inv_result['status_label']})")
    print(f"    - Recipient Identity: {inv_result.get('recipient_identity')}")
    print(f"    - Watermark ID:       {inv_result.get('watermark_id')}")
    print(f"    - Access Event ID:    {inv_result.get('access_event_id')}")
    print(f"    - Signature Verified: {inv_result.get('technical_evidence', {}).get('signature_algorithm')}")

    assert inv_result["status"] == "MATCH_FOUND"
    assert inv_result["recipient_identity"] == "Alice"
    assert inv_result["watermark_id"] == status_data.get("watermark_id")
    print("=" * 70)
    print("[PASS] REAL WATERMARKED ASYNC JOB FLOW FULLY VERIFIED!")
    print("=" * 70)

if __name__ == "__main__":
    run_test()
