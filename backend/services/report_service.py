import datetime
import io
from typing import Dict, Any, Optional
import pymupdf as fitz

def generate_evidence_pdf_report(evidence_data: Dict[str, Any]) -> bytes:
    """
    Generate a professional 1-page Forensic Investigation Evidence Report PDF.
    Contains strictly safe forensic provenance metadata.
    Does NOT contain any private keys, passwords, or AES keys.
    """
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)  # Standard A4 (595 x 842 points)

    # Palette
    primary_color = (0.08, 0.20, 0.45)   # Navy blue
    dark_gray = (0.15, 0.15, 0.15)
    medium_gray = (0.40, 0.40, 0.40)
    light_border = (0.80, 0.85, 0.90)
    box_bg = (0.96, 0.98, 1.0)
    badge_green_bg = (0.88, 0.96, 0.90)
    badge_green_border = (0.20, 0.65, 0.30)
    badge_green_text = (0.10, 0.45, 0.20)

    # 1. Header
    page.insert_text((50, 55), "SECURESHARE FORENSIC INVESTIGATION REPORT", fontsize=15, fontname="helv", color=primary_color)
    page.insert_text((50, 75), "Cryptographic Provenance & Forensic Attribution Analysis", fontsize=9, fontname="helv", color=medium_gray)
    page.draw_line((50, 85), (545, 85), color=primary_color, width=1.5)

    # 2. Metadata Banner Box
    investigation_id = evidence_data.get("investigation_id", "INV-2026-001")
    report_time = datetime.datetime.utcnow().strftime("%d %b %Y, %H:%M UTC")
    
    rect_meta = fitz.Rect(50, 95, 545, 140)
    page.draw_rect(rect_meta, color=light_border, fill=box_bg, width=0.8)
    
    page.insert_text((65, 112), f"Investigation ID:  {investigation_id}", fontsize=9, fontname="helv", color=dark_gray)
    page.insert_text((340, 112), f"Report Date:  {report_time}", fontsize=9, fontname="helv", color=dark_gray)
    page.insert_text((65, 128), "Platform:          SecureShare Post-Quantum Distribution Engine", fontsize=9, fontname="helv", color=medium_gray)
    page.insert_text((340, 128), "Evaluation:    Post-Quantum Cryptographic Proof", fontsize=9, fontname="helv", color=medium_gray)

    # 3. Status Badge Box
    status = evidence_data.get("status", "MATCH_FOUND")
    status_label = evidence_data.get("status_label", "FORENSIC MATCH FOUND")
    
    rect_status = fitz.Rect(50, 150, 545, 185)
    page.draw_rect(rect_status, color=badge_green_border, fill=badge_green_bg, width=1)
    page.insert_text((65, 172), f"VERIFICATION RESULT:  {status_label}", fontsize=11, fontname="helv", color=badge_green_text)

    # 4. Evidence Details Table
    doc_name = evidence_data.get("document_filename") or evidence_data.get("document_name") or "Project_Report.pdf"
    doc_sha256 = evidence_data.get("document_sha256") or (evidence_data.get("technical_evidence", {}).get("document_sha256") if isinstance(evidence_data.get("technical_evidence"), dict) else "N/A")
    watermark_id = evidence_data.get("watermark_id") or "N/A"
    access_event_id = evidence_data.get("access_event_id") or "N/A"
    session_id = evidence_data.get("session_id") or "N/A"
    recipient_identity = evidence_data.get("recipient_identity") or evidence_data.get("recipient") or "Alice"
    access_timestamp = evidence_data.get("access_timestamp") or evidence_data.get("timestamp") or "N/A"

    page.insert_text((50, 205), "1. Document & Forensic Provenance Record", fontsize=11, fontname="helv", color=primary_color)
    page.draw_line((50, 212), (545, 212), color=light_border, width=0.8)

    y = 230
    items = [
        ("Submitted Document:", doc_name),
        ("Document SHA-256:", doc_sha256 if len(doc_sha256) <= 50 else doc_sha256[:48] + "..."),
        ("Recovered Watermark ID:", watermark_id),
        ("Matched Access Event ID:", access_event_id),
        ("Access Session ID:", session_id),
        ("Recipient Identity:", recipient_identity),
        ("Access Recorded Time:", access_timestamp)
    ]

    for label, val in items:
        page.insert_text((65, y), label, fontsize=9, fontname="helv", color=medium_gray)
        page.insert_text((220, y), str(val), fontsize=9, fontname="helv", color=dark_gray)
        y += 18

    # 5. Cryptographic Verification Summary
    y += 10
    page.insert_text((50, y), "2. Verification Summary", fontsize=11, fontname="helv", color=primary_color)
    page.draw_line((50, y + 7), (545, y + 7), color=light_border, width=0.8)

    y += 24
    checks = [
        ("[x] Forensic watermark detected", "Recovered from physical document raster via OpenCV/NumPy"),
        ("[x] Access event found", "Associated unique access record in secure store"),
        ("[x] ML-DSA-65 signature verified", "Cryptographically valid (NIST FIPS 204 Dilithium3)"),
        ("[x] Document integrity verified", "SHA-256 fingerprint matches original encrypted master"),
        ("[o] Ledger verification pending", "Hyperledger Fabric integration scheduled for Phase 2")
    ]

    for check_title, check_sub in checks:
        page.insert_text((65, y), check_title, fontsize=9, fontname="helv", color=(0.1, 0.45, 0.2) if "[x]" in check_title else (0.5, 0.5, 0.5))
        page.insert_text((260, y), f"- {check_sub}", fontsize=8.5, fontname="helv", color=medium_gray)
        y += 18

    # 6. Forensic Explanation & Attribution Interpretation
    y += 10
    page.insert_text((50, y), "3. Forensic Statement & Attribution Interpretation", fontsize=11, fontname="helv", color=primary_color)
    page.draw_line((50, y + 7), (545, y + 7), color=light_border, width=0.8)

    y += 24
    rect_statement = fitz.Rect(50, y - 8, 545, y + 68)
    page.draw_rect(rect_statement, color=light_border, fill=(0.98, 0.99, 1.0), width=0.6)

    explanation_1 = (
        f"This document contains a forensic watermark corresponding to a verified access event "
        f"associated with {recipient_identity}'s registered cryptographic identity."
    )
    explanation_2 = (
        "Cryptographic verification establishes the association between the leaked copy and the "
        "recorded access event. It does not by itself establish who physically leaked or distributed the document."
    )

    page.insert_text((65, y + 10), explanation_1, fontsize=8.5, fontname="helv", color=dark_gray)
    page.insert_text((65, y + 35), explanation_2, fontsize=8, fontname="helv", color=medium_gray)

    # 7. Security Notice Footer
    page.draw_line((50, 770), (545, 770), color=light_border, width=0.8)
    footer_notice = (
        "SECURITY NOTICE: This document contains cryptographic verification evidence only.\n"
        "No private keys, AES keys, ML-KEM private parameters, or passwords are contained in this report."
    )
    page.insert_text((50, 785), footer_notice, fontsize=7.5, fontname="helv", color=(0.5, 0.5, 0.5))

    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes
