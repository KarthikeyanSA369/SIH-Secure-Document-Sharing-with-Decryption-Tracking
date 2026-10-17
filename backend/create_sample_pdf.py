import pymupdf as fitz
from pathlib import Path

def generate_sample_pdf(output_path: str = "Project_Report.pdf"):
    """Generate a clean sample Project_Report.pdf for demo testing."""
    doc = fitz.open()
    page = doc.new_page(width=595, height=842) # Standard A4

    # Header title
    page.insert_text((50, 70), "SECURESHARE DOCUMENT DISTRIBUTION", fontsize=16, color=(0.15, 0.25, 0.55))
    page.insert_text((50, 95), "Classification: STRICTLY CONFIDENTIAL // INTERNAL USE ONLY", fontsize=10, color=(0.8, 0.1, 0.1))

    # Decorative separator line
    page.draw_line((50, 110), (545, 110), color=(0.7, 0.7, 0.7), width=1)

    # Document details box
    rect_meta = fitz.Rect(50, 125, 545, 200)
    page.draw_rect(rect_meta, color=(0.8, 0.85, 0.95), fill=(0.96, 0.98, 1.0))
    page.insert_text((65, 145), "Document Name:  Project_Report.pdf", fontsize=10, color=(0.2, 0.2, 0.2))
    page.insert_text((65, 165), "Protection:     Post-Quantum Hybrid (ML-KEM-768 + AES-256-GCM)", fontsize=10, color=(0.2, 0.2, 0.2))
    page.insert_text((65, 185), "Integrity & Audit: ML-DSA-65 Digital Signatures + Invisible Watermarking", fontsize=10, color=(0.2, 0.2, 0.2))

    # Body Content
    page.insert_text((50, 230), "1. Executive Summary", fontsize=14, color=(0.1, 0.1, 0.1))
    body_text = (
        "This project report demonstrates next-generation secure multi-recipient document\n"
        "distribution protected against both classical and quantum computing adversaries.\n\n"
        "Key security pillars implemented in this prototype:\n"
        " • AES-256-GCM authenticated symmetric encryption for high-throughput data protection.\n"
        " • ML-KEM-768 (NIST FIPS 203 / Kyber768) lattice-based key encapsulation mechanism.\n"
        " • ML-DSA-65 (NIST FIPS 204 / Dilithium3) lattice-based digital signatures.\n"
        " • OpenCV + NumPy imperceptible steganographic watermarking embedded at decapsulation.\n"
        " • MySQL audit logs tracking every authorized decryption session."
    )
    page.insert_text((50, 255), body_text, fontsize=10, color=(0.25, 0.25, 0.25))

    # Section 2
    page.insert_text((50, 390), "2. Recipient Authorization & Verification", fontsize=14, color=(0.1, 0.1, 0.1))
    body_text_2 = (
        "Access to this document is strictly restricted to authorized recipients.\n"
        "When opened by Alice, an individual session identifier and cryptographically derived\n"
        "watermark token are embedded directly into the document raster layer."
    )
    page.insert_text((50, 415), body_text_2, fontsize=10, color=(0.25, 0.25, 0.25))

    # Footer
    page.draw_line((50, 780), (545, 780), color=(0.7, 0.7, 0.7), width=0.8)
    page.insert_text((50, 795), "SecureShare Prototype • Generated for Secure Distribution Demonstration", fontsize=9, color=(0.5, 0.5, 0.5))

    doc.save(output_path)
    doc.close()
    print(f"[OK] Generated sample PDF at: {output_path}")

if __name__ == "__main__":
    generate_sample_pdf()
