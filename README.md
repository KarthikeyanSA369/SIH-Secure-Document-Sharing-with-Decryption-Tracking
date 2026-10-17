# SecureShare — Post-Quantum Secure Document Distribution & Forensic Provenance

**SecureShare** is a lightweight, high-security prototype for post-quantum encrypted, multi-recipient document distribution and forensic provenance verification.

$$\text{ADMIN} \longrightarrow \text{Upload \& Encrypt (AES-256-GCM + ML-KEM-768)} \longrightarrow \text{Share with Recipient}$$
$$\text{RECIPIENT} \longrightarrow \text{Decapsulate \& Decrypt} \longrightarrow \text{Embed Invisible Watermark} \longrightarrow \text{Sign Access Event (ML-DSA-65)} \longrightarrow \text{View PDF}$$
$$\text{INVESTIGATOR} \longrightarrow \text{Upload Leaked PDF} \longrightarrow \text{Extract Watermark} \longrightarrow \text{Verify ML-DSA-65 \& Integrity} \longrightarrow \text{Forensic Provenance Result}$$

---

## 1. User Roles & Demo Credentials

| Role | Username | Password | Purpose |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin` | `admin123` | Uploads PDF, encapsulates key using ML-KEM-768 for Alice, sends document |
| **Recipient** | `alice` | `alice123` | Receives document, authorizes, decapsulates, decrypts, and views watermarked PDF |
| **Investigator** | `investigator` | `investigator123` | Analyzes suspected leaked PDFs, extracts watermarks, verifies ML-DSA-65 audit logs |

---

## 2. Cryptographic & Forensic Architecture

* **Document Encryption**: **AES-256-GCM** (NIST SP 800-38D) with authenticated data and 96-bit random nonces.
* **Post-Quantum Key Encapsulation**: **ML-KEM-768** (NIST FIPS 203 / Kyber768) protecting symmetric AES document keys per recipient.
* **Post-Quantum Digital Signatures**: **ML-DSA-65** (NIST FIPS 204 / Dilithium3) signing canonical access audit events.
* **Invisible Forensic Watermarking**: **OpenCV + NumPy** spatial/frequency steganographic modulation embedding unique Watermark IDs (`WM-XXXXXXXX`) and Session IDs (`SES-XXXXX`) into document raster layers without visual degradation.
* **Forensic Extraction Engine**: [`backend/services/watermark_service.py`](file:///e:/SIH/backend/services/watermark_service.py) automatically extracts and validates embedded forensic tokens from suspected leaked PDF files.
* **Non-Accusatory Forensic Standard**: Reports cryptographic linkage to verified access events and registered recipient identities without making unsubstantiated physical distribution accusations.
* **Ledger Transparency**: Transparently reports `"Ledger verification pending"` (`ledger_status = "NOT_IMPLEMENTED"`) without faking unconfigured blockchain infrastructure.

---

## 3. Project Structure

```text
SIH/
├── backend/
│   ├── crypto/
│   │   ├── aes_gcm.py            # AES-256-GCM encryption, decryption, HKDF, SHA-256
│   │   ├── ml_kem.py             # ML-KEM-768 keygen, encapsulation, decapsulation
│   │   ├── ml_dsa.py             # ML-DSA-65 keygen, signing, verification
│   │   ├── watermark.py          # Delegator to watermark_service
│   │   └── keystore.py           # Server-side secure private keystore
│   ├── services/
│   │   └── watermark_service.py  # OpenCV + NumPy forensic watermark embedder & extractor
│   ├── auth.py                   # PBKDF2 password hashing, JWT token handling, role RBAC
│   ├── config.py                 # Environment configuration (.env)
│   ├── database.py               # MySQL / SQLAlchemy session handling
│   ├── models.py                 # Database models (users, documents, recipients, access_events)
│   ├── schemas.py                # Pydantic request/response & forensic schemas
│   ├── main.py                   # FastAPI application endpoints
│   ├── seed.py                   # Database initialization and demo keypair generation
│   ├── test_pipeline.py          # Admin/Recipient pipeline test suite
│   ├── test_investigation.py     # Forensic investigation test suite
│   ├── requirements.txt          # Python dependencies
│   └── .env                      # Environment variables
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Navbar.tsx             # Clean top bar with role badge & logout
│   │   │   └── DocumentViewer.tsx     # 3-stage animated decryption modal & PDF viewer
│   │   ├── pages/
│   │   │   ├── LoginPage.tsx              # Screen 1: 3-role login with quick-fill buttons
│   │   │   ├── AdminDashboard.tsx         # Screen 2: PDF upload & send to recipient
│   │   │   ├── RecipientDashboard.tsx     # Screen 3: Recipient document card & [OPEN] trigger
│   │   │   └── InvestigatorDashboard.tsx  # Screen 4: Forensic analysis & 9-stage evidence loading
│   │   ├── api.ts                # Axios API client with investigatorApi
│   │   ├── types.ts              # TypeScript interfaces
│   │   ├── App.tsx               # Main application role router
│   │   └── main.tsx              # React entrypoint
│   ├── package.json
│   ├── vite.config.ts
│   └── tailwind.config.js
├── database/
│   └── schema.sql                # MySQL schema DDL
└── storage/
    ├── encrypted/                # Encrypted documents (e.g. DOC-001.enc)
    └── keystore/                 # Private key store (keys.json)
```

---

## 4. Setup & Running Instructions

### Step 1: Database Setup & Seeding
In `backend/.env`:
```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=secureshare
```

Seed all 3 demo accounts (Admin, Alice, Investigator) and their post-quantum keypairs:
```bash
cd backend
python seed.py
```

### Step 2: Run All Automated Test Suites
```bash
cd backend
python test_actual_file_verification.py
python test_pipeline.py
python test_investigation.py
python test_end_to_end_forensic.py
```

### Step 3: Start Backend Server
```bash
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

### Step 4: Start Frontend Server
```bash
cd frontend
npm run dev
```
Open **`http://localhost:5173`** in your browser.

---

## 5. Demonstration Walkthrough for Judges

### Flow 1: Admin Uploads & Distributes
1. Login as **Admin** (`admin` / `admin123`).
2. Observe the **Secure Distribution Summary** card (Documents, Recipients, Access Events, Protected Copies).
3. Select `Project_Report.pdf`, choose `Alice`, and click **SEND DOCUMENT**.
4. Observe: `✓ Document sent successfully (Project_Report.pdf → Alice)`. The document is encrypted with **AES-256-GCM** and the symmetric key is encapsulated via **ML-KEM-768**.

### Flow 2: Recipient Receives, Views & Downloads Watermarked Copy
1. Login as **Alice** (`alice` / `alice123`).
2. See `Project_Report.pdf` with status `Available`.
3. Click **[ OPEN ]**.
4. The modal decrypts the document, embeds an invisible watermark, records an ML-DSA-65 signed access event, and displays the status panel: `Document Opened Securely` (`✓ Document verified`, `✓ Secure access recorded`, `✓ Forensic protection applied`).
5. Click **View Security Details** to observe safe cryptographic details.
6. Click **DOWNLOAD SECURE COPY** to save `Project_Report_SECURE_COPY.pdf`.

### Flow 3: Investigator Analyzes Leaked Evidence
1. Login as **Investigator** (`investigator` / `investigator123`).
2. On the **Forensic Investigation** dashboard, upload `Project_Report_SECURE_COPY.pdf` and click **ANALYZE DOCUMENT**.
3. Watch the 9-stage analysis loading panel progress to 100%.
4. Inspect the **FORENSIC MATCH FOUND** card showing the verified Watermark ID, matching Access Event ID, recipient cryptographic identity (`Alice`), access timestamp, and the non-accusatory forensic disclosure.
5. Click **View Technical Evidence** to inspect and copy hashes and signature metadata.
6. Click **DOWNLOAD EVIDENCE REPORT** for the official investigation PDF.
7. Click **EXPORT EVIDENCE JSON** for the structured evidence file.
8. View the **Recent Investigations** history table below.

