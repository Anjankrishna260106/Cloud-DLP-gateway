# Seminar Presentation Script
## Design and Implementation of a Cloud-Based Data Loss Prevention (DLP) Gateway

---

### 1. Title & Problem Statement (00:00 – 01:30)
> **Speaker Script:**
> "Good morning, respected professors, evaluators, and colleagues. Today, I am presenting my cloud security seminar project: **Design and Implementation of a Cloud-Based Data Loss Prevention (DLP) Gateway**.
> 
> As organizations rapidly migrate enterprise workloads to cloud object storage like Amazon S3, cloud security breaches caused by sensitive data leaks have reached record highs. Employees routinely upload spreadsheets containing customer PAN or Aadhaar records, unencrypted database connection strings, and developers accidentally commit `.env` files containing high-privilege AWS access keys.
> 
> Once sensitive data lands in a cloud bucket, the blast radius is immediate: automated threat scanners discover public misconfigurations within minutes, compliance mandates like GDPR and PCI-DSS are violated, and retroactive data deletion from object storage versioning and backups is difficult, expensive, and legally reportable."

---

### 2. Existing Solutions vs. Stated Research Gap (01:30 – 03:00)
> **Speaker Script:**
> "Now, you might ask: *Doesn't the cloud already have DLP tools like AWS Macie and Google Cloud DLP?*
> 
> Yes, but here is my **stated research gap**:
> - **Existing Solutions (Post-Storage Scanning):** AWS Macie and Google Cloud DLP operate on an **asynchronous, post-storage** model. That means the user uploads the file directly to Amazon S3. Hours or minutes later, a background scanning worker inspects the bucket and triggers a finding. During that time window, the plaintext secret is already residing on cloud disk, exposed to bucket-level read permissions, replications, and unauthorized access.
> - **My Architecture (Pre-Storage Gateway):** CloudGuard sits **directly in front of cloud storage**. Inbound payloads are intercepted in-flight, multi-format text is extracted, pattern matching and algorithmic checksums are executed, risk is classified, and strict policy governance is applied **before** persistence.
> 
> Plaintext credentials are **blocked at the gateway perimeter and never touch Amazon S3**. Contact details are **masked in-flight**, financial identities are **isolated in a dedicated quarantine bucket**, and only clean, verified documents enter the safe production bucket."

---

### 3. Architecture & Data Flow Diagram (03:00 – 04:30)
```
  [ Client Browser / CLI ]
             │  (HTTPS Inbound File Upload)
             ▼
  ┌────────────────────────────────────────────────────────┐
  │         CloudGuard Pre-Storage DLP Gateway             │
  │                                                        │
  │  1. Ingestion: File Whitelist (10MB, .txt,.csv,.pdf,.docx,.xlsx)
  │  2. Extraction Engine: PyMuPDF, python-docx, openpyxl, pandas
  │  3. Detection Engine: RFC Regex + Luhn & Verhoeff Checksums
  │  4. Risk Classifier: PUBLIC (0) ➔ CRITICAL (100)       │
  │  5. Policy Engine: Rule Matrix Evaluation              │
  └───────────┬──────────────┬───────────────┬─────────────┘
              │              │               │             │
     [ALLOW]  │     [MASK]   │ [QUARANTINE]  │     [BLOCK] │
   Clean File │Sanitized File│ Isolated File │    Zero S3  │
              ▼              ▼               ▼             ▼
       ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────────┐
       │   AWS S3    │ │   AWS S3    │ │   AWS S3    │ │ HTTP 200/403  │
       │ Safe Bucket │ │ Safe Bucket │ │ Quarantine  │ │ Reject & Alert│
       │ (Encrypted) │ │ (Encrypted) │ │ (Encrypted) │ │ (No S3 Write) │
       └─────────────┘ └─────────────┘ └─────────────┘ └───────────────┘
              │              │               │             │
              └──────────────┴───────┬───────┴─────────────┘
                                     ▼
                       ┌───────────────────────────┐
                       │   MongoDB Atlas Audit DB  │
                       │ Immutable Audit Trail Log │
                       └─────────────┬─────────────┘
                                     ▼
                       ┌───────────────────────────┐
                       │  Live React.js Dashboard  │
                       │ Real-time Security Metrics│
                       └───────────────────────────┘
```

---

### 4. Live Demonstration — 5 Scenarios (04:30 – 07:30)
> **Speaker Script:**
> "Let's see this in action. I will log in to our CloudGuard dashboard at our HTTPS endpoint and walk through the five core demonstration scenarios:
> 
> 1. **Scenario 1 — Safe Business File (`demo_1_safe.txt`):**
>    - *Action:* The file contains engineering quarterly notes. The gateway extracts plain text, finds 0 sensitive patterns, assigns a **PUBLIC** rating (Score: 0), executes policy `POL-000-SAFE-PUBLIC-ALLOW`, and routes the original file directly into `cloudguard-dlp-safe-bucket`.
> 2. **Scenario 2 — PII Escalation Ticket (`demo_2_mask_pii.txt`):**
>    - *Action:* Contains customer emails and phone numbers. The risk classifier marks this **MEDIUM** (Score: 50). Policy `POL-003-PII-AUTOMASK` triggers in-flight sanitization. As you can see in the live preview, `priya.sharma.demo@example.com` is redacted to `p***@example.com`. The **sanitized file** is saved to the safe bucket, and the download link yields the redacted file.
> 3. **Scenario 3 — Financial Data Leak (`demo_3_quarantine_financial.csv`):**
>    - *Action:* Contains Indian PAN numbers, phone numbers, and Visa/Mastercard numbers. Luhn algorithm validation verifies the credit cards, and the 4th-character entity check validates the PANs. The classifier assigns **HIGH** risk (Score: 82). Policy `POL-002-FINANCIAL-IDENTITY-QUARANTINE` routes the file into the isolated `cloudguard-dlp-quarantine-bucket` for security officer audit.
> 4. **Scenario 4 — Cloud Credentials Leak (`demo_4_block_credentials.txt`):**
>    - *Action:* A configuration file containing AWS Access Key ID (`AKIA...`), AWS Secret Access Key, and Stripe tokens. Classified as **CRITICAL** (Score: 100). Policy `POL-001-STRICT-CREDENTIAL-BLOCK` **rejects the upload entirely**. Zero bytes are written to any S3 bucket, and a Critical Security Alert is recorded in the audit trail.
> 5. **Scenario 5 — Forensic Dashboard Telemetry Walkthrough:**
>    - *Action:* Returning to the dashboard, we view real-time KPI aggregations: total scans, breakdown by policy action, sensitive data distribution, and we click into Scan `scan-1010` to view character offsets, confidence ratings, and S3 encryption metadata."

---

### 5. Cloud Security Vulnerability, Exploit & Remediation Walkthrough (07:30 – 11:30)
> **Speaker Script:**
> "Because this is an advanced Cloud Security seminar, building a functional gateway is only half the battle. We also conducted an adversarial security evaluation by intentionally seeding and remediating 5 major cloud vulnerability classes inside our own architecture:
> 
> 1. **Vulnerability 1: Path Traversal & Unrestricted File Upload**
>    - *Flaw:* Unsanitized filenames concatenated directly into local staging directories.
>    - *Exploit:* Uploading `../poc_traversal_escape.txt` escapes the upload root.
>    - *Fix:* Strict filename basename sanitization, 10MB size limit, and strict extension whitelisting (`.txt, .csv, .pdf, .docx, .xlsx`).
> 
> 2. **Vulnerability 2: Broken Access Control / IDOR on Telemetry**
>    - *Flaw:* Predictable sequential IDs (`scan-1001`, `scan-1002`) accessible by any logged-in user.
>    - *Exploit:* A regular employee views the administrator's sensitive financial scan.
>    - *Fix:* Strict ownership verification enforcing `user_id == current_user['id']` or `admin` RBAC clearance (HTTP 403 Forbidden).
> 
> 3. **Vulnerability 3: Hardcoded Weak JWT Secret & Missing Expiry**
>    - *Flaw:* Signing JWTs with `'secret123'` without an `exp` claim.
>    - *Exploit:* Offline token forgery minting an unexpirable `admin` identity.
>    - *Fix:* 256-bit cryptographically secure random secret, strict 30-minute expiration, and unique JTI revocation on logout.
> 
> 4. **Vulnerability 4: Overly Permissive S3 Bucket Policies**
>    - *Flaw:* Public-read S3 ACLs with wildcard Principal `"*"` and disabled server-side encryption.
>    - *Exploit:* Unauthenticated exfiltration of quarantined financial payloads.
>    - *Fix:* `PublicAccessBlock: True`, mandatory Server-Side Encryption (`SSE-S3 AES-256`), TLS transport enforcement (`aws:SecureTransport: false` Deny), and IAM role least-privilege.
> 
> 5. **Vulnerability 5: Regular Expression Denial of Service (ReDoS)**
>    - *Flaw:* Nested quantifiers `([a-zA-Z0-9_.-]+)+@...` causing exponential catastrophic backtracking $O(2^n)$.
>    - *Exploit:* A crafted 24-character payload spikes server inspection latency to over 488 ms.
>    - *Fix:* Rewritten linear-time $O(n)$ bounded regex executing in 0.27 ms."

---

### 6. Quantitative Evaluation Results (11:30 – 13:00)
> **Speaker Script:**
> "To validate detection effectiveness, we tested the engine against a synthetic benchmark of 25 files across 5 formats:
> 
> - **Overall Binary Classification Accuracy:** **100.0%**
> - **Policy Enforcement Accuracy:** **100.0%**
> - **Precision:** **100.0%** ($\text{FP} = 0$, zero legitimate files blocked)
> - **Recall (Sensitivity):** **100.0%** ($\text{FN} = 0$, zero sensitive leaks missed)
> - **False Positive Rate:** **0.0%**
> - **Average Inspection Latency:** Sub-millisecond ($< 0.5\text{ ms}$) for text and CSV; sub-400 ms for rich DOCX, PDF, and XLSX archives."

---

### 7. Future Work & Conclusion (13:00 – 14:00)
> **Speaker Script:**
> "To conclude, pre-storage DLP effectively closes the dangerous exposure window inherent in cloud storage architectures.
> 
> For future work, we plan to extend CloudGuard with:
> 1. **Optical Character Recognition (OCR):** Using Tesseract/AWS Textract to detect sensitive data embedded inside image attachments (`.png`, `.jpg`).
> 2. **Transformer-based ML Classification:** Integrating RoBERTa or fine-tuned BERT models for context-aware classification beyond regex.
> 3. **Multi-Cloud Cloud Storage Support:** Adding dual-bucket adapters for Google Cloud Storage and Azure Blob Storage.
> 
> Thank you, and I am now open to your questions."
