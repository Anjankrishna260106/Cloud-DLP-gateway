<<<<<<< HEAD
# CloudGuard: Pre-Storage Cloud Data Loss Prevention (DLP) Gateway

A pre-storage Cloud Security DLP Gateway that intercepts inbound file uploads **before** persistence, extracts multi-format text, detects sensitive PII/financial/credential patterns, classifies risk, enforces configurable policies (`ALLOW`, `MASK`, `QUARANTINE`, `BLOCK`), routes files to dual AWS S3 buckets (safe vs. quarantine), logs immutable audit trails to MongoDB Atlas, and visualizes telemetry on a live React dashboard.

## Research Gap
Traditional cloud DLP services (AWS Macie, Google Cloud DLP) operate **post-storage**—scanning objects only after they have already landed in an S3/GCS bucket, leaving a dangerous exposure window and incurring post-hoc remediation overhead. CloudGuard enforces inspection **in-flight before storage**, ensuring plaintext secrets (`BLOCK`) never touch S3 and sensitive PII (`MASK`) is sanitized prior to persistence.

## Project Structure
- `dlp-engine/` — Multi-format text extractors (`PyMuPDF`, `python-docx`, `openpyxl`, `pandas`), regex + checksum detectors (Luhn, Verhoeff), risk classifier, sanitizer, and policy engine.
- `backend/` — FastAPI REST API, JWT + RBAC authentication, AWS S3 two-bucket router (`boto3` + local bucket emulator), audit logger, and security seminar toggle endpoints.
- `database/` — MongoDB Atlas async driver (`motor`) with automatic local JSON fallback and initial seed script.
- `frontend/` — React.js + Vite + Tailwind CSS security dashboard, upload inspection workflow, forensic event modal, policy manager, and security lab.
- `docker/` — `backend.Dockerfile`, `frontend.Dockerfile`, `nginx.conf`, and `docker-compose.yml`.
- `test-files/` — Repeatable demo payloads for all 4 DLP policy outcomes (`ALLOW`, `MASK`, `QUARANTINE`, `BLOCK`).

## Deliverables & Seminar Documentation
- **[DEPLOYMENT.md](file:///c:/Users/vanan/OneDrive/Desktop/CS%20Seminar/DEPLOYMENT.md)** — Comprehensive HTTPS deployment instructions (Ngrok, Cloudflare, Render, Vercel).
- **[SECURITY_VULNERABILITIES.md](file:///c:/Users/vanan/OneDrive/Desktop/CS%20Seminar/SECURITY_VULNERABILITIES.md)** — Deep-dive analysis of the 5 seeded vulnerabilities, safe PoC exploits, and fixes.
- **[SEMINAR_SCRIPT.md](file:///c:/Users/vanan/OneDrive/Desktop/CS%20Seminar/SEMINAR_SCRIPT.md)** — Step-by-step speaker presentation script (problem, research gap, live demo steps, evaluation, future work).
- **[DEMO_CHECKLIST.md](file:///c:/Users/vanan/OneDrive/Desktop/CS%20Seminar/DEMO_CHECKLIST.md)** — Exact morning-of checklist with sequential commands and expected outputs.
- **[EVALUATION_REPORT.md](file:///c:/Users/vanan/OneDrive/Desktop/CS%20Seminar/test-files/eval_dataset/EVALUATION_REPORT.md)** — Quantitative 25-file benchmark metrics (Precision: 100%, Recall: 100%, FPR: 0.0%).

## Automated Demo Scripts
- Run 4 Core DLP Demo Scenarios:
  ```powershell
  .\.venv\Scripts\python scripts\run_phase1_demo.py
  ```
- Run 5 Vulnerability & Remediation PoC Exploits:
  ```powershell
  .\.venv\Scripts\python scripts\run_phase3_exploits.py
  ```
- Run 25-File Benchmark Evaluation:
  ```powershell
  .\.venv\Scripts\python scripts\evaluate_dlp_engine.py
  ```

## Quick Local Run
1. **Backend**:
   ```powershell
   .\.venv\Scripts\python -m uvicorn backend.main:app --reload --port 8000
   ```
2. **Frontend**:
   ```powershell
   npm --prefix frontend run dev
   ```
3. **Seeded Demo Accounts**:
   - Admin: `admin@dlp-gateway.local` / `Admin@12345`
   - Auditor: `auditor@dlp-gateway.local` / `Auditor@12345`
   - Standard User: `demo@dlp-gateway.local` / `User@12345`
=======
# Cloud-DLP-gateway
>>>>>>> b3d78a8cec2916da64deef9856263739c9eb1ca0
