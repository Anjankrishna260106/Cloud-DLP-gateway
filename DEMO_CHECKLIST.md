# Morning-Of Live Demo Checklist
## CloudGuard Pre-Storage DLP Gateway — Presentation Day Runbook

Follow these steps in exact numerical sequence tomorrow morning to bring up the live HTTPS demonstration in under 3 minutes.

---

### Step 1: Open PowerShell / Terminal in Project Directory
Navigate to the repository folder:
```powershell
cd "c:\Users\vanan\OneDrive\Desktop\CS Seminar"
```
*Expected Output:* Active working directory is the project root.

---

### Step 2: Start the FastAPI Backend (Terminal 1)
```powershell
.\.venv\Scripts\python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```
*Expected Output:*
```
INFO:     Started server process
INFO:     Waiting for application startup.
[DB] Initialized persistent local database store.
[SEED] Created admin user: admin@dlp-gateway.local (pass: Admin@12345)
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000
```

---

### Step 3: Start the React Frontend Dev Server (Terminal 2)
```powershell
npm --prefix frontend run dev
```
*Expected Output:*
```
  VITE v7.3.8  ready in 310 ms
  ➜  Local:   http://localhost:5173/
  ➜  Network: http://192.168.x.x:5173/
```

---

### Step 4: Expose Live HTTPS Endpoint via Cloudflare Tunnel (Terminal 3)
I have placed the standalone `cloudflared.exe` directly in your project folder. No account, login, or installation is needed:
```powershell
.\cloudflared.exe tunnel --url http://localhost:5173
```
*Expected Output:*
```
+--------------------------------------------------------------------------------------------+
|  Your quick Tunnel has been created! Visit it at (it may take some time to be reachable):  |
|  https://xxxxxxxxxxxxxxxxxxxx.trycloudflare.com                                            |
+--------------------------------------------------------------------------------------------+
```
Simply open that `https://...trycloudflare.com` URL in any browser or phone to demo over live HTTPS!

---

### Step 5: Open Browser & Sign In
1. Open the generated `https://xxxx.ngrok-free.app` URL in Chrome/Edge.
2. Sign in using the pre-seeded Admin credential:
   - **Email:** `admin@dlp-gateway.local`
   - **Password:** `Admin@12345`
   - *(Or click the "Admin Role" quick-fill button on the login screen).*

---

### Step 6: Execute the 5 Live Demo Scenarios in the UI
Navigate to **Upload & Inspect** tab in the UI:
1. **Scenario 1 (ALLOW):** Select `test-files/demo_1_safe.txt` ➔ Click "Scan & Route".
   - *Result on Screen:* Green banner `ALLOW`, Risk: `PUBLIC (0/100)`, Bucket: `s3://cloudguard-dlp-safe-bucket`.
2. **Scenario 2 (MASK):** Select `test-files/demo_2_mask_pii.txt` ➔ Click "Scan & Route".
   - *Result on Screen:* Yellow banner `MASK`, Risk: `MEDIUM (50/100)`, Sanitized Preview displays `p***@example.com` and `***-***-4321`. Click "Download Sanitized File" to show redacted content.
3. **Scenario 3 (QUARANTINE):** Select `test-files/demo_3_quarantine_financial.csv` ➔ Click "Scan & Route".
   - *Result on Screen:* Orange banner `QUARANTINE`, Risk: `HIGH (82/100)`, Bucket: `s3://cloudguard-dlp-quarantine-bucket`. Shows detected PANs and Luhn-verified Credit Cards.
4. **Scenario 4 (BLOCK):** Select `test-files/demo_4_block_credentials.txt` ➔ Click "Scan & Route".
   - *Result on Screen:* Red banner `UPLOAD REJECTED BY DLP GATEWAY`, Risk: `CRITICAL (100/100)`, S3 Destination: `None (Rejected)`. Zero bytes stored in S3.
5. **Scenario 5 (Dashboard Walkthrough):** Click **Security Dashboard** in the sidebar:
   - View updated KPI cards (Total files, breakdown by action).
   - Click any recent scan row to open the **Forensic Event Detail Modal** showing exact confidence scores, checksum validation tags, and S3 encryption metadata.

---

### Step 7: Demonstrate Vulnerabilities & Fixes (Security Seminar Lab Tab)
1. Switch to **Security Seminar Lab** tab in the sidebar.
2. Click **Vulnerable Demo** mode button.
3. Run the automated exploit demonstration in Terminal 4:
   ```powershell
   .\.venv\Scripts\python scripts\run_phase3_exploits.py
   ```
   *Expected Output:*
   - Shows all 5 exploits succeeding in `Vulnerable` mode (Path Traversal escapes staging, IDOR reads admin scan, forged weak JWT accepted, S3 bucket public-read, ReDoS spikes to ~488 ms).
   - Shows all 5 exploits blocked in `Remediated` mode (Path Traversal blocked HTTP 400, IDOR blocked HTTP 403, forged JWT rejected HTTP 401, S3 enforced AES256 + private, ReDoS runs in 0.27 ms).

---

### Step 8: Present Quantitative Evaluation Benchmark
Show the evaluation table from `test-files/eval_dataset/EVALUATION_REPORT.md`:
- **Accuracy:** 100%
- **Precision:** 100%
- **Recall:** 100%
- **False Positive Rate:** 0.0%
