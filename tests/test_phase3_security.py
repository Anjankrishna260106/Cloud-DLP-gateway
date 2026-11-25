"""
Phase 3 Automated Security Verification Suite.
Asserts all 5 vulnerabilities are exploitable in 'vulnerable' mode
and strictly blocked/mitigated in 'remediated' mode.
"""

import os
import sys
from jose import jwt
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.main import app


def test_five_vulnerabilities_and_remediations():
    with TestClient(app) as client:
        admin_login = client.post("/api/auth/login", json={
            "email": "admin@dlp-gateway.local",
            "password": "Admin@12345"
        }).json()
        admin_token = admin_login["access_token"]

        # Ensure clean admin scan exists
        client.post(
            "/api/security/mode",
            json={"mode": "remediated"},
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        scan_resp = client.post(
            "/api/scan/upload",
            files={"file": ("admin_doc.txt", b"Admin test email admin@corp.com", "text/plain")},
            headers={"Authorization": f"Bearer {admin_token}"}
        ).json()
        target_scan_id = scan_resp["scan_id"]

        # === SWITCH TO VULNERABLE MODE ===
        client.post(
            "/api/security/mode",
            json={"mode": "vulnerable"},
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        v_admin_token = client.post("/api/auth/login", json={
            "email": "admin@dlp-gateway.local",
            "password": "Admin@12345"
        }).json()["access_token"]
        v_user_token = client.post("/api/auth/login", json={
            "email": "demo@dlp-gateway.local",
            "password": "User@12345"
        }).json()["access_token"]

        # 1. Vuln: Path traversal succeeds
        r1 = client.post(
            "/api/scan/upload",
            files={"file": ("../poc_test_escape.txt", b"test", "text/plain")},
            headers={"Authorization": f"Bearer {v_user_token}"}
        )
        assert r1.status_code == 200
        assert r1.json()["vulnerability_trace"]["escaped_staging_dir"] is True
        if os.path.exists("poc_test_escape.txt"):
            os.remove("poc_test_escape.txt")

        # 2. Vuln: IDOR succeeds
        r2 = client.get(f"/api/events/{target_scan_id}", headers={"Authorization": f"Bearer {v_user_token}"})
        assert r2.status_code == 200

        # 3. Vuln: Weak JWT forgery succeeds
        forged = jwt.encode({"sub": "usr-admin-001", "role": "admin"}, "secret123", algorithm="HS256")
        r3 = client.get("/api/auth/me", headers={"Authorization": f"Bearer {forged}"})
        assert r3.status_code == 200

        # 4. Vuln: S3 posture misconfigured
        r4 = client.get("/api/security/s3-audit", headers={"Authorization": f"Bearer {v_admin_token}"})
        assert r4.status_code == 200
        assert r4.json()["public_access_block"] is False

        # 5. Vuln: ReDoS latency spike (> 50ms on 24 chars)
        r5 = client.post("/api/security/redos-test", json={"payload": ("a" * 24) + "!"})
        assert r5.json()["backtracking_warning"] is True

        # === SWITCH TO REMEDIATED MODE ===
        client.post(
            "/api/security/mode",
            json={"mode": "remediated"},
            headers={"Authorization": f"Bearer {v_admin_token}"}
        )
        s_admin_token = client.post("/api/auth/login", json={
            "email": "admin@dlp-gateway.local",
            "password": "Admin@12345"
        }).json()["access_token"]
        s_user_token = client.post("/api/auth/login", json={
            "email": "demo@dlp-gateway.local",
            "password": "User@12345"
        }).json()["access_token"]

        # 1. Fix: Path traversal & invalid extension blocked
        f1 = client.post(
            "/api/scan/upload",
            files={"file": ("../poc_test_escape.txt", b"test", "text/plain")},
            headers={"Authorization": f"Bearer {s_user_token}"}
        )
        assert f1.status_code == 400

        f1_ext = client.post(
            "/api/scan/upload",
            files={"file": ("malware.exe", b"MZ", "application/octet-stream")},
            headers={"Authorization": f"Bearer {s_user_token}"}
        )
        assert f1_ext.status_code == 400

        # 2. Fix: IDOR blocked with 403
        f2 = client.get(f"/api/events/{target_scan_id}", headers={"Authorization": f"Bearer {s_user_token}"})
        assert f2.status_code == 403

        # 3. Fix: Forged weak JWT rejected with 401
        f3 = client.get("/api/auth/me", headers={"Authorization": f"Bearer {forged}"})
        assert f3.status_code == 401

        # 4. Fix: S3 posture enforces private + AES256
        f4 = client.get("/api/security/s3-audit", headers={"Authorization": f"Bearer {s_admin_token}"})
        assert f4.status_code == 200
        assert f4.json()["public_access_block"] is True
        assert "AES-256" in f4.json()["default_encryption"]

        # 5. Fix: ReDoS runs in linear time (< 50ms)
        f5 = client.post("/api/security/redos-test", json={"payload": ("a" * 24) + "!"})
        assert f5.json()["backtracking_warning"] is False
        assert f5.json()["execution_time_ms"] < 50.0
