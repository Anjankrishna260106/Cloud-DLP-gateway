"""
Phase 1 End-to-End Integration Verification Suite.
Verifies all 8 core modules:
1. Auth (JWT register/login/logout/me)
2. File upload (txt, csv, pdf, docx, xlsx)
3. Text extraction engine
4. Detection engine (emails, phones, PAN, Aadhaar, cards, API keys, AWS keys, passwords)
5. Risk classification
6. Policy engine (ALLOW, MASK, QUARANTINE, BLOCK)
7. S3 two-bucket storage routing (safe vs quarantine vs none)
8. Dashboard telemetry & event detail inspection
"""

import io
import os
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.main import app


def _create_sample_docx_bytes(text: str) -> bytes:
    import docx
    doc = docx.Document()
    doc.add_paragraph(text)
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _create_sample_xlsx_bytes(rows: list) -> bytes:
    import openpyxl
    wb = openpyxl.Workbook()
    ws = wb.active
    for row in rows:
        ws.append(row)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _create_sample_pdf_bytes(text: str) -> bytes:
    import fitz
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), text)
    return doc.tobytes()


def test_end_to_end_phase1_scenarios():
    with TestClient(app) as client:
        # 0. Health check
        h = client.get("/api/health")
        assert h.status_code == 200
        assert h.json()["status"] == "healthy"

        # 1. Auth login (seeded admin)
        login_res = client.post("/api/auth/login", json={
            "email": "admin@dlp-gateway.local",
            "password": "Admin@12345"
        })
        assert login_res.status_code == 200
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Scenario 1: Safe file -> ALLOW -> Safe Bucket
        with open("test-files/demo_1_safe.txt", "rb") as f:
            r1 = client.post("/api/scan/upload", files={"file": ("demo_1_safe.txt", f, "text/plain")}, headers=headers)
        assert r1.status_code == 200
        d1 = r1.json()
        assert d1["stored_in_s3"] is True
        assert d1["event"]["policy_action"] == "ALLOW"
        assert d1["event"]["risk_level"] == "PUBLIC"
        assert d1["event"]["destination_bucket"] == "cloudguard-dlp-safe-bucket"

        # 3. Scenario 2: Email + Phone -> MASK -> Sanitized file stored in Safe Bucket
        with open("test-files/demo_2_mask_pii.txt", "rb") as f:
            r2 = client.post("/api/scan/upload", files={"file": ("demo_2_mask_pii.txt", f, "text/plain")}, headers=headers)
        assert r2.status_code == 200
        d2 = r2.json()
        assert d2["stored_in_s3"] is True
        assert d2["event"]["policy_action"] == "MASK"
        assert d2["event"]["destination_bucket"] == "cloudguard-dlp-safe-bucket"
        assert "p***@example.com" in d2["event"]["masked_preview"]
        assert "priya.sharma.demo@example.com" not in d2["event"]["masked_preview"]
        # Download sanitized file
        dl2 = client.get(f"/api/scan/download/{d2['scan_id']}", headers=headers)
        assert dl2.status_code == 200
        assert b"p***@example.com" in dl2.content

        # 4. Scenario 3: PAN + Card + Phone -> HIGH -> QUARANTINE
        with open("test-files/demo_3_quarantine_financial.csv", "rb") as f:
            r3 = client.post("/api/scan/upload", files={"file": ("demo_3_quarantine_financial.csv", f, "text/csv")}, headers=headers)
        assert r3.status_code == 200
        d3 = r3.json()
        assert d3["stored_in_s3"] is True
        assert d3["event"]["policy_action"] == "QUARANTINE"
        assert d3["event"]["risk_level"] == "HIGH"
        assert d3["event"]["destination_bucket"] == "cloudguard-dlp-quarantine-bucket"
        assert d3["event"]["summary_by_type"].get("PAN", 0) >= 3
        assert d3["event"]["summary_by_type"].get("CREDIT_CARD", 0) >= 3

        # 5. Scenario 4: AWS Key + API Key -> CRITICAL -> BLOCK
        with open("test-files/demo_4_block_credentials.txt", "rb") as f:
            r4 = client.post("/api/scan/upload", files={"file": ("demo_4_block_credentials.txt", f, "text/plain")}, headers=headers)
        assert r4.status_code == 200
        d4 = r4.json()
        assert d4["upload_status"] == "REJECTED_BY_DLP"
        assert d4["stored_in_s3"] is False
        assert d4["event"]["policy_action"] == "BLOCK"
        assert d4["event"]["risk_level"] == "CRITICAL"
        assert d4["event"]["destination_bucket"] is None

        # 6. Multi-format extractors (PDF, DOCX, XLSX)
        pdf_bytes = _create_sample_pdf_bytes("Confidential user email: pdf.tester@example.com")
        r_pdf = client.post("/api/scan/upload", files={"file": ("sample.pdf", pdf_bytes, "application/pdf")}, headers=headers)
        assert r_pdf.status_code == 200
        assert r_pdf.json()["event"]["extractor_used"] == "pymupdf_fitz"
        assert r_pdf.json()["event"]["policy_action"] == "MASK"

        docx_bytes = _create_sample_docx_bytes("Clean DOCX engineering memo with zero secrets.")
        r_docx = client.post("/api/scan/upload", files={"file": ("memo.docx", docx_bytes, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")}, headers=headers)
        assert r_docx.status_code == 200
        assert r_docx.json()["event"]["extractor_used"] == "python_docx"
        assert r_docx.json()["event"]["policy_action"] == "ALLOW"

        xlsx_bytes = _create_sample_xlsx_bytes([["Name", "PAN"], ["Test User", "ABCPA1234F"]])
        r_xlsx = client.post("/api/scan/upload", files={"file": ("records.xlsx", xlsx_bytes, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}, headers=headers)
        assert r_xlsx.status_code == 200
        assert r_xlsx.json()["event"]["extractor_used"] == "openpyxl_pandas"
        assert r_xlsx.json()["event"]["summary_by_type"].get("PAN", 0) == 1

        # 7. Dashboard stats & event detail click-through (Scenario 5)
        stats = client.get("/api/dashboard/stats", headers=headers)
        assert stats.status_code == 200
        s_json = stats.json()
        assert s_json["total_files_scanned"] >= 7
        assert s_json["action_breakdown"]["ALLOW"] >= 2
        assert s_json["action_breakdown"]["MASK"] >= 2
        assert s_json["action_breakdown"]["QUARANTINE"] >= 1
        assert s_json["action_breakdown"]["BLOCK"] >= 1

        detail = client.get(f"/api/events/{d3['scan_id']}", headers=headers)
        assert detail.status_code == 200
        assert detail.json()["event"]["id"] == d3["scan_id"]
        assert len(detail.json()["event"]["findings"]) > 0

        # 8. Policy & Audit Log endpoints
        pols = client.get("/api/policies", headers=headers)
        assert pols.status_code == 200
        assert len(pols.json()["policies"]) >= 4

        aud = client.get("/api/audit-logs", headers=headers)
        assert aud.status_code == 200
        assert aud.json()["count"] >= 7
