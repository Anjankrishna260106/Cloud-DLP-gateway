"""
Automated Phase 1 Live Demo Runner.
Executes Demo Scenarios 1-4 against the running FastAPI DLP Gateway (http://localhost:8000).
"""

import os
import requests

BASE_URL = os.getenv("DLP_API_URL", "http://localhost:8000")


def run_demo():
    print(f"Connecting to CloudGuard DLP Gateway at {BASE_URL}...")
    r = requests.get(f"{BASE_URL}/api/health", timeout=5)
    r.raise_for_status()
    print("Health:", r.json())

    # 1. Authenticate
    login = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": "admin@dlp-gateway.local", "password": "Admin@12345"},
        timeout=5,
    )
    login.raise_for_status()
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("\nAuthenticated as admin@dlp-gateway.local (role: admin)\n")

    # 2. Run Scenarios 1-4
    scenarios = [
        ("Scenario 1 (Safe -> ALLOW)", "test-files/demo_1_safe.txt"),
        ("Scenario 2 (PII -> MASK)", "test-files/demo_2_mask_pii.txt"),
        ("Scenario 3 (Financial -> QUARANTINE)", "test-files/demo_3_quarantine_financial.csv"),
        ("Scenario 4 (Credentials -> BLOCK)", "test-files/demo_4_block_credentials.txt"),
    ]

    print(f"{'Scenario':<38} | {'Scan ID':<10} | {'Risk':<13} | {'Action':<11} | {'Bucket'}")
    print("-" * 110)

    for label, filepath in scenarios:
        filename = os.path.basename(filepath)
        with open(filepath, "rb") as f:
            resp = requests.post(
                f"{BASE_URL}/api/scan/upload",
                files={"file": (filename, f)},
                headers=headers,
                timeout=15,
            )
        resp.raise_for_status()
        data = resp.json()
        ev = data["event"]
        bucket = ev.get("destination_bucket") or "REJECTED (No S3 Write)"
        print(
            f"{label:<38} | {ev['id']:<10} | {ev['risk_level']:<13} | {ev['policy_action']:<11} | {bucket}"
        )
        if ev["policy_action"] == "MASK" and ev.get("masked_preview"):
            print("  -> Masked Preview:", ev["masked_preview"].splitlines()[2:5])

    # 3. Dashboard summary
    stats = requests.get(f"{BASE_URL}/api/dashboard/stats", headers=headers, timeout=5).json()
    print("\nDashboard Telemetry Summary:")
    print(f"  Total Files Scanned:      {stats['total_files_scanned']}")
    print(f"  Total Sensitive Findings: {stats['total_sensitive_findings']}")
    print(f"  Action Breakdown:         {stats['action_breakdown']}")
    print(f"  Entity Type Breakdown:    {stats['entity_type_breakdown']}")


if __name__ == "__main__":
    run_demo()
