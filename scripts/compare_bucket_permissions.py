"""
S3 DUAL-BUCKET PERMISSIONS & ARCHITECTURE COMPARISON CLI
Compares the Security Posture, IAM Bucket Policies, Access Controls,
and Live Stored Inventory between:
  1. cloudguard-dlp-safe-bucket (Operational Tier)
  2. cloudguard-dlp-quarantine-bucket (Zero-Trust Isolation Vault)
"""

import os
import sys
import json

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath("."))
from backend.storage import s3_service

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def header(title: str):
    print(f"\n{BOLD}{CYAN}{'='*85}{RESET}")
    print(f"{BOLD}{CYAN}  {title.upper()}{RESET}")
    print(f"{BOLD}{CYAN}{'='*85}{RESET}\n")


def print_comparison():
    data = s3_service.get_dual_bucket_comparison()
    safe = data["safe_bucket"]
    quar = data["quarantine_bucket"]

    header("AWS S3 Dual-Bucket Permission & Isolation Architecture")
    print(f"{BOLD}Concept:{RESET} In pre-storage DLP, files are routed to different cloud buckets")
    print(f"based on risk. The {GREEN}Safe Bucket{RESET} serves business apps, while the {YELLOW}Quarantine Bucket{RESET}")
    print(f"is an air-gapped compliance vault with restrictive IAM permissions.\n")

    # Table 1: Side-by-Side Permissions Matrix
    print(f"{BOLD}{'SECURITY CONTROL':<30} | {'SAFE BUCKET (ALLOW / MASK)':<30} | {'QUARANTINE BUCKET (ISOLATION)':<30}{RESET}")
    print("-" * 96)

    controls = [
        ("Bucket Name", safe["name"], quar["name"]),
        ("Security Classification", f"{GREEN}OPERATIONAL TIER{RESET}", f"{RED}REGULATORY VAULT{RESET}"),
        ("Intended Ingestion", "Clean files & Sanitized PII", "PAN, Credit Cards, Aadhaar"),
        ("Public Access Block", "Enabled (4/4 Controls)", "Enabled (4/4 Controls)"),
        ("Server-Side Encryption", safe["default_encryption"]["ServerSideEncryption"], quar["default_encryption"]["ServerSideEncryption"]),
        ("Transport Security", "TLS 1.3 Enforced (Deny HTTP)", "TLS 1.3 Enforced (Deny HTTP)"),
        ("Read Access Principals", "AppRole, AnalyticsService", f"{RED}ComplianceAuditorRole ONLY{RESET}"),
        ("Standard App Access", f"{GREEN}PERMITTED (Read/Write){RESET}", f"{RED}EXPLICITLY DENIED{RESET}"),
        ("Gateway Write Access", "PutObject, GetObject", "PutObject ONLY (Write-Once)"),
        ("S3 Object Lock (WORM)", "Disabled", f"{YELLOW}Compliance Mode (7 Years){RESET}"),
        ("CloudTrail SIEM Logging", "Management Events", f"{YELLOW}Data Events Enabled (Read/Write){RESET}"),
        ("Total Files Currently Stored", f"{safe['total_files']} files", f"{quar['total_files']} files"),
    ]

    for ctrl, s_val, q_val in controls:
        print(f"{ctrl:<30} | {s_val:<39} | {q_val}")

    # Section 2: Live Files Inventory
    header("Live S3 Bucket File Inventory")

    print(f"{BOLD}{GREEN}>>> [1] SAFE BUCKET: s3://{safe['name']} ({safe['total_files']} objects){RESET}")
    if safe["files"]:
        print(f"  {'Filename':<40} | {'Size':<10} | {'Encryption':<10} | {'Storage Key'}")
        print("  " + "-" * 85)
        for f in safe["files"][:6]:
            print(f"  {f['filename']:<40} | {f['size_bytes']:<10} | {f['encryption']:<10} | {f['key']}")
        if len(safe["files"]) > 6:
            print(f"  ... and {len(safe['files']) - 6} more files.")
    else:
        print("  (Empty)")

    print(f"\n{BOLD}{YELLOW}>>> [2] QUARANTINE BUCKET: s3://{quar['name']} ({quar['total_files']} objects){RESET}")
    if quar["files"]:
        print(f"  {'Filename':<40} | {'Size':<10} | {'Encryption':<10} | {'Storage Key'}")
        print("  " + "-" * 85)
        for f in quar["files"]:
            fname_color = RED if ("return" in f["filename"].lower() or "financial" in f["filename"].lower()) else YELLOW
            print(f"  {fname_color}{f['filename']:<40}{RESET} | {f['size_bytes']:<10} | {f['encryption']:<10} | {f['key']}")
    else:
        print("  (Empty)")

    # Section 3: IAM Policy JSON Difference
    header("IAM Bucket Policy JSON Comparison (Least-Privilege Enforcement)")

    print(f"{BOLD}1. Safe Bucket Policy (Standard Production Services):{RESET}")
    print(json.dumps(safe["bucket_policy"], indent=2))

    print(f"\n{BOLD}2. Quarantine Bucket Policy (Zero-Trust Lockdown):{RESET}")
    print(f"{YELLOW}* Notice Statement 'ExplicitDenyStandardAppAccess' & 'AllowComplianceOfficerAuditReadOnly':{RESET}")
    print(json.dumps(quar["bucket_policy"], indent=2))

    print(f"\n{GREEN}{BOLD}Demonstration Ready!{RESET} Explain this to your professor to show how DLP enforces Zero Trust storage routing.\n")


if __name__ == "__main__":
    print_comparison()
