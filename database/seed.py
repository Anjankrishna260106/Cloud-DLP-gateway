"""
Database Seed Script: Populates initial roles, policies, and demo audit entries.
"""

import asyncio
import os
import sys
import hashlib
from datetime import datetime, timezone

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import bcrypt

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

from database.connection import DatabaseManager


async def seed_database():
    db = await DatabaseManager.connect()
    users_col = DatabaseManager.get_users_col()
    policies_col = DatabaseManager.get_policies_col()

    # 1. Seed Users
    admin_exists = await users_col.find_one({"email": "admin@dlp-gateway.local"})
    if not admin_exists:
        await users_col.insert_one({
            "id": "usr-admin-001",
            "email": "admin@dlp-gateway.local",
            "hashed_password": hash_password("Admin@12345"),
            "full_name": "Cloud Security Administrator",
            "role": "admin",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "is_active": True
        })
        print("[SEED] Created admin user: admin@dlp-gateway.local (pass: Admin@12345)")

    auditor_exists = await users_col.find_one({"email": "auditor@dlp-gateway.local"})
    if not auditor_exists:
        await users_col.insert_one({
            "id": "usr-auditor-002",
            "email": "auditor@dlp-gateway.local",
            "hashed_password": hash_password("Auditor@12345"),
            "full_name": "Compliance Auditor",
            "role": "user",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "is_active": True
        })
        print("[SEED] Created auditor user: auditor@dlp-gateway.local (pass: Auditor@12345)")

    demo_exists = await users_col.find_one({"email": "demo@dlp-gateway.local"})
    if not demo_exists:
        await users_col.insert_one({
            "id": "usr-demo-003",
            "email": "demo@dlp-gateway.local",
            "hashed_password": hash_password("User@12345"),
            "full_name": "Demo Employee",
            "role": "user",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "is_active": True
        })
        print("[SEED] Created demo user: demo@dlp-gateway.local (pass: User@12345)")

    # 2. Seed Default Policies
    policy_count = await policies_col.count_documents()
    if policy_count == 0:
        default_policies = [
            {
                "id": "pol-001",
                "name": "POL-001-STRICT-CREDENTIAL-BLOCK",
                "risk_threshold": "CRITICAL",
                "action": "BLOCK",
                "is_active": True,
                "description": "Block all cloud credentials, AWS secret keys, and passwords from entering cloud storage."
            },
            {
                "id": "pol-002",
                "name": "POL-002-FINANCIAL-IDENTITY-QUARANTINE",
                "risk_threshold": "HIGH",
                "action": "QUARANTINE",
                "is_active": True,
                "description": "Quarantine payment cards, PAN numbers, and high-impact identity records in an isolated bucket."
            },
            {
                "id": "pol-003",
                "name": "POL-003-PII-AUTOMASK",
                "risk_threshold": "MEDIUM / SENSITIVE_LOW",
                "action": "MASK",
                "is_active": True,
                "description": "Automatically redact emails and contact numbers in-flight before safe bucket persistence."
            },
            {
                "id": "pol-000",
                "name": "POL-000-SAFE-PUBLIC-ALLOW",
                "risk_threshold": "PUBLIC",
                "action": "ALLOW",
                "is_active": True,
                "description": "Directly permit files containing zero sensitive indicators to enter safe bucket."
            }
        ]
        for p in default_policies:
            await policies_col.insert_one(p)
        print("[SEED] Populated 4 standard DLP governance policies.")


if __name__ == "__main__":
    asyncio.run(seed_database())
