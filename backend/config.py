"""
Application Configuration & Runtime Security Mode Settings.
"""

import os
import secrets
from typing import Set
from dotenv import load_dotenv

load_dotenv()


class Settings:
    APP_NAME: str = "CloudGuard Pre-Storage DLP Gateway"
    APP_VERSION: str = "1.0.0"

    # Database (MongoDB Atlas or automatic local fallback)
    MONGODB_URI: str = os.getenv("MONGODB_URI", "")
    MONGODB_DB_NAME: str = os.getenv("MONGODB_DB_NAME", "dlp_gateway")

    # Security Mode: "remediated" (default secure) or "vulnerable" (seminar exploit demo)
    SECURITY_MODE: str = os.getenv("SECURITY_MODE", "remediated").lower()

    # JWT Configuration
    # Strong secret generated or read from env for remediated mode
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY") or secrets.token_urlsafe(32)
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "30"))

    # Intentionally weak secret used ONLY when SECURITY_MODE == "vulnerable"
    VULN_WEAK_JWT_SECRET: str = "secret123"

    # AWS S3 Configuration
    AWS_ACCESS_KEY_ID: str = os.getenv("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY: str = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    AWS_REGION: str = os.getenv("AWS_REGION", "ap-south-1")
    AWS_SAFE_BUCKET: str = os.getenv("AWS_SAFE_BUCKET", "cloudguard-dlp-safe-bucket")
    AWS_QUARANTINE_BUCKET: str = os.getenv("AWS_QUARANTINE_BUCKET", "cloudguard-dlp-quarantine-bucket")
    AWS_ENDPOINT_URL: str = os.getenv("AWS_ENDPOINT_URL", "")

    # Upload Validation Limits
    MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB
    ALLOWED_EXTENSIONS: Set[str] = {"txt", "csv", "pdf", "docx", "xlsx"}

    # CORS
    CORS_ORIGINS: list = [
        origin.strip()
        for origin in os.getenv("CORS_ORIGINS", "*").split(",")
        if origin.strip()
    ]


settings = Settings()
