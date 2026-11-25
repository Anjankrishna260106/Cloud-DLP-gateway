"""
Seminar Security Demo Controls & Vulnerability Testing Endpoints.
Allows toggling between 'vulnerable' and 'remediated' modes and inspecting
S3 bucket policies and ReDoS timing behavior safely.
"""

import re
import time
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.auth import get_current_user
from backend.config import settings
from backend.storage import s3_service
from backend.audit import log_audit_event

router = APIRouter(prefix="/api/security", tags=["Seminar Security Lab"])


class ModeSwitchRequest(BaseModel):
    mode: str  # "vulnerable" or "remediated"


class ReDoSTestRequest(BaseModel):
    payload: str


@router.get("/mode")
async def get_security_mode():
    return {
        "security_mode": settings.SECURITY_MODE,
        "jwt_config": {
            "secret_strength": "WEAK ('secret123')" if settings.SECURITY_MODE == "vulnerable" else "STRONG (256-bit random)",
            "token_expiry": "NONE (Infinite)" if settings.SECURITY_MODE == "vulnerable" else f"{settings.JWT_EXPIRE_MINUTES} minutes"
        },
        "s3_posture": s3_service.get_bucket_security_posture()
    }


@router.post("/mode")
async def set_security_mode(
    req: ModeSwitchRequest,
    current_user: dict = Depends(get_current_user)
):
    target_mode = req.mode.lower().strip()
    if target_mode not in {"vulnerable", "remediated"}:
        raise HTTPException(status_code=400, detail="Mode must be 'vulnerable' or 'remediated'.")

    settings.SECURITY_MODE = target_mode
    await log_audit_event(
        event_type="SECURITY_MODE_CHANGE",
        severity="WARNING" if target_mode == "vulnerable" else "INFO",
        actor_id=current_user["id"],
        actor_email=current_user["email"],
        action_taken=f"Switched gateway security mode to '{target_mode}'"
    )
    return {
        "security_mode": settings.SECURITY_MODE,
        "message": f"Gateway switched to {target_mode.upper()} mode."
    }


@router.get("/s3-audit")
async def audit_s3_buckets(current_user: dict = Depends(get_current_user)):
    """Returns S3 bucket policy and encryption configuration for Vulnerability #4 demo."""
    return s3_service.get_bucket_security_posture()


@router.get("/buckets-comparison")
async def get_buckets_comparison(current_user: dict = Depends(get_current_user)):
    """Returns detailed architecture & permission comparison between Safe and Quarantine buckets."""
    return s3_service.get_dual_bucket_comparison()


@router.post("/redos-test")
async def test_redos_regex(req: ReDoSTestRequest):
    """
    Safely benchmarks vulnerable nested-quantifier regex vs bounded linear regex
    for Vulnerability #5 (ReDoS) live demo. Caps input length to prevent server DoS.
    """
    test_str = req.payload[:30] if settings.SECURITY_MODE == "vulnerable" else req.payload[:1000]

    start = time.perf_counter()
    if settings.SECURITY_MODE == "vulnerable":
        # Vulnerable nested quantifier regex: (a+)+
        vuln_regex = re.compile(r"^([a-zA-Z0-9_.-]+)+@([a-zA-Z0-9_.-]+)+\.([a-zA-Z0-9_.-]+)+$")
        matched = bool(vuln_regex.match(test_str))
        pattern_used = r"^([a-zA-Z0-9_.-]+)+@([a-zA-Z0-9_.-]+)+\.([a-zA-Z0-9_.-]+)+$"
    else:
        # Remediated linear-time regex
        safe_regex = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,128}\.[A-Za-z]{2,10}$")
        matched = bool(safe_regex.match(test_str))
        pattern_used = r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,128}\.[A-Za-z]{2,10}$"

    elapsed_ms = round((time.perf_counter() - start) * 1000, 3)

    return {
        "security_mode": settings.SECURITY_MODE,
        "input_length_tested": len(test_str),
        "regex_pattern": pattern_used,
        "matched": matched,
        "execution_time_ms": elapsed_ms,
        "backtracking_warning": elapsed_ms > 50.0
    }
