"""
Authentication & Authorization Module (JWT + RBAC).
Supports toggling between remediated (secure) and vulnerable (weak secret / no expiry)
behavior for live cloud security seminar demonstrations.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Set

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt

from backend.config import settings
from database.connection import DatabaseManager

security_scheme = HTTPBearer(auto_error=False)

# In-memory token revocation list for explicit logout
REVOKED_JTIS: Set[str] = set()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


def create_access_token(user_id: str, email: str, role: str) -> str:
    """
    Issues a JWT access token.
    - Remediated mode: Strong secret, 30-min expiration, JTI, issued-at.
    - Vulnerable mode: Weak hardcoded secret ('secret123'), NO expiration claim.
    """
    now = datetime.now(timezone.utc)
    if settings.SECURITY_MODE == "vulnerable":
        # VULNERABLE: Weak secret + no 'exp' claim (infinite session validity)
        payload = {
            "sub": user_id,
            "email": email,
            "role": role,
            "iat": int(now.timestamp()),
            "mode": "vulnerable"
        }
        return jwt.encode(payload, settings.VULN_WEAK_JWT_SECRET, algorithm="HS256")
    else:
        # REMEDIATED: Strong secret + short-lived expiry + JTI for revocation
        expire = now + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
        payload = {
            "sub": user_id,
            "email": email,
            "role": role,
            "jti": str(uuid.uuid4()),
            "iat": int(now.timestamp()),
            "exp": int(expire.timestamp()),
            "mode": "remediated"
        }
        return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decodes and validates JWT based on current security mode."""
    secret = (
        settings.VULN_WEAK_JWT_SECRET
        if settings.SECURITY_MODE == "vulnerable"
        else settings.JWT_SECRET_KEY
    )
    options = {"verify_exp": settings.SECURITY_MODE != "vulnerable"}
    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=[settings.JWT_ALGORITHM],
            options=options
        )
        jti = payload.get("jti")
        if jti and jti in REVOKED_JTIS:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked (logged out)."
            )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired authentication token: {str(e)}"
        )


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme)
) -> dict:
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided."
        )
    payload = decode_access_token(credentials.credentials)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token payload."
        )

    users_col = DatabaseManager.get_users_col()
    user = await users_col.find_one({"id": user_id})
    if not user:
        # In vulnerable mode, an attacker forging a JWT with role=admin for an arbitrary sub
        # might even spoof identity if DB check is skipped; we keep DB lookup or allow forged claims demo
        if settings.SECURITY_MODE == "vulnerable" and payload.get("role"):
            return {
                "id": user_id,
                "email": payload.get("email", "forged@attacker.local"),
                "role": payload.get("role", "user"),
                "full_name": "JWT Token Identity"
            }
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found."
        )
    # In vulnerable mode, trust role claim from token directly (even if forged with weak secret)
    effective_role = payload.get("role", user["role"]) if settings.SECURITY_MODE == "vulnerable" else user["role"]
    return {
        "id": user["id"],
        "email": user["email"],
        "full_name": user["full_name"],
        "role": effective_role,
        "jti": payload.get("jti")
    }


async def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required for this operation."
        )
    return current_user
