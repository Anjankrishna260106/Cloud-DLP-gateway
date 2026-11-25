"""
Authentication Routes: Register, Login, Logout, Me.
"""

import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel

from backend.auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
    security_scheme,
    REVOKED_JTIS
)
from backend.audit import log_audit_event
from backend.config import settings
from database.connection import DatabaseManager

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class RegisterRequest(BaseModel):
    email: str
    password: str
    full_name: str
    role: str = "user"


class LoginRequest(BaseModel):
    email: str
    password: str


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest, request: Request):
    users_col = DatabaseManager.get_users_col()
    existing = await users_col.find_one({"email": req.email.lower().strip()})
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email already exists."
        )

    # In remediated mode, prevent self-registration as admin (Privilege Escalation guard)
    assigned_role = req.role if settings.SECURITY_MODE == "vulnerable" else "user"

    user_id = f"usr-{uuid.uuid4().hex[:10]}"
    user_doc = {
        "id": user_id,
        "email": req.email.lower().strip(),
        "hashed_password": hash_password(req.password),
        "full_name": req.full_name.strip(),
        "role": assigned_role,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "is_active": True
    }
    await users_col.insert_one(user_doc)

    await log_audit_event(
        event_type="AUTH_REGISTER",
        severity="INFO",
        actor_id=user_id,
        actor_email=user_doc["email"],
        action_taken=f"Registered user with role '{assigned_role}'",
        ip_address=request.client.host if request.client else "127.0.0.1"
    )

    token = create_access_token(user_id, user_doc["email"], assigned_role)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user_id,
            "email": user_doc["email"],
            "full_name": user_doc["full_name"],
            "role": assigned_role
        }
    }


@router.post("/login")
async def login(req: LoginRequest, request: Request):
    users_col = DatabaseManager.get_users_col()
    user = await users_col.find_one({"email": req.email.lower().strip()})
    if not user or not verify_password(req.password, user["hashed_password"]):
        await log_audit_event(
            event_type="AUTH_FAILED",
            severity="WARNING",
            actor_id="unknown",
            actor_email=req.email,
            action_taken="Failed login attempt",
            ip_address=request.client.host if request.client else "127.0.0.1"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    token = create_access_token(user["id"], user["email"], user["role"])
    await log_audit_event(
        event_type="AUTH_LOGIN",
        severity="INFO",
        actor_id=user["id"],
        actor_email=user["email"],
        action_taken=f"Successful login (security_mode={settings.SECURITY_MODE})",
        ip_address=request.client.host if request.client else "127.0.0.1"
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "security_mode": settings.SECURITY_MODE,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"]
        }
    }


@router.post("/logout")
async def logout(
    request: Request,
    current_user: dict = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme)
):
    jti = current_user.get("jti")
    if jti:
        REVOKED_JTIS.add(jti)

    await log_audit_event(
        event_type="AUTH_LOGOUT",
        severity="INFO",
        actor_id=current_user["id"],
        actor_email=current_user["email"],
        action_taken="User logged out and token revoked",
        ip_address=request.client.host if request.client else "127.0.0.1"
    )
    return {"message": "Successfully logged out."}


@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "user": current_user,
        "security_mode": settings.SECURITY_MODE
    }
