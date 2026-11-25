"""
Scan Events & Audit Logs Routes.
Demonstrates Vulnerability #2 (Broken Access Control / IDOR) when SECURITY_MODE == 'vulnerable'.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.auth import get_current_user
from backend.config import settings
from database.connection import DatabaseManager

router = APIRouter(prefix="/api", tags=["Events & Audit Logs"])


@router.get("/events")
async def list_scan_events(
    action: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user)
):
    events_col = DatabaseManager.get_scan_events_col()
    query = {}

    # In remediated mode, non-admins only see their own events
    if settings.SECURITY_MODE != "vulnerable" and current_user["role"] != "admin":
        query["user_id"] = current_user["id"]

    if action:
        query["policy_action"] = action.upper()
    if risk_level:
        query["risk_level"] = risk_level.upper()

    events = await events_col.find(query).sort("timestamp", -1).limit(limit).to_list(length=limit)
    return {
        "count": len(events),
        "security_mode": settings.SECURITY_MODE,
        "events": events
    }


@router.get("/events/{event_id}")
async def get_scan_event_detail(
    event_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Retrieves full detection detail for a specific scan event.
    - Vulnerable mode: IDOR — any authenticated user can inspect any user's scan by ID!
    - Remediated mode: Enforces strict ownership / admin RBAC check.
    """
    events_col = DatabaseManager.get_scan_events_col()
    event = await events_col.find_one({"id": event_id})
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan event '{event_id}' not found."
        )

    if settings.SECURITY_MODE != "vulnerable":
        # REMEDIATED: Verify record ownership or admin role
        if current_user["role"] != "admin" and event["user_id"] != current_user["id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access Denied (IDOR Prevented): You are not authorized to inspect another user's DLP scan event."
            )

    return {
        "security_mode": settings.SECURITY_MODE,
        "event": event
    }


@router.get("/audit-logs")
async def list_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user)
):
    """Retrieves audit trail logs."""
    audit_col = DatabaseManager.get_audit_logs_col()
    query = {}
    if settings.SECURITY_MODE != "vulnerable" and current_user["role"] != "admin":
        query["actor_id"] = current_user["id"]

    logs = await audit_col.find(query).sort("timestamp", -1).limit(limit).to_list(length=limit)
    return {
        "count": len(logs),
        "logs": logs
    }
