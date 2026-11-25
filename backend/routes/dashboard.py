"""
Security Dashboard Analytics Routes.
"""

from fastapi import APIRouter, Depends

from backend.auth import get_current_user
from backend.config import settings
from database.connection import DatabaseManager

router = APIRouter(prefix="/api/dashboard", tags=["Security Dashboard"])


@router.get("/stats")
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    events_col = DatabaseManager.get_scan_events_col()
    query = {}
    if settings.SECURITY_MODE != "vulnerable" and current_user["role"] != "admin":
        query["user_id"] = current_user["id"]

    all_events = await events_col.find(query).sort("timestamp", -1).to_list(length=500)

    action_counts = {"ALLOW": 0, "MASK": 0, "QUARANTINE": 0, "BLOCK": 0}
    risk_counts = {"PUBLIC": 0, "SENSITIVE_LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    entity_type_counts = {}
    total_findings = 0

    for ev in all_events:
        act = ev.get("policy_action", "ALLOW")
        action_counts[act] = action_counts.get(act, 0) + 1

        rl = ev.get("risk_level", "PUBLIC")
        risk_counts[rl] = risk_counts.get(rl, 0) + 1

        total_findings += ev.get("findings_count", 0)
        for etype, cnt in ev.get("summary_by_type", {}).items():
            entity_type_counts[etype] = entity_type_counts.get(etype, 0) + cnt

    return {
        "total_files_scanned": len(all_events),
        "total_sensitive_findings": total_findings,
        "action_breakdown": action_counts,
        "risk_breakdown": risk_counts,
        "entity_type_breakdown": entity_type_counts,
        "recent_events": all_events[:10],
        "security_mode": settings.SECURITY_MODE,
        "database_mode": "MongoDB Atlas" if DatabaseManager.is_live_atlas else "Local Persistent Store"
    }
