"""
Policy Configuration Routes.
"""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.auth import get_current_user, require_admin
from backend.audit import log_audit_event
from database.connection import DatabaseManager

router = APIRouter(prefix="/api/policies", tags=["Policy Engine"])


class PolicyUpdateRequest(BaseModel):
    action: str
    is_active: bool
    description: str


@router.get("")
async def get_policies(current_user: dict = Depends(get_current_user)):
    policies_col = DatabaseManager.get_policies_col()
    policies = await policies_col.find().to_list(length=50)
    return {"policies": policies}


@router.put("/{policy_id}")
async def update_policy(
    policy_id: str,
    req: PolicyUpdateRequest,
    current_user: dict = Depends(require_admin)
):
    policies_col = DatabaseManager.get_policies_col()
    existing = await policies_col.find_one({"id": policy_id})
    if not existing:
        raise HTTPException(status_code=404, detail="Policy not found.")

    valid_actions = {"ALLOW", "MASK", "QUARANTINE", "BLOCK"}
    if req.action.upper() not in valid_actions:
        raise HTTPException(status_code=400, detail=f"Invalid action. Must be one of {valid_actions}")

    await policies_col.update_one(
        {"id": policy_id},
        {
            "$set": {
                "action": req.action.upper(),
                "is_active": req.is_active,
                "description": req.description,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
        }
    )

    await log_audit_event(
        event_type="POLICY_UPDATE",
        severity="WARNING",
        actor_id=current_user["id"],
        actor_email=current_user["email"],
        action_taken=f"Updated policy {policy_id} -> action={req.action.upper()}, active={req.is_active}"
    )

    updated = await policies_col.find_one({"id": policy_id})
    return {"policy": updated}
