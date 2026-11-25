"""
Audit Logging Service for MongoDB Atlas.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from database.connection import DatabaseManager


async def log_audit_event(
    event_type: str,
    severity: str,
    actor_id: str,
    actor_email: str,
    action_taken: str,
    details: Optional[Dict[str, Any]] = None,
    ip_address: str = "127.0.0.1"
) -> Dict[str, Any]:
    """Inserts an immutable audit log record into MongoDB."""
    audit_col = DatabaseManager.get_audit_logs_col()
    record = {
        "id": f"aud-{uuid.uuid4().hex[:12]}",
        "event_type": event_type,
        "severity": severity,
        "actor_id": actor_id,
        "actor_email": actor_email,
        "action_taken": action_taken,
        "details": details or {},
        "ip_address": ip_address,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    await audit_col.insert_one(record)
    return record
