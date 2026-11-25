"""
Pydantic Data Models and Schemas for MongoDB Atlas.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class UserRole(str):
    ADMIN = "admin"
    USER = "user"


class UserModel(BaseModel):
    id: str = Field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f"))
    email: str
    hashed_password: str
    full_name: str
    role: str = "user"  # "admin" or "user"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True


class FindingDetail(BaseModel):
    entity_type: str
    value_preview: str  # Partially masked or redacted
    start: int
    end: int
    confidence: float
    context_snippet: str
    validation_status: str


class ScanEventModel(BaseModel):
    id: str
    filename: str
    sanitized_filename: Optional[str] = None
    file_size_bytes: int
    extractor_used: str
    risk_level: str
    risk_score: int
    policy_action: str  # ALLOW, MASK, QUARANTINE, BLOCK
    destination_bucket: Optional[str] = None
    s3_key: Optional[str] = None
    policy_name: str
    decision_reason: str
    findings_count: int
    summary_by_type: Dict[str, int] = Field(default_factory=dict)
    findings: List[FindingDetail] = Field(default_factory=list)
    masked_preview: Optional[str] = None
    processing_time_ms: float
    user_id: str
    user_email: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PolicyRuleModel(BaseModel):
    id: str
    name: str
    entity_type: Optional[str] = None
    risk_threshold: Optional[str] = None
    action: str
    is_active: bool = True
    description: str
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AuditLogModel(BaseModel):
    id: str
    event_type: str  # UPLOAD_SCAN, AUTH_LOGIN, POLICY_UPDATE, SECURITY_ALERT, ACCESS_DENIED
    severity: str    # INFO, WARNING, CRITICAL
    actor_id: str
    actor_email: str
    action_taken: str
    details: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = "127.0.0.1"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
