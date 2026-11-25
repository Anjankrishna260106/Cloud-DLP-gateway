"""
Policy Engine: Evaluates scan findings and determines routing action.
Actions:
 - ALLOW: Route original file to safe S3 bucket.
 - MASK: Redact sensitive entities; route sanitized file to safe S3 bucket.
 - QUARANTINE: Route original sensitive file to quarantine S3 bucket (isolated).
 - BLOCK: Reject upload entirely; do NOT write to S3; log security block event.
"""

from enum import Enum
from typing import Dict, Any, Optional
from pydantic import BaseModel
try:
    from .classifiers import RiskLevel, RiskReport
    from .detectors import EntityType
except (ImportError, ValueError):
    from classifiers import RiskLevel, RiskReport
    from detectors import EntityType


class DLPAction(str, Enum):
    ALLOW = "ALLOW"
    MASK = "MASK"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"


class PolicyDecision(BaseModel):
    action: DLPAction
    destination_bucket: Optional[str]  # "safe-bucket", "quarantine-bucket", None
    policy_name: str
    decision_reason: str
    requires_sanitization: bool


class PolicyConfig(BaseModel):
    allow_public: bool = True
    mask_pii: bool = True
    quarantine_financial: bool = True
    block_credentials: bool = True
    custom_rules: Dict[str, str] = {}


class PolicyEngine:
    """Evaluates risk classification against active DLP gateway policies."""

    def __init__(self, config: Optional[PolicyConfig] = None):
        self.config = config or PolicyConfig()

    def evaluate(
        self,
        risk_report: RiskReport,
        safe_bucket_name: str = "dlp-safe-bucket",
        quarantine_bucket_name: str = "dlp-quarantine-bucket"
    ) -> PolicyDecision:
        counts = risk_report.summary_counts

        # Rule 1: CRITICAL Risk (AWS Keys, Passwords, API Keys) -> BLOCK
        if risk_report.risk_level == RiskLevel.CRITICAL:
            return PolicyDecision(
                action=DLPAction.BLOCK,
                destination_bucket=None,
                policy_name="POL-001-STRICT-CREDENTIAL-BLOCK",
                decision_reason=(
                    f"Blocked: High-risk secrets/credentials detected ({risk_report.primary_risk_driver}). "
                    "In accordance with Zero Trust storage rules, secret leaks are prohibited from upload."
                ),
                requires_sanitization=False
            )

        # Rule 2: HIGH Risk (PAN, Credit Card, multi-vector identity) -> QUARANTINE
        if risk_report.risk_level == RiskLevel.HIGH:
            return PolicyDecision(
                action=DLPAction.QUARANTINE,
                destination_bucket=quarantine_bucket_name,
                policy_name="POL-002-FINANCIAL-IDENTITY-QUARANTINE",
                decision_reason=(
                    f"Quarantined: Sensitive financial or high-impact identity records detected "
                    f"({risk_report.primary_risk_driver}). Stored in isolated quarantine bucket for compliance audit."
                ),
                requires_sanitization=False
            )

        # Rule 3: MEDIUM or SENSITIVE_LOW (Emails, Phone numbers) -> MASK
        if risk_report.risk_level in [RiskLevel.MEDIUM, RiskLevel.SENSITIVE_LOW]:
            return PolicyDecision(
                action=DLPAction.MASK,
                destination_bucket=safe_bucket_name,
                policy_name="POL-003-PII-AUTOMASK",
                decision_reason=(
                    f"Masked: Non-critical personal identifiable information detected "
                    f"({risk_report.primary_risk_driver}). Entities redacted in-flight before safe storage."
                ),
                requires_sanitization=True
            )

        # Rule 4: PUBLIC (No sensitive entities detected) -> ALLOW
        return PolicyDecision(
            action=DLPAction.ALLOW,
            destination_bucket=safe_bucket_name,
            policy_name="POL-000-SAFE-PUBLIC-ALLOW",
            decision_reason="Allowed: Payload inspected; no sensitive patterns or credentials found.",
            requires_sanitization=False
        )
