"""
Risk classification and scoring engine.
Categorizes scan results into:
 - PUBLIC (Score 0)
 - SENSITIVE_LOW (Score 1-30)
 - MEDIUM (Score 31-60)
 - HIGH (Score 61-85)
 - CRITICAL (Score 86-100)
"""

from enum import Enum
from typing import List, Dict
from pydantic import BaseModel
try:
    from .detectors import Finding, EntityType
except (ImportError, ValueError):
    from detectors import Finding, EntityType


class RiskLevel(str, Enum):
    PUBLIC = "PUBLIC"
    SENSITIVE_LOW = "SENSITIVE_LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Base severity weights per entity type
ENTITY_WEIGHTS: Dict[EntityType, int] = {
    EntityType.EMAIL: 12,
    EntityType.PHONE: 14,
    EntityType.AADHAAR: 45,
    EntityType.PAN: 55,
    EntityType.CREDIT_CARD: 75,
    EntityType.PASSWORD: 90,
    EntityType.API_KEY: 95,
    EntityType.AWS_KEY: 100,
}


class RiskReport(BaseModel):
    risk_level: RiskLevel
    risk_score: int  # 0 to 100
    summary_counts: Dict[str, int]
    primary_risk_driver: str
    rationale: str


class RiskClassifier:
    """Classifies detected entities into standard cloud security risk tiers."""

    @classmethod
    def evaluate(cls, findings: List[Finding]) -> RiskReport:
        if not findings:
            return RiskReport(
                risk_level=RiskLevel.PUBLIC,
                risk_score=0,
                summary_counts={},
                primary_risk_driver="None",
                rationale="No sensitive entities or secrets detected. Content is classified as safe/public."
            )

        counts: Dict[str, int] = {}
        for f in findings:
            counts[f.entity_type.value] = counts.get(f.entity_type.value, 0) + 1

        # Check for immediate CRITICAL conditions (Secrets / Credentials / Cloud Keys)
        if counts.get(EntityType.AWS_KEY.value, 0) > 0:
            return RiskReport(
                risk_level=RiskLevel.CRITICAL,
                risk_score=100,
                summary_counts=counts,
                primary_risk_driver="AWS Credentials Detected",
                rationale=f"Found {counts[EntityType.AWS_KEY.value]} AWS key(s). Immediate cloud compromise risk."
            )

        if counts.get(EntityType.API_KEY.value, 0) > 0 or counts.get(EntityType.PASSWORD.value, 0) > 0:
            return RiskReport(
                risk_level=RiskLevel.CRITICAL,
                risk_score=95,
                summary_counts=counts,
                primary_risk_driver="API Key or Plaintext Password Detected",
                rationale="Unencrypted credentials or high-privilege access tokens present in payload."
            )

        # Check for HIGH risk conditions (Financial & Core Government Identity)
        has_card = counts.get(EntityType.CREDIT_CARD.value, 0) > 0
        has_pan = counts.get(EntityType.PAN.value, 0) > 0
        has_aadhaar = counts.get(EntityType.AADHAAR.value, 0) > 0
        has_pii = (counts.get(EntityType.EMAIL.value, 0) + counts.get(EntityType.PHONE.value, 0)) > 0

        # Regulated data: Payment Cards, PAN cards, or Aadhaar identity -> HIGH (QUARANTINE)
        if has_card or has_pan or has_aadhaar:
            score = 80 if has_card else 75
            score = min(85, score + min(10, len(findings)))
            return RiskReport(
                risk_level=RiskLevel.HIGH,
                risk_score=score,
                summary_counts=counts,
                primary_risk_driver="Financial / Government Identity Records",
                rationale="High-severity regulated data (Payment Cards, PAN, or national identity) detected."
            )

        # Check for MEDIUM risk conditions (Isolated Aadhaar or multiple PII)
        total_pii = counts.get(EntityType.EMAIL.value, 0) + counts.get(EntityType.PHONE.value, 0)
        if has_pan or has_aadhaar or total_pii >= 3:
            score = 45 + min(15, total_pii * 3)
            return RiskReport(
                risk_level=RiskLevel.MEDIUM,
                risk_score=score,
                summary_counts=counts,
                primary_risk_driver="Aggregated PII / National Identity",
                rationale=f"Detected {total_pii} PII item(s) or government identifiers requiring controlled handling."
            )

        # SENSITIVE_LOW risk condition (1 or 2 standard PII like email/phone)
        score = 15 + min(15, total_pii * 5)
        return RiskReport(
            risk_level=RiskLevel.SENSITIVE_LOW,
            risk_score=score,
            summary_counts=counts,
            primary_risk_driver="Basic PII (Email / Phone)",
            rationale=f"Detected isolated contact details ({total_pii} item(s)). Eligible for automated redaction/masking."
        )
