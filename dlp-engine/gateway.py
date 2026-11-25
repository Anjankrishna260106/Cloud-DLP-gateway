"""
DLPGateway: Pre-Storage Cloud Data Loss Prevention Core Orchestrator.
Intercepts file uploads before persistence, extracts content, analyzes risk,
applies security policies, and dictates storage destination.
"""

import time
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

try:
    from .extractors import extract_text_from_file
    from .detectors import DetectionEngine, Finding
    from .classifiers import RiskClassifier, RiskReport, RiskLevel
    from .policy import PolicyEngine, PolicyDecision, DLPAction, PolicyConfig
    from .sanitizer import DataSanitizer
except (ImportError, ValueError):
    from extractors import extract_text_from_file
    from detectors import DetectionEngine, Finding
    from classifiers import RiskClassifier, RiskReport, RiskLevel
    from policy import PolicyEngine, PolicyDecision, DLPAction, PolicyConfig
    from sanitizer import DataSanitizer


class ScanResult(BaseModel):
    filename: str
    file_size_bytes: int
    extractor_used: str
    extracted_text_preview: str
    findings: List[Finding]
    findings_count: int
    risk_level: RiskLevel
    risk_score: int
    policy_action: DLPAction
    destination_bucket: Optional[str]
    policy_name: str
    decision_reason: str
    is_masked: bool
    masked_text_preview: Optional[str] = None
    sanitized_filename: Optional[str] = None
    processing_time_ms: float
    summary_by_type: Dict[str, int] = Field(default_factory=dict)


class DLPGateway:
    """Pre-Storage DLP Gateway engine."""

    def __init__(self, redos_vulnerable_mode: bool = False, policy_config: Optional[PolicyConfig] = None):
        self.detector = DetectionEngine(redos_vulnerable_mode=redos_vulnerable_mode)
        self.policy_engine = PolicyEngine(config=policy_config)

    def process(
        self,
        file_bytes: bytes,
        filename: str,
        safe_bucket: str = "dlp-safe-bucket",
        quarantine_bucket: str = "dlp-quarantine-bucket"
    ) -> (ScanResult, Optional[bytes]):
        """
        Executes the pre-storage inspection pipeline.
        Returns:
            (ScanResult, payload_to_store_bytes_or_none)
        """
        start_time = time.perf_counter()

        # Step 1: Text extraction
        extracted_text, metadata = extract_text_from_file(file_bytes, filename)

        # Step 2: Detection
        findings = self.detector.detect(extracted_text)

        # Step 3: Classification & Risk Scoring
        risk_report: RiskReport = RiskClassifier.evaluate(findings)

        # Step 4: Policy Decision
        decision: PolicyDecision = self.policy_engine.evaluate(
            risk_report,
            safe_bucket_name=safe_bucket,
            quarantine_bucket_name=quarantine_bucket
        )

        # Step 5: Sanitization / Payload preparation
        payload_to_store: Optional[bytes] = None
        masked_preview: Optional[str] = None
        sanitized_filename: Optional[str] = None

        if decision.action == DLPAction.ALLOW:
            payload_to_store = file_bytes

        elif decision.action == DLPAction.MASK:
            sanitized_bytes, sanitized_name = DataSanitizer.generate_sanitized_file(
                raw_text=extracted_text,
                findings=findings,
                original_filename=filename
            )
            payload_to_store = sanitized_bytes
            sanitized_filename = sanitized_name
            masked_preview = DataSanitizer.sanitize_text(extracted_text, findings)[:500]

        elif decision.action == DLPAction.QUARANTINE:
            # Original unmasked file stored in isolated quarantine bucket
            payload_to_store = file_bytes

        elif decision.action == DLPAction.BLOCK:
            # Upload rejected entirely - not stored anywhere
            payload_to_store = None

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Build preview string
        preview_len = min(500, len(extracted_text))
        extracted_preview = extracted_text[:preview_len]

        scan_result = ScanResult(
            filename=filename,
            file_size_bytes=len(file_bytes),
            extractor_used=metadata.get("extractor_used", "unknown"),
            extracted_text_preview=extracted_preview,
            findings=findings,
            findings_count=len(findings),
            risk_level=risk_report.risk_level,
            risk_score=risk_report.risk_score,
            policy_action=decision.action,
            destination_bucket=decision.destination_bucket,
            policy_name=decision.policy_name,
            decision_reason=decision.decision_reason,
            is_masked=(decision.action == DLPAction.MASK),
            masked_text_preview=masked_preview,
            sanitized_filename=sanitized_filename,
            processing_time_ms=elapsed_ms,
            summary_by_type=risk_report.summary_counts
        )

        return scan_result, payload_to_store
