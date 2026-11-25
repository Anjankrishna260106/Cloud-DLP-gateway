"""
Pre-Storage DLP Scan & Upload Routes.
Handles file ingestion, validation, DLP inspection, policy enforcement,
and AWS S3 two-bucket routing.
"""

import os
import sys
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, File, HTTPException, Request, Response, UploadFile, status

# Ensure dlp-engine is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "dlp-engine")))
from gateway import DLPGateway
from policy import DLPAction

from backend.auth import get_current_user
from backend.config import settings
from backend.storage import s3_service
from backend.audit import log_audit_event
from database.connection import DatabaseManager

router = APIRouter(prefix="/api/scan", tags=["DLP Gateway Scan"])


async def _next_scan_id() -> str:
    """Generates sequential readable scan IDs (e.g. scan-1001) to support IDOR demonstration."""
    events_col = DatabaseManager.get_scan_events_col()
    count = await events_col.count_documents()
    return f"scan-{1001 + count}"


@router.post("/upload")
async def upload_and_scan(
    request: Request,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    raw_filename = file.filename or "unnamed.txt"
    file_bytes = await file.read()

    # --- Security Control 1: Filename Sanitization, Type Whitelist & Size Limit ---
    staging_path_info = None
    if settings.SECURITY_MODE == "vulnerable":
        # VULNERABLE DEMO: No extension validation, no size cap, raw path concatenation
        staging_dir = os.path.abspath("temp_uploads")
        os.makedirs(staging_dir, exist_ok=True)
        # Intentionally vulnerable os.path.join allowing ../ path traversal
        unsafe_target = os.path.join(staging_dir, raw_filename)
        resolved_target = os.path.abspath(unsafe_target)
        # Keep write contained within project workspace directory for safety during seminar demo
        workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        if resolved_target.startswith(workspace_root):
            os.makedirs(os.path.dirname(resolved_target), exist_ok=True)
            with open(resolved_target, "wb") as f:
                f.write(file_bytes)
        staging_path_info = {
            "vulnerable_staging_write": True,
            "requested_filename": raw_filename,
            "resolved_path": resolved_target,
            "escaped_staging_dir": not resolved_target.startswith(staging_dir)
        }
        clean_filename = raw_filename
    else:
        # REMEDIATED: Strict validation before processing
        if not file_bytes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty."
            )
        if len(file_bytes) > settings.MAX_UPLOAD_SIZE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB."
            )
        if ".." in raw_filename or "/" in raw_filename or "\\" in raw_filename:
            await log_audit_event(
                event_type="SECURITY_ALERT",
                severity="CRITICAL",
                actor_id=current_user["id"],
                actor_email=current_user["email"],
                action_taken=f"Blocked path traversal attempt in filename: {raw_filename}",
                ip_address=request.client.host if request.client else "127.0.0.1"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid filename: path traversal characters are forbidden."
            )
        clean_filename = os.path.basename(raw_filename)
        ext = os.path.splitext(clean_filename)[1].lower().strip(".")
        if ext not in settings.ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported file type '.{ext}'. Allowed types: {', '.join(sorted(settings.ALLOWED_EXTENSIONS))}"
            )

    # --- Pre-Storage DLP Inspection Pipeline ---
    gateway = DLPGateway(redos_vulnerable_mode=(settings.SECURITY_MODE == "vulnerable"))
    scan_result, payload_to_store = gateway.process(
        file_bytes=file_bytes,
        filename=clean_filename,
        safe_bucket=settings.AWS_SAFE_BUCKET,
        quarantine_bucket=settings.AWS_QUARANTINE_BUCKET
    )

    scan_id = await _next_scan_id()
    s3_result = None
    stored_in_s3 = False
    s3_key = None

    # --- Post-Inspection Cloud Storage Routing ---
    if scan_result.policy_action != DLPAction.BLOCK and payload_to_store is not None:
        target_filename = scan_result.sanitized_filename or os.path.basename(clean_filename)
        s3_key = f"{current_user['id']}/{scan_id}_{uuid.uuid4().hex[:8]}_{target_filename}"
        s3_result = s3_service.put_object(
            bucket_name=scan_result.destination_bucket,
            object_key=s3_key,
            data=payload_to_store,
            content_type=file.content_type or "application/octet-stream",
            metadata={
                "scan_id": scan_id,
                "risk_level": scan_result.risk_level.value,
                "policy_action": scan_result.policy_action.value,
                "user_id": current_user["id"]
            }
        )
        stored_in_s3 = True

    # Prepare finding details for MongoDB persistence (never store raw secret values in logs!)
    finding_records = [
        {
            "entity_type": f.entity_type.value,
            "value_preview": f.masked_value,
            "start": f.start,
            "end": f.end,
            "confidence": f.confidence,
            "context_snippet": f.context_snippet.replace(f.value, f.masked_value),
            "validation_status": f.validation_status
        }
        for f in scan_result.findings
    ]

    event_doc = {
        "id": scan_id,
        "filename": clean_filename,
        "sanitized_filename": scan_result.sanitized_filename,
        "file_size_bytes": scan_result.file_size_bytes,
        "extractor_used": scan_result.extractor_used,
        "risk_level": scan_result.risk_level.value,
        "risk_score": scan_result.risk_score,
        "policy_action": scan_result.policy_action.value,
        "destination_bucket": scan_result.destination_bucket,
        "s3_key": s3_key,
        "s3_metadata": s3_result,
        "stored_in_s3": stored_in_s3,
        "policy_name": scan_result.policy_name,
        "decision_reason": scan_result.decision_reason,
        "findings_count": scan_result.findings_count,
        "summary_by_type": scan_result.summary_by_type,
        "findings": finding_records,
        "masked_preview": scan_result.masked_text_preview,
        "extracted_text_preview": scan_result.extracted_text_preview if scan_result.policy_action == DLPAction.ALLOW else None,
        "processing_time_ms": scan_result.processing_time_ms,
        "user_id": current_user["id"],
        "user_email": current_user["email"],
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    events_col = DatabaseManager.get_scan_events_col()
    await events_col.insert_one(event_doc)

    # Audit Logging
    severity = "INFO"
    if scan_result.policy_action == DLPAction.BLOCK:
        severity = "CRITICAL"
    elif scan_result.policy_action == DLPAction.QUARANTINE:
        severity = "WARNING"

    await log_audit_event(
        event_type="UPLOAD_SCAN",
        severity=severity,
        actor_id=current_user["id"],
        actor_email=current_user["email"],
        action_taken=f"DLP {scan_result.policy_action.value}: {clean_filename} (Risk: {scan_result.risk_level.value}, Score: {scan_result.risk_score})",
        details={
            "scan_id": scan_id,
            "destination_bucket": scan_result.destination_bucket,
            "findings_count": scan_result.findings_count
        },
        ip_address=request.client.host if request.client else "127.0.0.1"
    )

    response_payload = {
        "scan_id": scan_id,
        "upload_status": "REJECTED_BY_DLP" if scan_result.policy_action == DLPAction.BLOCK else "PROCESSED_AND_STORED",
        "stored_in_s3": stored_in_s3,
        "event": event_doc
    }
    if staging_path_info:
        response_payload["vulnerability_trace"] = staging_path_info

    return response_payload


@router.get("/download/{event_id}")
async def download_stored_file(
    event_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Downloads the stored (safe or sanitized) artifact from S3."""
    events_col = DatabaseManager.get_scan_events_col()
    event = await events_col.find_one({"id": event_id})
    if not event:
        raise HTTPException(status_code=404, detail="Scan event not found.")

    if settings.SECURITY_MODE != "vulnerable":
        if current_user["role"] != "admin" and event["user_id"] != current_user["id"]:
            raise HTTPException(status_code=403, detail="Access denied.")

    if not event.get("stored_in_s3") or not event.get("s3_key"):
        raise HTTPException(status_code=400, detail="File was blocked by DLP policy and never stored in S3.")

    if event.get("policy_action") == "QUARANTINE" and current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Quarantined files require administrator clearance to download.")

    obj = s3_service.get_object(event["destination_bucket"], event["s3_key"])
    if not obj:
        raise HTTPException(status_code=404, detail="Object not found in S3 bucket.")

    file_bytes, _ = obj
    download_name = event.get("sanitized_filename") or event["filename"]
    return Response(
        content=file_bytes,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{download_name}"'}
    )
