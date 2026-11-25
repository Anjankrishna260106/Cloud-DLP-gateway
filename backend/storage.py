"""
Cloud Storage Service (AWS S3 with Two-Bucket Routing + Resilient Local S3 Emulator).
Routes payloads exclusively AFTER pre-storage DLP inspection:
  - Safe Bucket: ALLOW or sanitized MASK payloads
  - Quarantine Bucket: HIGH-risk QUARANTINE payloads
  - None: CRITICAL-risk BLOCK payloads (never hits S3)
"""

import os
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
import boto3
from botocore.exceptions import BotoCoreError, ClientError

from backend.config import settings


class S3StorageService:
    """Manages two-bucket S3 storage with live boto3 or local S3 bucket simulation."""

    def __init__(self):
        self.local_root = os.path.abspath("storage_buckets")
        self.use_live_s3 = bool(settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY)
        self.s3_client = None

        if self.use_live_s3:
            client_kwargs: Dict[str, Any] = {
                "aws_access_key_id": settings.AWS_ACCESS_KEY_ID,
                "aws_secret_access_key": settings.AWS_SECRET_ACCESS_KEY,
                "region_name": settings.AWS_REGION,
            }
            if settings.AWS_ENDPOINT_URL:
                client_kwargs["endpoint_url"] = settings.AWS_ENDPOINT_URL
            self.s3_client = boto3.client("s3", **client_kwargs)

    def put_object(
        self,
        bucket_name: str,
        object_key: str,
        data: bytes,
        content_type: str = "application/octet-stream",
        metadata: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Stores an object in the chosen S3 bucket.
        Enforces Server-Side Encryption (SSE-S3 AES256) and Private ACL in remediated mode.
        """
        safe_meta = {k: str(v) for k, v in (metadata or {}).items()}
        is_vulnerable = (settings.SECURITY_MODE == "vulnerable")

        if self.use_live_s3 and self.s3_client:
            try:
                put_kwargs: Dict[str, Any] = {
                    "Bucket": bucket_name,
                    "Key": object_key,
                    "Body": data,
                    "ContentType": content_type,
                    "Metadata": safe_meta,
                }
                if not is_vulnerable:
                    put_kwargs["ServerSideEncryption"] = "AES256"
                else:
                    # Vulnerable mode: no encryption specified, potentially public-read if bucket allows
                    pass

                self.s3_client.put_object(**put_kwargs)
                return {
                    "provider": "aws_s3",
                    "bucket": bucket_name,
                    "key": object_key,
                    "encryption": "None (Vulnerable)" if is_vulnerable else "AES256 (SSE-S3)",
                    "acl": "public-read (Misconfigured)" if is_vulnerable else "private (Least-Privilege)",
                    "uri": f"s3://{bucket_name}/{object_key}"
                }
            except (BotoCoreError, ClientError) as e:
                print(f"[S3 Warning] Live AWS S3 put_object failed ({e}); falling back to local S3 emulator.")

        # Local S3 Bucket Emulator (mirrors real S3 structure & bucket policies)
        bucket_dir = os.path.join(self.local_root, bucket_name)
        os.makedirs(bucket_dir, exist_ok=True)
        # Ensure nested keys stay safely inside bucket_dir
        clean_key = object_key.lstrip("/\\")
        target_path = os.path.abspath(os.path.join(bucket_dir, clean_key))
        if not target_path.startswith(bucket_dir):
            raise ValueError("Invalid S3 object key path")

        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, "wb") as f:
            f.write(data)

        meta_record = {
            "bucket": bucket_name,
            "key": clean_key,
            "size": len(data),
            "content_type": content_type,
            "encryption": "None" if is_vulnerable else "AES256",
            "acl": "public-read" if is_vulnerable else "private",
            "metadata": safe_meta,
            "stored_at": datetime.now(timezone.utc).isoformat()
        }
        with open(f"{target_path}.meta.json", "w", encoding="utf-8") as mf:
            json.dump(meta_record, mf, indent=2)

        return {
            "provider": "local_s3_emulator",
            "bucket": bucket_name,
            "key": clean_key,
            "encryption": meta_record["encryption"],
            "acl": meta_record["acl"],
            "uri": f"s3://{bucket_name}/{clean_key}"
        }

    def get_object(self, bucket_name: str, object_key: str) -> Optional[Tuple[bytes, Dict[str, Any]]]:
        """Retrieves object bytes and metadata from S3 or local S3 emulator."""
        if self.use_live_s3 and self.s3_client:
            try:
                resp = self.s3_client.get_object(Bucket=bucket_name, Key=object_key)
                return resp["Body"].read(), {
                    "content_type": resp.get("ContentType", "application/octet-stream"),
                    "metadata": resp.get("Metadata", {})
                }
            except (BotoCoreError, ClientError):
                pass

        bucket_dir = os.path.join(self.local_root, bucket_name)
        target_path = os.path.abspath(os.path.join(bucket_dir, object_key.lstrip("/\\")))
        if not target_path.startswith(bucket_dir) or not os.path.exists(target_path):
            return None
        with open(target_path, "rb") as f:
            data = f.read()
        meta = {}
        if os.path.exists(f"{target_path}.meta.json"):
            with open(f"{target_path}.meta.json", "r", encoding="utf-8") as mf:
                meta = json.load(mf)
        return data, meta

    def list_bucket_objects(self, bucket_name: str) -> list:
        """Lists stored objects with metadata for a given bucket."""
        items = []
        bucket_dir = os.path.join(self.local_root, bucket_name)
        if not os.path.exists(bucket_dir):
            return items

        for root, _, files in os.walk(bucket_dir):
            for file in files:
                if file.endswith(".meta.json"):
                    continue
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, bucket_dir).replace("\\", "/")
                size = os.path.getsize(full_path)
                meta_file = f"{full_path}.meta.json"
                meta_data = {}
                if os.path.exists(meta_file):
                    try:
                        with open(meta_file, "r", encoding="utf-8") as mf:
                            meta_data = json.load(mf)
                    except Exception:
                        pass
                items.append({
                    "key": rel_path,
                    "filename": os.path.basename(rel_path),
                    "size_bytes": size,
                    "encryption": meta_data.get("encryption", "AES256"),
                    "acl": meta_data.get("acl", "private"),
                    "stored_at": meta_data.get("stored_at", datetime.now(timezone.utc).isoformat()),
                    "metadata": meta_data.get("metadata", {})
                })
        items.sort(key=lambda x: x["stored_at"], reverse=True)
        return items

    def get_dual_bucket_comparison(self) -> Dict[str, Any]:
        """
        Returns an architectural and permission comparison between
        Safe Bucket and Quarantine Bucket for seminar presentation.
        """
        safe_files = self.list_bucket_objects(settings.AWS_SAFE_BUCKET)
        quarantine_files = self.list_bucket_objects(settings.AWS_QUARANTINE_BUCKET)

        return {
            "safe_bucket": {
                "name": settings.AWS_SAFE_BUCKET,
                "arn": f"arn:aws:s3:::{settings.AWS_SAFE_BUCKET}",
                "classification": "PRODUCTION_OPERATIONAL_TIER",
                "purpose": "Stores verified clean documents (ALLOW) and in-flight sanitized PII files (MASK). Accessible to operational workloads.",
                "total_files": len(safe_files),
                "total_bytes": sum(f["size_bytes"] for f in safe_files),
                "public_access_block": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True
                },
                "default_encryption": {
                    "ServerSideEncryption": "SSE-S3 (AES-256)",
                    "BucketKeyEnabled": True
                },
                "access_permissions": {
                    "read_principals": [
                        "arn:aws:iam::123456789012:role/CloudGuardAppRole",
                        "arn:aws:iam::123456789012:role/CloudGuardAnalyticsService"
                    ],
                    "write_principals": [
                        "arn:aws:iam::123456789012:role/CloudGuardDLPGatewayRole"
                    ],
                    "tls_enforcement": "Enforced (TLS 1.3 Required)",
                    "object_lock_worm": "Disabled (Normal business lifecycle)"
                },
                "bucket_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "DenyNonSSLRequests",
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:*",
                            "Resource": [
                                f"arn:aws:s3:::{settings.AWS_SAFE_BUCKET}",
                                f"arn:aws:s3:::{settings.AWS_SAFE_BUCKET}/*"
                            ],
                            "Condition": {"Bool": {"aws:SecureTransport": "false"}}
                        },
                        {
                            "Sid": "AllowOperationalServicesAndGateway",
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": [
                                    "arn:aws:iam::123456789012:role/CloudGuardDLPGatewayRole",
                                    "arn:aws:iam::123456789012:role/CloudGuardAppRole"
                                ]
                            },
                            "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                            "Resource": [
                                f"arn:aws:s3:::{settings.AWS_SAFE_BUCKET}",
                                f"arn:aws:s3:::{settings.AWS_SAFE_BUCKET}/*"
                            ]
                        }
                    ]
                },
                "files": safe_files
            },
            "quarantine_bucket": {
                "name": settings.AWS_QUARANTINE_BUCKET,
                "arn": f"arn:aws:s3:::{settings.AWS_QUARANTINE_BUCKET}",
                "classification": "REGULATORY_ISOLATION_VAULT",
                "purpose": "Stores high-impact financial & identity documents (PAN, Credit Cards, Aadhaar). Air-gapped from operational workloads.",
                "total_files": len(quarantine_files),
                "total_bytes": sum(f["size_bytes"] for f in quarantine_files),
                "public_access_block": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True
                },
                "default_encryption": {
                    "ServerSideEncryption": "SSE-KMS / SSE-S3 (AES-256)",
                    "KmsMasterKeyArn": "arn:aws:kms:ap-south-1:123456789012:key/dlp-quarantine-key",
                    "BucketKeyEnabled": True
                },
                "access_permissions": {
                    "read_principals": [
                        "arn:aws:iam::123456789012:role/CloudGuardComplianceAuditorRole"
                    ],
                    "write_principals": [
                        "arn:aws:iam::123456789012:role/CloudGuardDLPGatewayRole (PutObject Only)"
                    ],
                    "explicit_deny_principals": [
                        "arn:aws:iam::123456789012:role/CloudGuardAppRole (Standard Business Users & Web App)"
                    ],
                    "tls_enforcement": "Strict (TLS 1.3 Required)",
                    "object_lock_worm": "Compliance Mode (Retention: 7 Years - Anti-Tamper)",
                    "cloudtrail_data_events": "Enabled (Every read/access attempt logged to Security SIEM)"
                },
                "bucket_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "DenyNonSSLRequests",
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:*",
                            "Resource": [
                                f"arn:aws:s3:::{settings.AWS_QUARANTINE_BUCKET}",
                                f"arn:aws:s3:::{settings.AWS_QUARANTINE_BUCKET}/*"
                            ],
                            "Condition": {"Bool": {"aws:SecureTransport": "false"}}
                        },
                        {
                            "Sid": "ExplicitDenyStandardAppAccess",
                            "Effect": "Deny",
                            "Principal": {
                                "AWS": "arn:aws:iam::123456789012:role/CloudGuardAppRole"
                            },
                            "Action": "s3:*",
                            "Resource": [
                                f"arn:aws:s3:::{settings.AWS_QUARANTINE_BUCKET}",
                                f"arn:aws:s3:::{settings.AWS_QUARANTINE_BUCKET}/*"
                            ]
                        },
                        {
                            "Sid": "AllowGatewayWriteOnly",
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": "arn:aws:iam::123456789012:role/CloudGuardDLPGatewayRole"
                            },
                            "Action": ["s3:PutObject"],
                            "Resource": f"arn:aws:s3:::{settings.AWS_QUARANTINE_BUCKET}/*"
                        },
                        {
                            "Sid": "AllowComplianceOfficerAuditReadOnly",
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": "arn:aws:iam::123456789012:role/CloudGuardComplianceAuditorRole"
                            },
                            "Action": ["s3:GetObject", "s3:ListBucket"],
                            "Resource": [
                                f"arn:aws:s3:::{settings.AWS_QUARANTINE_BUCKET}",
                                f"arn:aws:s3:::{settings.AWS_QUARANTINE_BUCKET}/*"
                            ]
                        }
                    ]
                },
                "files": quarantine_files
            }
        }

    def get_bucket_security_posture(self) -> Dict[str, Any]:
        """
        Returns the S3 bucket security policy and encryption posture based on SECURITY_MODE.
        Demonstrates Vulnerability #4 (Overly Permissive S3 Bucket Policy vs Least-Privilege).
        """
        if settings.SECURITY_MODE == "vulnerable":
            return {
                "mode": "vulnerable",
                "provider": "aws_s3" if self.use_live_s3 else "local_s3_emulator",
                "public_access_block": False,
                "default_encryption": "Disabled",
                "safe_bucket": settings.AWS_SAFE_BUCKET,
                "quarantine_bucket": settings.AWS_QUARANTINE_BUCKET,
                "bucket_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "PublicReadGetObject",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": ["s3:GetObject", "s3:ListBucket"],
                            "Resource": [
                                f"arn:aws:s3:::{settings.AWS_QUARANTINE_BUCKET}",
                                f"arn:aws:s3:::{settings.AWS_QUARANTINE_BUCKET}/*"
                            ]
                        }
                    ]
                },
                "risk_finding": "CRITICAL: Principal '*' grants public unauthenticated read/list access to sensitive quarantine bucket without TLS or KMS/AES256 encryption."
            }

        return {
            "mode": "remediated",
            "provider": "aws_s3" if self.use_live_s3 else "local_s3_emulator",
            "public_access_block": True,
            "default_encryption": "SSE-S3 (AES-256)",
            "safe_bucket": settings.AWS_SAFE_BUCKET,
            "quarantine_bucket": settings.AWS_QUARANTINE_BUCKET,
            "bucket_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "DenyInsecureTransport",
                        "Effect": "Deny",
                        "Principal": "*",
                        "Action": "s3:*",
                        "Resource": [
                            f"arn:aws:s3:::{settings.AWS_QUARANTINE_BUCKET}",
                            f"arn:aws:s3:::{settings.AWS_QUARANTINE_BUCKET}/*"
                        ],
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}}
                    },
                    {
                        "Sid": "AllowOnlyDLPGatewayRole",
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:role/CloudGuardDLPGatewayRole"},
                        "Action": ["s3:PutObject", "s3:GetObject"],
                        "Resource": f"arn:aws:s3:::{settings.AWS_QUARANTINE_BUCKET}/*"
                    }
                ]
            },
            "risk_finding": "SECURE: Public access blocked, TLS enforced, AES-256 SSE enabled, and access restricted strictly to the DLP Gateway IAM role."
        }


s3_service = S3StorageService()
