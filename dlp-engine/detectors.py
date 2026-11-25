"""
DLP Detection Engine: Pattern matching and algorithmic verification.
Detects:
 - EMAIL
 - PHONE (International and Indian)
 - PAN (Indian Permanent Account Number)
 - AADHAAR (Indian UIDAI with Verhoeff checksum algorithm)
 - CREDIT_CARD (Visa, MasterCard, Amex, Discover, RuPay with Luhn algorithm)
 - API_KEY (Stripe, GitHub, Google, generic high-entropy tokens)
 - AWS_KEY (AWS Access Key ID AKIA/ASIA and Secret Access Key)
 - PASSWORD (Password declarations and secret assignments)
"""

import re
from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel


class EntityType(str, Enum):
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    PAN = "PAN"
    AADHAAR = "AADHAAR"
    CREDIT_CARD = "CREDIT_CARD"
    API_KEY = "API_KEY"
    AWS_KEY = "AWS_KEY"
    PASSWORD = "PASSWORD"


class Finding(BaseModel):
    entity_type: EntityType
    value: str
    masked_value: str
    start: int
    end: int
    confidence: float  # 0.0 to 1.0
    context_snippet: str
    validation_status: str  # "checksum_valid", "pattern_match", "heuristic"


# --- Validation Algorithms ---

def luhn_checksum(card_number_str: str) -> bool:
    """Verifies Luhn algorithm for credit card numbers."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# Verhoeff algorithm multiplication table
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
]

# Verhoeff algorithm permutation table
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
]

def verhoeff_checksum(aadhaar_str: str) -> bool:
    """Verifies Verhoeff algorithm for 12-digit Indian Aadhaar number."""
    digits = [int(c) for c in aadhaar_str if c.isdigit()]
    if len(digits) != 12:
        return False
    c = 0
    reversed_digits = digits[::-1]
    for i, d in enumerate(reversed_digits):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][d]]
    return c == 0


def mask_sensitive_value(value: str, entity_type: EntityType) -> str:
    """Returns a redacted/masked representation of a sensitive entity."""
    clean_val = value.strip()
    length = len(clean_val)
    if entity_type == EntityType.EMAIL:
        if "@" in clean_val:
            user, domain = clean_val.split("@", 1)
            masked_user = user[0] + "***" if len(user) > 1 else "*"
            return f"{masked_user}@{domain}"
        return clean_val[:2] + "***"
    elif entity_type == EntityType.PHONE:
        digits = "".join(c for c in clean_val if c.isdigit())
        if len(digits) >= 10:
            return f"***-***-{digits[-4:]}"
        return clean_val[:2] + "****" + clean_val[-2:]
    elif entity_type == EntityType.PAN:
        if len(clean_val) == 10:
            return f"{clean_val[:4]}****{clean_val[-1]}"
        return clean_val[:2] + "*****"
    elif entity_type == EntityType.AADHAAR:
        digits = "".join(c for c in clean_val if c.isdigit())
        if len(digits) == 12:
            return f"XXXX-XXXX-{digits[-4:]}"
        return "XXXX-XXXX-XXXX"
    elif entity_type == EntityType.CREDIT_CARD:
        digits = "".join(c for c in clean_val if c.isdigit())
        if len(digits) >= 12:
            return f"****-****-****-{digits[-4:]}"
        return "****-****-****-****"
    elif entity_type in [EntityType.API_KEY, EntityType.AWS_KEY]:
        if clean_val.startswith("AKIA") or clean_val.startswith("ASIA"):
            return f"{clean_val[:4]}****************"
        return "[REDACTED_API_KEY]"
    elif entity_type == EntityType.PASSWORD:
        return "[REDACTED_PASSWORD]"
    return "*" * max(4, length)


class DetectionEngine:
    """Core pattern detection engine with algorithmic validation."""

    def __init__(self, redos_vulnerable_mode: bool = False):
        self.redos_vulnerable_mode = redos_vulnerable_mode
        self._init_regexes()

    def _init_regexes(self):
        # 1. Email pattern
        if self.redos_vulnerable_mode:
            # Intentionally vulnerable to ReDoS via nested quantifiers: (a+)+
            self.email_pattern = re.compile(r"([a-zA-Z0-9_.-]+)+@([a-zA-Z0-9_.-]+)+\.([a-zA-Z0-9_.-]+)+")
        else:
            # Safe linear/bounded regex
            self.email_pattern = re.compile(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,10}\b"
            )

        # 2. Phone patterns: Indian mobile + International formats (guarded against token substrings)
        self.phone_patterns = [
            # Indian mobile format with optional +91 or 0 prefix
            re.compile(r"(?<![a-zA-Z0-9_\-])(?:\+91[\s.-]?|0)?[6-9]\d{4}[\s.-]?\d{5}\b"),
            # International standard format (e.g. +1-555-555-5555 or (555) 555-5555)
            re.compile(r"(?<![a-zA-Z0-9_\-])(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        ]

        # 3. Indian PAN: 5 uppercase letters, 4 numbers, 1 letter. 4th letter is entity code.
        self.pan_pattern = re.compile(r"\b([A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z])\b")

        # 4. Indian Aadhaar: 12 digits (first digit not 0 or 1), formatted as 4-4-4
        self.aadhaar_pattern = re.compile(r"\b([2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4})\b")

        # 5. Credit Cards: Visa, MasterCard, Amex, Discover, RuPay (13-19 digits)
        self.card_pattern = re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|35\d{14}|60[0-9]{14}|6521[0-9]{12})\b"
        )

        # 6. AWS Credentials
        # AWS Access Key ID
        self.aws_access_key = re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b")
        # AWS Secret Key (40 chars base64-like preceded by assignment keyword)
        self.aws_secret_key = re.compile(
            r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_key|aws_access_secret)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        )

        # 7. Generic & Specific API Keys
        self.api_key_patterns = [
            # Stripe live secret / restricted key
            re.compile(r"\b([sr]k_live_[0-9a-zA-Z]{24,34})\b"),
            # Google API Key
            re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
            # GitHub Personal Access Token
            re.compile(r"\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{40,80})\b"),
            # Slack Token
            re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
            # Generic assigned API token
            re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|bearer_token|auth_token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{24,64})['\"]?"),
        ]

        # 8. Password declarations & URI connection strings
        self.password_pattern = re.compile(
            r"(?i)(?:password|passwd|pwd|db_pass|database_password|admin_password|redis_pass|auth_pass)\s*[:=]\s*['\"]?([^\s'\";\n\r]{6,64})['\"]?"
        )
        self.uri_password_pattern = re.compile(
            r"://[a-zA-Z0-9_\-\.]+:(?P<pwd>[^\s@]{6,64})@"
        )

    def detect(self, text: str) -> List[Finding]:
        """Scans extracted text and returns list of verified DLP findings."""
        findings: List[Finding] = []
        if not text:
            return findings

        # --- 1. Passwords (scan first to avoid substring false matches) ---
        for match in self.password_pattern.finditer(text):
            val = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
            findings.append(Finding(
                entity_type=EntityType.PASSWORD,
                value=val,
                masked_value=mask_sensitive_value(val, EntityType.PASSWORD),
                start=match.start(),
                end=match.end(),
                confidence=0.95,
                context_snippet=self._get_snippet(text, match.start(), match.end()),
                validation_status="pattern_match"
            ))

        for match in self.uri_password_pattern.finditer(text):
            val = match.group("pwd")
            findings.append(Finding(
                entity_type=EntityType.PASSWORD,
                value=val,
                masked_value=mask_sensitive_value(val, EntityType.PASSWORD),
                start=match.start("pwd"),
                end=match.end("pwd"),
                confidence=0.96,
                context_snippet=self._get_snippet(text, match.start(), match.end()),
                validation_status="pattern_match"
            ))

        # --- 2. AWS Credentials ---
        for match in self.aws_access_key.finditer(text):
            val = match.group(1)
            findings.append(Finding(
                entity_type=EntityType.AWS_KEY,
                value=val,
                masked_value=mask_sensitive_value(val, EntityType.AWS_KEY),
                start=match.start(),
                end=match.end(),
                confidence=0.99,
                context_snippet=self._get_snippet(text, match.start(), match.end()),
                validation_status="pattern_match"
            ))

        for match in self.aws_secret_key.finditer(text):
            val = match.group(1)
            findings.append(Finding(
                entity_type=EntityType.AWS_KEY,
                value=val,
                masked_value=mask_sensitive_value(val, EntityType.AWS_KEY),
                start=match.start(),
                end=match.end(),
                confidence=0.98,
                context_snippet=self._get_snippet(text, match.start(), match.end()),
                validation_status="pattern_match"
            ))

        # --- 3. API Keys ---
        for pattern in self.api_key_patterns:
            for match in pattern.finditer(text):
                val = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                findings.append(Finding(
                    entity_type=EntityType.API_KEY,
                    value=val,
                    masked_value=mask_sensitive_value(val, EntityType.API_KEY),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.95,
                    context_snippet=self._get_snippet(text, match.start(), match.end()),
                    validation_status="pattern_match"
                ))

        # --- 4. PAN (Indian Income Tax ID) ---
        for match in self.pan_pattern.finditer(text):
            val = match.group(1)
            findings.append(Finding(
                entity_type=EntityType.PAN,
                value=val,
                masked_value=mask_sensitive_value(val, EntityType.PAN),
                start=match.start(),
                end=match.end(),
                confidence=0.95,
                context_snippet=self._get_snippet(text, match.start(), match.end()),
                validation_status="pattern_match"
            ))

        # --- 5. Aadhaar (with Verhoeff Checksum) ---
        for match in self.aadhaar_pattern.finditer(text):
            val = match.group(1)
            clean_digits = "".join(c for c in val if c.isdigit())
            if len(clean_digits) == 12:
                is_valid = verhoeff_checksum(clean_digits)
                confidence = 0.98 if is_valid else 0.70
                status = "checksum_valid" if is_valid else "heuristic"
                findings.append(Finding(
                    entity_type=EntityType.AADHAAR,
                    value=val,
                    masked_value=mask_sensitive_value(val, EntityType.AADHAAR),
                    start=match.start(),
                    end=match.end(),
                    confidence=confidence,
                    context_snippet=self._get_snippet(text, match.start(), match.end()),
                    validation_status=status
                ))

        # --- 6. Credit / Debit Cards (with Luhn Checksum) ---
        # Normalize hyphens/spaces for card search
        for match in re.finditer(r"\b(?:\d[ -]*?){13,19}\b", text):
            raw_cand = match.group(0)
            digits = "".join(c for c in raw_cand if c.isdigit())
            if 13 <= len(digits) <= 19 and luhn_checksum(digits):
                findings.append(Finding(
                    entity_type=EntityType.CREDIT_CARD,
                    value=raw_cand,
                    masked_value=mask_sensitive_value(raw_cand, EntityType.CREDIT_CARD),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.99,
                    context_snippet=self._get_snippet(text, match.start(), match.end()),
                    validation_status="checksum_valid"
                ))

        # --- 7. Email Addresses ---
        for match in self.email_pattern.finditer(text):
            val = match.group(0)
            # Avoid matching if within already claimed spans
            if not self._overlaps(match.start(), match.end(), findings):
                findings.append(Finding(
                    entity_type=EntityType.EMAIL,
                    value=val,
                    masked_value=mask_sensitive_value(val, EntityType.EMAIL),
                    start=match.start(),
                    end=match.end(),
                    confidence=0.90,
                    context_snippet=self._get_snippet(text, match.start(), match.end()),
                    validation_status="pattern_match"
                ))

        # --- 8. Phone Numbers ---
        for pat in self.phone_patterns:
            for match in pat.finditer(text):
                val = match.group(0).strip()
                # Exclude if it overlaps with Credit Card, Aadhaar, or PAN
                if not self._overlaps(match.start(), match.end(), findings):
                    digits = "".join(c for c in val if c.isdigit())
                    if len(digits) >= 10:
                        findings.append(Finding(
                            entity_type=EntityType.PHONE,
                            value=val,
                            masked_value=mask_sensitive_value(val, EntityType.PHONE),
                            start=match.start(),
                            end=match.end(),
                            confidence=0.85,
                            context_snippet=self._get_snippet(text, match.start(), match.end()),
                            validation_status="pattern_match"
                        ))

        # Sort findings by starting position
        findings.sort(key=lambda f: f.start)
        return findings

    def _get_snippet(self, text: str, start: int, end: int, window: int = 40) -> str:
        snippet_start = max(0, start - window)
        snippet_end = min(len(text), end + window)
        prefix = "..." if snippet_start > 0 else ""
        suffix = "..." if snippet_end < len(text) else ""
        return f"{prefix}{text[snippet_start:snippet_end]}{suffix}"

    def _overlaps(self, start: int, end: int, existing_findings: List[Finding]) -> bool:
        for f in existing_findings:
            if max(start, f.start) < min(end, f.end):
                return True
        return False
