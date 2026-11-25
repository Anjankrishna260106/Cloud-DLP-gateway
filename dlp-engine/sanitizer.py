"""
Data Sanitizer: Masks/redacts sensitive entities in documents.
Generates sanitized versions of text, CSV, and tabular data.
"""

from typing import List, Tuple
try:
    from .detectors import Finding
except (ImportError, ValueError):
    from detectors import Finding


class DataSanitizer:
    """Replaces sensitive text spans with masked representations."""

    @classmethod
    def sanitize_text(cls, raw_text: str, findings: List[Finding]) -> str:
        """
        Substitutes all detected findings with their masked values.
        Replaces backwards from highest start index to preserve character offsets.
        """
        if not raw_text or not findings:
            return raw_text

        # Sort findings by start index descending
        sorted_findings = sorted(findings, key=lambda f: f.start, reverse=True)

        result = raw_text
        for f in sorted_findings:
            # Ensure indices are within bounds
            if 0 <= f.start <= f.end <= len(result):
                prefix = result[:f.start]
                suffix = result[f.end:]
                result = prefix + f.masked_value + suffix

        return result

    @classmethod
    def generate_sanitized_file(
        cls,
        raw_text: str,
        findings: List[Finding],
        original_filename: str
    ) -> Tuple[bytes, str]:
        """
        Produces sanitized file bytes and a sanitized filename label.
        e.g. 'customer_data.csv' -> 'customer_data_sanitized.csv'
        """
        sanitized_str = cls.sanitize_text(raw_text, findings)
        sanitized_bytes = sanitized_str.encode("utf-8")

        parts = original_filename.rsplit(".", 1)
        if len(parts) == 2:
            sanitized_name = f"{parts[0]}_sanitized.{parts[1]}"
        else:
            sanitized_name = f"{original_filename}_sanitized.txt"

        return sanitized_bytes, sanitized_name
