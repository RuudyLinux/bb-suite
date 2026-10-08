"""Standardized Finding and Confidence Taxonomy for BB-SUITE.

Defines four standard confidence levels to eliminate false positives:
- Confirmed: Verifiable, reproducible proof of exploitation or direct vulnerability.
- Likely: Strong differential evidence matching vulnerability signatures.
- Possible: Heuristic anomaly, behavior change, or missing defensive header.
- Not Detected: No evidence of vulnerability observed.
"""
from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"
    NOT_DETECTED = "not_detected"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


def create_finding(
    title: str,
    severity: str,
    confidence: str,
    detail: str,
    recommendation: str = "",
    evidence: str = "",
    **extra: Any
) -> Dict[str, Any]:
    """Create a standardized finding dictionary across all BB-SUITE scanners."""
    # Normalize severity and confidence
    sev = severity.lower() if isinstance(severity, str) else Severity.INFO.value
    if sev not in [s.value for s in Severity]:
        sev = Severity.INFO.value

    conf = confidence.lower() if isinstance(confidence, str) else Confidence.POSSIBLE.value
    if conf not in [c.value for c in Confidence]:
        conf = Confidence.POSSIBLE.value

    finding = {
        "title": title,
        "severity": sev,
        "confidence": conf,
        "detail": detail,
        "recommendation": recommendation,
        "evidence": evidence,
    }
    if extra:
        finding.update(extra)
    return finding


def standard_response(
    success: bool = True,
    summary: Optional[Dict[str, Any]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
    records: Optional[List[Any]] = None,
    record_columns: Optional[List[str]] = None,
    raw: str = "",
    error: str = "",
    **kwargs: Any
) -> Dict[str, Any]:
    """Standardized top-level API envelope expected by the BB-SUITE UI."""
    data: Dict[str, Any] = {
        "summary": summary if summary is not None else {},
        "findings": findings if findings is not None else [],
        "records": records if records is not None else [],
        "record_columns": record_columns if record_columns is not None else [],
        "raw": raw,
    }
    if kwargs:
        data.update(kwargs)

    return {
        "success": success,
        "data": data,
        "error": error,
    }
