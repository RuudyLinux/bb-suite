"""Centralized Structured Audit Logging and Redaction Engine for BB-SUITE.

Provides defense against sensitive data leakage by automatically redacting
passwords, API tokens, JWTs, private keys, and session cookies from log records.
"""
from __future__ import annotations
import json
import logging
import re
import sys
import time
from typing import Any, Dict, Optional

# Regex patterns to detect and mask sensitive credentials
SENSITIVE_PATTERNS = [
    (re.compile(r'(?i)(password|passwd|pwd|pass)\s*[:=]\s*["\']?([^"\'\s&]+)["\']?'), r'\1=[REDACTED]'),
    (re.compile(r'(?i)(api[_-]?key|apikey|secret|token)\s*[:=]\s*["\']?([^"\'\s&]+)["\']?'), r'\1=[REDACTED]'),
    (re.compile(r'(?i)(bearer\s+)[a-zA-Z0-9_\-\.]+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)(authorization\s*:\s*bearer\s+)[^\r\n]+'), r'\1[REDACTED]'),
    (re.compile(r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'), r'[JWT_REDACTED]'),
    (re.compile(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----'), r'[PRIVATE_KEY_REDACTED]'),
]


def redact_secrets(text: Any) -> str:
    """Scrub sensitive credentials, passwords, and tokens from text representation."""
    if not isinstance(text, str):
        try:
            text = json.dumps(text)
        except Exception:
            text = str(text)

    for pattern, replacement in SENSITIVE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class SensitiveDataFilter(logging.Filter):
    """Logging filter that scrubs sensitive fields before emission."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_secrets(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: redact_secrets(v) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(redact_secrets(a) for a in record.args)
        return True


def setup_logger(name: str = "bb_suite") -> logging.Logger:
    """Configure structured logger with sensitive data scrubbers."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        handler.setFormatter(formatter)
        handler.addFilter(SensitiveDataFilter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


audit_logger = setup_logger("bb_suite.audit")


def log_security_event(
    event_type: str,
    target: str,
    user: Optional[str] = None,
    tool: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    level: str = "warning",
) -> None:
    """Log an audit security event in structured JSON format with credentials scrubbed."""
    payload = {
        "event": event_type,
        "timestamp": time.time(),
        "user": user or "anonymous",
        "tool": tool or "system",
        "target": target,
        "details": details or {},
    }
    msg = redact_secrets(json.dumps(payload))
    log_func = getattr(audit_logger, level.lower(), audit_logger.info)
    log_func(f"AUDIT_EVENT: {msg}")
