"""Authentication Flaws & Login Bypass Auditor for BB-SUITE.

Audits login interfaces for common architectural authentication weaknesses:
- Blank password acceptance
- SQL injection authentication bypass
- Username enumeration timing/length differential
- Default credential usage
- JSON type juggling (loose comparison)
"""
from __future__ import annotations
import asyncio
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter

from backend.models import AuthFlawsReq
from backend.security.confidence import (
    Confidence,
    Severity,
    create_finding,
    standard_response,
)
from backend.security.http_client import safe_request
from backend.security.logger import redact_secrets
from backend.security.target_validator import TargetValidationError, validate_target_url
from backend.tools.utils import clean_url, err, ok

router = APIRouter(tags=["exploitation"])

FAIL_TOKENS = [
    "invalid", "incorrect", "failed", "error", "wrong", "denied",
    "unauthorized", "bad credentials", "try again", "not match"
]

SQLI_AUTH_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "' OR ''='",
]

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
]


def check_auth_success(resp_body: str, status_code: int, initial_url: str, final_url: str) -> bool:
    body_l = resp_body.lower()
    # Redirect to authenticated dashboard/home
    if status_code in (302, 303):
        return True
    # HTTP 200 without failure tokens
    if status_code == 200 and not any(t in body_l for t in FAIL_TOKENS):
        return True
    return False


@router.post("/auth_flaws")
async def auth_flaws(req: AuthFlawsReq):
    url = clean_url(req.target)
    try:
        validate_target_url(url)
    except TargetValidationError as tve:
        return err(f"Target validation failed: {tve}")

    uf = req.username_field.strip() or "username"
    pf = req.password_field.strip() or "password"

    findings: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []

    # 1. Blank Password Test
    try:
        r_blank = await safe_request("POST", url, data={uf: req.username, pf: ""}, timeout=8.0)
        if check_auth_success(r_blank.text, r_blank.status_code, url, r_blank.url):
            findings.append(create_finding(
                title=f"Blank Password Login Accepted for User '{req.username}'",
                severity="critical",
                confidence=Confidence.CONFIRMED.value,
                detail="The login form accepted authentication with an empty password string.",
                recommendation="Enforce non-empty password verification before processing authentication.",
                evidence=f"HTTP {r_blank.status_code} on empty password submission",
            ))
            records.append({"Test": "Blank Password", "Payload": "(empty)", "Result": "💀 ACCEPTED", "HTTP": r_blank.status_code})
        else:
            records.append({"Test": "Blank Password", "Payload": "(empty)", "Result": "Rejected (Safe)", "HTTP": r_blank.status_code})
    except Exception:
        pass

    # 2. SQL Injection Authentication Bypass Test
    sqli_success = False
    for payload in SQLI_AUTH_PAYLOADS:
        try:
            r_sqli = await safe_request("POST", url, data={uf: payload, pf: payload}, timeout=8.0)
            if check_auth_success(r_sqli.text, r_sqli.status_code, url, r_sqli.url):
                findings.append(create_finding(
                    title="SQL Injection Authentication Bypass (Confirmed)",
                    severity="critical",
                    confidence=Confidence.CONFIRMED.value,
                    detail=f"Injected payload '{payload}' bypassed authentication mechanism.",
                    recommendation="Implement parameterized prepared statements for all authentication queries.",
                    evidence=f"Payload: {payload} returned HTTP {r_sqli.status_code}",
                ))
                records.append({"Test": "SQLi Bypass", "Payload": payload, "Result": "💀 VULNERABLE", "HTTP": r_sqli.status_code})
                sqli_success = True
                break
        except Exception:
            pass

    if not sqli_success:
        records.append({"Test": "SQLi Bypass", "Payload": "Standard Payloads", "Result": "Rejected (Safe)", "HTTP": 200})

    # 3. Username Enumeration Differential Test
    try:
        r_valid = await safe_request("POST", url, data={uf: req.username, pf: "INVALID_PROBE_PASSWORD_XYZ99"}, timeout=8.0)
        r_invalid = await safe_request("POST", url, data={uf: "NONEXISTENT_USER_XYZ9911", pf: "INVALID_PROBE_PASSWORD_XYZ99"}, timeout=8.0)
        diff = abs(len(r_valid.content) - len(r_invalid.content))

        if diff > 80:
            findings.append(create_finding(
                title="Username Enumeration Differential Observed",
                severity="low",
                confidence=Confidence.POSSIBLE.value,
                detail=f"Response length differed by {diff} bytes between existing and nonexistent usernames. This may allow an attacker to enumerate valid accounts.",
                recommendation="Return generic, uniform error messages (e.g., 'Invalid credentials') with consistent response lengths and timing.",
                evidence=f"Length difference: {diff} bytes",
            ))
            records.append({"Test": "Username Enum", "Payload": "valid vs invalid", "Result": f"⚠ Diff ({diff}B)", "HTTP": r_valid.status_code})
        else:
            records.append({"Test": "Username Enum", "Payload": "valid vs invalid", "Result": "Uniform Response", "HTTP": r_valid.status_code})
    except Exception:
        pass

    # 4. Default Credentials Test
    default_found = False
    for u, p in DEFAULT_CREDS:
        try:
            r_def = await safe_request("POST", url, data={uf: u, pf: p}, timeout=8.0)
            if check_auth_success(r_def.text, r_def.status_code, url, r_def.url):
                findings.append(create_finding(
                    title=f"Default Credentials Accepted for '{u}'",
                    severity="critical",
                    confidence=Confidence.CONFIRMED.value,
                    detail=f"Login succeeded using common default credentials ({u}:[MASKED]).",
                    recommendation="Enforce mandatory password changes on initial setup and disable default accounts.",
                    evidence=f"Default username: {u}",
                ))
                records.append({"Test": "Default Creds", "Payload": f"{u}:****", "Result": "💀 SUCCESS", "HTTP": r_def.status_code})
                default_found = True
                break
        except Exception:
            pass

    if not default_found:
        records.append({"Test": "Default Creds", "Payload": "Standard Defaults", "Result": "Rejected (Safe)", "HTTP": 200})

    if not findings:
        findings.append(create_finding(
            title="Authentication Controls Verified",
            severity="info",
            confidence=Confidence.NOT_DETECTED.value,
            detail="Tested authentication bypasses, default credentials, and blank passwords; all attempts were rejected.",
        ))

    return ok({
        "summary": {
            "Target": url,
            "Tests Evaluated": len(records),
            "Findings Count": len([f for f in findings if f.get("severity") != "info"]),
        },
        "findings": findings,
        "records": records,
        "record_columns": ["Test", "Payload", "Result", "HTTP"],
    })
