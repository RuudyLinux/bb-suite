"""Brute Force Authentication Resilience Tester for BB-SUITE.

Provides controlled, rate-bounded authentication auditing:
- Requires operator authentication
- Target boundary validation
- Capped maximum attempts (100 max) and concurrency (10 max)
- CSRF token extraction and baseline differential verification
- Immediate cancellation upon rate limit (429) or verified success
- Credential masking in logs and audit events
"""
from __future__ import annotations
import asyncio
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends

from backend.models import BruteReq
from backend.security.auth import get_current_user
from backend.security.confidence import (
    Confidence,
    Severity,
    create_finding,
    standard_response,
)
from backend.security.http_client import safe_request
from backend.security.logger import log_security_event, redact_secrets
from backend.security.target_validator import TargetValidationError, validate_target_url
from backend.tools.utils import clean_url, err, load_wordlist, ok

router = APIRouter(tags=["exploitation"])

FAIL_TOKENS = [
    "invalid", "incorrect", "failed", "error", "wrong", "denied",
    "unauthorized", "bad credentials", "try again", "not match"
]

CSRF_FIELD_PATTERNS = [
    r'name=["\'](csrf[_-]?token|_token|authenticity_token|csrfmiddlewaretoken|anticsrf)["\']\s+value=["\']([^"\']+)["\']',
    r'value=["\']([^"\']+)["\']\s+name=["\'](csrf[_-]?token|_token|authenticity_token|csrfmiddlewaretoken|anticsrf)["\']',
]


async def extract_csrf_and_cookies(url: str) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Extract CSRF tokens and cookies from the initial login page GET request."""
    hidden_fields = {}
    cookies = {}
    try:
        r = await safe_request("GET", url, timeout=8.0)
        text = r.text
        for pat in CSRF_FIELD_PATTERNS:
            for match in re.finditer(pat, text, re.IGNORECASE):
                groups = match.groups()
                if len(groups) == 2:
                    g0_low = groups[0].lower()
                    if 'token' in g0_low or 'csrf' in g0_low:
                        name, val = groups[0], groups[1]
                    else:
                        name, val = groups[1], groups[0]
                    hidden_fields[name] = val
        for k, v in r.headers.items():
            if k.lower() == "set-cookie":
                parts = v.split(";")[0]
                if "=" in parts:
                    ck, cv = parts.split("=", 1)
                    cookies[ck.strip()] = cv.strip()
    except Exception:
        pass
    return hidden_fields, cookies


@router.post("/bruteforce")
async def brute_force(
    req: BruteReq,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    url = clean_url(req.target)
    try:
        validate_target_url(url)
    except TargetValidationError as tve:
        return err(f"Target validation failed: {tve}")

    operator = current_user.get("sub", "admin")
    log_security_event(
        event_type="BRUTE_FORCE_AUDIT_START",
        target=url,
        user=operator,
        tool="bruteforce",
        level="warning",
    )

    uf = req.username_field.strip() or "username"
    pf = req.password_field.strip() or "password"
    concurrency = max(1, min(req.concurrency or 5, 10))
    is_json = (req.payload_type or "form").lower() == "json"

    # Build bounded credential pair list (Maximum 100 attempts)
    cred_pairs: List[Tuple[str, str]] = []
    if req.credentials and req.credentials.strip():
        for line in req.credentials.strip().split("\n"):
            line = line.strip()
            if ":" in line:
                u, p = line.split(":", 1)
                cred_pairs.append((u.strip(), p.strip()))

    if not cred_pairs:
        raw_pwds: List[str] = []
        if req.passwords and req.passwords.strip():
            raw_pwds = [p.strip() for p in req.passwords.strip().split("\n") if p.strip()]
        else:
            full_list = load_wordlist("passwords.txt")
            raw_pwds = full_list[:50] if full_list else ["admin", "password", "123456", "admin123"]

        def_user = req.username.strip() or "admin"
        for item in raw_pwds[:100]:
            if ":" in item:
                u, p = item.split(":", 1)
                cred_pairs.append((u.strip(), p.strip()))
            else:
                cred_pairs.append((def_user, item))

    cred_pairs = cred_pairs[:100]  # Hard limit to prevent accidental denial of service

    findings: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []
    stop_event = asyncio.Event()
    rate_limited = False
    found_credentials: List[str] = []

    # Step 1: Detect CSRF & Baseline
    csrf_fields, session_cookies = await extract_csrf_and_cookies(url)
    baseline_payload = {uf: "admin", pf: "INVALID_PROBE_NONEXISTENT_PW_9999", **csrf_fields}
    baseline_code = 200
    baseline_len = 0
    try:
        base_resp = await safe_request(
            "POST",
            url,
            data=None if is_json else baseline_payload,
            json_data=baseline_payload if is_json else None,
            cookies=session_cookies,
            timeout=8.0,
        )
        baseline_code = base_resp.status_code
        baseline_len = len(base_resp.content)
    except Exception as e:
        return err(f"Unable to reach login target: {e}")

    semaphore = asyncio.Semaphore(concurrency)
    lock = asyncio.Lock()

    async def test_credential(user: str, password: str):
        nonlocal rate_limited
        if stop_event.is_set():
            return

        async with semaphore:
            if stop_event.is_set():
                return

            payload = {uf: user, pf: password, **csrf_fields}
            try:
                r = await safe_request(
                    "POST",
                    url,
                    data=None if is_json else payload,
                    json_data=payload if is_json else None,
                    cookies=session_cookies,
                    follow_redirects=False,
                    timeout=7.0,
                )
                code = r.status_code
                body_l = r.text.lower()
                loc = r.headers.get("location", "").lower()

                # Handle Rate Limiting
                if code == 429:
                    rate_limited = True
                    stop_event.set()
                    async with lock:
                        records.append({
                            "Username": user,
                            "Password": "[MASKED]",
                            "Status": "429 Rate Limited",
                            "Outcome": "Throttled",
                        })
                    return

                # Determine Success
                is_success = False
                reason = ""

                # Explicit success indicator configured
                if req.success_indicator and req.success_indicator.lower() in body_l:
                    is_success = True
                    reason = f"Response matched success indicator '{req.success_indicator}'"
                # Redirect on login (302 to /dashboard or /admin)
                elif code in (302, 303) and any(d in loc for d in ("dashboard", "admin", "home", "account", "profile", "welcome")):
                    is_success = True
                    reason = f"Redirected to '{loc}' (HTTP {code})"
                # Status changed from baseline 401/403/200 to 200 without error tokens
                elif code == 200 and baseline_code in (401, 403):
                    is_success = True
                    reason = "HTTP status shifted from 401/403 to 200"
                elif code == 200 and not any(tok in body_l for tok in FAIL_TOKENS) and abs(len(r.content) - baseline_len) > 200:
                    is_success = True
                    reason = "Response size diverged from baseline failure response"

                masked_pw = password[:2] + ("*" * max(4, len(password) - 2)) if len(password) > 2 else "****"

                async with lock:
                    if is_success:
                        found_credentials.append(f"{user}:{masked_pw}")
                        records.append({
                            "Username": user,
                            "Password": masked_pw,
                            "Status": f"HTTP {code}",
                            "Outcome": "✓ SUCCESS",
                        })
                        stop_event.set()  # Stop further attempts on success
                    else:
                        records.append({
                            "Username": user,
                            "Password": masked_pw,
                            "Status": f"HTTP {code}",
                            "Outcome": "Failed",
                        })

            except Exception:
                pass

    await asyncio.gather(*[test_credential(u, p) for u, p in cred_pairs])

    if found_credentials:
        findings.append(create_finding(
            title=f"Valid Credentials Discovered ({len(found_credentials)} matches)",
            severity="critical",
            confidence=Confidence.CONFIRMED.value,
            detail=f"Automated authentication audit identified valid login credentials: {', '.join(found_credentials)}.",
            recommendation="Enforce multi-factor authentication (MFA), account lockout policies, and strong password complexity requirements.",
            evidence=f"Credentials verified for target: {url}",
        ))
    elif rate_limited:
        findings.append(create_finding(
            title="Brute Force Blocked by Target Rate Limiting (HTTP 429)",
            severity="info",
            confidence=Confidence.CONFIRMED.value,
            detail="The target server actively blocked brute force probing with HTTP 429 / rate limit enforcement.",
        ))
    else:
        findings.append(create_finding(
            title="No Valid Credentials Found",
            severity="info",
            confidence=Confidence.NOT_DETECTED.value,
            detail=f"Tested {len(records)} candidate credentials without discovering valid authentication pairs.",
        ))

    return ok({
        "summary": {
            "Target": url,
            "Operator": operator,
            "Attempts Tested": len(records),
            "Credentials Found": len(found_credentials),
            "Rate Limited": "Yes" if rate_limited else "No",
        },
        "findings": findings,
        "records": records,
        "record_columns": ["Username", "Password", "Status", "Outcome"],
    })
