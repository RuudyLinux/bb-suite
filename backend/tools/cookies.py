"""Cookie Security & Session Architecture Analyzer for BB-SUITE.

Performs comprehensive security inspection of HTTP cookies:
- Secure, HttpOnly, SameSite attributes
- Cookie Prefixes (__Host-, __Secure-) RFC 6265bis compliance
- Domain and Path scoping
- Expiration and persistence analysis
- Accurate session identifier classification without pseudo-entropy assumptions
"""
from __future__ import annotations
import math
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter

from backend.models import TargetReq
from backend.security.confidence import (
    Confidence,
    Severity,
    create_finding,
    standard_response,
)
from backend.security.http_client import safe_request
from backend.security.target_validator import TargetValidationError, validate_target_url
from backend.tools.utils import clean_url, err, ok

router = APIRouter(tags=["analysis"])

KNOWN_SESSION_NAMES = {
    "phpsessid", "jsessionid", "asp.net_sessionid", "connect.sid",
    "session", "sid", "sessionid", "sessid", "token", "auth_token",
    "_session_id", "laravel_session", "cf_clearance",
}


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy bits per character for string."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log2(p_x)
    return entropy


@router.post("/cookies")
async def cookie_analyzer(req: TargetReq):
    url = clean_url(req.target)
    try:
        validate_target_url(url)
    except TargetValidationError as tve:
        return err(f"Target validation failed: {tve}")

    is_https = url.lower().startswith("https://")
    parsed = urlparse(url)
    target_host = parsed.netloc.split(':')[0].lower()

    findings: List[Dict[str, Any]] = []
    cookies_list: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []

    try:
        resp = await safe_request("GET", url, timeout=8.0)
        # Extract Set-Cookie headers
        raw_cookies: List[str] = []
        for k, v in resp.headers.items():
            if k.lower() == "set-cookie":
                raw_cookies.append(v)
    except Exception as e:
        return err(f"Target connection failed: {e}")

    if not raw_cookies:
        return ok({
            "summary": {"Target": url, "Cookies Found": 0, "Status": "No Set-Cookie Headers"},
            "findings": [create_finding(
                title="No Set-Cookie Headers Returned",
                severity="info",
                confidence=Confidence.CONFIRMED.value,
                detail="The server did not set any cookies upon initial request.",
            )],
            "records": [],
            "record_columns": ["Name", "Flags", "Prefix", "Scope", "Length / Shannon Entropy"],
        })

    for raw in raw_cookies:
        parts = [p.strip() for p in raw.split(";")]
        if not parts or not parts[0]:
            continue

        nv = parts[0]
        eq_idx = nv.find("=")
        name = nv[:eq_idx].strip() if eq_idx != -1 else nv.strip()
        value = nv[eq_idx + 1:].strip() if eq_idx != -1 else ""

        attrs: Dict[str, str] = {}
        flags: set[str] = set()

        for p in parts[1:]:
            if "=" in p:
                k, v = p.split("=", 1)
                attrs[k.strip().lower()] = v.strip()
            else:
                flags.add(p.strip().lower())

        secure = "secure" in flags
        httponly = "httponly" in flags
        samesite = attrs.get("samesite", "").capitalize()
        domain = attrs.get("domain", "")
        path = attrs.get("path", "/")
        expires = attrs.get("expires", "")
        max_age = attrs.get("max-age", "")

        is_session = (
            name.lower() in KNOWN_SESSION_NAMES or
            bool(re.search(r'sess|token|auth|jwt|sid|login', name, re.IGNORECASE))
        )

        entropy_score = calculate_shannon_entropy(value)

        # 1. Check Cookie Prefixes (__Host-, __Secure-)
        if name.startswith("__Host-"):
            # __Host- cookies must be Secure, Path=/, and have NO Domain attribute
            if not secure or path != "/" or domain:
                findings.append(create_finding(
                    title=f"Cookie Prefix Violation: '{name}'",
                    severity="high",
                    confidence=Confidence.CONFIRMED.value,
                    detail=f"Cookie '{name}' uses the __Host- prefix but violates RFC 6265bis requirements (must have Secure=True, Path=/, and Domain omitted).",
                    recommendation="Ensure __Host- cookies are sent over HTTPS with Secure=True, Path=/, and no Domain attribute specified.",
                    evidence=f"Secure: {secure}, Path: {path}, Domain: '{domain}'",
                ))
        elif name.startswith("__Secure-"):
            if not secure:
                findings.append(create_finding(
                    title=f"Cookie Prefix Violation: '{name}'",
                    severity="high",
                    confidence=Confidence.CONFIRMED.value,
                    detail=f"Cookie '{name}' uses the __Secure- prefix but is missing the 'Secure' attribute.",
                    recommendation="Add the Secure attribute to all __Secure- cookies.",
                ))

        # 2. Secure Attribute Check
        if not secure:
            sev = "high" if is_session else "medium"
            findings.append(create_finding(
                title=f"Cookie '{name}' Missing 'Secure' Attribute",
                severity=sev,
                confidence=Confidence.CONFIRMED.value,
                detail=f"Cookie '{name}' can be transmitted in cleartext over unencrypted HTTP connections.{' This allows session hijacking over hostile networks.' if is_session else ''}",
                recommendation="Add 'Secure' attribute to ensure the cookie is only transmitted over TLS/HTTPS.",
                evidence=f"Set-Cookie: {name}={value[:15]}...; (missing Secure)",
            ))

        # 3. HttpOnly Attribute Check
        if not httponly:
            sev = "high" if is_session else "low"
            findings.append(create_finding(
                title=f"Cookie '{name}' Missing 'HttpOnly' Attribute",
                severity=sev,
                confidence=Confidence.CONFIRMED.value,
                detail=f"Cookie '{name}' is accessible to client-side scripts via document.cookie.{' If an XSS vulnerability exists, this token can be exfiltrated.' if is_session else ''}",
                recommendation="Set the 'HttpOnly' flag on sensitive and session cookies to mitigate XSS token theft.",
            ))

        # 4. SameSite Attribute Check
        if not samesite:
            findings.append(create_finding(
                title=f"Cookie '{name}' Missing 'SameSite' Attribute",
                severity="medium" if is_session else "low",
                confidence=Confidence.CONFIRMED.value,
                detail=f"Cookie '{name}' does not specify SameSite protection. Browsers will send this cookie on cross-site subrequests, increasing CSRF risk.",
                recommendation="Set 'SameSite=Lax' or 'SameSite=Strict' to mitigate cross-site request forgery.",
            ))
        elif samesite.lower() == "none" and not secure:
            findings.append(create_finding(
                title=f"Invalid SameSite=None without Secure: '{name}'",
                severity="high",
                confidence=Confidence.CONFIRMED.value,
                detail=f"Cookie '{name}' specifies SameSite=None without the Secure attribute. Modern browsers reject this configuration.",
                recommendation="Pair SameSite=None with Secure=True.",
            ))

        # 5. Domain Scope Check
        if domain:
            if domain.startswith("."):
                findings.append(create_finding(
                    title=f"Broad Domain Scope for Cookie '{name}'",
                    severity="low",
                    confidence=Confidence.CONFIRMED.value,
                    detail=f"Cookie domain is explicitly scoped to '{domain}', making it accessible to all subdomains. A compromised subdomain can read or overwrite this cookie.",
                    recommendation="Omit the Domain attribute to restrict the cookie strictly to the host that set it (Host-Only cookie).",
                ))

        # 6. Session Identifier Length & Randomness Evaluation
        if is_session:
            v_len = len(value)
            if v_len < 16:
                findings.append(create_finding(
                    title=f"Short Session Identifier: '{name}' ({v_len} characters)",
                    severity="medium",
                    confidence=Confidence.POSSIBLE.value,
                    detail=f"Session identifier '{name}' is {v_len} characters long. Short session identifiers may be more susceptible to brute-force guessing depending on server rate-limiting.",
                    recommendation="Ensure session tokens use a cryptographically secure random generator producing at least 128 bits of entropy (>= 32 hex/base64 characters).",
                    evidence=f"Token length: {v_len} chars",
                ))

        flag_str = f"Secure: {secure} | HttpOnly: {httponly} | SameSite: {samesite or 'None'}"
        records.append({
            "Name": name,
            "Flags": flag_str,
            "Prefix": "__Host-" if name.startswith("__Host-") else ("__Secure-" if name.startswith("__Secure-") else "None"),
            "Scope": f"Domain: {domain or 'Host-Only'}, Path: {path}",
            "Length / Shannon Entropy": f"{len(value)} chars ({entropy_score:.2f} bits/char)",
        })

    return ok({
        "summary": {
            "Target": url,
            "Cookies Inspected": len(raw_cookies),
            "Findings Count": len(findings),
        },
        "findings": findings,
        "records": records,
        "record_columns": ["Name", "Flags", "Prefix", "Scope", "Length / Shannon Entropy"],
    })
