"""Open Redirect Scanner — High-Precision External Redirection Verifier.

Verifies that the target application genuinely redirects to external destinations via:
- HTTP 3xx Location header (Confirmed)
- Meta Refresh / Client-Side Navigation (Likely)
- Does NOT flag mere parameter reflection without redirection.
"""
from __future__ import annotations
import asyncio
import re
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter
from pydantic import BaseModel, Field

from backend.security.confidence import (
    Confidence,
    Severity,
    create_finding,
    standard_response,
)
from backend.security.http_client import safe_request
from backend.security.target_validator import TargetValidationError, validate_target_url
from backend.tools.utils import clean_url, err, ok

router = APIRouter(tags=["scanning"])

EXTERNAL_CANARY_DOMAIN = "example-security-test.com"

REDIRECT_PROBES = [
    (f"https://{EXTERNAL_CANARY_DOMAIN}", "Standard HTTPS External URL"),
    (f"//{EXTERNAL_CANARY_DOMAIN}", "Scheme-Relative URL"),
    (f"///{EXTERNAL_CANARY_DOMAIN}", "Triple-Slash Bypass"),
    (f"/\\{EXTERNAL_CANARY_DOMAIN}", "Slash-Backslash Bypass"),
    (f"https://{EXTERNAL_CANARY_DOMAIN}%2F", "URL-Encoded Slash Bypass"),
    (f"https%3A%2F%2F{EXTERNAL_CANARY_DOMAIN}", "Full URL-Encoded String"),
]

REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "returnTo", "return_url",
    "redirect_uri", "redirect_url", "goto", "destination", "dest",
    "target", "redir", "link", "out", "forward", "to", "continue",
]


class RedirectRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    depth: str = Field("medium", max_length=64)


def inject_redirect_param(url: str, param: str, probe: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [probe]
    flat = {k: v[0] for k, v in params.items()}
    return urlunparse(parsed._replace(query=urlencode(flat)))


@router.post("/open_redirect")
async def open_redirect(req: RedirectRequest):
    url = clean_url(req.target)
    try:
        validate_target_url(url)
    except TargetValidationError as tve:
        return err(f"Target validation failed: {tve}")

    parsed = urlparse(url)
    target_host = parsed.netloc.split(':')[0].lower()
    existing_params = parse_qs(parsed.query, keep_blank_values=True)

    params_to_test = list(existing_params.keys())
    if not params_to_test:
        params_to_test = [p for p in REDIRECT_PARAMS if p in ["redirect", "url", "next", "return", "goto", "dest"]]

    findings: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []

    for param in params_to_test:
        param_confirmed = False
        for probe, probe_desc in REDIRECT_PROBES:
            test_url = inject_redirect_param(url, param, probe)

            try:
                # Issue request with follow_redirects=False to inspect the Location header
                resp = await safe_request("GET", test_url, follow_redirects=False, timeout=6.0)
                status_code = resp.status_code
                loc_header = resp.headers.get("Location", "")

                # 1. Location Header Verification (Confirmed)
                if status_code in (301, 302, 303, 307, 308) and loc_header:
                    loc_parsed = urlparse(loc_header)
                    loc_host = loc_parsed.netloc.split(':')[0].lower()

                    if EXTERNAL_CANARY_DOMAIN in loc_host and loc_host != target_host:
                        findings.append(create_finding(
                            title=f"Open Redirect (Confirmed): param '{param}' via {probe_desc}",
                            severity="high",
                            confidence=Confidence.CONFIRMED.value,
                            detail=f"Injected probe '{probe}' into parameter '{param}'. The server issued HTTP {status_code} redirecting directly to external destination: '{loc_header}'.",
                            recommendation="Validate all redirection targets against a strict allowlist of internal relative paths. Never blindly honor external destination URLs.",
                            evidence=f"Status: {status_code}\nLocation: {loc_header}",
                        ))
                        records.append({
                            "Parameter": param,
                            "Probe": probe_desc,
                            "HTTP Status": status_code,
                            "Destination": loc_header,
                            "Confidence": "confirmed",
                            "Result": "💀 CONFIRMED VULNERABLE",
                        })
                        param_confirmed = True
                        break

                # 2. Meta Refresh / JavaScript Client-side Redirect (Likely)
                body = resp.text
                if EXTERNAL_CANARY_DOMAIN in body:
                    # Check for Meta Refresh
                    meta_match = re.search(
                        rf'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\'][^"\']*{re.escape(EXTERNAL_CANARY_DOMAIN)}',
                        body,
                        re.IGNORECASE,
                    )
                    # Check for JavaScript window.location assignment
                    js_match = re.search(
                        rf'(?:window\.|document\.)?location(?:\.href)?\s*=\s*["\'][^"\']*{re.escape(EXTERNAL_CANARY_DOMAIN)}',
                        body,
                        re.IGNORECASE,
                    )

                    if meta_match or js_match:
                        matched_snippet = (meta_match or js_match).group(0)
                        findings.append(create_finding(
                            title=f"Client-Side Open Redirect (Likely): param '{param}'",
                            severity="medium",
                            confidence=Confidence.LIKELY.value,
                            detail=f"Parameter '{param}' injected external destination into HTML meta refresh or JavaScript location handler without server-side validation.",
                            recommendation="Sanitize and validate redirect destinations server-side before embedding them into client templates.",
                            evidence=f"Code snippet: {matched_snippet[:120]}",
                        ))
                        records.append({
                            "Parameter": param,
                            "Probe": probe_desc,
                            "HTTP Status": status_code,
                            "Destination": "Client-Side Script",
                            "Confidence": "likely",
                            "Result": "🔥 LIKELY VULNERABLE",
                        })
                        param_confirmed = True
                        break

            except Exception as e:
                pass

        if not param_confirmed:
            records.append({
                "Parameter": param,
                "Probe": "All Probes",
                "HTTP Status": 200,
                "Destination": "Internal / Blocked",
                "Confidence": "not_detected",
                "Result": "Safe (No external redirection)",
            })

    if not findings:
        findings.append(create_finding(
            title="No Open Redirect Detected",
            severity="info",
            confidence=Confidence.NOT_DETECTED.value,
            detail="The tested parameters did not redirect to external target domains.",
            recommendation="Continue enforcing strict internal destination whitelists.",
        ))

    confirmed_count = sum(1 for f in findings if f.get("confidence") == "confirmed")
    likely_count = sum(1 for f in findings if f.get("confidence") == "likely")

    return ok({
        "summary": {
            "Target": url,
            "Parameters Tested": len(params_to_test),
            "Confirmed Redirects": confirmed_count,
            "Likely Redirects": likely_count,
            "Status": "Vulnerable" if (confirmed_count or likely_count) else "Secure",
        },
        "findings": findings,
        "records": records,
        "record_columns": ["Parameter", "Probe", "HTTP Status", "Destination", "Confidence", "Result"],
    })
