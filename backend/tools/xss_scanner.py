"""XSS Scanner — Context-Aware Cross-Site Scripting Detection Engine.

Distinguishes between:
- Safe encoded reflection (HTML entities)
- Benign reflected text
- Attribute-context breakout
- Script/event-handler execution context
Employs safe unique markers and four-tier confidence taxonomy: Confirmed, Likely, Possible, Not Detected.
"""
from __future__ import annotations
import asyncio
import html
import re
import secrets
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from typing import Any, Dict, List, Optional, Set, Tuple

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

DOM_SINKS = [
    r"document\.write\s*\(",
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"eval\s*\(",
    r"setTimeout\s*\([^,]+[+\`]",
    r"setInterval\s*\([^,]+[+\`]",
    r"location\.href\s*=",
    r"location\.replace\s*\(",
]


class XSSRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    mode: str = Field("reflected", max_length=64)   # reflected | dom | all
    max_params: int = Field(10, ge=1, le=50)


def build_probe_url(url: str, param: str, probe_value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [probe_value]
    flat = {k: v[0] for k, v in params.items()}
    return urlunparse(parsed._replace(query=urlencode(flat)))


def analyze_reflection_context(response_body: str, marker: str) -> Tuple[str, bool, str]:
    """Analyze the specific DOM context where the marker is reflected.

    Returns:
        (context_name, is_executable, evidence_snippet)
    """
    idx = response_body.find(marker)
    if idx == -1:
        return "not_found", False, ""

    start = max(0, idx - 100)
    end = min(len(response_body), idx + len(marker) + 100)
    snippet = response_body[start:end]

    # Check if inside an existing <script> tag
    script_open = response_body.rfind("<script", 0, idx)
    script_close = response_body.rfind("</script>", 0, idx)
    if script_open > script_close:
        return "javascript_context", True, snippet

    # Check if inside a tag attribute (e.g. <input value="MARKER">)
    tag_open = response_body.rfind("<", 0, idx)
    tag_close = response_body.rfind(">", 0, idx)
    if tag_open > tag_close:
        # We are inside an HTML tag definition
        return "attribute_context", True, snippet

    # Check if inside comment
    if "<!--" in response_body[max(0, idx - 50):idx] and "-->" in response_body[idx:idx + 50]:
        return "comment_context", False, snippet

    # In HTML body text context
    return "html_body_context", True, snippet


@router.post("/xss_scanner")
async def xss_scanner(req: XSSRequest):
    url = clean_url(req.target)
    try:
        validate_target_url(url)
    except TargetValidationError as tve:
        return err(f"Target validation failed: {tve}")

    parsed = urlparse(url)
    existing_params = parse_qs(parsed.query, keep_blank_values=True)

    params_to_test = list(existing_params.keys())[:req.max_params]
    if not params_to_test:
        params_to_test = ["q", "search", "query", "id", "keyword"]

    findings: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []

    # Test baseline
    try:
        baseline_resp = await safe_request("GET", url, timeout=8.0)
        baseline_body = baseline_resp.text
    except Exception as e:
        return err(f"Failed to reach target: {e}")

    # Check DOM sinks in baseline HTML
    if req.mode in ("dom", "all"):
        for sink in DOM_SINKS:
            match = re.search(sink, baseline_body, re.IGNORECASE)
            if match:
                findings.append(create_finding(
                    title=f"Potential DOM XSS Sink Detected",
                    severity="medium",
                    confidence=Confidence.POSSIBLE.value,
                    detail=f"Found dangerous DOM sink matching regex '{sink}' in client scripts.",
                    recommendation="Avoid assigning untrusted data to dangerous DOM sinks (innerHTML, document.write). Use textContent or safe DOM APIs.",
                    evidence=match.group(0),
                ))

    # Test reflected parameters
    if req.mode in ("reflected", "all"):
        for param in params_to_test:
            # Step 1: Benign Canary Probe
            canary_id = secrets.token_hex(4)
            canary = f"bbcanary_{canary_id}"
            probe_url = build_probe_url(url, param, canary)

            try:
                canary_resp = await safe_request("GET", probe_url, timeout=7.0)
                if canary not in canary_resp.text:
                    records.append({
                        "Parameter": param,
                        "Status": "Not Reflected",
                        "Confidence": "not_detected",
                        "Context": "None",
                        "Result": "Safe (No reflection)",
                    })
                    continue

                # Step 2: Context Evaluation with HTML Breakout Probe
                breakout_probe = f"bbxss{canary_id}<xss'\"test>"
                breakout_url = build_probe_url(url, param, breakout_probe)
                breakout_resp = await safe_request("GET", breakout_url, timeout=7.0)
                breakout_body = breakout_resp.text

                # Check if characters were entity encoded
                encoded_lt = "&lt;" in breakout_body
                unencoded_lt = f"<xss'\"test>" in breakout_body

                if not unencoded_lt and encoded_lt:
                    records.append({
                        "Parameter": param,
                        "Status": "Properly Encoded",
                        "Confidence": "not_detected",
                        "Context": "HTML Entity Encoded",
                        "Result": "Safe (Input sanitized/encoded)",
                    })
                    continue

                # Step 3: Executable Probe Test
                tag_marker = f"bbsuite{canary_id}"
                exec_payload = f"<{tag_marker} id=1>"
                exec_url = build_probe_url(url, param, exec_payload)
                exec_resp = await safe_request("GET", exec_url, timeout=7.0)

                context_type, is_executable, snippet = analyze_reflection_context(exec_resp.text, tag_marker)

                if exec_payload in exec_resp.text and is_executable:
                    conf = Confidence.CONFIRMED
                    sev = "critical" if context_type == "javascript_context" else "high"
                    title = f"Reflected XSS ({conf.value.capitalize()}): param '{param}' in {context_type}"
                    findings.append(create_finding(
                        title=title,
                        severity=sev,
                        confidence=conf.value,
                        detail=f"Injected unescaped HTML tag probe '{exec_payload}' into parameter '{param}'. The server reflected it unencoded in {context_type}.",
                        recommendation="Encode all user-supplied output according to context (HTML entity encoding, JavaScript string escaping) and implement a restrictive Content-Security-Policy.",
                        evidence=f"Reflected snippet: {snippet[:150]}",
                    ))
                    records.append({
                        "Parameter": param,
                        "Status": "Executable Reflection",
                        "Confidence": conf.value,
                        "Context": context_type,
                        "Result": "💀 CONFIRMED VULNERABLE",
                    })
                elif unencoded_lt:
                    conf = Confidence.LIKELY
                    findings.append(create_finding(
                        title=f"Potential Executable XSS (Likely): param '{param}'",
                        severity="medium",
                        confidence=conf.value,
                        detail=f"Parameter '{param}' reflected special characters '<', '\"', ''' without HTML entity encoding, but custom tag execution was restricted.",
                        recommendation="Enforce context-aware output encoding across all templates.",
                        evidence=f"Unencoded reflection observed for parameter {param}",
                    ))
                    records.append({
                        "Parameter": param,
                        "Status": "Unencoded Reflection",
                        "Confidence": conf.value,
                        "Context": context_type,
                        "Result": "🔥 LIKELY VULNERABLE",
                    })
                else:
                    records.append({
                        "Parameter": param,
                        "Status": "Reflected Text Only",
                        "Confidence": "possible",
                        "Context": "Textual",
                        "Result": "Reflected Text (Sanitized)",
                    })

            except Exception as e:
                records.append({
                    "Parameter": param,
                    "Status": "Error",
                    "Confidence": "not_detected",
                    "Context": "None",
                    "Result": f"Probe error: {str(e)[:30]}",
                })

    if not findings:
        findings.append(create_finding(
            title="No Executable XSS Detected",
            severity="info",
            confidence=Confidence.NOT_DETECTED.value,
            detail="All tested parameters either did not reflect or properly encoded HTML special characters.",
            recommendation="Maintain secure templating practices and CSP headers.",
        ))

    confirmed_count = sum(1 for f in findings if f.get("confidence") == "confirmed")
    likely_count = sum(1 for f in findings if f.get("confidence") == "likely")

    return ok({
        "summary": {
            "Target": url,
            "Parameters Tested": len(params_to_test),
            "Confirmed XSS": confirmed_count,
            "Likely XSS": likely_count,
            "Status": "Vulnerable" if (confirmed_count or likely_count) else "Secure",
        },
        "findings": findings,
        "records": records,
        "record_columns": ["Parameter", "Status", "Confidence", "Context", "Result"],
    })
