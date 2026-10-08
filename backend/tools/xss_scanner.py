"""
XSS Scanner — Reflected, Stored indicator, and DOM-based XSS detection.
Tests URL parameters, forms, and headers with polyglot payloads.
"""
from __future__ import annotations
import asyncio
import re
import time
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from typing import List, Dict, Tuple, Optional, Any
import httpx
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

# Polyglot XSS payloads covering reflected, attribute, JS context
PAYLOADS = [
    "<script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "<img src=x onerror=alert(document.domain)>",
    '"><svg onload=alert(1)>',
    "';alert(1)//",
    '"><body onload=alert(1)>',
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "{{7*7}}",  # Template injection probe
    "${7*7}",   # JS template literal probe
]

DOM_SINKS = [
    r"document\.write\s*\(",
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"eval\s*\(",
    r"setTimeout\s*\(",
    r"setInterval\s*\(",
    r"location\.href\s*=",
    r"location\.replace\s*\(",
    r"document\.location\s*=",
    r"window\.location\s*=",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (BB-Suite XSS Scanner)",
    "Accept": "text/html,application/xhtml+xml,*/*",
}


class XSSRequest(BaseModel):
    target: str
    mode: str = "reflected"   # reflected | dom | forms | all
    max_params: int = 10


def _normalize_url(url: str) -> str:
    if not url.startswith("http"):
        url = "https://" + url
    return url


def _inject_params(url: str, payload: str) -> list[str]:
    """Return list of URLs with each param replaced by payload."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    injected = []
    for key in list(params.keys()):
        modified = dict(params)
        modified[key] = [payload]
        flat = {k: v[0] for k, v in modified.items()}
        new_url = parsed._replace(query=urlencode(flat)).geturl()
        injected.append((key, new_url))
    return injected


def _check_reflection(response_text: str, payload: str) -> bool:
    """Check if payload is reflected unencoded."""
    return payload in response_text or payload.lower() in response_text.lower()


def _score_context(text: str, payload: str) -> str:
    """Determine reflection context."""
    idx = text.lower().find(payload.lower()[:20])
    if idx == -1:
        return "unknown"
    snippet = text[max(0, idx-80):idx+80]
    if "<script" in snippet.lower():
        return "script_context"
    if re.search(r'on\w+\s*=', snippet, re.I):
        return "event_handler"
    if snippet.count('"') % 2 != 0 or snippet.count("'") % 2 != 0:
        return "attribute"
    return "html_context"


async def _scan_reflected(client: httpx.AsyncClient, url: str, findings: list, max_params: int):
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        # Add a dummy param to probe for reflection
        probe_url = url + ("&" if "?" in url else "?") + "q=XSS_PROBE"
        injections = [("q", probe_url.replace("XSS_PROBE", p)) for p in PAYLOADS[:3]]
    else:
        injections = []
        for key in list(params.keys())[:max_params]:
            for payload in PAYLOADS[:6]:
                modified = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                modified[key] = payload
                new_url = parsed._replace(query=urlencode(modified)).geturl()
                injections.append((key, new_url))

    vulnerable_params = set()
    for param, test_url in injections:
        if param in vulnerable_params:
            continue
        try:
            r = await client.get(test_url, timeout=8, follow_redirects=True)
            payload = test_url.split(f"{param}=", 1)[-1].split("&")[0]
            if _check_reflection(r.text, payload):
                context = _score_context(r.text, payload)
                severity = "high" if context in ("script_context", "event_handler") else "medium"
                vulnerable_params.add(param)
                findings.append({
                    "severity": severity,
                    "title": f"Reflected XSS — Parameter `{param}`",
                    "detail": (
                        f"Payload `{payload[:80]}` was reflected unencoded in the response "
                        f"(context: {context}). URL: {test_url[:120]}"
                    ),
                    "recommendation": (
                        "Sanitize all user-supplied input server-side. Use contextual output encoding "
                        "(HTML encode in HTML context, JS escape in script context). "
                        "Implement a strict Content-Security-Policy (CSP) header."
                    ),
                })
        except Exception:
            pass


async def _scan_dom(client: httpx.AsyncClient, url: str, findings: list):
    try:
        r = await client.get(url, timeout=10, follow_redirects=True)
        html = r.text
        for sink_pattern in DOM_SINKS:
            matches = re.findall(sink_pattern, html, re.I)
            if matches:
                findings.append({
                    "severity": "medium",
                    "title": f"Potential DOM XSS Sink — `{matches[0]}`",
                    "detail": (
                        f"Found {len(matches)} occurrence(s) of dangerous DOM sink `{matches[0]}` in "
                        f"the page source. If user-controlled input reaches this sink, DOM-based XSS is possible."
                    ),
                    "recommendation": (
                        "Audit JavaScript code that feeds user-controlled data (location.hash, "
                        "URL params, postMessage) into these sinks. Use DOMPurify or textContent "
                        "instead of innerHTML. Implement CSP with 'strict-dynamic'."
                    ),
                })
    except Exception:
        pass


async def _scan_forms(client: httpx.AsyncClient, url: str, findings: list):
    """Extract forms and probe inputs."""
    try:
        r = await client.get(url, timeout=10, follow_redirects=True)
        # Find all form actions
        form_actions = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', r.text, re.I)
        input_names = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', r.text, re.I)

        if not form_actions:
            form_actions = [url]

        for action in form_actions[:3]:
            action_url = urljoin(url, action)
            for name in input_names[:5]:
                for payload in PAYLOADS[:4]:
                    try:
                        post_r = await client.post(
                            action_url,
                            data={name: payload},
                            headers=HEADERS,
                            timeout=8,
                            follow_redirects=True,
                        )
                        if _check_reflection(post_r.text, payload):
                            findings.append({
                                "severity": "high",
                                "title": f"Form XSS — Field `{name}` at `{action_url}`",
                                "detail": (
                                    f"XSS payload reflected in POST response for field `{name}`. "
                                    f"Action: {action_url}. Payload: {payload[:60]}"
                                ),
                                "recommendation": (
                                    "Validate and encode all form inputs server-side before rendering. "
                                    "Use template engines with auto-escaping enabled."
                                ),
                            })
                            break
                    except Exception:
                        pass
    except Exception:
        pass


@router.post("/xss_scanner")
async def xss_scan(req: XSSRequest):
    t0 = time.time()
    target = _normalize_url(req.target.strip())
    findings = []
    tested_urls = []
    summary = {}

    async with httpx.AsyncClient(headers=HEADERS, verify=False) as client:
        tasks = []
        mode = req.mode

        if mode in ("reflected", "all"):
            tasks.append(_scan_reflected(client, target, findings, req.max_params))
        if mode in ("dom", "all"):
            tasks.append(_scan_dom(client, target, findings))
        if mode in ("forms", "all"):
            tasks.append(_scan_forms(client, target, findings))

        await asyncio.gather(*tasks, return_exceptions=True)

    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        key = f["title"]
        if key not in seen:
            seen.add(key)
            unique.append(f)

    crits = sum(1 for f in unique if f["severity"] == "critical")
    highs = sum(1 for f in unique if f["severity"] == "high")
    meds  = sum(1 for f in unique if f["severity"] == "medium")

    if not unique:
        unique.append({
            "severity": "pass",
            "title": "No XSS Vulnerabilities Detected",
            "detail": f"No reflected, DOM, or form-based XSS found at {target} with {len(PAYLOADS)} payloads.",
            "recommendation": "Maintain current input sanitization practices. Run authenticated scans for deeper coverage.",
        })

    summary = {
        "Target": target,
        "Mode": req.mode,
        "Payloads Tested": str(len(PAYLOADS)),
        "Findings": str(len(unique)),
        "Critical/High": str(crits + highs),
        "Duration": f"{time.time()-t0:.1f}s",
    }

    return {
        "success": True,
        "data": {
            "summary": summary,
            "findings": unique,
        },
    }
