"""
Open Redirect Scanner
Detects open redirect vulnerabilities in URL parameters and headers.
"""
from __future__ import annotations
import asyncio
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from typing import List, Dict, Tuple, Optional, Any
import httpx
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

EVIL_DOMAINS = [
    "https://evil.com",
    "//evil.com",
    "https://attacker.com",
    "//attacker.com/redirect",
    "https://google.com",            # benign indicator domain for detection
    "https://example-phishing.com",
]

# Bypass techniques
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "/\\evil.com",
    "https:evil.com",
    "https://evil.com%2F",
    "https://evil.com@target.com",
    "%2F%2Fevil.com",
    "https%3A//evil.com",
    "javascript://evil.com%0aalert(1)",
    "data:text/html,<script>window.location='https://evil.com'</script>",
    "/%5cevil.com",
    "//evil%E3%80%82com",
]

# Common redirect parameter names
REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "returnTo", "return_url",
    "returnUrl", "redirect_uri", "redirect_url", "goto", "destination",
    "dest", "target", "redir", "link", "out", "forward", "to", "location",
    "continue", "back", "ref", "r", "go",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (BB-Suite Open Redirect Scanner)",
    "Accept": "text/html,*/*",
}


class RedirectRequest(BaseModel):
    target: str
    depth: str = "medium"  # quick | medium | deep


def _normalize_url(url: str) -> str:
    if not url.startswith("http"):
        url = "https://" + url
    return url


def _is_external_redirect(response: httpx.Response, payload: str) -> tuple[bool, str]:
    """Check if response redirects to external domain."""
    # Check Location header
    loc = response.headers.get("Location", "")
    if loc:
        parsed = urlparse(loc)
        if parsed.netloc and "evil.com" in parsed.netloc:
            return True, f"Location header redirects to `{loc}`"
        if parsed.netloc and parsed.netloc not in ["", "target.com"]:
            # Check if it's a known indicator domain
            if any(d in loc for d in ["evil.com", "attacker.com", "google.com"]):
                return True, f"Location header: `{loc}`"

    # Check final URL after redirect following
    history = response.history
    for hist_r in history:
        hist_loc = hist_r.headers.get("Location", "")
        if hist_loc and any(d in hist_loc for d in ["evil.com", "attacker.com"]):
            return True, f"Redirect chain to `{hist_loc}`"

    return False, ""


async def _test_redirect_param(
    client: httpx.AsyncClient,
    base_url: str,
    param: str,
    payloads: list[str],
    findings: list,
):
    parsed = urlparse(base_url)
    existing_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

    for payload in payloads:
        test_params = dict(existing_params)
        test_params[param] = payload
        test_url = parsed._replace(query=urlencode(test_params)).geturl()

        try:
            # First test WITHOUT following redirects to catch the Location header
            r = await client.get(test_url, timeout=8, follow_redirects=False)
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "")
                if loc and any(d in loc for d in ["evil.com", "attacker.com", "google.com"]):
                    findings.append({
                        "severity": "high",
                        "title": f"Open Redirect — Parameter `{param}`",
                        "detail": (
                            f"Parameter `{param}` with payload `{payload}` triggers a {r.status_code} redirect "
                            f"to external domain: `{loc}`. This can be used for phishing attacks."
                        ),
                        "recommendation": (
                            "Implement a strict redirect whitelist. Never redirect to user-supplied URLs. "
                            "Use server-side token-based redirects. Add a confirmation page for external redirects."
                        ),
                    })
                    return  # Found for this param, stop

            # Check if payload appears in meta refresh or JS redirect
            if payload in r.text or "evil.com" in r.text:
                if re.search(r'(meta.*refresh|window\.location|location\.href)', r.text, re.I):
                    findings.append({
                        "severity": "medium",
                        "title": f"Possible JS/Meta Redirect Injection — Parameter `{param}`",
                        "detail": (
                            f"Payload `{payload}` appears in page source alongside redirect JavaScript or "
                            f"meta refresh tag. May indicate client-side open redirect."
                        ),
                        "recommendation": "Sanitize redirect destinations server-side before embedding in page.",
                    })
                    return

        except Exception:
            pass


async def _crawl_redirect_params(client: httpx.AsyncClient, url: str, findings: list, depth: str):
    """Find redirect params in the page itself and test them."""
    try:
        r = await client.get(url, timeout=10, follow_redirects=True)
        html = r.text

        # Find links with potential redirect params
        link_matches = re.findall(
            r'href=["\']([^"\']*(?:' + '|'.join(REDIRECT_PARAMS[:10]) + r')[^"\']*)["\']',
            html, re.I
        )
        found_urls = set()
        for link in link_matches[:20]:
            full = urljoin(url, link)
            if urlparse(full).query:
                found_urls.add(full)

        payloads_map = {"quick": 4, "medium": 8, "deep": len(REDIRECT_PAYLOADS)}
        payloads = REDIRECT_PAYLOADS[:payloads_map.get(depth, 8)]

        for found_url in list(found_urls)[:10]:
            parsed = urlparse(found_url)
            params = list(parse_qs(parsed.query).keys())
            for p in params:
                if p.lower() in [rp.lower() for rp in REDIRECT_PARAMS]:
                    await _test_redirect_param(client, found_url, p, payloads, findings)

    except Exception:
        pass


@router.post("/open_redirect")
async def open_redirect_scan(req: RedirectRequest):
    t0 = time.time()
    target = _normalize_url(req.target.strip())
    findings = []

    payloads_map = {"quick": 4, "medium": 8, "deep": len(REDIRECT_PAYLOADS)}
    payloads = REDIRECT_PAYLOADS[:payloads_map.get(req.depth, 8)]

    async with httpx.AsyncClient(headers=HEADERS, verify=False) as client:
        parsed = urlparse(target)
        existing_params = list(parse_qs(parsed.query).keys())

        # Test existing URL params that look like redirect params
        redirect_like = [p for p in existing_params if p.lower() in [r.lower() for r in REDIRECT_PARAMS]]

        tasks = []
        if redirect_like:
            for p in redirect_like[:5]:
                tasks.append(_test_redirect_param(client, target, p, payloads, findings))
        else:
            # Inject common redirect params
            for p in REDIRECT_PARAMS[:8]:
                tasks.append(_test_redirect_param(client, target, p, payloads, findings))

        # Also crawl the page for redirect links
        tasks.append(_crawl_redirect_params(client, target, findings, req.depth))

        await asyncio.gather(*tasks, return_exceptions=True)

    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        key = f["title"]
        if key not in seen:
            seen.add(key)
            unique.append(f)

    if not unique:
        unique.append({
            "severity": "pass",
            "title": "No Open Redirect Vulnerabilities Detected",
            "detail": f"Tested {len(REDIRECT_PARAMS[:8])} redirect parameters with {len(payloads)} payloads at {target}.",
            "recommendation": "Continue to validate all redirect destinations against a strict whitelist.",
        })

    highs = sum(1 for f in unique if f["severity"] in ("critical", "high"))

    return {
        "success": True,
        "data": {
            "summary": {
                "Target": target,
                "Depth": req.depth,
                "Redirect Params Tested": str(len(REDIRECT_PARAMS[:8])),
                "Payloads per Param": str(len(payloads)),
                "Vulnerable": str(highs),
                "Duration": f"{time.time()-t0:.1f}s",
            },
            "findings": unique,
        },
    }
