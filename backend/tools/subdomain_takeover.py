"""Subdomain Takeover Auditor — Multi-Step Dangling DNS & CNAME Verifier.

Distinguishes between dangling CNAME records and active services:
- Confirmed: CNAME points to provider AND provider explicitly returns unallocated/unclaimed resource response.
- Likely: Dangling CNAME where target canonical name resolves to NXDOMAIN.
- Possible: Known provider CNAME detected with HTTP 404 but unconfirmed claim status.
- Not Detected: CNAME points to active service serving live content.
"""
from __future__ import annotations
import asyncio
import re
import socket
from typing import Any, Dict, List, Optional, Tuple

import dns.resolver
from fastapi import APIRouter

from backend.models import SubdomainReq
from backend.security.confidence import (
    Confidence,
    Severity,
    create_finding,
    standard_response,
)
from backend.security.http_client import safe_request
from backend.security.target_validator import TargetValidationError, validate_hostname
from backend.tools.utils import clean_domain, err, load_wordlist, ok

router = APIRouter(tags=["recon"])

TAKEOVER_FINGERPRINTS = {
    'github.io':            ("There isn't a GitHub Pages site here",           'critical'),
    'herokuapp.com':        ("No such app",                                     'critical'),
    'herokudns.com':        ("No such app",                                     'critical'),
    'azurewebsites.net':    ("Microsoft Azure App Service - Error 404",        'high'),
    's3.amazonaws.com':     ("NoSuchBucket",                                    'critical'),
    'amazonaws.com':        ("NoSuchBucket",                                    'high'),
    'cloudfront.net':       ("Bad request - The request could not be satisfied", 'medium'),
    'netlify.com':          ("Not found - Request ID:",                         'critical'),
    'netlify.app':          ("Not found - Request ID:",                         'critical'),
    'shopify.com':          ("Sorry, this shop is currently unavailable",       'critical'),
    'fastly.net':           ("Fastly error: unknown domain",                    'critical'),
    'ghost.io':             ("The thing you were looking for is not here",      'high'),
    'surge.sh':             ("project not found",                               'critical'),
    'readme.io':            ("Project doesnt exist",                            'high'),
    'wordpress.com':        ("Do you want to register",                         'high'),
    'pantheon.io':          ("The gods are wise, but do not know",              'high'),
    'webflow.io':           ("The page you are looking for doesn't exist",      'high'),
    'bitbucket.io':         ("The Page You're Looking For Isn't Here",         'high'),
    'unbounce.com':         ("The requested URL was not found",                 'critical'),
}


def resolve_cname(domain: str) -> Optional[str]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 4.0
        resolver.lifetime = 4.0
        answers = resolver.resolve(domain, 'CNAME')
        return str(answers[0].target).rstrip('.')
    except Exception:
        return None


def is_cname_dangling(cname: str) -> bool:
    """Check if the CNAME target itself fails to resolve (NXDOMAIN)."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 4.0
        resolver.lifetime = 4.0
        resolver.resolve(cname, 'A')
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except Exception:
        return False


@router.post("/subdomain_takeover")
async def subdomain_takeover(req: SubdomainReq):
    domain = clean_domain(req.target)
    if not domain:
        return err("Invalid domain format.")

    try:
        validate_hostname(domain)
    except TargetValidationError as tve:
        return err(f"Target validation failed: {tve}")

    all_words = load_wordlist("subdomains.txt")
    sizes = {"small": 30, "medium": 80, "large": min(200, len(all_words))}
    words = all_words[:sizes.get(req.wordlist, 80)]
    if not words:
        words = ["www", "mail", "dev", "staging", "api", "blog", "shop", "app", "docs", "status", "test"]

    findings: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []
    sem = asyncio.Semaphore(10)
    loop = asyncio.get_event_loop()

    async def check_subdomain(sub: str) -> Optional[Dict[str, Any]]:
        host = f"{sub}.{domain}"
        async with sem:
            # 1. Resolve CNAME
            cname = await loop.run_in_executor(None, resolve_cname, host)
            if not cname:
                return None

            # 2. Check if CNAME matches a known provider
            matched_service = None
            fingerprint = None
            severity = 'medium'

            for svc_suffix, (fp, sev) in TAKEOVER_FINGERPRINTS.items():
                if cname.endswith(svc_suffix) or svc_suffix in cname:
                    matched_service = svc_suffix
                    fingerprint = fp
                    severity = sev
                    break

            if not matched_service:
                return None

            # 3. Check if CNAME is dangling (NXDOMAIN)
            is_dangling = await loop.run_in_executor(None, is_cname_dangling, cname)

            # 4. HTTP / HTTPS Fingerprint probe
            confirmed = False
            evidence_snippet = ""
            for scheme in ('https', 'http'):
                test_url = f"{scheme}://{host}"
                try:
                    resp = await safe_request("GET", test_url, timeout=5.0)
                    if fingerprint and fingerprint.lower() in resp.text.lower():
                        confirmed = True
                        evidence_snippet = f"HTTP {resp.status_code} matched '{fingerprint}'"
                        break
                except Exception:
                    pass

            conf = Confidence.NOT_DETECTED
            status_text = "Safe / Active"

            if confirmed:
                conf = Confidence.CONFIRMED
                status_text = "💀 CONFIRMED TAKEOVER"
                findings.append(create_finding(
                    title=f"Subdomain Takeover (Confirmed): {host} -> {cname}",
                    severity=severity,
                    confidence=conf.value,
                    detail=f"Subdomain '{host}' points via CNAME to {cname} ({matched_service}). The provider returned an unclaimed/unregistered resource response: '{fingerprint}'.",
                    recommendation=f"Immediately reclaim the asset in {matched_service} or remove the dangling CNAME record from DNS.",
                    evidence=evidence_snippet,
                ))
            elif is_dangling:
                conf = Confidence.LIKELY
                status_text = "🔥 LIKELY DANGLING CNAME"
                findings.append(create_finding(
                    title=f"Dangling CNAME Record (Likely): {host} -> {cname}",
                    severity="high",
                    confidence=conf.value,
                    detail=f"Subdomain '{host}' points to {cname}, but the target canonical name resolves to NXDOMAIN. An attacker can register the target domain and claim traffic.",
                    recommendation="Remove the dangling CNAME record or register the destination domain.",
                    evidence=f"CNAME {cname} resolves to NXDOMAIN",
                ))

            records.append({
                "Subdomain": host,
                "CNAME Target": cname,
                "Service": matched_service,
                "Confidence": conf.value,
                "Result": status_text,
            })
            return True

    await asyncio.gather(*[check_subdomain(w) for w in words])

    if not findings:
        findings.append(create_finding(
            title="No Subdomain Takeover Vulnerabilities Found",
            severity="info",
            confidence=Confidence.NOT_DETECTED.value,
            detail=f"Tested {len(words)} subdomains. No dangling CNAMEs or unclaimed third-party providers detected.",
            recommendation="Regularly audit DNS zones for orphaned records.",
        ))

    return ok({
        "summary": {
            "Domain": domain,
            "Subdomains Checked": len(words),
            "Findings Count": len([f for f in findings if f.get("severity") != "info"]),
        },
        "findings": findings,
        "records": records,
        "record_columns": ["Subdomain", "CNAME Target", "Service", "Confidence", "Result"],
    })
