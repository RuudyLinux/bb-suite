"""Cloud Storage & Asset Exposure Auditor for BB-SUITE.

Extracts real cloud asset URLs directly from page markup and checks candidate buckets:
- Confirmed: Verifiable public cloud bucket listing (HTTP 200 with XML ListBucketResult / public blobs).
- Likely: Referenced storage container exposing downloadable files.
- Possible / Info: Bucket exists (HTTP 403 Forbidden) or candidate name pattern identified.
"""
from __future__ import annotations
import asyncio
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from fastapi import APIRouter

from backend.models import CloudReq
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

CLOUD_URL_REGEX = re.compile(
    r'https?://(?:[a-zA-Z0-9_\-\.]+\.s3(?:[.-][a-zA-Z0-9_\-]+)?\.amazonaws\.com|'
    r's3\.amazonaws\.com/[a-zA-Z0-9_\-\.]+|'
    r'[a-zA-Z0-9_\-\.]+\.blob\.core\.windows\.net|'
    r'storage\.googleapis\.com/[a-zA-Z0-9_\-\.]+)',
    re.IGNORECASE,
)


def derive_name(target: str) -> str:
    n = re.sub(r'^https?://', '', target.strip().lower())
    n = n.split('/')[0].split(':')[0]
    n = re.sub(r'\.(com|org|net|io|co|uk|in|de|fr|app|dev|xyz|tech).*$', '', n)
    return re.sub(r'[^a-z0-9\-]', '', n)


@router.post("/cloud")
async def cloud_exposure(req: CloudReq):
    target_url = clean_url(req.target)
    try:
        validate_target_url(target_url)
    except TargetValidationError as tve:
        return err(f"Target validation failed: {tve}")

    name = derive_name(target_url)
    findings: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []

    discovered_cloud_urls: Set[str] = set()

    # Step 1: Extract real cloud asset URLs from target page HTML
    try:
        resp = await safe_request("GET", target_url, timeout=7.0)
        found_matches = CLOUD_URL_REGEX.findall(resp.text)
        for m in found_matches:
            discovered_cloud_urls.add(m.rstrip('/'))
    except Exception:
        pass

    # Step 2: Build candidate list combining discovered assets and conservative name guessing
    test_targets: List[Tuple[str, str, str]] = []  # (Provider, ResourceURL, SourceType)

    for cloud_url in list(discovered_cloud_urls)[:10]:
        prov = "AWS S3" if "amazonaws.com" in cloud_url else ("Azure Blob" if "windows.net" in cloud_url else "GCP Storage")
        test_targets.append((prov, cloud_url, "Extracted from Markup"))

    if name and len(name) >= 3:
        candidates = [name, f"{name}-assets", f"{name}-media", f"{name}-public", f"{name}-backup"]
        for c in candidates:
            test_targets.append(("AWS S3", f"https://{c}.s3.amazonaws.com/", "Candidate Guess"))
            test_targets.append(("GCP Storage", f"https://storage.googleapis.com/{c}/", "Candidate Guess"))
            test_targets.append(("Azure Blob", f"https://{c.replace('-', '')}.blob.core.windows.net/$web/", "Candidate Guess"))

    sem = asyncio.Semaphore(10)

    async def probe_resource(provider: str, r_url: str, source_type: str):
        async with sem:
            try:
                r = await safe_request("GET", r_url, timeout=5.0)
                status_code = r.status_code
                body = r.text

                # Check for public listing XML
                is_public_listing = status_code == 200 and ("<ListBucketResult" in body or "<EnumerationResults" in body)
                is_public_asset = status_code == 200 and not is_public_listing and len(r.content) > 10
                is_forbidden = status_code in (401, 403) or "<AccessDenied" in body

                conf = Confidence.NOT_DETECTED
                status_label = "Private / Inaccessible"

                if is_public_listing:
                    conf = Confidence.CONFIRMED
                    status_label = "💀 PUBLIC READ (Listing Open)"
                    findings.append(create_finding(
                        title=f"Public Cloud Storage Bucket Exposed ({provider}): {r_url}",
                        severity="critical",
                        confidence=conf.value,
                        detail=f"Resource '{r_url}' is publicly accessible and allows unauthenticated directory listing (HTTP 200 ListBucketResult).",
                        recommendation="Disable public read access on the bucket policy and enable S3 Block Public Access.",
                        evidence=f"XML Listing Snippet: {body[:150]}",
                    ))
                elif is_public_asset and source_type == "Candidate Guess":
                    conf = Confidence.LIKELY
                    status_label = "🔥 PUBLIC ACCESSIBLE"
                    findings.append(create_finding(
                        title=f"Candidate Cloud Storage Responds HTTP 200 ({provider})",
                        severity="medium",
                        confidence=conf.value,
                        detail=f"Candidate storage '{r_url}' responded with HTTP 200 OK. Public files may be hosted.",
                        recommendation="Verify whether public read permissions are intentional.",
                        evidence=f"HTTP 200 returned ({len(r.content)} bytes)",
                    ))
                elif is_forbidden:
                    status_label = "Exists (Access Denied / 403)"

                records.append({
                    "Provider": provider,
                    "Resource": r_url,
                    "Source": source_type,
                    "Status": status_label,
                    "Confidence": conf.value,
                })
            except Exception:
                pass

    await asyncio.gather(*[probe_resource(p, u, s) for p, u, s in test_targets])

    if not findings:
        findings.append(create_finding(
            title="No Public Cloud Storage Exposure Detected",
            severity="info",
            confidence=Confidence.NOT_DETECTED.value,
            detail=f"Checked {len(records)} extracted and candidate cloud resources. No public bucket listings found.",
            recommendation="Continue enforcing cloud account identity access management.",
        ))

    return ok({
        "summary": {
            "Target": target_url,
            "Resources Tested": len(records),
            "Extracted Assets": len(discovered_cloud_urls),
            "Exposed Findings": len([f for f in findings if f.get("severity") != "info"]),
        },
        "findings": findings,
        "records": records,
        "record_columns": ["Provider", "Resource", "Source", "Status", "Confidence"],
    })
