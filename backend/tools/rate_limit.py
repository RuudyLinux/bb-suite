"""Rate Limit Resilience & Throttling Tester for BB-SUITE.

Analyzes HTTP rate-limiting mechanisms safely without causing accidental denial-of-service:
- HTTP 429 / Retry-After inspection (Confirmed Rate Limiting Active)
- RateLimit headers (RateLimit-Limit, X-RateLimit-Remaining)
- Latency escalation & progressive throttling analysis
- Reports absence as 'No obvious HTTP rate limiting observed within test threshold' (Possible).
"""
from __future__ import annotations
import asyncio
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter

from backend.models import RateLimitReq
from backend.security.confidence import (
    Confidence,
    Severity,
    create_finding,
    standard_response,
)
from backend.security.target_validator import TargetValidationError, validate_target_url
from backend.tools.utils import clean_url, err, http_get, ok

router = APIRouter(tags=["exploit"])


@router.post("/rate_limit")
async def rate_limit_test(req: RateLimitReq):
    url = clean_url(req.target)
    try:
        validate_target_url(url)
    except TargetValidationError as tve:
        return err(f"Target validation failed: {tve}")

    total = max(1, min(req.requests, 100))
    concurrency = max(1, min(req.concurrency, 10))

    results: List[Dict[str, Any]] = []
    rate_limited_at: Optional[int] = None
    lock = asyncio.Lock()
    semaphore = asyncio.Semaphore(concurrency)

    async def fire(i: int) -> Dict[str, Any]:
        nonlocal rate_limited_at
        async with semaphore:
            t0 = time.monotonic()
            extra = {}
            if req.custom_header:
                try:
                    k, _, v = req.custom_header.partition(":")
                    extra = {k.strip(): v.strip()}
                except Exception:
                    pass
            r = await http_get(url, timeout=10, extra_headers=extra)
            elapsed_ms = round((time.monotonic() - t0) * 1000)
            code = r["status"]

            headers = r.get("headers", {})
            retry_after = headers.get("retry-after", "")
            rl_remaining = headers.get("x-ratelimit-remaining", headers.get("ratelimit-remaining", ""))

            # Rate limited triggers: 429, or 403 with rate limit body, or Retry-After
            is_rl = (code == 429) or (bool(retry_after)) or (code == 403 and "rate limit" in r.get("body", "").lower())

            async with lock:
                if is_rl and rate_limited_at is None:
                    rate_limited_at = i + 1

            return {
                "req": i + 1,
                "status": code,
                "ms": elapsed_ms,
                "rate_limited": "YES" if is_rl else "NO",
                "retry_after": retry_after,
                "rl_remaining": rl_remaining,
            }

    tasks = [fire(i) for i in range(total)]
    results = list(await asyncio.gather(*tasks))
    results.sort(key=lambda x: x["req"])

    codes: Dict[int, int] = {}
    for row in results:
        codes[row["status"]] = codes.get(row["status"], 0) + 1

    rl_count = sum(1 for r in results if r["rate_limited"] == "YES")
    avg_ms = round(sum(r["ms"] for r in results) / len(results)) if results else 0
    min_ms = min(r["ms"] for r in results) if results else 0
    max_ms = max(r["ms"] for r in results) if results else 0

    # Progressive throttling check: compare first quarter latency to last quarter
    first_quarter_ms = sum(r["ms"] for r in results[:max(1, total // 4)]) / max(1, total // 4)
    last_quarter_ms = sum(r["ms"] for r in results[-max(1, total // 4):]) / max(1, total // 4)
    progressive_throttling = last_quarter_ms > (first_quarter_ms * 2.5) and last_quarter_ms > 1000

    findings: List[Dict[str, Any]] = []

    if rl_count > 0:
        findings.append(create_finding(
            title=f"Rate Limiting Active (Triggered at #{rate_limited_at})",
            severity="info",
            confidence=Confidence.CONFIRMED.value,
            detail=f"{rl_count}/{total} requests were throttled or blocked by the server with HTTP 429 or Retry-After.",
            recommendation="Rate limiting is actively enforcing threshold policies.",
            evidence=f"First blocked at request #{rate_limited_at}",
        ))
    elif progressive_throttling:
        findings.append(create_finding(
            title="Progressive Latency Throttling Observed",
            severity="info",
            confidence=Confidence.LIKELY.value,
            detail=f"Average response time escalated significantly from {round(first_quarter_ms)}ms to {round(last_quarter_ms)}ms under burst load, suggesting dynamic server throttling.",
            recommendation="Review server throttling curves to balance defense and UX.",
        ))
    else:
        findings.append(create_finding(
            title="No Obvious HTTP Rate Limiting Observed Within Test Threshold",
            severity="medium",
            confidence=Confidence.POSSIBLE.value,
            detail=f"{total} requests completed without triggering HTTP 429, Retry-After, or perceptible delay. Rate limiting may have a higher threshold or require authentication.",
            recommendation="Consider adding rate limiting on sensitive API endpoints, login forms, and resource-heavy operations.",
            evidence=f"{total} requests sent at concurrency={concurrency}, 0 throttled.",
        ))

    if codes.get(500, 0) > 0:
        findings.append(create_finding(
            title="Server Errors Under Burst Load (HTTP 500)",
            severity="high",
            confidence=Confidence.CONFIRMED.value,
            detail=f"{codes[500]} requests returned HTTP 500 internal server errors during concurrent probing.",
            recommendation="Investigate application logs for database connection pool exhaustion or uncaught exceptions.",
            evidence=f"{codes[500]} 500-responses recorded.",
        ))

    return ok({
        "summary": {
            "Target": url,
            "Requests Sent": total,
            "Rate Limited Count": rl_count,
            "Rate Limited At": f"#{rate_limited_at}" if rate_limited_at else "Never",
            "Avg Response Latency": f"{avg_ms}ms",
            "Min / Max Latency": f"{min_ms}ms / {max_ms}ms",
            "Throttling Status": "Enforced" if rl_count else ("Progressive" if progressive_throttling else "Not Observed"),
        },
        "findings": findings,
        "records": results,
        "record_columns": ["req", "status", "ms", "rate_limited", "retry_after", "rl_remaining"],
        "code_breakdown": codes,
    })
