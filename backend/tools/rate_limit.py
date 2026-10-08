from __future__ import annotations
import asyncio
import time
from fastapi import APIRouter
from models import RateLimitReq
from tools.utils import clean_url, http_get, f, ok, err

router = APIRouter(tags=["exploit"])


@router.post("/rate_limit")
async def rate_limit_test(req: RateLimitReq):
    url = clean_url(req.target)
    total = max(1, min(req.requests, 150))
    concurrency = max(1, min(req.concurrency, 20))

    results: list[dict] = []
    rate_limited_at: int | None = None
    lock = asyncio.Lock()
    semaphore = asyncio.Semaphore(concurrency)

    async def fire(i: int) -> dict:
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
            elapsed = round((time.monotonic() - t0) * 1000)
            code = r["status"]

            rl_headers = {
                k: v for k, v in r["headers"].items()
                if any(x in k.lower() for x in
                       ["x-ratelimit", "x-rate-limit", "retry-after",
                        "ratelimit", "rate-limit"])
            }
            is_rl = code == 429 or bool(rl_headers)

            async with lock:
                if is_rl and rate_limited_at is None:
                    rate_limited_at = i + 1

            return {
                "req":          i + 1,
                "status":       code,
                "ms":           elapsed,
                "rate_limited": "YES" if is_rl else "—",
                "retry_after":  r["headers"].get("retry-after", ""),
                "rl_remaining": r["headers"].get("x-ratelimit-remaining",
                                r["headers"].get("ratelimit-remaining", "")),
            }

    tasks = [fire(i) for i in range(total)]
    results = list(await asyncio.gather(*tasks))
    results.sort(key=lambda x: x["req"])

    codes: dict[int, int] = {}
    for row in results:
        codes[row["status"]] = codes.get(row["status"], 0) + 1

    rl_count = sum(1 for r in results if r["rate_limited"] == "YES")
    avg_ms   = round(sum(r["ms"] for r in results) / len(results)) if results else 0
    min_ms   = min(r["ms"] for r in results) if results else 0
    max_ms   = max(r["ms"] for r in results) if results else 0

    findings = []

    if rl_count == 0:
        findings.append(f(
            "high", "No Rate Limiting Detected",
            f"{total} requests sent — none returned 429 or rate-limit headers",
            "Add rate limiting (nginx limit_req_zone, express-rate-limit, etc.)",
        ))
    else:
        findings.append(f(
            "pass", f"Rate Limit Triggered at Request #{rate_limited_at}",
            f"{rl_count}/{total} requests were blocked. Rate limiting is active.",
            "Rate limiting is working correctly",
        ))

    if codes.get(500, 0) > 0:
        findings.append(f(
            "high", "Server Errors Under Load",
            f"{codes[500]} requests returned HTTP 500 — server may crash under load",
            "Check error logs; fix server stability",
        ))
    if codes.get(503, 0) > 0:
        findings.append(f(
            "medium", "Service Unavailable Under Load",
            f"{codes[503]} requests returned HTTP 503",
            "Tune server concurrency limits or add load balancer",
        ))

    slowest = max(results, key=lambda x: x["ms"])
    if max_ms > 5000:
        findings.append(f(
            "medium", f"Slow Response Detected ({max_ms}ms)",
            f"Request #{slowest['req']} took {max_ms}ms",
            "Investigate slow endpoints; add caching or connection pooling",
        ))

    return ok({
        "summary": {
            "Target":        url,
            "Requests Sent": total,
            "Rate Limited":  rl_count,
            "Rate Limit At": f"#{rate_limited_at}" if rate_limited_at else "Never",
            "Avg Response":  f"{avg_ms}ms",
            "Min/Max":       f"{min_ms}ms / {max_ms}ms",
        },
        "findings": findings,
        "records":  results,
        "record_columns": ["req", "status", "ms", "rate_limited", "retry_after", "rl_remaining"],
        "code_breakdown": codes,
    })
