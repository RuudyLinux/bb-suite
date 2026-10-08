import re
import httpx
from fastapi import APIRouter
from models import TargetReq
from tools.utils import clean_url, f, ok, err, HEADERS

router = APIRouter(tags=["analysis"])

SESSION_NAMES = [
    "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "connect.sid",
    "session", "sid", "sessionid", "SESSID", "token", "auth_token", "jwt", "_session_id"
]


@router.post("/cookies")
async def cookie_analyzer(req: TargetReq):
    url = clean_url(req.target)
    raw_cookies = []
    status = 0
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as c:
            r = await c.get(url, headers=HEADERS)
            status = r.status_code
            raw_cookies = [v for k, v in r.headers.multi_items() if k.lower() == "set-cookie"]
    except Exception as e:
        return err(str(e))

    if not raw_cookies:
        return ok({
            "summary": {"URL": url, "Cookies Found": 0, "Session Security": "No Cookies Set"},
            "findings": [f("info", "No Cookies Set", "Server did not return any Set-Cookie headers on landing.")],
            "cookies": [],
            "records": [],
            "record_columns": ["Name", "Secure", "HttpOnly", "SameSite", "Type", "Entropy / Length"]
        })

    findings = []
    cookies = []
    records = []

    for raw in raw_cookies:
        parts = [p.strip() for p in raw.split(";")]
        nv = parts[0]
        eq = nv.find("=")
        name = nv[:eq] if eq != -1 else nv
        value = nv[eq+1:] if eq != -1 else ""
        attrs = {p.lower(): True if "=" not in p else p.split("=", 1)[1]
                 for p in parts[1:]}

        secure   = "secure" in attrs
        httponly = "httponly" in attrs
        samesite = attrs.get("samesite", "")
        domain   = attrs.get("domain", "")
        path     = attrs.get("path", "/")
        is_sess  = any(s.lower() == name.lower() for s in SESSION_NAMES) or bool(re.search(r'sess|token|auth|jwt|sid|user|login|remember', name, re.I))

        cookies.append({
            "name": name,
            "secure": secure,
            "httponly": httponly,
            "samesite": samesite,
            "domain": domain,
            "path": path,
            "value_len": len(value),
            "is_session": is_sess,
        })

        # Base severity escalation for session tokens
        sev = lambda base: "critical" if (is_sess and base == "high") else ("high" if (is_sess and base == "medium") else base)

        # 1. Secure Flag check
        if not secure:
            findings.append(f(
                sev("medium"),
                f"Cookie '{name}' Missing Secure Flag",
                f"Transmitted in cleartext over unencrypted HTTP connections. {'Critical session hijacking risk.' if is_sess else ''}",
                "Add 'Secure' attribute to ensure cookie is only transmitted over HTTPS."
            ))
        else:
            findings.append(f("pass", f"Cookie '{name}' Secure OK", "Encrypted transmission enforced"))

        # 2. HttpOnly Flag check
        if not httponly:
            findings.append(f(
                sev("medium"),
                f"Cookie '{name}' Missing HttpOnly Flag",
                f"Accessible to JavaScript (document.cookie). {'Attackers can steal session tokens via XSS.' if is_sess else ''}",
                "Add 'HttpOnly' attribute to prevent client-side script access."
            ))
        else:
            findings.append(f("pass", f"Cookie '{name}' HttpOnly OK", "Protected against XSS theft"))

        # 3. SameSite Flag check
        if not samesite:
            findings.append(f(
                "medium",
                f"Cookie '{name}' Missing SameSite",
                "Browser includes cookie in cross-site requests, creating CSRF attack vector.",
                "Set 'SameSite=Lax' or 'SameSite=Strict'."
            ))
        elif samesite.lower() == "none" and not secure:
            findings.append(f(
                "high",
                f"Cookie '{name}' SameSite=None Without Secure",
                "Modern browsers reject SameSite=None unless the Secure attribute is also present.",
                "Pair SameSite=None with the Secure attribute."
            ))
        else:
            findings.append(f("pass", f"Cookie '{name}' SameSite OK", f"Configured as SameSite={samesite}"))

        # 4. Session ID Entropy & Predictability analysis
        if is_sess:
            v_len = len(value)
            if v_len < 16:
                findings.append(f(
                    "critical",
                    f"Session Token '{name}' Low Entropy ({v_len} chars)",
                    f"Session identifier '{name}' is dangerously short ({v_len} characters). Highly susceptible to brute-force.",
                    "Use cryptographically secure random session tokens with at least 128 bits of entropy (32+ chars)."
                ))
            elif v_len < 32:
                findings.append(f(
                    "medium",
                    f"Session Token '{name}' Moderate Length ({v_len} chars)",
                    f"Token length is {v_len} chars. Ensure high cryptographic pseudo-randomness.",
                    "Verify token generator uses CSPRNG."
                ))

            if re.match(r'^(0+|1+|abcdef|123456|test|admin|guest)', value, re.I):
                findings.append(f(
                    "critical",
                    f"Session Token '{name}' Predictable Pattern",
                    f"Session value appears static or sequential: '{value[:20]}...'",
                    "Use cryptographically secure random numbers (e.g., secrets.token_hex in Python)."
                ))

        # 5. JWT token detection in cookies
        if value.startswith("eyJ") and value.count(".") >= 2:
            findings.append(f(
                "info",
                f"Cookie '{name}' Contains JWT Token",
                "Authentication token is stored as a client-side JSON Web Token.",
                "Ensure token algorithm cannot be set to 'none' and signature is verified server-side."
            ))

        # 6. Prefix security (__Host- and __Secure-)
        if name.startswith("__Host-"):
            if not (secure and path == "/" and not domain):
                findings.append(f("high", f"Invalid __Host- Cookie Prefix on '{name}'",
                                   "__Host- prefix requires Secure, Path=/, and no Domain attribute."))
        elif name.startswith("__Secure-") and not secure:
            findings.append(f("high", f"Invalid __Secure- Cookie Prefix on '{name}'",
                               "__Secure- prefix requires the Secure attribute."))

        records.append({
            "Name": name,
            "Secure": "✓ Yes" if secure else "✗ No",
            "HttpOnly": "✓ Yes" if httponly else "✗ No",
            "SameSite": samesite or "None",
            "Type": "Session Token" if is_sess else "General",
            "Entropy / Length": f"{len(value)} chars"
        })

    return ok({
        "summary": {
            "URL": url,
            "Cookies Found": len(cookies),
            "Session Cookies": sum(1 for c in cookies if c.get("is_session")),
            "Missing Secure": sum(1 for c in cookies if not c.get("secure")),
            "Missing HttpOnly": sum(1 for c in cookies if not c.get("httponly")),
        },
        "findings": findings,
        "cookies": cookies,
        "records": records,
        "record_columns": ["Name", "Secure", "HttpOnly", "SameSite", "Type", "Entropy / Length"]
    })
