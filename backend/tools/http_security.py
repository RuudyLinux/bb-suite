import re
from fastapi import APIRouter
from models import TargetReq
from tools.utils import clean_url, http_get, f, ok, err

router = APIRouter(tags=["analysis"])

TECH_HINTS = {
    "wp-content": "WordPress", "joomla": "Joomla", "drupal": "Drupal",
    "laravel": "Laravel", "django": "Django", "/rails/": "Ruby on Rails",
    "jquery": "jQuery", "react": "React", "angular": "Angular",
    "vue.js": "Vue.js", "bootstrap": "Bootstrap",
}

ERROR_PATTERNS = [
    (r'You have an error in your SQL syntax', "critical", "MySQL Error Exposed", "SQL error in response"),
    (r'ORA-\d{5}:', "critical", "Oracle DB Error", "Oracle error exposed"),
    (r'Microsoft OLE DB Provider for SQL', "critical", "MSSQL Error Exposed", "MSSQL error in response"),
    (r'Warning: mysql_|Warning: mysqli_', "high", "PHP MySQL Warning", "PHP DB warnings visible"),
    (r'Parse error:|Fatal error:', "high", "PHP Fatal Error", "PHP error in response"),
    (r'stack trace:|Traceback \(most recent', "high", "Stack Trace Exposed", "App stack trace visible"),
    (r'django\.debug|djdt', "high", "Django Debug Mode", "Django debug active"),
    (r'Index of /', "high", "Directory Listing", "Server lists directory contents"),
]


@router.post("/http_security")
async def http_security(req: TargetReq):
    url = clean_url(req.target)
    resp = await http_get(url)
    if not resp["ok"]:
        return err(f"Cannot reach: {resp['error']}")
    try:
        hdrs = resp["headers"]
        body = resp["body"]
        body_l = body.lower()
        findings = []
        stack = []

        server = hdrs.get("server", "")
        if server:
            stack.append(server)
            findings.append(f("medium", "Server Header Exposes Tech", f"Server: {server}",
                               "Remove or generic-ize Server header"))
        xpb = hdrs.get("x-powered-by", "")
        if xpb:
            stack.append(xpb)
            findings.append(f("medium", "X-Powered-By Leaks Tech", f"X-Powered-By: {xpb}",
                               "Remove X-Powered-By header"))

        for hint, name in TECH_HINTS.items():
            if hint in body_l and name not in stack:
                stack.append(name)

        for pat, sev, title, detail in ERROR_PATTERNS:
            if re.search(pat, body, re.I):
                findings.append(f(sev, title, detail, "Disable error display in production"))

        is_https = url.startswith("https://")
        http_url = "http://" + re.sub(r'^https?://', '', url)
        http_resp = await http_get(http_url, follow_redirects=False)
        if is_https:
            loc = http_resp["headers"].get("location", "")
            if http_resp["status"] == 200:
                findings.append(f("high", "No HTTP→HTTPS Redirect",
                                   "HTTP accessible without redirect", "301 redirect all HTTP → HTTPS"))
            elif loc.startswith("https://"):
                findings.append(f("pass", "HTTP→HTTPS Redirect OK", f"→ {loc}"))
            else:
                findings.append(f("high", "Bad HTTP Redirect", f"Redirects to HTTP: {loc}"))

        if not hdrs.get("x-frame-options") and not hdrs.get("content-security-policy"):
            findings.append(f("medium", "Clickjacking Risk",
                               "No X-Frame-Options or CSP frame-ancestors", "Add X-Frame-Options: DENY"))

        if is_https and re.search(r'src=["\']http://', body, re.I):
            findings.append(f("medium", "Mixed Content", "HTTPS page loads HTTP resources",
                               "Update all resource URLs to HTTPS"))

        sc = hdrs.get("set-cookie", "")
        if sc:
            if "secure" not in sc.lower():
                findings.append(f("high", "Session Cookie Missing Secure Flag", sc[:100],
                                   "Add Secure attribute"))
            if "httponly" not in sc.lower():
                findings.append(f("high", "Session Cookie Missing HttpOnly", sc[:100],
                                   "Add HttpOnly attribute"))

        records = [{"Header": k, "Value": v[:150]} for k, v in hdrs.items()]
        return ok({"summary": {"URL": resp["url"], "Status": resp["status"],
                                "Tech Stack": ", ".join(set(stack)) or "Unknown"},
                   "findings": findings, "records": records,
                   "record_columns": ["Header", "Value"],
                   "raw": "\n".join(f"{k}: {v}" for k, v in hdrs.items())})
    except Exception as e:
        return err(str(e))
