import re
import asyncio
from fastapi import APIRouter
from models import TargetReq
from tools.utils import clean_url, http_get, f, ok, err

router = APIRouter(tags=["scanning"])

ERROR_PATTERNS = [
    (r'You have an error in your SQL syntax', "critical", "MySQL Error Exposed"),
    (r'ORA-\d{5}:', "critical", "Oracle DB Error"),
    (r'Microsoft OLE DB Provider for SQL', "critical", "MSSQL Error"),
    (r'Warning: mysql_|Warning: mysqli_', "high", "PHP MySQL Warning"),
    (r'Parse error:|Fatal error:', "high", "PHP Fatal Error"),
    (r'stack trace:|Traceback \(most recent', "high", "Stack Trace Exposed"),
    (r'django\.debug|djdt', "high", "Django Debug Mode"),
    (r'Index of /', "high", "Directory Listing"),
    (r'JNDI|log4j', "critical", "Potential Log4Shell (CVE-2021-44228)"),
    (r'phpMyAdmin', "medium", "phpMyAdmin Detected"),
    (r'wp-json/wp/v2/', "info", "WordPress REST API"),
]

VERSION_PATTERNS = [
    (r'Apache/(\d+\.\d+\.\d+)', "Apache"),
    (r'nginx/(\d+\.\d+\.\d+)', "nginx"),
    (r'PHP/(\d+\.\d+\.\d+)', "PHP"),
    (r'WordPress (\d+\.\d+[\.\d]*)', "WordPress"),
]

ADMIN_PATHS = ["/admin", "/administrator", "/wp-admin/", "/manager/html", "/phpmyadmin/"]
BACKUP_EXTS = [".bak", ".backup", ".old", ".orig", ".copy", ".tmp"]


@router.post("/vuln_detection")
async def vuln_detection(req: TargetReq):
    url = clean_url(req.target)
    resp = await http_get(url)
    if not resp["ok"]:
        return err(f"Cannot reach URL: {resp['error']}")

    body = resp["body"]
    hdrs = resp["headers"]
    findings = []
    records = []

    for pat, sev, title in ERROR_PATTERNS:
        if re.search(pat, body, re.I):
            findings.append(f(sev, title, f"Pattern matched in response", "Disable error output in production"))
            records.append({"Check": title, "Status": "DETECTED", "Severity": sev.upper()})

    server_str = hdrs.get("server", "") + " " + hdrs.get("x-powered-by", "") + " " + body[:5000]
    for pat, name in VERSION_PATTERNS:
        m = re.search(pat, server_str)
        if m:
            findings.append(f("low", f"{name} Version Disclosed", f"Version: {name} {m.group(1)}",
                               "Remove version strings from headers"))
            records.append({"Check": f"{name} Version", "Status": m.group(1), "Severity": "LOW"})

    async def check_admin(path: str):
        r = await http_get(url + path, timeout=4, follow_redirects=False)
        return path, r["status"]

    admin_results = await asyncio.gather(*[check_admin(p) for p in ADMIN_PATHS])
    for path, code in admin_results:
        if code in [200, 401, 403, 302]:
            findings.append(f("medium", f"Admin Panel Found: {path}",
                               f"HTTP {code}", "Restrict to internal IPs; enable 2FA"))
            records.append({"Check": "Admin Panel", "Status": f"{path} ({code})", "Severity": "MEDIUM"})
            break

    async def check_backup(ext: str):
        backup_url = url + ext
        r = await http_get(backup_url, timeout=4, follow_redirects=False)
        return ext, r["status"], len(r["body"])

    backup_results = await asyncio.gather(*[check_backup(e) for e in BACKUP_EXTS])
    for ext, code, size in backup_results:
        if code == 200 and size > 100:
            findings.append(f("high", f"Backup File Accessible: {ext}",
                               f"URL: {url}{ext} returns {code}",
                               "Remove backup files from webroot"))
            records.append({"Check": "Backup File", "Status": f"{url}{ext}", "Severity": "HIGH"})

    if not findings:
        findings.append(f("pass", "No Common Vulnerabilities Detected",
                           "Automated checks found no obvious issues",
                           "Manual testing recommended"))

    return ok({"summary": {"URL": url, "HTTP Status": resp["status"],
                            "Issues Found": len([x for x in findings if x["severity"] != "pass"])},
               "findings": findings, "records": records,
               "record_columns": ["Check", "Status", "Severity"]})
