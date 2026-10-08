import re
import asyncio
from fastapi import APIRouter
from models import TargetReq
from tools.utils import clean_url, http_get, f, ok, err

router = APIRouter(tags=["analysis"])

FILES = {
    "/robots.txt": "Robots.txt",
    "/sitemap.xml": "Sitemap",
    "/.well-known/security.txt": "Security.txt",
    "/security.txt": "Security.txt (alt)",
    "/crossdomain.xml": "Flash Crossdomain",
    "/clientaccesspolicy.xml": "Silverlight Policy",
    "/.well-known/assetlinks.json": "Android Asset Links",
    "/.well-known/apple-app-site-association": "Apple App Association",
    "/humans.txt": "Humans.txt",
    "/ads.txt": "Ads.txt",
}


@router.post("/security_files")
async def security_files(req: TargetReq):
    url = clean_url(req.target)
    findings = []
    records = []
    raw = ""

    async def check(path, name):
        r = await http_get(url + path, follow_redirects=False)
        return path, name, r

    tasks = [check(p, n) for p, n in FILES.items()]
    results = await asyncio.gather(*tasks)

    for path, name, r in results:
        code = r["status"]
        body = r["body"]
        found = code in [200, 301, 302]
        records.append({"File": name, "Path": path, "Status": code, "Found": "YES" if found and code == 200 else "No"})

        if path == "/robots.txt" and code == 200:
            disallowed = re.findall(r'Disallow:\s*(.+)', body, re.I)
            disallowed = [d.strip() for d in disallowed if d.strip()]
            raw += f"=== robots.txt ===\n{body[:2000]}\n\n"
            findings.append(f("pass", "robots.txt Found", f"{len(disallowed)} disallowed paths"))
            for dp in disallowed:
                if re.search(r'admin|login|secret|config|backup|api', dp, re.I):
                    findings.append(f("medium", f"Sensitive Path in robots.txt: {dp}",
                                       "Reveals hidden admin/sensitive path", "Verify not publicly accessible"))

        if path == "/.well-known/security.txt" and code == 200:
            findings.append(f("pass", "Security.txt Found", "Vulnerability disclosure policy in place"))
            raw += f"=== security.txt ===\n{body[:1000]}\n\n"
        elif path == "/.well-known/security.txt" and code != 200:
            findings.append(f("info", "No Security.txt", "Add /.well-known/security.txt per RFC 9116",
                               "Add security.txt"))

        if path == "/crossdomain.xml" and code == 200:
            if 'domain="*"' in body or "domain='*'" in body:
                findings.append(f("high", "Wildcard crossdomain.xml",
                                   "Any domain can access Flash resources",
                                   "Restrict to specific origins"))
            raw += f"=== crossdomain.xml ===\n{body[:500]}\n\n"

        if path == "/sitemap.xml" and code == 200:
            url_count = body.count("<url>")
            findings.append(f("info", "Sitemap Found", f"{url_count} URLs indexed",
                               "Review for sensitive URLs"))

    return ok({"summary": {"Target": url, "Files Checked": len(FILES)},
               "findings": findings, "records": records,
               "record_columns": ["File", "Path", "Status", "Found"],
               "raw": raw or "No readable content retrieved"})
