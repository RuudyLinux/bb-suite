from __future__ import annotations
import asyncio
import re
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from html.parser import HTMLParser
from fastapi import APIRouter
from models import VulnMapReq
from tools.utils import clean_url, http_get, f, ok, err

router = APIRouter(tags=["scanning"])

# ── SQL error fingerprints ────────────────────────────────────────────────────
SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql",
    "ora-\d{5}", "microsoft ole db", "postgresql.*error",
    "pg_query", "sqlite3", "unclosed quotation", "odbc driver",
    "native client", "invalid query", "sqlstate",
]
SQL_RE = re.compile("|".join(SQL_ERRORS), re.I)

# ── XSS reflection marker ────────────────────────────────────────────────────
XSS_PROBE = "<xss-probe-7x9>"

# ── Sensitive path patterns ───────────────────────────────────────────────────
SENSITIVE_PATHS = [
    ".env", ".git/HEAD", "config.php.bak", "wp-config.php.bak",
    ".htpasswd", "backup.sql", "db.sql", "dump.sql",
    "phpinfo.php", "test.php", "info.php",
]
SENSITIVE_RE = re.compile(r"\.(env|bak|sql|backup|old|orig|htpasswd)$", re.I)

# ── Open redirect ────────────────────────────────────────────────────────────
REDIRECT_PARAMS = {"url", "redirect", "return", "next", "goto", "location",
                   "dest", "destination", "redir", "redirect_url", "return_url"}

IGNORE_EXT = re.compile(
    r"\.(png|jpg|jpeg|gif|svg|ico|css|woff|ttf|eot|mp4|mp3|zip|pdf)(\?.*)?$",
    re.I,
)


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        href = d.get("href") if tag in ("a", "link", "area") else \
               d.get("action") if tag == "form" else \
               d.get("src") if tag == "iframe" else None
        if href and not href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            self.links.append(href)


def _normalize(url: str) -> str:
    p = urlparse(url)
    path = p.path.rstrip("/") or "/"
    return f"{p.scheme}://{p.netloc}{path}"


def _inject(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))


async def _spider(base_url: str, max_pages: int) -> dict[str, dict]:
    base_netloc = urlparse(base_url).netloc
    visited: dict[str, dict] = {}
    queue: list[tuple[str, int]] = [(base_url, 0)]

    sem = asyncio.Semaphore(10)

    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)
        norm = _normalize(url)
        if norm in visited or IGNORE_EXT.search(url):
            continue

        async with sem:
            r = await http_get(url, timeout=8, follow_redirects=True)

        visited[norm] = {
            "url":    norm,
            "status": r["status"],
            "body":   r["body"],
            "params": list(parse_qs(urlparse(url).query).keys()),
        }

        if depth >= 2 or not r["ok"]:
            continue
        ct = r["headers"].get("content-type", "")
        if "text/html" not in ct:
            continue

        parser = _LinkParser()
        try:
            parser.feed(r["body"])
        except Exception:
            pass
        for href in parser.links:
            try:
                absolute = urljoin(url, href)
                if urlparse(absolute).netloc == base_netloc:
                    n = _normalize(absolute)
                    if n not in visited:
                        queue.append((absolute, depth + 1))
            except Exception:
                pass

    return visited


async def _test_sqli(url: str, param: str) -> bool:
    for payload in ("'", "''", "' OR '1'='1"):
        injected = _inject(url, param, payload)
        r = await http_get(injected, timeout=8)
        if SQL_RE.search(r["body"]):
            return True
    return False


async def _test_xss(url: str, param: str) -> bool:
    injected = _inject(url, param, XSS_PROBE)
    r = await http_get(injected, timeout=8)
    return XSS_PROBE.lower() in r["body"].lower()


async def _test_open_redirect(url: str, param: str) -> bool:
    injected = _inject(url, param, "https://evil.example.com")
    r = await http_get(injected, timeout=8, follow_redirects=False)
    loc = r["headers"].get("location", "")
    return "evil.example.com" in loc


async def _probe_page(page: dict) -> dict:
    url    = page["url"]
    params = page["params"]
    vulns: list[str] = []

    # Check for error/info disclosure in base response
    body = page["body"]
    if SQL_RE.search(body):
        vulns.append("sql_error_disclosure")

    if re.search(r"Parse error:|Fatal error:|Warning: .*\(\)", body, re.I):
        vulns.append("php_error_disclosure")

    if re.search(r"Traceback \(most recent|django\.debug|djdt", body, re.I):
        vulns.append("debug_mode")

    if re.search(r"Index of /", body):
        vulns.append("directory_listing")

    # Param-based tests
    for param in params[:5]:  # limit to first 5 params
        sqli = await _test_sqli(url, param)
        if sqli:
            vulns.append(f"sqli:{param}")
        xss = await _test_xss(url, param)
        if xss:
            vulns.append(f"xss:{param}")
        if param.lower() in REDIRECT_PARAMS:
            redir = await _test_open_redirect(url, param)
            if redir:
                vulns.append(f"open_redirect:{param}")

    # Check if sensitive path
    path = urlparse(url).path
    if SENSITIVE_RE.search(path):
        if page["status"] == 200 and len(body) > 50:
            vulns.append("sensitive_file_exposed")

    return {"url": url, "status": page["status"], "vulns": vulns}


@router.post("/vuln_map")
async def vuln_map(req: VulnMapReq):
    base_url = clean_url(req.target)
    max_pages = min(req.max_pages, 80)

    # 1. Spider
    pages = await _spider(base_url, max_pages)

    if not pages:
        return err("Could not reach target — check URL")

    # 2. Also probe sensitive paths directly
    sem = asyncio.Semaphore(10)

    async def check_sensitive(path: str):
        async with sem:
            url = base_url.rstrip("/") + "/" + path.lstrip("/")
            r = await http_get(url, timeout=5, follow_redirects=False)
            if r["status"] == 200 and len(r["body"]) > 50:
                norm = _normalize(url)
                if norm not in pages:
                    pages[norm] = {
                        "url": norm, "status": 200,
                        "body": r["body"], "params": [],
                    }

    await asyncio.gather(*[check_sensitive(p) for p in SENSITIVE_PATHS])

    # 3. Probe each page for vulns (concurrency-limited)
    probe_sem = asyncio.Semaphore(5)

    async def safe_probe(p):
        async with probe_sem:
            return await _probe_page(p)

    probed = list(await asyncio.gather(*[safe_probe(p) for p in pages.values()]))

    # 4. Build results
    cracked: list[dict] = []
    clean:   list[dict] = []
    records: list[dict] = []
    findings = []

    SEV_MAP = {
        "sqli":                   ("critical", "SQL Injection"),
        "xss":                    ("high",     "Reflected XSS"),
        "open_redirect":          ("high",     "Open Redirect"),
        "sql_error_disclosure":   ("high",     "SQL Error Disclosure"),
        "sensitive_file_exposed": ("high",     "Sensitive File Exposed"),
        "php_error_disclosure":   ("medium",   "PHP Error Disclosure"),
        "debug_mode":             ("high",     "Debug Mode Active"),
        "directory_listing":      ("medium",   "Directory Listing"),
    }

    for p in probed:
        url = p["url"]
        vulns = p["vulns"]
        if not vulns:
            clean.append(p)
            records.append({
                "URL":    url,
                "Status": p["status"],
                "Vulns":  "—",
                "Cracked": "—",
            })
            continue

        # Determine highest severity
        max_sev = "info"
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        labels = []
        for v in vulns:
            key = v.split(":")[0]
            sev, label = SEV_MAP.get(key, ("info", v))
            param = v.split(":", 1)[1] if ":" in v else ""
            display = f"{label} ({param})" if param else label
            labels.append(display)
            if sev_order.get(sev, 0) > sev_order.get(max_sev, 0):
                max_sev = sev
            findings.append(f(
                sev, f"{label}: {urlparse(url).path or '/'}",
                f"URL: {url}" + (f" | param: {param}" if param else ""),
                "Immediately patch this vulnerability",
            ))

        cracked.append({
            "url":    url,
            "status": p["status"],
            "vulns":  vulns,
            "labels": labels,
            "sev":    max_sev,
        })
        records.append({
            "URL":     url,
            "Status":  p["status"],
            "Vulns":   ", ".join(labels),
            "Cracked": "⚡ YES",
        })

    if not cracked:
        findings.append(f("pass", "No Vulnerabilities Detected",
                           f"Scanned {len(probed)} pages — all clean",
                           "Continue manual testing; automated scans miss logic flaws"))
    else:
        findings.insert(0, f(
            "critical",
            f"⚡ {len(cracked)} VULNERABLE PAGES FOUND",
            f"{len(cracked)} pages cracked out of {len(probed)} scanned",
            "Fix all critical issues before deploying",
        ))

    return ok({
        "summary": {
            "Target":           base_url,
            "Pages Scanned":    len(probed),
            "Cracked Pages":    len(cracked),
            "Clean Pages":      len(clean),
        },
        "findings":       findings,
        "records":        records,
        "record_columns": ["URL", "Status", "Vulns", "Cracked"],
        "cracked_pages":  cracked,
        "clean_pages":    [p["url"] for p in clean],
    })
