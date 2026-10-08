"""Vulnerability Map & Multi-Vector Surface Mapper for BB-SUITE.

Integrates multi-vector discovery (SQL error fingerprints, context-checked XSS, open redirect,
information disclosure) with target validation and confidence classification.
"""
from __future__ import annotations
import asyncio
from html.parser import HTMLParser
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from fastapi import APIRouter

from backend.models import VulnMapReq
from backend.security.confidence import (
    Confidence,
    Severity,
    create_finding,
    standard_response,
)
from backend.security.target_validator import TargetValidationError, validate_target_url
from backend.tools.utils import clean_url, err, f, http_get, ok

router = APIRouter(tags=["scanning"])

SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysql",
    r"ora-\d{4,5}",
    r"microsoft ole db",
    r"postgresql.*error",
    r"pg_query",
    r"sqlite3::sqlexception",
    r"unclosed quotation",
    r"odbc.*driver",
]
SQL_RE = re.compile("|".join(SQL_ERRORS), re.IGNORECASE)

XSS_CANARY = "bbprobe7x9<test\"tag>"

SENSITIVE_PATHS = [
    ".env", ".git/HEAD", "config.php.bak", "wp-config.php.bak",
    "backup.sql", "db.sql", "phpinfo.php",
]

REDIRECT_PARAMS = {
    "url", "redirect", "return", "next", "goto", "location",
    "dest", "destination", "redir", "redirect_url", "return_url",
}

IGNORE_EXT = re.compile(
    r"\.(png|jpg|jpeg|gif|svg|ico|css|woff|woff2|ttf|eot|mp4|mp3|zip|pdf|exe)(\?.*)?$",
    re.IGNORECASE,
)


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: List[str] = []

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


async def _spider(base_url: str, max_pages: int) -> Dict[str, Dict[str, Any]]:
    base_netloc = urlparse(base_url).netloc
    visited: Dict[str, Dict[str, Any]] = {}
    queue: List[Tuple[str, int]] = [(base_url, 0)]
    sem = asyncio.Semaphore(10)

    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)
        norm = _normalize(url)
        if norm in visited or IGNORE_EXT.search(url):
            continue

        async with sem:
            r = await http_get(url, timeout=7, follow_redirects=True)

        visited[norm] = {
            "url": norm,
            "status": r["status"],
            "body": r.get("body", ""),
            "params": list(parse_qs(urlparse(url).query).keys()),
        }

        if depth >= 2 or not r["ok"]:
            continue
        ct = r.get("headers", {}).get("content-type", "")
        if "text/html" not in ct:
            continue

        parser = _LinkParser()
        try:
            parser.feed(r.get("body", ""))
        except Exception:
            pass
        for href in parser.links:
            try:
                absolute = urljoin(url, href)
                if urlparse(absolute).netloc == base_netloc:
                    n = _normalize(absolute)
                    if n not in visited and len(visited) < max_pages:
                        queue.append((absolute, depth + 1))
            except Exception:
                pass

    return visited


async def _test_sqli(url: str, param: str) -> bool:
    for payload in ("'", "''", "' OR '1'='1"):
        injected = _inject(url, param, payload)
        r = await http_get(injected, timeout=6)
        if SQL_RE.search(r.get("body", "")):
            return True
    return False


async def _test_xss(url: str, param: str) -> bool:
    injected = _inject(url, param, XSS_CANARY)
    r = await http_get(injected, timeout=6)
    body = r.get("body", "")
    # Must reflect unescaped tag without entity encoding
    return "<test\"tag>" in body and "&lt;test" not in body


async def _test_open_redirect(url: str, param: str) -> bool:
    injected = _inject(url, param, "https://example-security-test.com")
    r = await http_get(injected, timeout=6, follow_redirects=False)
    loc = r.get("headers", {}).get("location", "")
    return "example-security-test.com" in loc


async def _probe_page(page: Dict[str, Any]) -> Dict[str, Any]:
    url = page["url"]
    params = page["params"]
    vulns: List[str] = []

    body = page["body"]
    if SQL_RE.search(body):
        vulns.append("sql_error_disclosure")

    if re.search(r"Parse error:|Fatal error:|Warning: .*\(\)", body, re.IGNORECASE):
        vulns.append("php_error_disclosure")

    if re.search(r"Traceback \(most recent|django\.debug", body, re.IGNORECASE):
        vulns.append("debug_mode")

    if "Index of /" in body and page["status"] == 200:
        vulns.append("directory_listing")

    # Limit param testing to first 3 to prevent excessive requests
    for param in params[:3]:
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

    path = urlparse(url).path
    if any(path.endswith(ext) for ext in (".env", ".bak", ".sql", ".backup")):
        if page["status"] == 200 and len(body) > 30:
            vulns.append("sensitive_file_exposed")

    return {"url": url, "status": page["status"], "vulns": vulns}


@router.post("/vuln_map")
async def vuln_map(req: VulnMapReq):
    base_url = clean_url(req.target)
    try:
        validate_target_url(base_url)
    except TargetValidationError as tve:
        return err(f"Target validation failed: {tve}")

    max_pages = min(req.max_pages, 50)

    # 1. Spider
    pages = await _spider(base_url, max_pages)
    if not pages:
        return err("Could not reach target or target is empty.")

    # 2. Probe sensitive paths
    sem = asyncio.Semaphore(5)

    async def check_sensitive(path: str):
        async with sem:
            url = base_url.rstrip("/") + "/" + path.lstrip("/")
            r = await http_get(url, timeout=5, follow_redirects=False)
            if r["status"] == 200 and len(r.get("body", "")) > 30:
                norm = _normalize(url)
                if norm not in pages:
                    pages[norm] = {
                        "url": norm,
                        "status": 200,
                        "body": r["body"],
                        "params": [],
                    }

    await asyncio.gather(*[check_sensitive(p) for p in SENSITIVE_PATHS])

    # 3. Probe pages
    probe_sem = asyncio.Semaphore(5)

    async def safe_probe(p):
        async with probe_sem:
            return await _probe_page(p)

    probed = list(await asyncio.gather(*[safe_probe(p) for p in pages.values()]))

    # 4. Build results
    cracked: List[Dict[str, Any]] = []
    clean: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    SEV_MAP = {
        "sqli": ("critical", "SQL Injection", "confirmed"),
        "xss": ("high", "Reflected XSS", "confirmed"),
        "open_redirect": ("high", "Open Redirect", "confirmed"),
        "sql_error_disclosure": ("high", "SQL Error Disclosure", "confirmed"),
        "sensitive_file_exposed": ("high", "Sensitive File Exposed", "confirmed"),
        "php_error_disclosure": ("medium", "PHP Error Disclosure", "likely"),
        "debug_mode": ("high", "Debug Mode Active", "confirmed"),
        "directory_listing": ("medium", "Directory Listing", "confirmed"),
    }

    for p in probed:
        url = p["url"]
        vulns = p["vulns"]
        if not vulns:
            clean.append(p)
            records.append({
                "URL": url,
                "Status": p["status"],
                "Vulns": "—",
                "Cracked": "—",
            })
            continue

        max_sev = "info"
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        labels = []
        for v in vulns:
            key = v.split(":")[0]
            sev, label, conf = SEV_MAP.get(key, ("info", v, "possible"))
            param = v.split(":", 1)[1] if ":" in v else ""
            display = f"{label} ({param})" if param else label
            labels.append(display)
            if sev_order.get(sev, 0) > sev_order.get(max_sev, 0):
                max_sev = sev
            findings.append(f(
                sev,
                f"{label}: {urlparse(url).path or '/'}",
                f"URL: {url}" + (f" | param: {param}" if param else ""),
                "Remediate input validation and output encoding on this endpoint.",
                confidence=conf,
            ))

        cracked.append({
            "url": url,
            "status": p["status"],
            "vulns": vulns,
            "labels": labels,
            "sev": max_sev,
        })
        records.append({
            "URL": url,
            "Status": p["status"],
            "Vulns": ", ".join(labels),
            "Cracked": "⚡ YES",
        })

    if not cracked:
        findings.append(f(
            "pass",
            "No Vulnerabilities Detected on Crawled Endpoints",
            f"Crawled and analyzed {len(probed)} pages; no high-severity vulnerabilities observed.",
            confidence="not_detected",
        ))

    return ok({
        "summary": {
            "Target": base_url,
            "Pages Scanned": len(probed),
            "Vulnerable Pages": len(cracked),
            "Clean Pages": len(clean),
        },
        "findings": findings,
        "records": records,
        "record_columns": ["URL", "Status", "Vulns", "Cracked"],
        "cracked_pages": cracked,
        "clean_pages": [p["url"] for p in clean],
    })
