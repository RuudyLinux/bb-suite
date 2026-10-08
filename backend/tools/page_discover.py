from __future__ import annotations
import asyncio
import re
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser
from fastapi import APIRouter
from models import PageDiscoverReq
from tools.utils import clean_url, http_get, f, ok, err, load_wordlist

router = APIRouter(tags=["scanning"])

ADMIN_RE = re.compile(
    r'/(admin|administrator|manage|management|panel|dashboard|control|'
    r'wp-admin|wp-login|cpanel|phpmyadmin|pma|backend|staff|superuser|'
    r'moderator|console|portal|manager|webmaster|sysadmin|root|system|'
    r'login|signin|auth|secure|restricted|private|account|accounts|'
    r'user[-_]admin|site[-_]admin|control[-_]panel|master)',
    re.IGNORECASE
)

IGNORE_EXT = re.compile(
    r'\.(png|jpg|jpeg|gif|svg|ico|css|js|woff|woff2|ttf|eot|mp4|mp3|'
    r'zip|pdf|doc|docx|xls|xlsx|xml|json|csv|txt|map)(\?.*)?$',
    re.IGNORECASE
)


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        href = None
        if tag == 'a':
            href = d.get('href')
        elif tag == 'form':
            href = d.get('action')
        elif tag in ('link', 'area'):
            href = d.get('href')
        elif tag == 'iframe':
            href = d.get('src')
        if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
            self.links.append(href)


def same_origin(url: str, base_netloc: str) -> bool:
    try:
        return urlparse(url).netloc == base_netloc
    except Exception:
        return False


def normalize(url: str) -> str:
    p = urlparse(url)
    path = p.path.rstrip('/') or '/'
    return f"{p.scheme}://{p.netloc}{path}"


async def spider(base_url: str, max_depth: int, max_pages: int) -> dict[str, int]:
    parsed_base = urlparse(base_url)
    base_netloc = parsed_base.netloc
    visited: dict[str, int] = {}
    queue: list[tuple[str, int]] = [(base_url, 0)]

    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)
        norm = normalize(url)
        if norm in visited:
            continue
        if IGNORE_EXT.search(url):
            continue

        r = await http_get(url, timeout=8, follow_redirects=True)
        visited[norm] = r['status']

        if depth >= max_depth:
            continue
        ct = r['headers'].get('content-type', '')
        if not r['ok'] or 'text/html' not in ct:
            continue

        parser = LinkParser()
        try:
            parser.feed(r['body'])
        except Exception:
            pass

        for href in parser.links:
            try:
                absolute = urljoin(url, href)
                if same_origin(absolute, base_netloc):
                    n = normalize(absolute)
                    if n not in visited:
                        queue.append((absolute, depth + 1))
            except Exception:
                pass

    return visited


@router.post("/page_discover")
async def page_discover(req: PageDiscoverReq):
    url = clean_url(req.target)
    base = urlparse(url)

    # 1. Spider the site
    crawled = await spider(url, min(req.depth, 3), min(req.max_pages, 200))

    # 2. Wordlist brute force
    all_paths = load_wordlist("common_paths.txt")
    wl_sizes = {"small": 60, "medium": 150, "full": len(all_paths)}
    paths = all_paths[:wl_sizes.get(req.wordlist, 150)]
    semaphore = asyncio.Semaphore(15)

    async def check_path(path: str):
        async with semaphore:
            target = url.rstrip("/") + "/" + path.lstrip("/")
            r = await http_get(target, timeout=5, follow_redirects=False)
            return target, r['status']

    wl_results = await asyncio.gather(*[check_path(p) for p in paths])
    for wl_url, code in wl_results:
        if code not in [0, 404, 503]:
            n = normalize(wl_url)
            if n not in crawled:
                crawled[n] = code

    # 3. Classify results
    findings = []
    records = []
    admin_pages = []
    all_pages = []

    for page_url, code in sorted(crawled.items()):
        if code == 0:
            continue
        path = urlparse(page_url).path or '/'
        is_admin = bool(ADMIN_RE.search(path))
        label = {
            200: '✓ OK', 301: '→ Redirect', 302: '→ Redirect',
            307: '→ Redirect', 308: '→ Redirect',
            401: '⚠ Auth Required', 403: '⊘ Forbidden',
            500: '✗ Server Error', 404: '✗ Not Found'
        }.get(code, f'HTTP {code}')

        row = {
            'URL':    page_url,
            'Status': code,
            'Label':  label,
            'Admin':  'YES' if is_admin else '—',
        }
        all_pages.append(row)
        records.append(row)

        if is_admin:
            admin_pages.append(page_url)
            sev = 'high' if code == 200 else 'medium'
            findings.append(f(sev, f"Admin Page Found: {path}",
                               f"URL: {page_url} — HTTP {code} ({label})",
                               "Restrict access to internal IPs only; enforce 2FA"))

    if not admin_pages:
        findings.append(f("pass", "No Admin Pages Found",
                           "No admin/management URLs detected", ""))

    # Summary finding for total pages
    c200 = sum(1 for r in records if r['Status'] == 200)
    c403 = sum(1 for r in records if r['Status'] == 403)
    findings.append(f("info", f"{len(records)} Pages Discovered",
                       f"{c200} accessible, {c403} forbidden, {len(admin_pages)} admin panels"))

    return ok({
        "summary": {
            "Target":       url,
            "Total Pages":  len(records),
            "Accessible":   c200,
            "Forbidden":    c403,
            "Admin Pages":  len(admin_pages),
            "Depth":        req.depth,
        },
        "findings": findings,
        "records":  records,
        "record_columns": ["URL", "Status", "Label", "Admin"],
        "admin_pages": admin_pages,
    })
