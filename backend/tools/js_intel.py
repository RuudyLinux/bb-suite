from __future__ import annotations
import asyncio
import re
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser
from fastapi import APIRouter
from models import TargetReq
from tools.utils import clean_url, http_get, f, ok, err

router = APIRouter(tags=["analysis"])

SECRET_PATTERNS = [
    (r'(?i)(?:api[_\-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9\-_]{10,})["\']',          'API Key'),
    (r'(?i)(?:secret|password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']',              'Secret/Password'),
    (r'(?i)(?:access[_\-]?token|auth[_\-]?token|bearer)\s*[:=]\s*["\']([^"\']{10,})["\']', 'Auth Token'),
    (r'AKIA[0-9A-Z]{16}',                                                                   'AWS Access Key'),
    (r'aws_secret_access_key\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})',                        'AWS Secret'),
    (r'(?:sk-|sk_live_|sk_test_)[A-Za-z0-9]{24,}',                                        'Stripe/OpenAI Key'),
    (r'ghp_[A-Za-z0-9]{36}',                                                               'GitHub Token'),
    (r'xox[baprs]-[A-Za-z0-9\-]{10,}',                                                    'Slack Token'),
    (r'AIza[0-9A-Za-z\-_]{35}',                                                            'Google API Key'),
    (r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',                                 'Private Key (PEM)'),
    (r'(?i)(?:mongodb|mysql|postgres|redis|mssql)://[^\s"\'<]+',                           'DB Connection String'),
    (r'(?i)(?:private_key|private_key_id)\s*[:=]\s*["\']([^"\']{10,})["\']',             'Private Key ID'),
    (r'(?:eyJ[A-Za-z0-9_-]{10,}\.){2}[A-Za-z0-9_-]{10,}',                               'JWT Token'),
]

ENDPOINT_PATTERNS = [
    r'(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*[`"\']([/][^`"\'<\s]{2,})[`"\']',
    r'(?:url|endpoint|path|route|api)\s*[:=]\s*[`"\']([/][^`"\'<\s]{2,})[`"\']',
    r'\$\.(?:get|post|ajax)\s*\(\s*["\']([/][^"\'<\s]+)["\']',
    r'XMLHttpRequest.*?open.*?["\'](?:GET|POST|PUT|DELETE)["\'].*?["\']([/][^"\'<\s]+)["\']',
    r'["\'](?:GET|POST|PUT|DELETE|PATCH)["\'],\s*["\']([/][a-zA-Z0-9_\-/\.]+)["\']',
    r'(?:href|src|action)\s*[:=]\s*["\']([/](?:api|v\d|rest|service)[^"\'<\s]*)["\']',
]


class ScriptExtractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.src_scripts: list[str] = []
        self.inline_scripts: list[str] = []
        self.base_url = base_url
        self._in_script = False
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == 'script':
            self._in_script = True
            self._buf = []
            d = dict(attrs)
            src = d.get('src', '')
            if src and not src.startswith(('data:', 'javascript:')):
                self.src_scripts.append(urljoin(self.base_url, src))

    def handle_endtag(self, tag):
        if tag == 'script':
            self._in_script = False
            if self._buf:
                self.inline_scripts.append(''.join(self._buf))

    def handle_data(self, data):
        if self._in_script:
            self._buf.append(data)


@router.post("/js_intel")
async def js_intel(req: TargetReq):
    url = clean_url(req.target)
    findings = []
    records  = []

    resp = await http_get(url)
    if not resp['ok']:
        return err(f"Cannot reach: {resp['error']}")

    parser = ScriptExtractor(url)
    try:
        parser.feed(resp['body'])
    except Exception:
        pass

    target_netloc = urlparse(url).netloc
    own_scripts   = [s for s in parser.src_scripts
                     if urlparse(s).netloc in ('', target_netloc)]

    # Common bundle paths
    for path in ['/static/js/main.chunk.js', '/assets/js/app.js', '/js/app.js',
                 '/build/static/js/main.chunk.js', '/dist/bundle.js',
                 '/assets/index.js', '/js/main.js', '/js/bundle.js']:
        candidate = url.rstrip('/') + path
        if candidate not in own_scripts:
            own_scripts.append(candidate)

    # Fetch JS files in parallel
    sem = asyncio.Semaphore(10)
    async def fetch_js(js_url: str):
        async with sem:
            r = await http_get(js_url, timeout=10, follow_redirects=True)
            if r['ok'] and r['status'] == 200 and len(r['body']) > 50:
                return js_url, r['body']
            return js_url, None

    js_results = await asyncio.gather(*[fetch_js(s) for s in own_scripts[:20]])
    js_files_found = []
    all_js = '\n'.join(parser.inline_scripts)
    for js_url, content in js_results:
        if content:
            js_files_found.append(js_url)
            all_js += f'\n/* === {js_url} === */\n{content}'

    # Extract secrets
    secrets_total = 0
    for pat, stype in SECRET_PATTERNS:
        for m in re.finditer(pat, all_js):
            secrets_total += 1
            val = m.group(1) if m.lastindex else m.group(0)
            records.append({'Type': 'SECRET', 'Category': stype, 'Value': val, 'Source': 'JS'})
            findings.append(f('critical', f'{stype} Found in JavaScript',
                               f'Exposed value: {val}',
                               'Remove all secrets from JS — use server-side env vars'))

    # Extract API endpoints
    endpoints = set()
    for pat in ENDPOINT_PATTERNS:
        for m in re.finditer(pat, all_js, re.IGNORECASE | re.DOTALL):
            ep = m.group(1) if m.lastindex else m.group(0)
            ep = ep.strip()
            if ep and len(ep) > 2 and ep not in endpoints:
                endpoints.add(ep)
                records.append({'Type': 'ENDPOINT', 'Category': 'API', 'Value': ep, 'Source': 'JS'})

    # WebSockets
    ws_urls = list(set(re.findall(r'wss?://[^\s"\'`<>]+', all_js)))
    for ws in ws_urls:
        records.append({'Type': 'WEBSOCKET', 'Category': 'WS URL', 'Value': ws, 'Source': 'JS'})
        findings.append(f('info', f'WebSocket Endpoint: {ws}',
                           'WebSocket connection found in JS',
                           'Test for authentication bypass and message injection'))

    # GraphQL
    gql_paths = list(set(re.findall(r'["\']([^"\']*graphql[^"\']*)["\']', all_js, re.I)))
    for gp in gql_paths[:5]:
        records.append({'Type': 'GRAPHQL', 'Category': 'Endpoint', 'Value': gp, 'Source': 'JS'})
        findings.append(f('medium', f'GraphQL Endpoint in JS: {gp}',
                           'Test for introspection and batch queries',
                           'Disable introspection in production'))

    # Internal/dev URLs
    internal_urls = list(set(re.findall(
        r'https?://(?:localhost|127\.\d+\.\d+\.\d+|192\.168\.|10\.\d+\.|staging\.|dev\.|internal\.)[^\s"\'`<>]*',
        all_js, re.I)))
    for iu in internal_urls:
        records.append({'Type': 'INTERNAL', 'Category': 'Internal URL', 'Value': iu, 'Source': 'JS'})
        findings.append(f('high', f'Internal URL Hardcoded: {iu}',
                           'Dev/staging URL exposed in production JS',
                           'Remove internal URLs from production builds'))

    # Emails
    emails = list(set(re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', all_js)))
    emails = [e for e in emails if not re.search(r'\.(js|css|png|svg|jpg)$', e)][:10]
    for e in emails:
        records.append({'Type': 'EMAIL', 'Category': 'Contact', 'Value': e, 'Source': 'JS'})

    if endpoints:
        findings.append(f('info', f'{len(endpoints)} API Endpoints Discovered in JS',
                           ', '.join(list(endpoints)[:4]) + ('...' if len(endpoints) > 4 else ''),
                           'Test each for IDOR, missing auth, injection'))
    if emails:
        findings.append(f('low', f'{len(emails)} Email Addresses in JS',
                           ', '.join(emails[:3]), 'Verify intentionally public'))
    if not js_files_found and not parser.inline_scripts:
        findings.append(f('info', 'No JavaScript Analyzed', 'No JS files found or accessible', ''))

    return ok({
        'summary': {
            'Target':     url,
            'JS Files':   len(js_files_found),
            'Endpoints':  len(endpoints),
            'Secrets':    secrets_total,
            'WebSockets': len(ws_urls),
            'GraphQL':    len(gql_paths),
            'Emails':     len(emails),
        },
        'findings':       findings,
        'records':        records,
        'record_columns': ['Type', 'Category', 'Value', 'Source'],
    })
