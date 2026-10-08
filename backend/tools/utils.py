from __future__ import annotations
import re
import os
import asyncio
from typing import Optional
import httpx


def clean_domain(s: str) -> Optional[str]:
    d = re.sub(r'^https?://', '', s.strip().lower())
    d = d.split('/')[0].split('?')[0].split('#')[0]
    if not re.match(r'^[a-z0-9][a-z0-9.\-]{1,252}[a-z0-9]$', d):
        return None
    return d


def clean_url(s: str) -> str:
    u = s.strip()
    if not re.match(r'^https?://', u, re.I):
        u = 'https://' + u
    return u.rstrip('/')


def clean_host(s: str) -> str:
    h = re.sub(r'^https?://', '', s.strip())
    return h.split('/')[0].split(':')[0]


HEADERS = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0 BugBountySuite/2.0'}


async def http_get(url: str, headers: dict = None, timeout: int = 10,
                   follow_redirects: bool = True, method: str = 'GET',
                   data: dict = None, json: dict = None,
                   extra_headers: dict = None) -> dict:
    h = {**HEADERS, **(headers or {}), **(extra_headers or {})}
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=follow_redirects,
                                     timeout=timeout) as c:
            if method == 'POST':
                r = await c.post(url, headers=h, data=data, json=json)
            else:
                r = await c.get(url, headers=h)
            return {'ok': True, 'status': r.status_code,
                    'headers': dict(r.headers), 'body': r.text,
                    'url': str(r.url), 'error': None}
    except Exception as e:
        return {'ok': False, 'status': 0, 'headers': {}, 'body': '',
                'url': url, 'error': str(e)}


async def check_port(host: str, port: int, timeout: float = 1.0) -> tuple[bool, str]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        banner = ''
        try:
            data = await asyncio.wait_for(reader.read(512), timeout=0.5)
            banner = data.decode('utf-8', errors='replace').strip()[:200]
            banner = banner.replace('\r', ' ').replace('\n', ' ')
        except Exception:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return True, banner
    except Exception:
        return False, ''


def f(severity: str, title: str, detail: str, rec: str = '') -> dict:
    return {'severity': severity, 'title': title, 'detail': detail, 'recommendation': rec}


PORT_NAMES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    465: 'SMTPS', 587: 'Submission', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MSSQL', 1521: 'Oracle', 2375: 'Docker API', 2376: 'Docker TLS',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5672: 'AMQP',
    5900: 'VNC', 6379: 'Redis', 7001: 'WebLogic', 8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt', 8888: 'Jupyter', 9200: 'Elasticsearch',
    11211: 'Memcached', 27017: 'MongoDB',
}


def load_wordlist(filename: str) -> list[str]:
    base = os.path.dirname(__file__)
    candidates = [
        os.path.join(base, '..', '..', 'wordlists', filename),
        os.path.join(base, '..', 'wordlists', filename),
    ]
    for p in candidates:
        if os.path.exists(p):
            with open(p) as fh:
                return [l.strip() for l in fh if l.strip()]
    return []


def ok(data: dict) -> dict:
    return {'success': True, 'data': data}


def err(msg: str) -> dict:
    return {'success': False, 'data': {}, 'error': msg}
