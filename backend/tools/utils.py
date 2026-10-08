"""Shared utilities for BB-SUITE security tools.

Integrated with central security boundary: SSRF target validation,
TLS verification by default, response size limiting, and confidence taxonomy.
"""
from __future__ import annotations
import asyncio
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from backend.security.confidence import (
    Confidence,
    Severity,
    create_finding,
    standard_response,
)
from backend.security.http_client import SafeResponse, safe_request
from backend.security.target_validator import (
    TargetValidationError,
    validate_hostname,
    validate_target_url,
)


def clean_domain(s: str) -> Optional[str]:
    """Extract clean domain/host without protocol, path, or port."""
    if not s or not isinstance(s, str):
        return None
    d = re.sub(r'^https?://', '', s.strip().lower())
    d = d.split('/')[0].split('?')[0].split('#')[0].split(':')[0]
    if not re.match(r'^[a-z0-9][a-z0-9.\-]{0,252}[a-z0-9]$', d):
        return None
    return d


def clean_url(s: str) -> str:
    """Normalize URL with scheme."""
    if not s or not isinstance(s, str):
        return ""
    u = s.strip()
    if not re.match(r'^https?://', u, re.I):
        u = 'https://' + u
    return u.rstrip('/')


def clean_host(s: str) -> str:
    """Extract host string."""
    h = re.sub(r'^https?://', '', s.strip())
    return h.split('/')[0].split(':')[0]


HEADERS = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0 BugBountySuite/2.0 (Authorized Security Assessment)'}


async def http_get(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = 10.0,
    follow_redirects: bool = True,
    method: str = 'GET',
    data: Any = None,
    json: Any = None,
    extra_headers: Optional[Dict[str, str]] = None,
    verify: Optional[bool] = None,
    allow_private: Optional[bool] = None,
) -> Dict[str, Any]:
    """Execute HTTP request through centralized safe HTTP client."""
    h = {**HEADERS, **(headers or {}), **(extra_headers or {})}
    try:
        norm_url = clean_url(url)
        # safe_request enforces target validation, TLS verification, redirect validation, and max size
        res: SafeResponse = await safe_request(
            method=method,
            url=norm_url,
            headers=h,
            data=data,
            json_data=json,
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify=verify,
            allow_private=allow_private,
        )
        return {
            'ok': True,
            'status': res.status_code,
            'headers': dict(res.headers),
            'body': res.text,
            'url': res.url,
            'truncated': res.truncated,
            'error': None,
        }
    except TargetValidationError as sve:
        return {
            'ok': False,
            'status': 0,
            'headers': {},
            'body': '',
            'url': url,
            'error': f"Target Security Policy: {sve}",
        }
    except Exception as e:
        return {
            'ok': False,
            'status': 0,
            'headers': {},
            'body': '',
            'url': url,
            'error': str(e),
        }


async def check_port(host: str, port: int, timeout: float = 1.0) -> Tuple[bool, str]:
    """Check TCP port status with target boundary validation."""
    try:
        # Validate hostname/IP boundary first
        validate_hostname(host)
    except TargetValidationError:
        return False, 'Blocked by target policy'
    except Exception:
        return False, ''

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
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


def f(
    severity: str,
    title: str,
    detail: str,
    rec: str = '',
    confidence: str = "possible",
    evidence: str = "",
    **extra: Any
) -> Dict[str, Any]:
    """Create a standardized finding dictionary with confidence level."""
    return create_finding(
        title=title,
        severity=severity,
        confidence=confidence,
        detail=detail,
        recommendation=rec,
        evidence=evidence,
        **extra
    )


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


def load_wordlist(filename: str) -> List[str]:
    base = os.path.dirname(__file__)
    candidates = [
        os.path.join(base, '..', '..', 'wordlists', filename),
        os.path.join(base, '..', 'wordlists', filename),
    ]
    for p in candidates:
        if os.path.exists(p):
            with open(p, encoding='utf-8', errors='ignore') as fh:
                return [l.strip() for l in fh if l.strip()]
    return []


def ok(data: Dict[str, Any]) -> Dict[str, Any]:
    """Wrap data in standard success envelope."""
    # Ensure standard response keys exist
    if "findings" not in data:
        data["findings"] = []
    if "summary" not in data:
        data["summary"] = {}
    return {'success': True, 'data': data, 'error': ''}


def err(msg: str) -> Dict[str, Any]:
    """Wrap error in standard error envelope."""
    return {
        'success': False,
        'data': {
            'summary': {},
            'findings': [],
            'records': [],
            'record_columns': [],
            'raw': '',
        },
        'error': msg,
    }
