"""Secure Report Generation, Storage, and Viewing Engine for BB-SUITE.

Defends against Stored XSS by rigorously escaping all dynamic HTML fields,
redacts sensitive credentials/tokens, and prevents path traversal.
"""
from __future__ import annotations
from datetime import datetime
import html
import json
import os
import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from backend.security.auth import get_current_user, optional_current_user
from backend.security.confidence import Severity
from backend.security.logger import audit_logger, redact_secrets

router = APIRouter(tags=["reports"])

REPORTS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..', 'reports')
)
os.makedirs(REPORTS_DIR, exist_ok=True)
MAX_REPORT_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10 MB


class SaveReportReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    results: Dict[str, Any] = Field(default_factory=dict)
    all_findings: List[Dict[str, Any]] = Field(default_factory=list)
    sev_counts: Dict[str, int] = Field(default_factory=dict)
    duration_s: float = Field(0.0, ge=0.0)


def sev_color(sev: str) -> str:
    return {
        'critical': '#ff0000',
        'high': '#ff6600',
        'medium': '#ffff00',
        'low': '#0088ff',
        'info': '#00d4ff',
        'pass': '#00ff41',
    }.get(sev.lower(), '#888888')


def sanitize_filename(name: str) -> str:
    """Ensure filename only contains safe characters without path traversal."""
    cleaned = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', name)
    return cleaned.strip('._')


def generate_html(data: Dict[str, Any]) -> str:
    """Generate XSS-safe static HTML report with all user/target input escaped."""
    raw_target = str(data.get("target", "Unknown"))
    target = html.escape(redact_secrets(raw_target))
    ts = html.escape(str(data.get("timestamp", "")))
    counts = data.get("sev_counts", {})
    findings = data.get("all_findings", [])
    results = data.get("results", {})

    order = ['critical', 'high', 'medium', 'low', 'info', 'pass']
    sorted_findings = sorted(
        findings,
        key=lambda f: order.index(f.get('severity', 'info').lower())
        if f.get('severity', 'info',).lower() in order else 9
    )

    findings_html_list = []
    for fnd in sorted_findings:
        sev = html.escape(str(fnd.get("severity", "info")).lower())
        conf = html.escape(str(fnd.get("confidence", "possible")).upper())
        col = sev_color(sev)
        tool = html.escape(str(fnd.get("_tool", "")))
        title = html.escape(redact_secrets(str(fnd.get('title', ''))))
        detail = html.escape(redact_secrets(str(fnd.get('detail', ''))))
        rec = html.escape(redact_secrets(str(fnd.get('recommendation', ''))))
        evidence = html.escape(redact_secrets(str(fnd.get('evidence', ''))))

        tool_badge = f'<span style="color:#666;font-size:11px;margin-left:auto;border:1px solid #222;padding:1px 6px">{tool}</span>' if tool else ''
        fix_badge = f'<p style="color:{col};font-size:11px;margin:4px 0"><strong>REMEDIATION:</strong> {rec}</p>' if rec else ''
        ev_box = f'<pre style="background:#0a0a0f;padding:6px;margin-top:4px;color:#88ff88;font-size:11px;overflow-x:auto"><code>{evidence}</code></pre>' if evidence else ''

        findings_html_list.append(f"""
        <div style="border-left:3px solid {col};background:{col}10;margin:8px 0;padding:10px 14px;border-radius:0 4px 4px 0">
          <div style="display:flex;gap:10px;align-items:center;margin-bottom:4px">
            <span style="background:{col}25;color:{col};padding:2px 8px;font-size:11px;font-weight:bold;border-radius:3px">{sev.upper()}</span>
            <span style="border:1px solid #444;color:#aaa;padding:1px 6px;font-size:10px;border-radius:2px">{conf}</span>
            <strong style="color:{col}">{title}</strong>
            {tool_badge}
          </div>
          <p style="color:#aaa;font-size:12px;margin:4px 0">{detail}</p>
          {ev_box}
          {fix_badge}
        </div>""")

    findings_html = "".join(findings_html_list)

    # Tool results summary
    tools_html_list = []
    for tool_name, res in results.items():
        if not res or not res.get('success'):
            continue
        safe_tool_name = html.escape(str(tool_name).replace('_', ' ').title())
        d = res.get('data', {})
        s = d.get('summary', {})
        fcount = len([fnd for fnd in d.get('findings', []) if str(fnd.get('severity', '')).lower() not in ('pass', 'info')])
        summary_items = []
        for k, v in list(s.items())[:3]:
            summary_items.append(f"{html.escape(str(k))}: {html.escape(redact_secrets(str(v)))}")
        summary_text = ', '.join(summary_items)
        issues_color = '#ff4444' if fcount else '#555'

        tools_html_list.append(f"""
        <tr>
          <td style="padding:8px;border-bottom:1px solid #1a1a1a;color:#00cc33">{safe_tool_name}</td>
          <td style="padding:8px;border-bottom:1px solid #1a1a1a;color:#888">{summary_text}</td>
          <td style="padding:8px;border-bottom:1px solid #1a1a1a;color:{issues_color}">{fcount} issues</td>
        </tr>""")

    tools_html = "".join(tools_html_list)

    crit = int(counts.get('critical', 0))
    high = int(counts.get('high', 0))
    med = int(counts.get('medium', 0))
    low = int(counts.get('low', 0))
    duration = float(data.get('duration_s', 0))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; font-src data:;">
<title>BB-SUITE Report — {target}</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{background:#050508;color:#e0e0e0;font-family:'Courier New',Courier,monospace;padding:30px;font-size:13px;line-height:1.5}}
  h1{{color:#00ff41;font-size:22px;letter-spacing:3px;text-shadow:0 0 10px #00ff41}}
  h2{{color:#00ff41;font-size:14px;letter-spacing:2px;margin:24px 0 12px;border-bottom:1px solid #003300;padding-bottom:8px}}
  .meta{{color:#777;font-size:11px;margin-top:6px}}
  .stats{{display:flex;gap:12px;margin:20px 0;flex-wrap:wrap}}
  .stat-box{{border:1px solid #1a1a1a;padding:14px 20px;text-align:center;min-width:100px;background:#090910}}
  table{{width:100%;border-collapse:collapse;margin-top:10px}}
  th{{text-align:left;padding:10px;border-bottom:1px solid #003300;color:#666;font-size:11px;text-transform:uppercase;letter-spacing:1px}}
  ::-webkit-scrollbar{{width:4px}} ::-webkit-scrollbar-thumb{{background:#1a1a1a}}
</style>
</head>
<body>
<h1>&#9632; BB-SUITE SECURITY ASSESSMENT REPORT</h1>
<div class="meta">Target: <strong style="color:#fff">{target}</strong> &nbsp;|&nbsp; Generated: {ts} &nbsp;|&nbsp; Duration: {duration:.1f}s</div>

<div class="stats">
  <div class="stat-box"><div style="font-size:28px;color:#ff0000;text-shadow:0 0 10px #ff0000">{crit}</div><div style="color:#666;font-size:10px;margin-top:4px">CRITICAL</div></div>
  <div class="stat-box"><div style="font-size:28px;color:#ff6600">{high}</div><div style="color:#666;font-size:10px;margin-top:4px">HIGH</div></div>
  <div class="stat-box"><div style="font-size:28px;color:#ffff00">{med}</div><div style="color:#666;font-size:10px;margin-top:4px">MEDIUM</div></div>
  <div class="stat-box"><div style="font-size:28px;color:#0088ff">{low}</div><div style="color:#666;font-size:10px;margin-top:4px">LOW</div></div>
  <div class="stat-box"><div style="font-size:28px;color:#00ff41">{len(findings)}</div><div style="color:#666;font-size:10px;margin-top:4px">TOTAL</div></div>
  <div class="stat-box"><div style="font-size:28px;color:#00cc33">{len([r for r in results.values() if r and r.get('success')])}</div><div style="color:#666;font-size:10px;margin-top:4px">TOOLS RUN</div></div>
</div>

<h2>FINDINGS</h2>
{findings_html if findings_html else '<p style="color:#555">No vulnerabilities recorded.</p>'}

<h2>TOOL RESULTS SUMMARY</h2>
<table>
  <thead><tr><th>Tool</th><th>Key Data</th><th>Issues</th></tr></thead>
  <tbody>{tools_html}</tbody>
</table>

<div style="margin-top:40px;border-top:1px solid #003300;padding-top:16px;color:#444;font-size:10px;text-align:center">
  Generated by BB-SUITE &nbsp;|&nbsp; Production Security Boundary &nbsp;|&nbsp; Authorized Security Testing Only
</div>
</body>
</html>"""


@router.post("/save_report")
async def save_report(req: SaveReportReq, user: Dict[str, Any] = Depends(optional_current_user)):
    """Save an assessment report safely with secrets redacted and HTML escaped."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_tgt = sanitize_filename(
        req.target.replace('https://', '').replace('http://', '').split('/')[0]
    )
    if not safe_tgt:
        safe_tgt = "target"
    base_name = f"report_{safe_tgt}_{ts}"

    # Scrub sensitive tokens/passwords from the report payload
    cleaned_target = redact_secrets(req.target)
    cleaned_findings = json.loads(redact_secrets(json.dumps(req.all_findings)))
    cleaned_results = json.loads(redact_secrets(json.dumps(req.results)))

    payload = {
        "target": cleaned_target,
        "timestamp": datetime.now().isoformat(),
        "duration_s": req.duration_s,
        "sev_counts": req.sev_counts,
        "all_findings": cleaned_findings,
        "results": cleaned_results,
    }

    raw_json = json.dumps(payload, indent=2, default=str)
    if len(raw_json) > MAX_REPORT_PAYLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Report payload exceeds maximum allowed size (10 MB).",
        )

    json_path = os.path.join(REPORTS_DIR, base_name + ".json")
    html_path = os.path.join(REPORTS_DIR, base_name + ".html")

    with open(json_path, 'w', encoding='utf-8') as fp:
        fp.write(raw_json)

    with open(html_path, 'w', encoding='utf-8') as fp:
        fp.write(generate_html(payload))

    audit_logger.info("Report saved: %s for target: %s", base_name, cleaned_target)

    return {"success": True, "data": {
        "json_file": base_name + ".json",
        "html_file": base_name + ".html",
    }}


@router.get("/reports")
async def list_reports(user: Optional[Dict[str, Any]] = Depends(optional_current_user)):
    """List available scan reports."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    files = sorted(
        [f for f in os.listdir(REPORTS_DIR) if f.endswith('.json')],
        reverse=True
    )[:50]

    reports = []
    for fname in files:
        fp = os.path.join(REPORTS_DIR, fname)
        try:
            stat = os.stat(fp)
            with open(fp, encoding='utf-8', errors='ignore') as fh:
                meta = json.load(fh)
            reports.append({
                "filename": fname,
                "html_file": fname.replace('.json', '.html'),
                "target": meta.get("target", "?"),
                "timestamp": meta.get("timestamp", ""),
                "duration": meta.get("duration_s", 0),
                "critical": meta.get("sev_counts", {}).get("critical", 0),
                "high": meta.get("sev_counts", {}).get("high", 0),
                "total_findings": len(meta.get("all_findings", [])),
                "size_kb": round(stat.st_size / 1024, 1),
            })
        except Exception:
            pass

    return {"success": True, "data": {"reports": reports}}


@router.get("/reports/{filename}")
async def get_report_html(filename: str, user: Optional[Dict[str, Any]] = Depends(optional_current_user)):
    """Fetch report HTML or JSON preventing path traversal."""
    filename = os.path.basename(filename)
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename) or '..' in filename:
        raise HTTPException(status_code=400, detail="Invalid filename.")

    fp = os.path.abspath(os.path.join(REPORTS_DIR, filename))
    # Path traversal check
    if os.path.commonpath([REPORTS_DIR, fp]) != REPORTS_DIR or not os.path.exists(fp):
        raise HTTPException(status_code=404, detail="Report not found.")

    if filename.endswith('.html'):
        with open(fp, encoding='utf-8') as fh:
            return HTMLResponse(
                fh.read(),
                headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline';"}
            )

    with open(fp, encoding='utf-8') as fh:
        return {"success": True, "data": json.load(fh)}
