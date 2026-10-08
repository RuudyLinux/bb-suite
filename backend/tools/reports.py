from __future__ import annotations
import json
import os
import re
from datetime import datetime
from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Any, Dict, List

router = APIRouter(tags=["reports"])

REPORTS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..', 'reports')
)
os.makedirs(REPORTS_DIR, exist_ok=True)


class SaveReportReq(BaseModel):
    target: str
    results: Dict[str, Any]
    all_findings: List[Dict]
    sev_counts: Dict[str, int]
    duration_s: float = 0


def sev_color(sev: str) -> str:
    return {
        'critical': '#ff0000', 'high': '#ff6600',
        'medium': '#ffff00', 'low': '#0088ff',
        'info': '#00d4ff', 'pass': '#00ff41',
    }.get(sev, '#888')


def generate_html(data: dict) -> str:
    target  = data.get("target", "Unknown")
    ts      = data.get("timestamp", "")
    counts  = data.get("sev_counts", {})
    findings = data.get("all_findings", [])
    results  = data.get("results", {})

    ORDER = ['critical', 'high', 'medium', 'low', 'info', 'pass']
    sorted_findings = sorted(findings, key=lambda f: ORDER.index(f.get('severity', 'info'))
                             if f.get('severity', 'info') in ORDER else 9)

    findings_html = ""
    for fnd in sorted_findings:
        sev   = fnd.get("severity", "info")
        col   = sev_color(sev)
        tool  = fnd.get("_tool", "")
        findings_html += f"""
        <div style="border-left:3px solid {col};background:{col}10;margin:6px 0;padding:10px 14px;border-radius:0 4px 4px 0">
          <div style="display:flex;gap:10px;align-items:center;margin-bottom:4px">
            <span style="background:{col}25;color:{col};padding:2px 8px;font-size:11px;font-weight:bold;border-radius:3px">{sev.upper()}</span>
            <strong style="color:{col}">{fnd.get('title','')}</strong>
            {f'<span style="color:#444;font-size:11px;margin-left:auto;border:1px solid #222;padding:1px 6px">{tool}</span>' if tool else ''}
          </div>
          <p style="color:#aaa;font-size:12px;margin:4px 0">{fnd.get('detail','')}</p>
          {f'<p style="color:{col};font-size:11px;margin:4px 0"><strong>FIX:</strong> {fnd.get("recommendation","")}</p>' if fnd.get("recommendation") else ''}
        </div>"""

    # Tool results summary
    tools_html = ""
    for tool_name, res in results.items():
        if not res or not res.get('success'):
            continue
        d = res.get('data', {})
        s = d.get('summary', {})
        fcount = len([fnd for fnd in d.get('findings', []) if fnd.get('severity') not in ('pass', 'info')])
        tools_html += f"""
        <tr>
          <td style="padding:8px;border-bottom:1px solid #1a1a1a;color:#00cc33">{tool_name.replace('_',' ').title()}</td>
          <td style="padding:8px;border-bottom:1px solid #1a1a1a;color:#555">{', '.join(f'{k}: {v}' for k,v in list(s.items())[:3])}</td>
          <td style="padding:8px;border-bottom:1px solid #1a1a1a;color:{'#ff4444' if fcount else '#555'}">{fcount} issues</td>
        </tr>"""

    crit = counts.get('critical', 0)
    high = counts.get('high', 0)
    med  = counts.get('medium', 0)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>BB-SUITE Report — {target}</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{background:#050508;color:#e0e0e0;font-family:'Courier New',monospace;padding:30px;font-size:13px}}
  h1{{color:#00ff41;font-size:22px;letter-spacing:3px;text-shadow:0 0 10px #00ff41}}
  h2{{color:#00ff41;font-size:14px;letter-spacing:2px;margin:24px 0 12px;border-bottom:1px solid #003300;padding-bottom:8px}}
  .meta{{color:#555;font-size:11px;margin-top:6px}}
  .stats{{display:flex;gap:12px;margin:20px 0;flex-wrap:wrap}}
  .stat-box{{border:1px solid #1a1a1a;padding:14px 20px;text-align:center;min-width:100px}}
  table{{width:100%;border-collapse:collapse}}
  th{{text-align:left;padding:10px;border-bottom:1px solid #003300;color:#555;font-size:11px;text-transform:uppercase;letter-spacing:1px}}
  ::-webkit-scrollbar{{width:4px}} ::-webkit-scrollbar-thumb{{background:#1a1a1a}}
</style>
</head>
<body>
<h1>&#9632; BB-SUITE SECURITY REPORT</h1>
<div class="meta">Target: <strong style="color:#fff">{target}</strong> &nbsp;|&nbsp; Generated: {ts} &nbsp;|&nbsp; Duration: {data.get('duration_s',0):.1f}s</div>

<div class="stats">
  <div class="stat-box"><div style="font-size:28px;color:#ff0000;text-shadow:0 0 10px #ff0000">{crit}</div><div style="color:#555;font-size:10px;margin-top:4px">CRITICAL</div></div>
  <div class="stat-box"><div style="font-size:28px;color:#ff6600">{high}</div><div style="color:#555;font-size:10px;margin-top:4px">HIGH</div></div>
  <div class="stat-box"><div style="font-size:28px;color:#ffff00">{med}</div><div style="color:#555;font-size:10px;margin-top:4px">MEDIUM</div></div>
  <div class="stat-box"><div style="font-size:28px;color:#0088ff">{counts.get('low',0)}</div><div style="color:#555;font-size:10px;margin-top:4px">LOW</div></div>
  <div class="stat-box"><div style="font-size:28px;color:#00ff41">{len(findings)}</div><div style="color:#555;font-size:10px;margin-top:4px">TOTAL</div></div>
  <div class="stat-box"><div style="font-size:28px;color:#00cc33">{len([r for r in results.values() if r and r.get('success')])}</div><div style="color:#555;font-size:10px;margin-top:4px">TOOLS RUN</div></div>
</div>

<h2>FINDINGS</h2>
{findings_html if findings_html else '<p style="color:#333">No findings recorded.</p>'}

<h2>TOOL RESULTS SUMMARY</h2>
<table>
  <thead><tr><th>Tool</th><th>Key Data</th><th>Issues</th></tr></thead>
  <tbody>{tools_html}</tbody>
</table>

<div style="margin-top:40px;border-top:1px solid #003300;padding-top:16px;color:#333;font-size:10px;text-align:center">
  Generated by BB-SUITE v3.1 &nbsp;|&nbsp; For authorized security testing only
</div>
</body>
</html>"""


@router.post("/save_report")
async def save_report(req: SaveReportReq):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_tgt = re.sub(r'[^a-z0-9_\-]', '_', req.target.replace('https://','').replace('http://','').split('/')[0])
    base_name = f"report_{safe_tgt}_{ts}"

    payload = {
        "target":      req.target,
        "timestamp":   datetime.now().isoformat(),
        "duration_s":  req.duration_s,
        "sev_counts":  req.sev_counts,
        "all_findings": req.all_findings,
        "results":     req.results,
    }

    json_path = os.path.join(REPORTS_DIR, base_name + ".json")
    html_path = os.path.join(REPORTS_DIR, base_name + ".html")

    with open(json_path, 'w', encoding='utf-8') as fp:
        json.dump(payload, fp, indent=2, default=str)

    with open(html_path, 'w', encoding='utf-8') as fp:
        fp.write(generate_html(payload))

    return {"success": True, "data": {
        "json_file": base_name + ".json",
        "html_file": base_name + ".html",
    }}


@router.get("/reports")
async def list_reports():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    files = sorted(
        [f for f in os.listdir(REPORTS_DIR) if f.endswith('.json')],
        reverse=True
    )[:30]
    reports = []
    for fname in files:
        fp = os.path.join(REPORTS_DIR, fname)
        stat = os.stat(fp)
        try:
            with open(fp, encoding='utf-8') as fh:
                meta = json.load(fh)
            reports.append({
                "filename":  fname,
                "html_file": fname.replace('.json', '.html'),
                "target":    meta.get("target", "?"),
                "timestamp": meta.get("timestamp", ""),
                "duration":  meta.get("duration_s", 0),
                "critical":  meta.get("sev_counts", {}).get("critical", 0),
                "high":      meta.get("sev_counts", {}).get("high", 0),
                "total_findings": len(meta.get("all_findings", [])),
                "size_kb":   round(stat.st_size / 1024, 1),
            })
        except Exception:
            pass
    return {"success": True, "data": {"reports": reports}}


@router.get("/reports/{filename}")
async def get_report_html(filename: str):
    filename = os.path.basename(filename)
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
        return JSONResponse({"error": "Invalid filename"}, status_code=400)
    fp = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(fp):
        return JSONResponse({"error": "Not found"}, status_code=404)
    if filename.endswith('.html'):
        with open(fp, encoding='utf-8') as fh:
            return HTMLResponse(fh.read())
    with open(fp, encoding='utf-8') as fh:
        return {"success": True, "data": json.load(fh)}
