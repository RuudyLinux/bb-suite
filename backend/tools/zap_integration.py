from __future__ import annotations
import asyncio
from fastapi import APIRouter
from models import ZapReq
from tools.utils import clean_url, http_get, f, ok, err

try:
    from key_loader import ZAP_KEY as _ZAP_DEFAULT
except Exception:
    _ZAP_DEFAULT = ""

router = APIRouter(tags=["zap"])


async def zap_call(host: str, path: str, api_key: str = "") -> dict | None:
    sep = "&" if "?" in path else "?"
    key_param = f"{sep}apikey={api_key}" if api_key else ""
    r = await http_get(f"{host}{path}{key_param}", timeout=15)
    if not r["ok"]:
        return None
    import json
    try:
        return json.loads(r["body"])
    except Exception:
        return None


@router.post("/zap")
async def zap_integration(req: ZapReq):
    host = req.zap_host.rstrip("/")
    key  = req.api_key or _ZAP_DEFAULT  # Fall back to key.env

    if req.action == "status":
        ver = await zap_call(host, "/JSON/core/view/version/", key)
        if ver and "version" in ver:
            return ok({"running": True, "version": ver["version"]})
        return ok({"running": False})

    url = clean_url(req.target)
    ver = await zap_call(host, "/JSON/core/view/version/", key)
    if not ver:
        return err(f"Cannot connect to ZAP at {host}. Start ZAP with API enabled (Tools → Options → API).")

    findings = []
    records  = []
    zap_ver  = ver.get("version", "?")

    await zap_call(host, f"/JSON/core/action/accessUrl/?url={url}", key)
    await asyncio.sleep(2)

    # Spider
    if req.scan_type in ["spider", "full", "active"]:
        spider = await zap_call(host, f"/JSON/spider/action/scan/?url={url}", key)
        spider_id = spider.get("scan") if spider else None
        if spider_id is not None:
            waited = 0
            while waited < 60:
                await asyncio.sleep(3)
                waited += 3
                prog = await zap_call(host, f"/JSON/spider/view/status/?scanId={spider_id}", key)
                if prog and int(prog.get("status", 0)) >= 100:
                    break
            spider_urls = await zap_call(host, f"/JSON/spider/view/results/?scanId={spider_id}", key)
            if spider_urls and "results" in spider_urls:
                for u in spider_urls["results"][:50]:
                    records.append({"Type": "Spider URL", "URL": u[:80], "Risk": "—", "Alert": "—"})
                findings.append(f("info", "Spider Complete", f"{len(spider_urls['results'])} URLs found"))

    # Active scan
    if req.scan_type in ["active", "full"]:
        scan = await zap_call(host, f"/JSON/ascan/action/scan/?url={url}&recurse=true", key)
        scan_id = scan.get("scan") if scan else None
        if scan_id is not None:
            waited = 0
            while waited < 180:
                await asyncio.sleep(5)
                waited += 5
                prog = await zap_call(host, f"/JSON/ascan/view/status/?scanId={scan_id}", key)
                if prog and int(prog.get("status", 0)) >= 100:
                    break

    # Get alerts
    alerts_data = await zap_call(host, f"/JSON/core/view/alerts/?baseurl={url}&start=0&count=100", key)
    alerts = alerts_data.get("alerts", []) if alerts_data else []
    risk_map = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}

    for alert in alerts:
        risk = alert.get("risk", "Informational")
        sev  = risk_map.get(risk, "info")
        name = alert.get("alert", "Unknown")
        desc = alert.get("description", "")[:200]
        sol  = alert.get("solution", "")[:200]
        a_url = alert.get("url", "")
        findings.append(f(sev, name, f"URL: {a_url[:60]} — {desc}", sol))
        records.append({"Type": "Alert", "URL": a_url[:60], "Risk": risk, "Alert": name})

    if not alerts:
        findings.append(f("pass", "No ZAP Alerts Found", "Active scan returned no alerts"))

    high   = sum(1 for a in alerts if a.get("risk") == "High")
    medium = sum(1 for a in alerts if a.get("risk") == "Medium")

    return ok({"summary": {"ZAP Version": zap_ver, "Target": url,
                            "Total Alerts": len(alerts), "High": high, "Medium": medium},
               "findings": findings, "records": records,
               "record_columns": ["Type", "URL", "Risk", "Alert"]})
