from fastapi import APIRouter
from models import TargetReq
from tools.utils import clean_url, http_get, f, ok, err

router = APIRouter(tags=["analysis"])

SEC_HEADERS = {
    "strict-transport-security": {
        "name": "HSTS", "sev": "high",
        "rec": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "content-security-policy": {
        "name": "CSP", "sev": "high",
        "rec": "Implement strict CSP: default-src 'self'; script-src 'self'"
    },
    "x-frame-options": {
        "name": "X-Frame-Options", "sev": "medium",
        "rec": "X-Frame-Options: DENY or use CSP frame-ancestors"
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options", "sev": "medium",
        "rec": "X-Content-Type-Options: nosniff"
    },
    "referrer-policy": {
        "name": "Referrer-Policy", "sev": "low",
        "rec": "Referrer-Policy: strict-origin-when-cross-origin"
    },
    "permissions-policy": {
        "name": "Permissions-Policy", "sev": "low",
        "rec": "Add Permissions-Policy to restrict browser features"
    },
    "cross-origin-opener-policy": {
        "name": "COOP", "sev": "low",
        "rec": "Cross-Origin-Opener-Policy: same-origin"
    },
    "cross-origin-resource-policy": {
        "name": "CORP", "sev": "low",
        "rec": "Cross-Origin-Resource-Policy: same-origin"
    },
}


@router.post("/headers")
async def headers_check(req: TargetReq):
    url = clean_url(req.target)
    resp = await http_get(url)
    if not resp["ok"]:
        return err(f"Cannot reach URL: {resp['error']}")
    try:
        hdrs = resp["headers"]
        findings = []
        records = []
        present = missing = 0

        for hdr, cfg in SEC_HEADERS.items():
            val = hdrs.get(hdr)
            if val:
                present += 1
                records.append({"Header": hdr, "Value": val[:150], "Status": "✓ Present"})
                if hdr == "strict-transport-security":
                    import re
                    m = re.search(r'max-age=(\d+)', val)
                    if m and int(m.group(1)) < 31536000:
                        findings.append(f("medium", "HSTS max-age Too Short",
                                           f"max-age={m.group(1)} — min 31536000",
                                           "Set max-age to at least 1 year"))
                    else:
                        findings.append(f("pass", "HSTS OK", val[:80]))
                if hdr == "content-security-policy":
                    if "'unsafe-inline'" in val:
                        findings.append(f("high", "CSP allows unsafe-inline", val[:100],
                                           "Remove 'unsafe-inline'"))
                    if "'unsafe-eval'" in val:
                        findings.append(f("high", "CSP allows unsafe-eval", val[:100],
                                           "Remove 'unsafe-eval'"))
            else:
                missing += 1
                findings.append(f(cfg["sev"], f"Missing {cfg['name']}",
                                   f"{hdr} not set", cfg["rec"]))
                records.append({"Header": hdr, "Value": "—", "Status": "✗ Missing"})

        for lh in ["server", "x-powered-by", "x-aspnet-version"]:
            if hdrs.get(lh):
                findings.append(f("medium", f"Info Leak: {lh}", hdrs[lh],
                                   f"Remove or obscure '{lh}' header"))
                records.append({"Header": lh, "Value": hdrs[lh], "Status": "⚠ Leaking"})

        score = round(present / (present + missing) * 100) if (present + missing) else 0
        return ok({"summary": {"URL": url, "HTTP Status": resp["status"],
                                "Headers Present": present, "Missing": missing,
                                "Score": f"{score}%"},
                   "findings": findings, "records": records,
                   "record_columns": ["Header", "Value", "Status"],
                   "raw": "\n".join(f"{k}: {v}" for k, v in hdrs.items())})
    except Exception as e:
        return err(str(e))
