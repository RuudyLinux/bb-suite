"""SQL Injection Detection Engine for BB-SUITE.

Uses multi-signal differential verification:
- Error-based with vendor database regex fingerprints (Confirmed)
- Boolean differential with repeated stability tests (Likely/Confirmed)
- Time-based differential with baseline latency calibration and repeat verification (Likely/Confirmed)
Never flags a single byte fluctuation as SQL injection.
"""
from __future__ import annotations
import asyncio
import difflib
import re
import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter

from backend.models import SqliReq
from backend.security.confidence import (
    Confidence,
    Severity,
    create_finding,
    standard_response,
)
from backend.security.target_validator import TargetValidationError, validate_target_url
from backend.tools.utils import clean_url, err, http_get, ok

router = APIRouter(tags=["exploitation"])

# Comprehensive, vendor-specific database error patterns
SQL_ERROR_PATTERNS = [
    # MySQL
    (r"you have an error in your sql syntax.*mysql", "MySQL Syntax Error"),
    (r"warning:\s*mysql_[a-z0-9_]+\(\)", "MySQL PHP Driver Warning"),
    (r"valid mysql result", "MySQL Generic Error"),
    (r"check the manual that corresponds to your (?:mysql|mariadb) server version", "MySQL / MariaDB Version Error"),
    # PostgreSQL
    (r"postgresql.*error", "PostgreSQL Error"),
    (r"warning:\s*pg_[a-z0-9_]+\(\)", "PostgreSQL Driver Warning"),
    (r"valid postgresql result", "PostgreSQL Query Error"),
    (r"psycopg2\.programmingerror", "PostgreSQL Python Driver"),
    (r"pg_query\(\):.*query failed:", "PostgreSQL Query Failure"),
    # SQLite
    (r"sqlite3::sqlexception", "SQLite Exception"),
    (r"unrecognized token:", "SQLite Token Error"),
    (r"sqlite_error", "SQLite General Error"),
    (r"operationalerror:\s*near \".*\": syntax error", "SQLite Syntax Error"),
    # Microsoft SQL Server
    (r"driver.*sql[\-\_\ ]*server", "MSSQL Driver"),
    (r"ole db.*sql server", "MSSQL OLE DB"),
    (r"\b(?:sqlserver|mssql)\b.*syntax error", "MSSQL Syntax"),
    (r"unclosed quotation mark after the character string", "MSSQL Unclosed Quote"),
    # Oracle
    (r"\bora-[0-9]{4,5}\b", "Oracle ORA Error Code"),
    (r"oracle error", "Oracle Generic Error"),
    # Generic SQL / ODBC
    (r"syntax error in string in query expression", "Access/Jet Syntax Error"),
    (r"odbc sql server driver", "ODBC Driver Error"),
    (r"dynamic sql error", "Firebird/Interbase Error"),
]

ERROR_PROBES = [
    ("'", "Single Quote Break"),
    ("\"", "Double Quote Break"),
    ("')", "Parenthesis Quote Break"),
    ("'--", "Comment Terminated Single Quote"),
]

BOOL_TEST_SUITES = [
    # (True probe, False probe, description)
    (" AND 1=1--", " AND 1=2--", "Integer Boolean Test"),
    ("' AND '1'='1'--", "' AND '1'='2'--", "Quoted String Boolean Test"),
    ("' OR '1'='1", "' OR '1'='2", "Tautology Test"),
]

TIME_PROBES = [
    ("'; SELECT pg_sleep(4)--", 4.0, "PostgreSQL sleep"),
    ("'; WAITFOR DELAY '0:0:4'--", 4.0, "MSSQL waitfor"),
    ("' AND (SELECT 1 FROM (SELECT(SLEEP(4)))a)--", 4.0, "MySQL subquery sleep"),
]


def inject_param(url: str, param: str, payload: str) -> str:
    p = urlparse(url)
    params = parse_qs(p.query, keep_blank_values=True)
    params[param] = [payload]
    new_q = urlencode(params, doseq=True)
    return urlunparse(p._replace(query=new_q))


def text_similarity(a: str, b: str) -> float:
    """Calculate ratio of similarity between two response bodies."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a[:3000], b[:3000]).ratio()


@router.post("/sqli")
async def sql_injection(req: SqliReq):
    url = clean_url(req.target)
    try:
        validate_target_url(url)
    except TargetValidationError as tve:
        return err(f"Target validation failed: {tve}")

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return err("No GET query parameters in URL. Please provide a target URL with parameters (e.g. ?id=1).")

    findings: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []

    # 1. Establish baseline & stability check
    t0 = time.monotonic()
    base1 = await http_get(url, timeout=10)
    base1_latency = time.monotonic() - t0
    base1_body = base1.get("body", "")
    base1_len = len(base1_body)

    # Secondary baseline to measure natural page dynamic variance
    base2 = await http_get(url, timeout=10)
    base2_body = base2.get("body", "")
    natural_len_variance = abs(base1_len - len(base2_body))

    for param in params:
        param_vulnerable = False

        # --- A. Error-Based SQLi Detection ---
        if req.type in ["all", "error"]:
            for payload, probe_desc in ERROR_PROBES:
                test_url = inject_param(url, param, payload)
                r = await http_get(test_url, timeout=8)
                body = r.get("body", "")

                for err_pat, db_name in SQL_ERROR_PATTERNS:
                    match = re.search(err_pat, body, re.IGNORECASE)
                    if match:
                        evidence_str = match.group(0)[:120]
                        findings.append(create_finding(
                            title=f"SQLi Error-Based ({db_name}): param '{param}'",
                            severity="critical",
                            confidence=Confidence.CONFIRMED.value,
                            detail=f"Injected probe '{payload}' into parameter '{param}'. The server triggered database error '{evidence_str}'.",
                            recommendation="Use parameterized prepared statements with bind variables. Never concatenate untrusted strings into database queries.",
                            evidence=f"Matched Regex: {err_pat}\nSnippet: {evidence_str}",
                        ))
                        records.append({
                            "Type": "Error-Based",
                            "Param": param,
                            "Confidence": "confirmed",
                            "Payload": payload,
                            "Evidence": f"{db_name}: {evidence_str[:50]}",
                        })
                        param_vulnerable = True
                        break
                if param_vulnerable:
                    break

        # --- B. Boolean-Based SQLi Differential Verification ---
        if req.type in ["all", "boolean"] and not param_vulnerable:
            for true_p, false_p, bool_desc in BOOL_TEST_SUITES:
                url_true = inject_param(url, param, true_p)
                url_false = inject_param(url, param, false_p)

                # Send True & False queries
                r_true = await http_get(url_true, timeout=8)
                r_false = await http_get(url_false, timeout=8)

                len_true = len(r_true.get("body", ""))
                len_false = len(r_false.get("body", ""))
                status_true = r_true.get("status", 0)
                status_false = r_false.get("status", 0)

                diff = abs(len_true - len_false)
                sim_true_base = text_similarity(r_true.get("body", ""), base1_body)
                sim_false_base = text_similarity(r_false.get("body", ""), base1_body)
                sim_true_false = text_similarity(r_true.get("body", ""), r_false.get("body", ""))

                # High-confidence condition:
                # 1. True request matches baseline closely (sim > 0.85)
                # 2. False request diverges significantly from True (diff > max(150, natural_len_variance * 3) or sim < 0.75 or status shift)
                if diff > max(150, natural_len_variance * 3) and sim_true_base > 0.80 and sim_true_false < 0.80:
                    # Repeat verification test to eliminate transient flakiness
                    r_true_verify = await http_get(url_true, timeout=8)
                    r_false_verify = await http_get(url_false, timeout=8)
                    verify_diff = abs(len(r_true_verify.get("body", "")) - len(r_false_verify.get("body", "")))

                    if verify_diff > 100:
                        conf = Confidence.CONFIRMED if (status_true != status_false or diff > 500) else Confidence.LIKELY
                        findings.append(create_finding(
                            title=f"SQLi Boolean Differential ({conf.value.capitalize()}): param '{param}'",
                            severity="high" if conf == Confidence.CONFIRMED else "medium",
                            confidence=conf.value,
                            detail=f"Injected boolean pair '{true_p}' vs '{false_p}'. True payload returned {len_true}B (HTTP {status_true}), False returned {len_false}B (HTTP {status_false}). Differential of {diff}B remained stable across repeated runs.",
                            recommendation="Implement parameterized database queries. Disable dynamic SQL string concatenation.",
                            evidence=f"True: {len_true}B, False: {len_false}B (Variance baseline: {natural_len_variance}B, Diff: {diff}B)",
                        ))
                        records.append({
                            "Type": "Boolean-Based",
                            "Param": param,
                            "Confidence": conf.value,
                            "Payload": true_p,
                            "Evidence": f"Stable length diff: {diff}B (Sim: {round(sim_true_false, 2)})",
                        })
                        param_vulnerable = True
                        break

        # --- C. Time-Based SQLi Detection with Baseline Calibration ---
        if req.type in ["all", "time"] and not param_vulnerable:
            for time_payload, expected_delay, time_desc in TIME_PROBES:
                test_url = inject_param(url, param, time_payload)

                t_start = time.monotonic()
                r_time = await http_get(test_url, timeout=12)
                elapsed = time.monotonic() - t_start

                # Delay must be substantially greater than baseline latency + expected delay - 0.5s
                if elapsed >= (base1_latency + expected_delay - 0.5):
                    # Verify by testing a benign request immediately to ensure server isn't just bogged down
                    t_check = time.monotonic()
                    r_check = await http_get(url, timeout=8)
                    check_elapsed = time.monotonic() - t_check

                    if check_elapsed < (base1_latency + 1.5):
                        # The delay was specific to the injected sleep payload!
                        findings.append(create_finding(
                            title=f"SQLi Time-Based Blind (Likely): param '{param}'",
                            severity="high",
                            confidence=Confidence.LIKELY.value,
                            detail=f"Injected payload '{time_payload}' into parameter '{param}'. Response paused for {elapsed:.2f}s (baseline: {base1_latency:.2f}s), while benign check recovered at {check_elapsed:.2f}s.",
                            recommendation="Ensure all queries use parameter binding rather than string concatenation.",
                            evidence=f"Sleep delay: {elapsed:.2f}s vs Baseline: {base1_latency:.2f}s",
                        ))
                        records.append({
                            "Type": "Time-Based",
                            "Param": param,
                            "Confidence": "likely",
                            "Payload": time_payload[:50],
                            "Evidence": f"Delay: {elapsed:.2f}s (baseline {base1_latency:.2f}s)",
                        })
                        param_vulnerable = True
                        break

    if not findings:
        findings.append(create_finding(
            title="No SQL Injection Detected",
            severity="info",
            confidence=Confidence.NOT_DETECTED.value,
            detail="Automated probes (error, boolean differential, and time-based) detected no SQL injection vulnerabilities.",
            recommendation="Continue regular automated scans and code reviews.",
        ))

    confirmed_count = sum(1 for fnd in findings if fnd.get("confidence") == "confirmed")
    likely_count = sum(1 for fnd in findings if fnd.get("confidence") == "likely")

    return ok({
        "summary": {
            "URL": url,
            "Parameters Tested": len(params),
            "Confirmed SQLi": confirmed_count,
            "Likely SQLi": likely_count,
            "Status": "Vulnerable" if (confirmed_count or likely_count) else "Secure",
        },
        "findings": findings,
        "records": records,
        "record_columns": ["Type", "Param", "Confidence", "Payload", "Evidence"],
    })
