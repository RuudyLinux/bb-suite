"""Prototype Pollution & Parameter Pollution (HPP) Scanner for BB-SUITE.

Audits client-side/Node.js prototype pollution via __proto__ and constructor.prototype,
and tests HTTP Parameter Pollution (HPP) parameter precedence safely using centralized HTTP client.
"""
from __future__ import annotations
import asyncio
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from fastapi import APIRouter
from pydantic import BaseModel, Field

from backend.security.confidence import (
    Confidence,
    Severity,
    create_finding,
    standard_response,
)
from backend.security.http_client import safe_request
from backend.security.target_validator import TargetValidationError, validate_target_url
from backend.tools.utils import clean_url, err, ok

router = APIRouter(tags=["scanning"])

PROTO_PAYLOADS = [
    {
        "name": "Object Prototype Query Assignment",
        "query": "__proto__[polluted_strix]=strix_test_val",
        "target_key": "polluted_strix",
        "target_val": "strix_test_val",
    },
    {
        "name": "Dot Notation Prototype Query",
        "query": "__proto__.polluted_strix=strix_test_val",
        "target_key": "polluted_strix",
        "target_val": "strix_test_val",
    },
    {
        "name": "Constructor Prototype Property Injection",
        "query": "constructor[prototype][polluted_strix]=strix_test_val",
        "target_key": "polluted_strix",
        "target_val": "strix_test_val",
    },
]

JSON_PROTO_PAYLOADS = [
    {"__proto__": {"polluted_strix": "strix_test_val", "admin": True}},
    {"constructor": {"prototype": {"polluted_strix": "strix_test_val"}}},
]


class ProtoRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    method: str = Field("ALL", max_length=16)


@router.post("/proto_pollution")
async def proto_pollution(req: ProtoRequest):
    url = clean_url(req.target)
    try:
        validate_target_url(url)
    except TargetValidationError as tve:
        return err(f"Target validation failed: {tve}")

    findings: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []
    vulnerable_vectors = []
    pocs = []

    # Baseline request
    baseline_status = 200
    baseline_body = ""
    try:
        base_resp = await safe_request("GET", url, timeout=8.0)
        baseline_status = base_resp.status_code
        baseline_body = base_resp.text
    except Exception as e:
        return err(f"Unable to reach target for baseline: {e}")

    # 1. Query String Prototype Pollution
    for item in PROTO_PAYLOADS:
        delim = '&' if '?' in url else '?'
        test_url = f"{url}{delim}{item['query']}"
        try:
            r = await safe_request("GET", test_url, timeout=7.0)
            status = r.status_code
            body = r.text

            is_vuln = False
            reason = ""

            if item["target_key"] in body and item["target_val"] in body:
                if item["target_key"] not in baseline_body:
                    is_vuln = True
                    reason = f"Response reflected injected prototype property '{item['target_key']}': '{item['target_val']}'"

            if re.search(r"TypeError:.*prototype|Cannot read properties of Object", body, re.IGNORECASE):
                is_vuln = True
                reason = "Server threw unhandled V8 JavaScript prototype error"

            anomaly = (status != baseline_status and status == 500)

            if is_vuln:
                vulnerable_vectors.append(item["name"])
                findings.append(create_finding(
                    title=f"Prototype Pollution Detected ({item['name']})",
                    severity="critical",
                    confidence=Confidence.CONFIRMED.value,
                    detail=f"Target modified object prototype via query parameter: {item['query']}. {reason}.",
                    recommendation="Freeze Object.prototype via Object.freeze(), validate incoming parameter keys, and use Object.create(null) for dictionary storage.",
                    evidence=f"Reflected key/val: {item['target_key']}={item['target_val']}",
                ))
                pocs.append(f"curl -s -k '{test_url}'")

            records.append({
                "Attack Category": "Query Prototype Pollution",
                "Vector": item["name"],
                "Injected Payload": item["query"],
                "HTTP Status": status,
                "Confidence": "confirmed" if is_vuln else "not_detected",
                "Result": "💀 VULNERABLE" if is_vuln else ("⚠ Server Error" if anomaly else "Safe / Filtered"),
            })

        except Exception as e:
            records.append({
                "Attack Category": "Query Prototype Pollution",
                "Vector": item["name"],
                "Injected Payload": item["query"],
                "HTTP Status": 0,
                "Confidence": "not_detected",
                "Result": f"Error ({str(e)[:25]})",
            })

    # 2. JSON Body Prototype Pollution
    if req.method.upper() in ("POST", "ALL"):
        for payload in JSON_PROTO_PAYLOADS:
            try:
                r_post = await safe_request("POST", url, json_data=payload, timeout=7.0)
                body_post = r_post.text
                status_post = r_post.status_code

                is_post_vuln = False
                if "polluted_strix" in body_post and "polluted_strix" not in baseline_body:
                    is_post_vuln = True

                if is_post_vuln:
                    findings.append(create_finding(
                        title="JSON Body Prototype Pollution (Confirmed)",
                        severity="critical",
                        confidence=Confidence.CONFIRMED.value,
                        detail="Server parsed JSON payload containing '__proto__' and modified runtime object attributes.",
                        recommendation="Use safe JSON parsers with prototype poisoning protection (e.g., secure-json-parse in Node.js).",
                    ))

                records.append({
                    "Attack Category": "JSON Body Prototype Pollution",
                    "Vector": "JSON __proto__ Injection",
                    "Injected Payload": str(payload)[:35],
                    "HTTP Status": status_post,
                    "Confidence": "confirmed" if is_post_vuln else "not_detected",
                    "Result": "💀 VULNERABLE" if is_post_vuln else "Safe / Rejected",
                })
            except Exception:
                pass

    # 3. HTTP Parameter Pollution (HPP) Test
    try:
        delim = '&' if '?' in url else '?'
        hpp_test_url = f"{url}{delim}hpp_test=first_val&hpp_test=second_val"
        r_hpp = await safe_request("GET", hpp_test_url, timeout=7.0)
        hpp_body = r_hpp.text

        precedence = "Unknown / Neither Reflected"
        if "first_val" in hpp_body and "second_val" in hpp_body:
            precedence = "Array / Concatenated (WAF Precedence Vector)"
            findings.append(create_finding(
                title="HTTP Parameter Pollution: Array Concatenation",
                severity="low",
                confidence=Confidence.CONFIRMED.value,
                detail="Server accepts duplicate parameters and concatenates both values. May assist in bypassing WAF query filtering.",
                recommendation="Configure application framework to strictly enforce single parameter occurrence.",
            ))
        elif "second_val" in hpp_body:
            precedence = "Last Parameter Wins"
        elif "first_val" in hpp_body:
            precedence = "First Parameter Wins"

        records.append({
            "Attack Category": "HTTP Parameter Pollution (HPP)",
            "Vector": "Duplicate Parameter Evaluation",
            "Injected Payload": "hpp_test=first_val&hpp_test=second_val",
            "HTTP Status": r_hpp.status_code,
            "Confidence": "confirmed",
            "Result": precedence,
        })
    except Exception:
        pass

    if not vulnerable_vectors:
        findings.append(create_finding(
            title="No Prototype Pollution Exploited",
            severity="info",
            confidence=Confidence.NOT_DETECTED.value,
            detail="Evaluated query and JSON prototype manipulation vectors without server-side modification.",
        ))

    summary = {
        "Target URL": url,
        "Vectors Tested": len(records),
        "Prototype Pollution Found": "CRITICAL YES" if vulnerable_vectors else "No",
        "HPP Evaluated": "Completed",
    }

    result = {
        "summary": summary,
        "findings": findings,
        "records": records,
        "record_columns": ["Attack Category", "Vector", "Injected Payload", "HTTP Status", "Confidence", "Result"],
    }
    if pocs:
        result["raw"] = "\n\n".join(pocs)

    return ok(result)
