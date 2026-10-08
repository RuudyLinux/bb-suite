"""
Prototype Pollution & Parameter Pollution (HPP) Scanner.
Tests client-side/Node.js prototype pollution via __proto__ and constructor.prototype,
and audits HTTP Parameter Pollution (HPP) parameter precedence.
Inspired by Strix prototype_pollution.md & semantic_confusion.md playbooks.
"""
from __future__ import annotations
import asyncio
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any, Optional
import httpx
from fastapi import APIRouter
from pydantic import BaseModel
from tools.utils import clean_url, f, ok, err, HEADERS

router = APIRouter(tags=["scanning"])

PROTO_PAYLOADS = [
    {
        "name": "Object Prototype Query Assignment",
        "query": "__proto__[polluted_strix]=strix_test_val",
        "target_key": "polluted_strix",
        "target_val": "strix_test_val"
    },
    {
        "name": "Dot Notation Prototype Query",
        "query": "__proto__.polluted_strix=strix_test_val",
        "target_key": "polluted_strix",
        "target_val": "strix_test_val"
    },
    {
        "name": "Constructor Prototype Property Injection",
        "query": "constructor[prototype][polluted_strix]=strix_test_val",
        "target_key": "polluted_strix",
        "target_val": "strix_test_val"
    },
    {
        "name": "Admin Privilege Escalation Probe",
        "query": "__proto__[admin]=true&__proto__[isAdmin]=true",
        "target_key": "admin",
        "target_val": "true"
    },
]

JSON_PROTO_PAYLOADS = [
    {"__proto__": {"polluted_strix": "strix_test_val", "admin": True}},
    {"constructor": {"prototype": {"polluted_strix": "strix_test_val"}}},
]


class ProtoRequest(BaseModel):
    target: str
    method: str = "ALL"  # GET | POST | ALL


@router.post("/proto_pollution")
async def proto_pollution(req: ProtoRequest):
    url = clean_url(req.target)
    parsed = urlparse(url)

    findings = []
    records = []
    vulnerable_vectors = []
    pocs = []

    # Step 1: Capture baseline response
    baseline_status = 200
    baseline_body = ""
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8) as c:
            base_r = await c.get(url, headers=HEADERS)
            baseline_status = base_r.status_code
            baseline_body = base_r.text
    except Exception as e:
        return err(f"Unable to reach target: {str(e)}")

    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=8) as client:
        # 1. Test Query String Prototype Pollution
        for item in PROTO_PAYLOADS:
            test_url = f"{url}{'&' if '?' in url else '?'}{item['query']}"
            try:
                r = await client.get(test_url, headers=HEADERS)
                status = r.status_code
                body = r.text

                is_vuln = False
                reason = ""

                # Check if injected prototype property is reflected in JSON response or body
                if item["target_key"] in body and item["target_val"] in body:
                    if item["target_key"] not in baseline_body:
                        is_vuln = True
                        reason = f"Response reflected injected prototype property '{item['target_key']}': '{item['target_val']}'"

                # Check for Node.js / V8 prototype mutation exceptions
                if re.search(r"TypeError:.*prototype|Cannot read properties of Object", body, re.I):
                    is_vuln = True
                    reason = "Server threw unhandled V8 JavaScript prototype error"

                # Check status code anomaly
                anomaly = (status != baseline_status and status == 500)

                if is_vuln:
                    vulnerable_vectors.append(item["name"])
                    findings.append(f(
                        "critical",
                        f"Prototype Pollution Detected ({item['name']})",
                        f"Target modified object prototype via query parameter: {item['query']}. {reason}.",
                        "Freeze Object.prototype (Object.freeze), validate incoming parameter keys, and use Object.create(null) for dictionary lookups."
                    ))
                    pocs.append(f"# Prototype Pollution PoC:\ncurl -s -k '{test_url}'")

                records.append({
                    "Attack Category": "Query Prototype Pollution",
                    "Vector": item["name"],
                    "Injected Payload": item["query"],
                    "HTTP Status": status,
                    "Result": "💀 VULNERABLE" if is_vuln else ("⚠ Server Error" if anomaly else "Safe / Filtered")
                })

            except Exception as e:
                records.append({
                    "Attack Category": "Query Prototype Pollution",
                    "Vector": item["name"],
                    "Injected Payload": item["query"],
                    "HTTP Status": 0,
                    "Result": f"Error ({str(e)[:25]})"
                })

        # 2. Test JSON POST Body Prototype Pollution
        if req.method.upper() in ("POST", "ALL"):
            for payload in JSON_PROTO_PAYLOADS:
                try:
                    r_post = await client.post(url, json=payload, headers={**HEADERS, "Content-Type": "application/json"})
                    body_post = r_post.text
                    status_post = r_post.status_code

                    is_post_vuln = False
                    if "polluted_strix" in body_post and "polluted_strix" not in baseline_body:
                        is_post_vuln = True

                    if is_post_vuln:
                        findings.append(f(
                            "critical",
                            "JSON Body Prototype Pollution",
                            "Server parsed JSON payload containing '__proto__' and modified runtime object attributes.",
                            "Use safe JSON parsers with prototype poisoning protection (e.g., secure-json-parse in Node.js)."
                        ))

                    records.append({
                        "Attack Category": "JSON Body Prototype Pollution",
                        "Vector": "JSON __proto__ Injection",
                        "Injected Payload": str(payload)[:35],
                        "HTTP Status": status_post,
                        "Result": "💀 VULNERABLE" if is_post_vuln else "Safe / Rejected"
                    })
                except Exception:
                    pass

        # 3. HTTP Parameter Pollution (HPP) Test
        try:
            hpp_test_url = f"{url}{'&' if '?' in url else '?'}hpp_test=first_val&hpp_test=second_val"
            r_hpp = await client.get(hpp_test_url, headers=HEADERS)
            hpp_body = r_hpp.text

            precedence = "Unknown / Neither Reflected"
            if "first_val" in hpp_body and "second_val" in hpp_body:
                precedence = "Array / Concatenated (Vulnerable to WAF Bypass)"
                findings.append(f(
                    "medium",
                    "HTTP Parameter Pollution: Array Concatenation",
                    "Server accepts duplicate parameters and concatenates both values. Common vector for bypassing Web Application Firewalls (WAF) and input validation.",
                    "Configure application framework to strictly enforce single parameter occurrence."
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
                "Result": precedence
            })

        except Exception:
            pass

    if not vulnerable_vectors:
        findings.append(f(
            "pass",
            "No Prototype Pollution Vectors Exploited",
            "Evaluated query and JSON prototype manipulation vectors without server-side modification."
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
        "record_columns": ["Attack Category", "Vector", "Injected Payload", "HTTP Status", "Result"],
    }

    if pocs:
        result["raw"] = "\n\n".join(pocs)

    return ok(result)
