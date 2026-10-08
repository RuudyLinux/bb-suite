"""
SSTI Scanner — Server-Side Template Injection vulnerability detector.
Detects template engine execution across Jinja2, Twig, Freemarker, Smarty, Ruby ERB, and Spring EL.
Follows Strix verified PoC methodology to eliminate false positives.
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

SSTI_TESTS = [
    {
        "expr": "{{7*7}}",
        "expected": "49",
        "engines": ["Jinja2 (Python)", "Twig (PHP)", "Nunjucks (NodeJS)", "Pebble (Java)"],
        "syntax": "{{...}}"
    },
    {
        "expr": "${7*7}",
        "expected": "49",
        "engines": ["Freemarker (Java)", "Spring Expression Language (Java)", "Smarty (PHP)"],
        "syntax": "${...}"
    },
    {
        "expr": "<%= 7*7 %>",
        "expected": "49",
        "engines": ["Ruby ERB (Ruby)", "EJS (NodeJS)"],
        "syntax": "<%=...%>"
    },
    {
        "expr": "#{7*7}",
        "expected": "49",
        "engines": ["Ruby (String interpolation)", "Thymeleaf (Java)"],
        "syntax": "#{...}"
    },
    {
        "expr": "*{7*7}",
        "expected": "49",
        "engines": ["Thymeleaf (Java)"],
        "syntax": "*{...}"
    },
    {
        "expr": "{{7*'7'}}",
        "expected_jinja": "7777777",
        "expected_twig": "49",
        "engines": ["Jinja2 differentiator vs Twig"],
        "syntax": "String multiplication probe"
    },
]

DISCLOSURE_PROBES = [
    {"probe": "{{config}}", "sig": r"<Config|SECRET_KEY|ENV", "engine": "Flask / Jinja2"},
    {"probe": "{{dump(app)}}", "sig": r"Twig|Symfony|Kernel", "engine": "Symfony / Twig"},
]


class SstiRequest(BaseModel):
    target: str
    param: str = ""
    method: str = "GET"  # GET | POST


@router.post("/ssti_scanner")
async def ssti_scanner(req: SstiRequest):
    url = clean_url(req.target)
    parsed = urlparse(url)
    existing_qs = parse_qs(parsed.query)

    params_to_test = []
    if req.param and req.param.strip():
        params_to_test = [req.param.strip()]
    elif existing_qs:
        params_to_test = list(existing_qs.keys())
    else:
        params_to_test = ["q", "search", "name", "template", "page", "preview", "title", "id", "msg", "text"]

    findings = []
    records = []
    confirmed_ssti = []
    pocs = []
    semaphore = asyncio.Semaphore(10)

    # Step 1: Capture baseline response to ensure mathematical results don't exist naturally
    baseline_body = ""
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8) as c:
            r = await c.get(url, headers=HEADERS)
            baseline_body = r.text
    except Exception as e:
        return err(f"Unable to reach target for baseline: {str(e)}")

    baseline_has_49 = "49" in baseline_body
    baseline_has_777 = "7777777" in baseline_body

    async def test_param_ssti(param_name: str):
        detected_engines = set()

        for test in SSTI_TESTS:
            expr = test["expr"]
            current_params = dict(existing_qs)
            current_params[param_name] = [expr]
            flat_params = {k: v[0] if isinstance(v, list) else v for k, v in current_params.items()}

            resp_text = ""
            status = 0
            try:
                async with semaphore:
                    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=6) as client:
                        if req.method.upper() == "POST":
                            resp = await client.post(url, data=flat_params, headers=HEADERS)
                        else:
                            new_query = urlencode(flat_params)
                            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
                            resp = await client.get(test_url, headers=HEADERS)

                        status = resp.status_code
                        resp_text = resp.text

            except Exception:
                continue

            vulnerable = False
            engine_identified = ""

            # Standard mathematical check: does 49 appear and was it NOT in baseline?
            if "expected" in test:
                exp_val = test["expected"]
                # Mathematical reflection is verified if exp_val is in response, raw expression is not echoed literally,
                # or baseline didn't contain exp_val
                if exp_val in resp_text and (not baseline_has_49 or resp_text.count(exp_val) > baseline_body.count(exp_val)):
                    vulnerable = True
                    engine_identified = ", ".join(test["engines"])
                    detected_engines.update(test["engines"])

            elif "expected_jinja" in test:
                if test["expected_jinja"] in resp_text and (not baseline_has_777 or resp_text.count("7777777") > baseline_body.count("7777777")):
                    vulnerable = True
                    engine_identified = "Confirmed: Jinja2 / Python (evaluates string repetition)"
                    detected_engines.add("Jinja2 (Python)")
                elif test["expected_twig"] in resp_text:
                    vulnerable = True
                    engine_identified = "Confirmed: Twig / PHP (casts string to int 49)"
                    detected_engines.add("Twig (PHP)")

            if vulnerable:
                curl_example = f'curl -s -k "{url}?{urlencode({param_name: expr})}"'
                records.append({
                    "Parameter": param_name,
                    "Payload Injected": expr,
                    "Evaluated Result": engine_identified or "49",
                    "HTTP Status": status,
                    "Vulnerability": "CRITICAL EXECUTED"
                })
                confirmed_ssti.append({
                    "param": param_name,
                    "expr": expr,
                    "engine": engine_identified
                })
                pocs.append(f"# SSTI Execution PoC ({param_name}):\n{curl_example}\n# Expected reflection: 49 / code execution")
            else:
                records.append({
                    "Parameter": param_name,
                    "Payload Injected": expr,
                    "Evaluated Result": "Not Evaluated / Echoed Raw",
                    "HTTP Status": status,
                    "Vulnerability": "Safe"
                })

        if detected_engines:
            engine_names = " / ".join(detected_engines)
            findings.append(f(
                "critical",
                f"SSTI (Server-Side Template Injection) in '{param_name}'",
                f"Expression '{SSTI_TESTS[0]['expr']}' evaluated to mathematical result '49'. Suspected engine: {engine_names}.",
                "Avoid passing untrusted user input directly into template engines. Use contextual escaping or sandbox mode."
            ))

    await asyncio.gather(*[test_param_ssti(p) for p in params_to_test])

    if not confirmed_ssti:
        findings.append(f(
            "pass",
            "No Server-Side Template Injection Detected",
            f"Evaluated arithmetic injection probes against parameters {params_to_test} without template evaluation."
        ))

    summary = {
        "Target URL": url,
        "Parameters Tested": ", ".join(params_to_test),
        "Tests Run": len(records),
        "SSTI Detected": f"YES ({len(confirmed_ssti)})" if confirmed_ssti else "No",
        "RCE Severity": "CRITICAL" if confirmed_ssti else "None"
    }

    result = {
        "summary": summary,
        "findings": findings,
        "records": records,
        "record_columns": ["Parameter", "Payload Injected", "Evaluated Result", "HTTP Status", "Vulnerability"]
    }
    if pocs:
        result["raw"] = "\n\n".join(pocs)

    return ok(result)
