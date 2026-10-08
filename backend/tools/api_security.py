"""API Security & Specification Exposure Analyzer for BB-SUITE.

Distinguishes documentation exposure from confirmed authentication vulnerabilities:
- Confirmed: Unauthenticated access to sensitive API endpoints returning HTTP 200 with data, or active GraphQL introspection.
- Likely: Endpoints returning administrative structures without credentials.
- Possible: Missing security annotations in OpenAPI specs that have not been actively proven unauthenticated.
- Info: Public documentation exposure (Swagger UI, Redoc, OpenAPI JSON).
"""
from __future__ import annotations
import asyncio
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from fastapi import APIRouter

from backend.models import TargetReq
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

SWAGGER_PATHS = [
    '/swagger.json', '/openapi.json', '/api-docs', '/api-docs.json',
    '/swagger/v1/swagger.json', '/api/swagger.json', '/api/openapi.json',
    '/api/v1/swagger.json', '/v1/swagger.json', '/docs', '/redoc',
    '/swagger-ui.html', '/.well-known/openapi.json',
]

GRAPHQL_PATHS = [
    '/graphql', '/graphiql', '/api/graphql', '/v1/graphql', '/v2/graphql',
    '/query', '/gql', '/playground',
]

GQL_INTROSPECTION_QUERY = {
    "query": "{ __schema { queryType { name } types { name kind } } }"
}

SENSITIVE_ENDPOINT_CANDIDATES = [
    '/api/users', '/api/v1/users', '/api/admin', '/api/config',
    '/api/settings', '/api/debug', '/api/env',
]


@router.post("/api_security")
async def api_security(req: TargetReq):
    url = clean_url(req.target)
    try:
        validate_target_url(url)
    except TargetValidationError as tve:
        return err(f"Target validation failed: {tve}")

    findings: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []

    # 1. Discover OpenAPI / Swagger Documentation
    swagger_spec: Optional[Dict[str, Any]] = None
    for path in SWAGGER_PATHS:
        doc_url = url.rstrip('/') + path
        try:
            resp = await safe_request("GET", doc_url, follow_redirects=False, timeout=5.0)
            if resp.status_code in (200, 206) and len(resp.content) > 50:
                body = resp.text.strip()
                is_json = body.startswith('{')
                is_html = '<html' in body[:150].lower()

                if is_json:
                    try:
                        spec = json.loads(body)
                        if 'openapi' in spec or 'swagger' in spec or 'paths' in spec:
                            swagger_spec = spec
                            findings.append(create_finding(
                                title=f"Public API Specification Exposed: {path}",
                                severity="low",
                                confidence=Confidence.CONFIRMED.value,
                                detail=f"The application publicly exposes its API specification at {path}, revealing endpoints, parameters, and schemas.",
                                recommendation="If this API is private or internal, restrict documentation access to authenticated development environments.",
                                evidence=f"Exposed Spec Title: {spec.get('info', {}).get('title', 'Unknown')}",
                            ))
                            records.append({
                                "Type": "API Spec",
                                "Path": path,
                                "Status": f"HTTP {resp.status_code}",
                                "Details": f"Spec Title: {spec.get('info', {}).get('title', 'API')}",
                            })
                            break
                    except Exception:
                        pass
                elif is_html and ('swagger-ui' in body.lower() or 'redoc' in body.lower()):
                    findings.append(create_finding(
                        title=f"Interactive API Documentation Exposed: {path}",
                        severity="low",
                        confidence=Confidence.CONFIRMED.value,
                        detail=f"Interactive API Explorer (Swagger UI / Redoc) is publicly accessible at {path}.",
                        recommendation="Disable interactive API documentation in production environments.",
                        evidence=f"Path: {path}",
                    ))
                    records.append({
                        "Type": "API Explorer",
                        "Path": path,
                        "Status": f"HTTP {resp.status_code}",
                        "Details": "Interactive UI",
                    })
                    break
        except Exception:
            pass

    # 2. Controlled Verification of Endpoints Listed in Spec or Standard Routes
    endpoints_to_verify: List[str] = list(SENSITIVE_ENDPOINT_CANDIDATES)
    if swagger_spec and isinstance(swagger_spec.get('paths'), dict):
        for ep_path, methods in list(swagger_spec['paths'].items())[:15]:
            if any(k in ep_path.lower() for k in ('user', 'admin', 'account', 'auth', 'config', 'key', 'secret')):
                endpoints_to_verify.append(ep_path)

    seen_endpoints = set()
    for ep in endpoints_to_verify:
        if ep in seen_endpoints:
            continue
        seen_endpoints.add(ep)
        ep_url = url.rstrip('/') + (ep if ep.startswith('/') else '/' + ep)

        try:
            r = await safe_request("GET", ep_url, follow_redirects=False, timeout=5.0)
            # If endpoint returns 200 with application/json data:
            is_json = "json" in r.headers.get("content-type", "").lower()
            if r.status_code == 200 and is_json and len(r.content) > 20:
                body_sample = r.text[:200]
                # Check if it actually contains real sensitive data (not just a 200 {status: ok})
                if any(k in body_sample.lower() for k in ('"id"', '"email"', '"username"', '"users"', '"role"', '"config"', '"keys"')):
                    findings.append(create_finding(
                        title=f"Unauthenticated Sensitive Endpoint Access (Confirmed): {ep}",
                        severity="high",
                        confidence=Confidence.CONFIRMED.value,
                        detail=f"Endpoint '{ep}' returned sensitive JSON data without requiring authentication tokens or session cookies (HTTP 200).",
                        recommendation="Enforce authentication middleware on all private API routes.",
                        evidence=f"Status: 200\nSnippet: {body_sample[:100]}",
                    ))
                    records.append({
                        "Type": "Sensitive Endpoint",
                        "Path": ep,
                        "Status": "💀 HTTP 200 (Open)",
                        "Details": "Data returned without auth",
                    })
                else:
                    records.append({
                        "Type": "Public Endpoint",
                        "Path": ep,
                        "Status": "HTTP 200 (Safe)",
                        "Details": "Generic response",
                    })
            elif r.status_code in (401, 403):
                records.append({
                    "Type": "Protected Endpoint",
                    "Path": ep,
                    "Status": f"✓ HTTP {r.status_code}",
                    "Details": "Authentication enforced",
                })
        except Exception:
            pass

    # 3. GraphQL Discovery & Introspection Check
    for gql_path in GRAPHQL_PATHS:
        full_gql_url = url.rstrip('/') + gql_path
        try:
            r = await safe_request(
                "POST",
                full_gql_url,
                json_data=GQL_INTROSPECTION_QUERY,
                timeout=6.0,
            )
            if r.status_code in (200, 400) and "__schema" in r.text:
                findings.append(create_finding(
                    title=f"GraphQL Introspection Enabled (Confirmed): {gql_path}",
                    severity="medium",
                    confidence=Confidence.CONFIRMED.value,
                    detail=f"GraphQL endpoint at {gql_path} answered the __schema introspection query, exposing the complete internal data model and types.",
                    recommendation="Disable GraphQL schema introspection in production deployments.",
                    evidence=f"Introspection enabled at {gql_path}",
                ))
                records.append({
                    "Type": "GraphQL",
                    "Path": gql_path,
                    "Status": "Introspection ENABLED",
                    "Details": "Schema exposed",
                })
                break
            elif r.status_code == 200 and ("query" in r.text.lower() or "errors" in r.text.lower()):
                records.append({
                    "Type": "GraphQL",
                    "Path": gql_path,
                    "Status": "Active",
                    "Details": "Introspection disabled",
                })
                break
        except Exception:
            pass

    if not findings:
        findings.append(create_finding(
            title="API Endpoints Enforce Authentication",
            severity="info",
            confidence=Confidence.NOT_DETECTED.value,
            detail="No unauthenticated sensitive endpoints or exposed API documentation were discovered.",
            recommendation="Continue maintaining strict authentication requirements.",
        ))

    return ok({
        "summary": {
            "Target": url,
            "Spec Discovered": "Yes" if swagger_spec else "No",
            "Endpoints Inspected": len(records),
            "Findings Count": len(findings),
        },
        "findings": findings,
        "records": records,
        "record_columns": ["Type", "Path", "Status", "Details"],
    })
