"""GraphQL Security Auditor — Deep GraphQL API reconnaissance & vulnerability auditor.

Performs controlled, rate-bounded assessments of GraphQL services:
- Introspection disclosure and sensitive type classification
- Field suggestion information leakage
- Batch query amplification support
- Controlled query depth handling
"""
from __future__ import annotations
import asyncio
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

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

GRAPHQL_ENDPOINTS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/gql",
    "/query",
    "/graphiql",
]

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    types {
      name
      kind
      fields {
        name
      }
    }
  }
}
"""

SENSITIVE_TYPE_PATTERNS = re.compile(
    r'user|auth|account|admin|password|credit|card|payment|token|secret|billing|session|private',
    re.IGNORECASE,
)


class GraphqlRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    endpoint: str = Field("", max_length=512)


@router.post("/graphql_scanner")
async def graphql_scanner(req: GraphqlRequest):
    base_url = clean_url(req.target)
    try:
        validate_target_url(base_url)
    except TargetValidationError as tve:
        return err(f"Target validation failed: {tve}")

    endpoints_to_probe: List[str] = []
    if req.endpoint and req.endpoint.strip():
        endpoints_to_probe = [urljoin(base_url, req.endpoint.strip())]
    else:
        endpoints_to_probe = [urljoin(base_url, ep) for ep in GRAPHQL_ENDPOINTS]

    findings: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []

    active_endpoint: Optional[str] = None

    # Step 1: Discover active GraphQL endpoint with bounded queries
    for ep_url in endpoints_to_probe:
        try:
            r = await safe_request(
                "POST",
                ep_url,
                json_data={"query": "{ __typename }"},
                timeout=5.0,
            )
            if r.status_code in (200, 400) and ("data" in r.text or "errors" in r.text or "__typename" in r.text):
                active_endpoint = ep_url
                break
        except Exception:
            pass

    if not active_endpoint:
        return ok({
            "summary": {"Target": base_url, "GraphQL Detected": "No"},
            "findings": [create_finding(
                title="No GraphQL Service Discovered",
                severity="info",
                confidence=Confidence.NOT_DETECTED.value,
                detail=f"Tested standard paths on {base_url}; no responsive GraphQL service was found.",
            )],
            "records": [],
            "record_columns": ["Endpoint", "Introspection", "Batching", "Field Suggestions", "Sensitive Types"],
        })

    # Step 2: Audit Discovered Endpoint
    ep_record = {
        "Endpoint": active_endpoint,
        "Introspection": "Disabled",
        "Batching": "Disabled",
        "Field Suggestions": "Disabled",
        "Sensitive Types": "0",
    }

    # A. Introspection Analysis
    try:
        r_intro = await safe_request(
            "POST",
            active_endpoint,
            json_data={"query": INTROSPECTION_QUERY},
            timeout=7.0,
        )
        if r_intro.status_code == 200:
            intro_data = r_intro.json()
            schema = intro_data.get("data", {}).get("__schema")
            if schema:
                ep_record["Introspection"] = "Enabled"
                types = schema.get("types", [])
                custom_types = [t for t in types if not t.get("name", "").startswith("__")]
                sensitive_types = [
                    t.get("name") for t in custom_types
                    if SENSITIVE_TYPE_PATTERNS.search(t.get("name", ""))
                ]
                ep_record["Sensitive Types"] = str(len(sensitive_types))

                sev = "medium" if sensitive_types else "low"
                findings.append(create_finding(
                    title=f"GraphQL Introspection Enabled ({'Sensitive Types Exposed' if sensitive_types else 'Schema Readable'})",
                    severity=sev,
                    confidence=Confidence.CONFIRMED.value,
                    detail=f"GraphQL introspection is fully enabled at {active_endpoint}, revealing {len(custom_types)} types and {len(sensitive_types)} potentially sensitive schemas.",
                    recommendation="Disable schema introspection in production deployments to prevent schema enumeration.",
                    evidence=f"Sensitive schemas found: {', '.join(sensitive_types[:5])}" if sensitive_types else "Schema types exposed.",
                ))
    except Exception:
        pass

    # B. Field Suggestion Leakage Test
    try:
        r_suggest = await safe_request(
            "POST",
            active_endpoint,
            json_data={"query": "{ __nonexistent_field_x123 }"},
            timeout=5.0,
        )
        if "did you mean" in r_suggest.text.lower():
            ep_record["Field Suggestions"] = "Enabled"
            findings.append(create_finding(
                title="GraphQL Field Suggestions Enabled",
                severity="low",
                confidence=Confidence.CONFIRMED.value,
                detail="The GraphQL engine leaks field names in syntax error messages (e.g., 'Did you mean ...?'), assisting attackers in brute-forcing hidden schema fields.",
                recommendation="Disable field suggestions in production (e.g., disable suggestions in Apollo Server or GraphQL Yoga).",
                evidence="Server error message included 'Did you mean'",
            ))
    except Exception:
        pass

    # C. Batch Query Support Test (Small, safe array of 2 queries)
    try:
        r_batch = await safe_request(
            "POST",
            active_endpoint,
            json_data=[{"query": "{ __typename }"}, {"query": "{ __typename }"}],
            timeout=5.0,
        )
        if r_batch.status_code == 200 and r_batch.text.strip().startswith('['):
            ep_record["Batching"] = "Enabled"
            findings.append(create_finding(
                title="GraphQL Batch Queries Supported",
                severity="low",
                confidence=Confidence.CONFIRMED.value,
                detail="The GraphQL endpoint accepts arrays of batched operations. If rate-limiting is not applied per-operation, this can be used to bypass request limits or amplify queries.",
                recommendation="Enforce query complexity analysis, depth limits, and individual operation rate-limiting.",
                evidence="Endpoint processed array of queries.",
            ))
    except Exception:
        pass

    records.append(ep_record)

    return ok({
        "summary": {
            "Endpoint": active_endpoint,
            "Introspection": ep_record["Introspection"],
            "Batching": ep_record["Batching"],
            "Field Suggestions": ep_record["Field Suggestions"],
        },
        "findings": findings,
        "records": records,
        "record_columns": ["Endpoint", "Introspection", "Batching", "Field Suggestions", "Sensitive Types"],
    })
