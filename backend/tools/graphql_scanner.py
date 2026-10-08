"""
GraphQL Security Auditor — Deep GraphQL API reconnaissance & vulnerability auditor.
Tests Introspection disclosure, schema extraction, field suggestion leaks, and batch query DoS amplification.
Inspired by Strix protocols/graphql methodologies.
"""
from __future__ import annotations
import asyncio
import json
import re
from urllib.parse import urljoin
from typing import List, Dict, Any, Optional
import httpx
from fastapi import APIRouter
from pydantic import BaseModel
from tools.utils import clean_url, f, ok, err, HEADERS

router = APIRouter(tags=["scanning"])

GRAPHQL_ENDPOINTS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/gql",
    "/query",
    "/api/query",
    "/api/v1/graphql",
    "/graphql/console",
    "/graphiql"
]

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields {
        name
      }
    }
  }
}
"""

SENSITIVE_TYPE_PATTERNS = re.compile(
    r'user|auth|account|admin|password|credit|card|payment|token|secret|billing|session|order',
    re.I
)


class GraphqlRequest(BaseModel):
    target: str
    endpoint: str = ""  # If specified, tests directly; else probes common paths


@router.post("/graphql_scanner")
async def graphql_scanner(req: GraphqlRequest):
    base_url = clean_url(req.target)
    
    endpoints_to_probe = []
    if req.endpoint and req.endpoint.strip():
        endpoints_to_probe = [urljoin(base_url, req.endpoint.strip())]
    else:
        endpoints_to_probe = [urljoin(base_url, ep) for ep in GRAPHQL_ENDPOINTS]

    findings = []
    records = []
    active_endpoints = []
    discovered_schema = {}
    introspection_enabled = False
    field_suggestions_enabled = False
    batching_enabled = False

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=8) as client:
        # Step 1: Discover valid GraphQL endpoints
        async def probe_endpoint(ep_url: str):
            try:
                # Query simple __typename
                payload = {"query": "{ __typename }"}
                r = await client.post(ep_url, json=payload, headers={**HEADERS, "Content-Type": "application/json"})
                if r.status_code in (200, 400):
                    data = r.text
                    if "data" in data or "errors" in data or "GraphQL" in data or "syntax" in data.lower():
                        return ep_url, r.status_code
            except Exception:
                pass
            return None, 0

        probe_results = await asyncio.gather(*[probe_endpoint(ep) for ep in endpoints_to_probe])
        for ep, status in probe_results:
            if ep:
                active_endpoints.append(ep)

        if not active_endpoints:
            # Also test GET on base_url for GraphiQL
            try:
                get_r = await client.get(urljoin(base_url, "/graphql"), headers=HEADERS)
                if "GraphiQL" in get_r.text or "playground" in get_r.text.lower():
                    active_endpoints.append(urljoin(base_url, "/graphql"))
            except Exception:
                pass

        if not active_endpoints:
            return ok({
                "summary": {"Target URL": base_url, "Endpoints Tested": len(endpoints_to_probe), "GraphQL Detected": "No"},
                "findings": [f("info", "No GraphQL Endpoints Found", f"Audited {len(endpoints_to_probe)} standard paths without GraphQL response.")],
                "records": [],
                "record_columns": ["Endpoint", "Status", "Introspection", "Batching", "Sensitive Types Found"]
            })

        # Step 2: Audit each discovered GraphQL endpoint
        for ep_url in active_endpoints:
            ep_records = {
                "Endpoint": ep_url,
                "Status": "Active (HTTP 200)",
                "Introspection": "Disabled",
                "Batching": "Disabled",
                "Sensitive Types Found": "0"
            }

            # A. Introspection Test
            try:
                r_intro = await client.post(ep_url, json={"query": INTROSPECTION_QUERY}, headers={**HEADERS, "Content-Type": "application/json"})
                if r_intro.status_code == 200:
                    intro_json = r_intro.json()
                    schema = intro_json.get("data", {}).get("__schema")
                    if schema:
                        introspection_enabled = True
                        ep_records["Introspection"] = "✓ VULNERABLE (Enabled)"
                        types = schema.get("types", [])
                        custom_types = [t for t in types if not t.get("name", "").startswith("__")]

                        sensitive_types = [
                            t.get("name") for t in custom_types
                            if SENSITIVE_TYPE_PATTERNS.search(t.get("name", ""))
                        ]

                        discovered_schema[ep_url] = {
                            "queryType": schema.get("queryType", {}).get("name"),
                            "mutationType": schema.get("mutationType", {}).get("name"),
                            "total_types": len(custom_types),
                            "sensitive_types": sensitive_types,
                        }

                        ep_records["Sensitive Types Found"] = f"{len(sensitive_types)} ({', '.join(sensitive_types[:3])})"

                        findings.append(f(
                            "critical",
                            f"GraphQL Introspection Enabled ({ep_url})",
                            f"Full API schema exposed via Introspection. Found {len(custom_types)} types and {len(sensitive_types)} sensitive models ({', '.join(sensitive_types[:5])}).",
                            "Disable Introspection in production deployments (e.g., Apollo Server `introspection: false`)."
                        ))
            except Exception:
                pass

            # B. Field Suggestion Leakage Test (deliberate invalid field)
            try:
                typo_query = {"query": "{ testInvalidFieldXYZ99 }"}
                r_typo = await client.post(ep_url, json=typo_query, headers={**HEADERS, "Content-Type": "application/json"})
                resp_text = r_typo.text
                if "Did you mean" in resp_text or "did you mean" in resp_text.lower():
                    field_suggestions_enabled = True
                    findings.append(f(
                        "high",
                        f"GraphQL Field Suggestions Leaked ({ep_url})",
                        "Server suggests valid schema fields on invalid queries. Attackers can brute-force the entire schema even with introspection disabled.",
                        "Disable field suggestions in GraphQL production configuration (e.g. `validationRules`)."
                    ))
            except Exception:
                pass

            # C. Batch Query / Query Amplification (DoS) Test
            try:
                batch_payload = [{"query": "{ __typename }"}] * 25
                r_batch = await client.post(ep_url, json=batch_payload, headers={**HEADERS, "Content-Type": "application/json"})
                if r_batch.status_code == 200 and isinstance(r_batch.json(), list) and len(r_batch.json()) == 25:
                    batching_enabled = True
                    ep_records["Batching"] = "✓ VULNERABLE (25x Batch Allowed)"
                    findings.append(f(
                        "high",
                        f"GraphQL Batch Query Amplification Allowed ({ep_url})",
                        "Server processes 25+ operations bundled in a single HTTP request without rate-limiting. Enables brute-force attacks and application DoS.",
                        "Enforce query batch limits or disable batch queries entirely."
                    ))
            except Exception:
                pass

            records.append(ep_records)

    summary = {
        "Base URL": base_url,
        "Active Endpoints": len(active_endpoints),
        "Introspection Exposed": "CRITICAL YES" if introspection_enabled else "Disabled",
        "Field Suggestions Leaked": "YES" if field_suggestions_enabled else "No",
        "Batch Query DoS Risk": "YES" if batching_enabled else "No",
    }

    result = {
        "summary": summary,
        "findings": findings,
        "records": records,
        "record_columns": ["Endpoint", "Status", "Introspection", "Batching", "Sensitive Types Found"],
    }

    if discovered_schema:
        result["raw"] = json.dumps(discovered_schema, indent=2)

    return ok(result)
