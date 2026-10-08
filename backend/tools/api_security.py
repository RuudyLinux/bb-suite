from __future__ import annotations
import asyncio
import json
import re
from fastapi import APIRouter
from models import TargetReq
from tools.utils import clean_url, http_get, f, ok, err

router = APIRouter(tags=["scanning"])

SWAGGER_PATHS = [
    '/swagger.json', '/swagger.yaml', '/openapi.json', '/openapi.yaml',
    '/api-docs', '/api-docs.json', '/api-docs.yaml',
    '/swagger/v1/swagger.json', '/swagger/v2/swagger.json',
    '/api/swagger.json', '/api/openapi.json', '/api/v1/swagger.json',
    '/v1/swagger.json', '/v2/swagger.json', '/v3/swagger.json',
    '/docs', '/redoc', '/swagger-ui.html',
    '/.well-known/openapi.json', '/api-explorer',
    '/swagger-resources', '/v2/api-docs', '/v3/api-docs',
]

GRAPHQL_PATHS = [
    '/graphql', '/graphiql', '/api/graphql', '/v1/graphql', '/v2/graphql',
    '/query', '/gql', '/playground', '/graphql/console',
    '/api/v1/graphql', '/api/v2/graphql',
]

GQL_INTROSPECTION = json.dumps({
    "query": "{ __schema { queryType { name } types { name kind } } }"
})

GQL_SIMPLE = json.dumps({"query": "{ __typename }"})

REST_TEST_PATHS = [
    '/api/users', '/api/v1/users', '/api/v2/users',
    '/api/admin', '/api/config', '/api/settings',
    '/api/debug', '/api/env', '/api/health',
    '/api/version', '/api/status', '/api/info',
]


async def check_graphql(base_url: str, path: str) -> dict | None:
    url = base_url.rstrip('/') + path
    r = await http_get(url, method='POST', json={'query': '{ __typename }'},
                       headers={'Content-Type': 'application/json'}, timeout=6)
    if r['status'] in [200, 400]:
        try:
            d = json.loads(r['body'])
            if 'data' in d or 'errors' in d:
                # Try introspection
                ri = await http_get(url, method='POST', json=json.loads(GQL_INTROSPECTION),
                                    headers={'Content-Type': 'application/json'}, timeout=8)
                intro_enabled = '__schema' in ri.get('body', '')
                return {'url': url, 'status': r['status'], 'introspection': intro_enabled}
        except Exception:
            pass
    # GET check for graphiql
    rg = await http_get(url, timeout=5)
    if rg['status'] == 200 and 'graphi' in rg['body'].lower():
        return {'url': url, 'status': 200, 'introspection': True}
    return None


@router.post("/api_security")
async def api_security(req: TargetReq):
    url = clean_url(req.target)
    findings = []
    records  = []
    swagger_found = None
    graphql_found = []

    # 1. Find Swagger / OpenAPI
    sem = asyncio.Semaphore(10)
    async def check_swagger(path: str):
        async with sem:
            target = url.rstrip('/') + path
            r = await http_get(target, timeout=5, follow_redirects=False)
            return path, r['status'], r['body']

    swagger_results = await asyncio.gather(*[check_swagger(p) for p in SWAGGER_PATHS])
    for path, code, body in swagger_results:
        if code not in [200, 206]:
            continue
        # Validate it looks like API spec
        is_json  = body.strip().startswith('{')
        is_yaml  = 'openapi:' in body[:200] or 'swagger:' in body[:200]
        is_html  = '<html' in body[:200].lower()
        if not (is_json or is_yaml or is_html):
            continue

        records.append({'Type': 'OpenAPI Spec', 'Path': path, 'Status': code,
                         'Format': 'JSON' if is_json else 'YAML' if is_yaml else 'HTML'})
        findings.append(f('medium', f'API Documentation Found: {path}',
                           f'OpenAPI/Swagger spec exposed at {url}{path}',
                           'Restrict API docs to authenticated/internal users only'))

        if is_json and not swagger_found:
            try:
                spec = json.loads(body)
                swagger_found = spec

                # Extract endpoints from spec
                paths_obj = spec.get('paths', {})
                findings.append(f('info', f'{len(paths_obj)} API Endpoints in Spec',
                                   'Spec exposes full API surface',
                                   'Review each endpoint for auth and input validation'))
                for ep, methods in list(paths_obj.items())[:20]:
                    for method in methods:
                        if method.lower() in ['get','post','put','delete','patch']:
                            ep_info = methods[method]
                            requires_auth = bool(ep_info.get('security') or spec.get('security'))
                            records.append({
                                'Type': 'API Endpoint',
                                'Path': f'{method.upper()} {ep}',
                                'Status': 'Auth Required' if requires_auth else '⚠ No Auth Spec',
                                'Format': ep_info.get('summary', '')[:60],
                            })
                            if not requires_auth:
                                findings.append(f('high', f'Endpoint Missing Auth: {method.upper()} {ep}',
                                                   'No security scheme specified in OpenAPI spec',
                                                   'Add authentication requirement to endpoint'))
            except Exception:
                pass
        break  # Found one swagger, enough

    # 2. GraphQL discovery
    gql_checks = await asyncio.gather(*[check_graphql(url, path) for path in GRAPHQL_PATHS])
    for res in gql_checks:
        if res:
            graphql_found.append(res)
            records.append({'Type': 'GraphQL', 'Path': res['url'],
                             'Status': res['status'],
                             'Format': 'Introspection: ' + ('ENABLED' if res['introspection'] else 'Disabled')})
            if res['introspection']:
                findings.append(f('high', f'GraphQL Introspection Enabled: {res["url"]}',
                                   'Full schema exposed — attacker can map entire API',
                                   'Disable introspection in production'))
            else:
                findings.append(f('medium', f'GraphQL Endpoint Found: {res["url"]}',
                                   'GraphQL available — test for batch queries, field suggestions',
                                   'Disable introspection and limit query depth/complexity'))

    # 3. REST API probing
    async def probe_rest(path: str):
        async with sem:
            target = url.rstrip('/') + path
            r = await http_get(target, timeout=5)
            return path, r['status'], r['body'][:200] if r['body'] else ''

    rest_results = await asyncio.gather(*[probe_rest(p) for p in REST_TEST_PATHS])
    for path, code, preview in rest_results:
        if code in [200, 201]:
            is_json = preview.strip().startswith('{') or preview.strip().startswith('[')
            if is_json:
                findings.append(f('high', f'API Endpoint Accessible Without Auth: {path}',
                                   f'HTTP {code} — returns JSON data without authentication',
                                   'Add authentication/authorization to this endpoint'))
                records.append({'Type': 'REST Endpoint', 'Path': path, 'Status': code,
                                 'Format': 'JSON (no auth)'})
        elif code == 401:
            records.append({'Type': 'REST Endpoint', 'Path': path, 'Status': code, 'Format': 'Auth required'})
        elif code == 403:
            records.append({'Type': 'REST Endpoint', 'Path': path, 'Status': code, 'Format': 'Forbidden'})

    # 4. Check rate limiting on API
    rl_url = url.rstrip('/') + '/api/'
    tasks = [http_get(rl_url, timeout=3) for _ in range(5)]
    rl_results = await asyncio.gather(*tasks)
    has_rl = any(r['status'] == 429 for r in rl_results)
    if has_rl:
        findings.append(f('pass', 'API Rate Limiting Active', 'API returns 429 on rapid requests', ''))
    else:
        findings.append(f('medium', 'No API Rate Limiting Detected',
                           '5 rapid requests returned no 429 — rate limiting may be absent',
                           'Implement rate limiting on all API endpoints'))

    if not swagger_found and not graphql_found:
        findings.append(f('pass', 'No Public API Documentation Found',
                           'Swagger/OpenAPI docs not exposed at standard paths', ''))

    return ok({
        'summary': {
            'Target':          url,
            'Swagger Found':   'YES' if swagger_found else 'No',
            'GraphQL Found':   len(graphql_found),
            'Endpoints Found': len(records),
            'Rate Limiting':   'YES' if has_rl else 'No',
        },
        'findings':       findings,
        'records':        records,
        'record_columns': ['Type', 'Path', 'Status', 'Format'],
    })
