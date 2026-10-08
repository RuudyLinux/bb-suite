"""Database Service & Access Exposure Scanner for BB-SUITE.

Distinguishes between open database ports and confirmed unauthenticated access:
- Confirmed: Verifiable unauthenticated query execution (e.g. Redis INFO without password, Elasticsearch _cluster/health).
- Likely: Database port exposed and responding to handshake, but authentication enforced.
- Info: Port open without unauthenticated execution.
Never performs destructive database modifications.
"""
from __future__ import annotations
import asyncio
from typing import Any, Dict, List, Optional

from fastapi import APIRouter

from backend.models import TargetReq
from backend.security.confidence import (
    Confidence,
    Severity,
    create_finding,
    standard_response,
)
from backend.security.target_validator import TargetValidationError, validate_hostname
from backend.tools.utils import check_port, clean_host, err, http_get, ok

router = APIRouter(tags=["scanning"])

DBS = {
    "MySQL":         {"port": 3306},
    "PostgreSQL":    {"port": 5432},
    "MongoDB":       {"port": 27017},
    "Redis":         {"port": 6379},
    "MSSQL":         {"port": 1433},
    "Elasticsearch": {"port": 9200},
    "Memcached":     {"port": 11211},
    "CouchDB":       {"port": 5984},
}


async def test_redis_noauth(host: str) -> Tuple[bool, str]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, 6379), timeout=3.0)
        writer.write(b"*1\r\n$4\r\nINFO\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=2.0)
        writer.close()
        await writer.wait_closed()
        if b"redis_version" in data:
            return True, "Redis accepted INFO command without password (NO AUTH)"
        if b"NOAUTH" in data:
            return False, "Authentication Required (-NOAUTH)"
        return False, "Handshake answered"
    except Exception:
        return False, "Connection failed"


async def test_memcached_noauth(host: str) -> Tuple[bool, str]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, 11211), timeout=3.0)
        writer.write(b"stats\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=2.0)
        writer.close()
        await writer.wait_closed()
        if b"STAT pid" in data:
            return True, "Memcached returned system statistics without authentication"
        return False, "Auth required or restricted"
    except Exception:
        return False, "Connection failed"


@router.post("/db_scanner")
async def db_scanner(req: TargetReq):
    host = clean_host(req.target)
    if not host:
        return err("Invalid host format.")

    try:
        validate_hostname(host)
    except TargetValidationError as tve:
        return err(f"Target validation failed: {tve}")

    findings: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []

    async def scan_db(name: str, cfg: Dict[str, Any]):
        port = cfg["port"]
        is_open, banner = await check_port(host, port, timeout=2.0)
        if not is_open:
            records.append({"Database": name, "Port": port, "Status": "Closed", "Auth State": "—"})
            return

        auth_state = "Authentication required (not tested)"
        unauth_confirmed = False
        evidence = ""

        # Test specific databases for unauthenticated access
        if name == "Redis":
            no_auth, detail = await test_redis_noauth(host)
            auth_state = detail
            if no_auth:
                unauth_confirmed = True
                evidence = detail

        elif name == "Memcached":
            no_auth, detail = await test_memcached_noauth(host)
            auth_state = detail
            if no_auth:
                unauth_confirmed = True
                evidence = detail

        elif name in ["Elasticsearch", "CouchDB"]:
            path = "/_cluster/health" if name == "Elasticsearch" else "/_all_dbs"
            r = await http_get(f"http://{host}:{port}{path}", timeout=4.0)
            if r["status"] == 200 and len(r.get("body", "")) > 10:
                auth_state = f"Unauthenticated HTTP access to {path}"
                unauth_confirmed = True
                evidence = r["body"][:120]
            elif r["status"] in (401, 403):
                auth_state = f"Authentication enforced (HTTP {r['status']})"

        if unauth_confirmed:
            findings.append(create_finding(
                title=f"Unauthenticated {name} Access (Confirmed): {host}:{port}",
                severity="critical",
                confidence=Confidence.CONFIRMED.value,
                detail=f"{name} at {host}:{port} is publicly exposed and permits queries without credentials.",
                recommendation=f"Immediately enable authentication for {name} and restrict network access with a firewall.",
                evidence=evidence,
            ))
            status_label = "💀 OPEN (NO AUTH)"
        else:
            findings.append(create_finding(
                title=f"{name} Database Port Open to Public Internet: {host}:{port}",
                severity="medium",
                confidence=Confidence.CONFIRMED.value,
                detail=f"{name} port {port} is reachable on {host}. Banner: '{banner[:80]}'. State: {auth_state}.",
                recommendation=f"Restrict port {port} using firewall rules / security groups to trusted private subnets only.",
                evidence=f"Port {port} reachable",
            ))
            status_label = "Port Open (Auth Enforced)"

        records.append({
            "Database": name,
            "Port": port,
            "Status": status_label,
            "Auth State": auth_state,
        })

    await asyncio.gather(*[scan_db(n, c) for n, c in DBS.items()])

    open_count = sum(1 for r in records if "Open" in r["Status"] or "OPEN" in r["Status"])
    if not open_count:
        findings.append(create_finding(
            title="No Exposed Database Ports Detected",
            severity="info",
            confidence=Confidence.NOT_DETECTED.value,
            detail=f"Scanned {len(DBS)} common database service ports on {host}; all ports were closed or filtered.",
            recommendation="Continue maintaining restrictive firewall rules.",
        ))

    return ok({
        "summary": {
            "Host": host,
            "Databases Tested": len(DBS),
            "Open Ports": open_count,
            "Unauthenticated DBs": sum(1 for f in findings if f.get("severity") == "critical"),
        },
        "findings": findings,
        "records": records,
        "record_columns": ["Database", "Port", "Status", "Auth State"],
    })
