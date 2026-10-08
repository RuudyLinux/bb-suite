import asyncio
from fastapi import APIRouter
from models import TargetReq
from tools.utils import clean_host, check_port, http_get, f, ok, err

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


async def test_redis_noauth(host: str) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, 6379), timeout=3)
        writer.write(b"*1\r\n$4\r\nINFO\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=2)
        writer.close()
        return b"redis_version" in data
    except Exception:
        return False


@router.post("/db_scanner")
async def db_scanner(req: TargetReq):
    host = clean_host(req.target)
    if not host:
        return err("Invalid host")
    try:
        findings = []
        records = []

        async def scan_db(name: str, cfg: dict):
            port = cfg["port"]
            is_open, banner = await check_port(host, port)
            if not is_open:
                records.append({"DB": name, "Port": port, "Status": "Closed", "Auth": "—"})
                return
            findings.append(f("high", f"{name} Port Open: {host}:{port}",
                               f"Banner: {banner[:100]}",
                               f"Firewall port {port} from public internet"))
            auth_status = "Auth required (not tested)"

            if name == "Redis":
                no_auth = await test_redis_noauth(host)
                if no_auth:
                    auth_status = "NO AUTH — CRITICAL"
                    findings.append(f("critical", "Redis No Authentication",
                                       f"Redis at {host}:{port} accepts commands without password",
                                       "Set requirepass in redis.conf immediately"))

            if name in ["Elasticsearch", "CouchDB"]:
                path = "/_cluster/health" if name == "Elasticsearch" else "/_all_dbs"
                r = await http_get(f"http://{host}:{port}{path}", timeout=3)
                if r["status"] == 200:
                    auth_status = "NO AUTH — CRITICAL"
                    findings.append(f("critical", f"{name} Open Without Auth",
                                       f"{path} accessible without credentials",
                                       f"Enable {name} authentication"))

            if name == "MongoDB":
                r = await http_get(f"http://{host}:28017/", timeout=2)
                if r["status"] == 200:
                    auth_status = "HTTP Interface Open — NO AUTH"
                    findings.append(f("critical", "MongoDB HTTP Interface Exposed",
                                       f"MongoDB web interface at {host}:28017 accessible without auth",
                                       "Disable HTTP interface"))

            records.append({"DB": name, "Port": port, "Status": "OPEN", "Auth": auth_status})

        await asyncio.gather(*[scan_db(n, c) for n, c in DBS.items()])

        open_count = sum(1 for r in records if r["Status"] == "OPEN")
        if not open_count:
            findings.append(f("pass", "No Exposed Databases Found", "All DB ports closed"))

        return ok({"summary": {"Host": host, "DBs Checked": len(DBS), "Open": open_count},
                   "findings": findings, "records": records,
                   "record_columns": ["DB", "Port", "Status", "Auth"]})
    except Exception as e:
        return err(str(e))
