import asyncio
from fastapi import APIRouter
from models import PortScanReq
from tools.utils import clean_host, check_port, f, ok, err, PORT_NAMES

router = APIRouter(tags=["recon"])

PORT_GROUPS = {
    "common":   [21,22,23,25,53,80,110,143,443,445,465,587,993,995,
                 1433,2375,2376,3306,3389,5432,5900,6379,8080,8443,9200,11211,27017],
    "web":      [80,443,8080,8443,8000,8888,3000,4000,5000,8090,9090,9443],
    "db":       [3306,5432,1433,1521,27017,6379,11211,5672,9200,2379],
    "extended": [21,22,23,25,53,80,110,143,389,443,445,465,514,587,631,873,993,995,
                 1080,1433,1521,1723,2049,2375,2376,3306,3389,4444,5432,5900,
                 6379,7001,8000,8080,8443,8888,9200,9300,11211,27017,50000],
}

RISKY = {
    21: "FTP cleartext credentials", 23: "Telnet — plaintext",
    445: "SMB — EternalBlue risk", 3389: "RDP exposed",
    5900: "VNC exposed", 2375: "Docker API unauthenticated",
    6379: "Redis no-auth", 11211: "Memcached exposed",
    27017: "MongoDB no-auth", 9200: "Elasticsearch open",
}


@router.post("/portscan")
async def port_scan(req: PortScanReq):
    host = clean_host(req.target)
    if not host:
        return err("Invalid host")
    try:
        ports = PORT_GROUPS.get(req.ports, PORT_GROUPS["common"])
        semaphore = asyncio.Semaphore(30)

        async def scan(port: int):
            async with semaphore:
                is_open, banner = await check_port(host, port)
                return {"port": port, "service": PORT_NAMES.get(port, "?"),
                        "open": is_open, "banner": banner}

        results = await asyncio.gather(*[scan(p) for p in ports])
        results = sorted(results, key=lambda x: x["port"])
        open_ports = [r for r in results if r["open"]]
        findings = []

        for p in open_ports:
            if p["port"] in RISKY:
                findings.append(f("high", f"Dangerous Port Open: {p['port']}",
                                   RISKY[p["port"]],
                                   f"Firewall port {p['port']} — not exposed to internet"))

        if not open_ports:
            findings.append(f("pass", "No Open Ports", "Good firewall posture"))

        return ok({"summary": {"Host": host, "Ports Checked": len(ports),
                                "Open Ports": len(open_ports)},
                   "findings": findings, "ports": results})
    except Exception as e:
        return err(str(e))
