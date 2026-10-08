from __future__ import annotations
import asyncio
import socket
from fastapi import APIRouter
from models import SubdomainReq
from tools.utils import clean_domain, f, ok, err, load_wordlist

router = APIRouter(tags=["recon"])


async def resolve_host(host: str) -> str | None:
    loop = asyncio.get_event_loop()
    try:
        ip = await loop.run_in_executor(None, socket.gethostbyname, host)
        return ip if ip != host else None
    except Exception:
        return None


@router.post("/subdomain")
async def subdomain_enum(req: SubdomainReq):
    domain = clean_domain(req.target)
    if not domain:
        return err("Invalid domain")
    try:
        all_words = load_wordlist("subdomains.txt")
        if not all_words:
            return err("Wordlist not found")

        size_map = {"small": 50, "medium": 120, "large": len(all_words)}
        words = all_words[:size_map.get(req.wordlist, 120)]

        hosts = [f"{w}.{domain}" for w in words]
        semaphore = asyncio.Semaphore(50)

        async def check(h: str):
            async with semaphore:
                ip = await resolve_host(h)
                return (h, ip) if ip else None

        results = await asyncio.gather(*[check(h) for h in hosts])
        found = [{"Subdomain": h, "IP": ip} for h, ip in results if results and (h, ip) != (None, None)
                 if h is not None and ip is not None]

        findings = []
        if not found:
            findings.append(f("info", "No Subdomains Found",
                               f"Checked {len(words)} entries — no DNS resolution"))
        else:
            findings.append(f("info", f"{len(found)} Subdomains Found",
                               "Enumerate each for additional attack surface",
                               "Run HTTP Security on each"))
            for r in found:
                ip = r["IP"]
                if any(x in ip for x in ["amazonaws", "cloudfront", "azurewebsites"]):
                    findings.append(f("medium", f"Potential Takeover Candidate: {r['Subdomain']}",
                                       f"Points to cloud resource: {ip}",
                                       "Verify ownership of cloud resource"))

        return ok({"summary": {"Domain": domain, "Checked": len(words), "Found": len(found)},
                   "findings": findings, "records": found,
                   "record_columns": ["Subdomain", "IP"]})
    except Exception as e:
        return err(str(e))
