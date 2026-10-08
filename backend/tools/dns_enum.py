from __future__ import annotations
import dns.resolver
import dns.exception
from fastapi import APIRouter
from models import TargetReq
from tools.utils import clean_domain, f, ok, err

router = APIRouter(tags=["recon"])

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV"]


def resolve(domain: str, rtype: str) -> list[dict]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, rtype)
        results = []
        for r in answers:
            val = r.to_text()
            ttl = answers.rrset.ttl if answers.rrset else None
            results.append({"value": val, "ttl": ttl})
        return results
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout,
            dns.resolver.NoNameservers):
        return []
    except Exception:
        return []


@router.post("/dns")
async def dns_enum(req: TargetReq):
    domain = clean_domain(req.target)
    if not domain:
        return err("Invalid domain")
    try:
        dns_data = {}
        total = 0
        for rtype in RECORD_TYPES:
            recs = resolve(domain, rtype)
            if recs:
                dns_data[rtype] = recs
                total += len(recs)

        findings = []
        if "A" not in dns_data and "AAAA" not in dns_data:
            findings.append(f("info", "No A/AAAA Records", "Domain may not host a web server"))

        if "MX" in dns_data:
            findings.append(f("info", f"Mail Servers Found ({len(dns_data['MX'])})",
                               "Check SPF/DMARC — run DNS Security tool", "Run DNS Security"))

        spf_found = dmarc_found = False
        for rec in dns_data.get("TXT", []):
            if "v=spf1" in rec["value"].lower():
                spf_found = True
                findings.append(f("pass", "SPF Record Found", rec["value"]))
            if "v=dmarc1" in rec["value"].lower():
                dmarc_found = True
                findings.append(f("pass", "DMARC Record Found", rec["value"]))

        ns_count = len(dns_data.get("NS", []))
        if ns_count == 0:
            findings.append(f("high", "No NS Records", "Cannot determine nameservers"))
        elif ns_count < 2:
            findings.append(f("high", "Single Nameserver", "Single point of failure",
                               "Add redundant nameservers"))
        else:
            findings.append(f("pass", f"{ns_count} Nameservers", "Redundant NS configured"))

        if "CAA" in dns_data:
            findings.append(f("pass", "CAA Records Present", "Certificate authority authorization configured"))
        else:
            findings.append(f("medium", "No CAA Records", "Any CA can issue certs for this domain",
                               "Add CAA records"))

        return ok({"summary": {"Domain": domain, "Total Records": total,
                                "Record Types": len(dns_data)},
                   "findings": findings, "dns": dns_data})
    except Exception as e:
        return err(str(e))
