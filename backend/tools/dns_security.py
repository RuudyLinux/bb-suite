from __future__ import annotations
import dns.resolver
import dns.exception
from fastapi import APIRouter
from models import TargetReq
from tools.utils import clean_domain, f, ok, err

router = APIRouter(tags=["analysis"])

DKIM_SELECTORS = ["default", "google", "mail", "k1", "selector1", "selector2",
                   "dkim", "s1", "s2", "key1", "mxvault", "smtp"]


def resolve_txt(domain: str) -> list[str]:
    try:
        r = dns.resolver.Resolver()
        r.timeout = 5
        return [str(a) for a in r.resolve(domain, "TXT")]
    except Exception:
        return []


@router.post("/dns_security")
async def dns_security(req: TargetReq):
    domain = clean_domain(req.target)
    if not domain:
        return err("Invalid domain")
    try:
        findings = []
        records = []
        raw = ""

        # SPF
        spf = None
        for txt in resolve_txt(domain):
            if txt.lower().startswith("v=spf1"):
                spf = txt.strip('"')
                break
        if not spf:
            findings.append(f("high", "No SPF Record",
                               "Email spoofing possible",
                               f'Add TXT: v=spf1 include:_spf.google.com ~all'))
            records.append({"Check": "SPF", "Status": "✗ Missing", "Value": "—"})
        else:
            records.append({"Check": "SPF", "Status": "✓ Found", "Value": spf[:100]})
            raw += f"SPF: {spf}\n"
            if "+all" in spf:
                findings.append(f("critical", "SPF Uses +all (Permissive)",
                                   "+all allows ANY server to send as this domain",
                                   "Change to -all or ~all"))
            elif "?all" in spf:
                findings.append(f("high", "SPF Uses ?all (Neutral)", "No protection",
                                   "Change to -all"))
            elif "~all" in spf:
                findings.append(f("medium", "SPF Uses ~all (Softfail)",
                                   "Spoofed emails may still be delivered",
                                   "Consider -all if all mail flows known"))
            elif "-all" in spf:
                findings.append(f("pass", "SPF Policy Strict (-all)", "Rejects unauthorized senders"))

        # DMARC
        dmarc = None
        for txt in resolve_txt(f"_dmarc.{domain}"):
            if txt.lower().startswith("v=dmarc1"):
                dmarc = txt.strip('"')
                break
        if not dmarc:
            findings.append(f("high", "No DMARC Record",
                               "Email spoofing via SPF/DKIM bypass possible",
                               f'Add TXT at _dmarc.{domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}'))
            records.append({"Check": "DMARC", "Status": "✗ Missing", "Value": "—"})
        else:
            records.append({"Check": "DMARC", "Status": "✓ Found", "Value": dmarc[:120]})
            raw += f"DMARC: {dmarc}\n"
            import re
            pm = re.search(r'p=([^;]+)', dmarc, re.I)
            policy = (pm.group(1).strip().lower() if pm else "none")
            if policy == "none":
                findings.append(f("high", "DMARC Policy is None (Monitor Only)",
                                   "Spoofed emails pass; monitoring mode only",
                                   "Upgrade to p=quarantine or p=reject"))
            elif policy == "quarantine":
                findings.append(f("medium", "DMARC Policy Quarantine",
                                   "Spoofed emails go to spam — not strict",
                                   "Consider p=reject"))
            else:
                findings.append(f("pass", "DMARC Policy Reject", "Full spoofing protection"))
            if "rua=" not in dmarc.lower():
                findings.append(f("low", "DMARC Missing rua Tag", "No aggregate report recipient",
                                   "Add rua=mailto:dmarc@yourdomain.com"))

        # DKIM
        dkim_found = []
        for sel in DKIM_SELECTORS:
            for txt in resolve_txt(f"{sel}._domainkey.{domain}"):
                if "v=dkim1" in txt.lower():
                    dkim_found.append(sel)
                    records.append({"Check": f"DKIM ({sel})", "Status": "✓ Found", "Value": txt[:80] + "..."})
                    raw += f"DKIM ({sel}): {txt[:80]}\n"
                    break
        if not dkim_found:
            findings.append(f("medium", "No DKIM Records Found",
                               f"Checked: {', '.join(DKIM_SELECTORS)}",
                               "Configure DKIM for outbound email signing"))
            records.append({"Check": "DKIM", "Status": "✗ Not found", "Value": f"Checked: {', '.join(DKIM_SELECTORS)}"})
        else:
            findings.append(f("pass", "DKIM Found", f"Selectors: {', '.join(dkim_found)}"))

        # CAA
        try:
            r = dns.resolver.Resolver()
            caas = list(r.resolve(domain, "CAA"))
            if caas:
                for caa in caas:
                    records.append({"Check": "CAA", "Status": "✓ Found", "Value": caa.to_text()})
                findings.append(f("pass", "CAA Records Present", f"{len(caas)} CAA configured"))
            else:
                raise Exception("empty")
        except Exception:
            findings.append(f("medium", "No CAA Records",
                               "Any CA can issue TLS certs for this domain",
                               'Add CAA: 0 issue "letsencrypt.org"'))
            records.append({"Check": "CAA", "Status": "✗ Missing", "Value": "—"})

        return ok({"summary": {"Domain": domain,
                                "SPF": "Found" if spf else "Missing",
                                "DMARC": "Found" if dmarc else "Missing",
                                "DKIM": ", ".join(dkim_found) if dkim_found else "Not found"},
                   "findings": findings, "records": records,
                   "record_columns": ["Check", "Status", "Value"],
                   "raw": raw})
    except Exception as e:
        return err(str(e))
