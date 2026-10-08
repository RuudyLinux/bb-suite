import asyncio
import re
from datetime import datetime, timezone
from fastapi import APIRouter
from models import TargetReq
from tools.utils import clean_domain, f, ok, err

router = APIRouter(tags=["recon"])


async def whois_query(domain: str, server: str = "whois.iana.org") -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, 43), timeout=10)
        writer.write(f"{domain}\r\n".encode())
        await writer.drain()
        data = b""
        while True:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=5)
            if not chunk:
                break
            data += chunk
        writer.close()
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


@router.post("/whois")
async def whois_lookup(req: TargetReq):
    domain = clean_domain(req.target)
    if not domain:
        return err("Invalid domain")
    try:
        raw = await whois_query(domain)
        server = None
        for pat in [r'refer:\s*(\S+)', r'whois:\s*(\S+)']:
            m = re.search(pat, raw, re.I)
            if m:
                server = m.group(1).strip()
                break
        if server and server != "whois.iana.org":
            detail = await whois_query(domain, server)
            if detail:
                raw = detail

        fields = {}
        patterns = {
            "Registrar":          r'Registrar:\s*(.+)',
            "Created":            r'Creation Date:\s*(.+)',
            "Updated":            r'Updated Date:\s*(.+)',
            "Expires":            r'Registry Expiry Date:\s*(.+)',
            "Status":             r'Domain Status:\s*(.+)',
            "Nameserver":         r'Name Server:\s*(.+)',
            "Registrant Org":     r'Registrant Organization:\s*(.+)',
            "Registrant Email":   r'Registrant Email:\s*(.+)',
            "Registrant Country": r'Registrant Country:\s*(.+)',
        }
        for k, pat in patterns.items():
            m = re.search(pat, raw, re.I)
            if m:
                fields[k] = m.group(1).strip()

        findings = []
        summary = {"Domain": domain}

        if "Expires" in fields:
            try:
                exp_str = re.sub(r'\.\d+Z?$', '', fields["Expires"])
                for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"]:
                    try:
                        exp = datetime.strptime(exp_str[:19], fmt).replace(tzinfo=timezone.utc)
                        break
                    except ValueError:
                        pass
                else:
                    exp = None
                if exp:
                    days = (exp - datetime.now(timezone.utc)).days
                    summary["Expires In"] = f"{days} days"
                    if days < 0:
                        findings.append(f("critical", "Domain Expired", f"Expired {abs(days)} days ago", "Renew immediately"))
                    elif days < 30:
                        findings.append(f("high", "Domain Expiring Soon", f"Expires in {days} days", "Renew now"))
                    elif days < 90:
                        findings.append(f("medium", "Domain Expires < 90 Days", f"Expires in {days} days", "Schedule renewal"))
                    else:
                        findings.append(f("pass", "Domain Expiry OK", f"Valid for {days} more days"))
            except Exception:
                pass

        privacy = bool(re.search(r'privacy|redacted|protected|withheld', raw, re.I))
        summary["Privacy"] = "Enabled" if privacy else "Disabled"
        if privacy:
            findings.append(f("pass", "WHOIS Privacy Enabled", "Registrant details redacted"))
        else:
            findings.append(f("low", "WHOIS Privacy Disabled", "Registrant details publicly visible",
                               "Enable WHOIS privacy"))
        if "Registrar" in fields:
            summary["Registrar"] = fields["Registrar"]

        records = [{"Field": k, "Value": v} for k, v in fields.items()]
        return ok({"summary": summary, "findings": findings, "records": records,
                   "record_columns": ["Field", "Value"], "raw": raw})
    except Exception as e:
        return err(str(e))
