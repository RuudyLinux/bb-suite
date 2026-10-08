import ssl
import socket
from datetime import datetime, timezone
from fastapi import APIRouter
from models import TlsReq
from tools.utils import clean_domain, f, ok, err

router = APIRouter(tags=["recon"])


@router.post("/tls")
async def tls_inspect(req: TlsReq):
    domain = clean_domain(req.target)
    port = req.port or 443
    if not domain:
        return err("Invalid domain")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, port), timeout=15) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()

        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        now = datetime.now(timezone.utc)

        subject_cn = ""
        try:
            subject_cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except Exception:
            pass

        issuer_o = issuer_cn = ""
        try:
            issuer_o = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
        except Exception:
            pass
        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except Exception:
            pass

        not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after  = cert.not_valid_after_utc  if hasattr(cert, 'not_valid_after_utc')  else cert.not_valid_after.replace(tzinfo=timezone.utc)
        days_left  = (not_after - now).days

        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            pass

        findings = []
        if days_left < 0:
            findings.append(f("critical", "Certificate Expired", f"Expired {abs(days_left)} days ago", "Renew immediately"))
        elif days_left < 14:
            findings.append(f("critical", "Cert Expiring Critically", f"Expires in {days_left} days", "Renew now"))
        elif days_left < 30:
            findings.append(f("high", "Cert Expiring Soon", f"Expires in {days_left} days", "Renew soon"))
        elif days_left < 90:
            findings.append(f("medium", "Cert Expiring < 90 Days", f"Expires in {days_left} days"))
        else:
            findings.append(f("pass", "Certificate Validity OK", f"Valid {days_left} more days"))

        self_signed = (issuer_cn == subject_cn) or (not issuer_o and not issuer_cn)
        if self_signed:
            findings.append(f("high", "Self-Signed Certificate", "No trusted CA", "Use Let's Encrypt or a trusted CA"))
        else:
            findings.append(f("pass", "Trusted CA Cert", f"Issued by {issuer_o or issuer_cn}"))

        if subject_cn.startswith("*."):
            findings.append(f("low", "Wildcard Certificate", f"CN={subject_cn} — all subdomains share key"))

        if sans:
            import re
            matched = any(
                re.match(r'^' + re.escape(s).replace(r'\*', r'[^.]+') + r'$', domain, re.I)
                for s in sans
            )
            if not matched:
                findings.append(f("high", "Domain Not in SAN", f"{domain} not in certificate SANs"))
            else:
                findings.append(f("pass", "Domain Matches Cert SAN", ""))

        weak_protocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
        if version in weak_protocols:
            findings.append(f("critical", f"Weak Protocol: {version}", "Vulnerable to POODLE/BEAST",
                               "Disable old TLS versions; use TLS 1.2+"))
        else:
            findings.append(f("pass", f"Protocol OK: {version}", ""))

        records = [
            {"Field": "Subject CN",     "Value": subject_cn},
            {"Field": "Issuer",         "Value": f"{issuer_o} / {issuer_cn}"},
            {"Field": "Valid From",     "Value": not_before.strftime("%Y-%m-%d %H:%M")},
            {"Field": "Valid To",       "Value": not_after.strftime("%Y-%m-%d %H:%M")},
            {"Field": "Days Remaining", "Value": str(days_left)},
            {"Field": "Protocol",       "Value": version or "?"},
            {"Field": "Cipher",         "Value": cipher[0] if cipher else "?"},
            {"Field": "Key Bits",       "Value": str(cipher[2]) if cipher and len(cipher) > 2 else "?"},
            {"Field": "SANs",           "Value": ", ".join(sans[:10])},
        ]
        return ok({"summary": {"Domain": domain, "Port": port, "CN": subject_cn,
                                "Days Left": days_left, "Protocol": version},
                   "findings": findings, "records": records,
                   "record_columns": ["Field", "Value"]})
    except Exception as e:
        return err(f"TLS connection failed: {e}")
