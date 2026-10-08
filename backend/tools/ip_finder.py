from __future__ import annotations
import asyncio
import socket
import dns.resolver
import dns.exception
from fastapi import APIRouter
from models import TargetReq
from tools.utils import clean_domain, http_get, f, ok, err

router = APIRouter(tags=["recon"])

CDN_SIGNATURES = {
    "Cloudflare":  ["cloudflare", "104.16.", "104.17.", "104.18.", "104.19.", "172.64.", "172.65.", "172.66.", "172.67."],
    "AWS CloudFront": ["cloudfront.net", "205.251.", "204.246.", "54.230.", "13.32.", "13.224.", "13.225.", "13.226."],
    "Akamai":      ["akamai", "akamaitechnologies", "akamaitech", "23.32.", "23.64.", "23.192.", "23.194."],
    "Fastly":      ["fastly", "151.101.", "199.27.", "199.232."],
    "AWS":         ["amazonaws.com", "ec2", "elasticloadbalancing"],
    "Azure":       ["azure", "azurewebsites", "cloudapp.azure"],
    "Google":      ["googleusercontent", "google.com", "34.64.", "34.65.", "34.96.", "34.117."],
    "Sucuri":      ["sucuri.net"],
    "Incapsula":   ["incapsula", "imperva"],
}


def detect_cdn(ip: str, hostname: str) -> str | None:
    combined = f"{ip} {hostname}".lower()
    for cdn, sigs in CDN_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in combined:
                return cdn
    return None


async def geoip(ip: str) -> dict:
    """Use ip-api.com free tier — no key needed."""
    r = await http_get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,query",
                       timeout=6, follow_redirects=False)
    if r['ok'] and r['body']:
        import json
        try:
            d = json.loads(r['body'])
            if d.get('status') == 'success':
                return d
        except Exception:
            pass
    return {}


async def reverse_dns(ip: str) -> str:
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return result[0]
    except Exception:
        return ''


@router.post("/ip_finder")
async def ip_finder(req: TargetReq):
    domain = clean_domain(req.target)
    if not domain:
        return err("Invalid domain")
    try:
        findings = []
        records  = []
        ips_v4   = []
        ips_v6   = []

        # Resolve A records
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            answers_a = resolver.resolve(domain, 'A')
            ips_v4 = [str(r) for r in answers_a]
        except Exception:
            pass

        # Resolve AAAA records
        try:
            answers_aaaa = dns.resolver.resolve(domain, 'AAAA')
            ips_v6 = [str(r) for r in answers_aaaa]
        except Exception:
            pass

        if not ips_v4 and not ips_v6:
            return err(f"Cannot resolve IP for {domain}")

        all_ips = ips_v4 + ips_v6

        # Geoip + reverse DNS for each IP (parallel)
        geo_tasks  = [geoip(ip)        for ip in all_ips]
        rdns_tasks = [reverse_dns(ip)  for ip in all_ips]
        geo_results  = await asyncio.gather(*geo_tasks)
        rdns_results = await asyncio.gather(*rdns_tasks)

        cdn_detected = None
        primary_ip   = all_ips[0] if all_ips else '—'
        primary_geo  = geo_results[0] if geo_results else {}

        for ip, geo, rdns in zip(all_ips, geo_results, rdns_results):
            cdn = detect_cdn(ip, rdns or '')
            if cdn and not cdn_detected:
                cdn_detected = cdn

            records.append({
                'IP':        ip,
                'Type':      'IPv4' if ip in ips_v4 else 'IPv6',
                'Reverse DNS': rdns or '—',
                'Country':   geo.get('country', '—'),
                'City':      geo.get('city', '—'),
                'ISP':       geo.get('isp', '—'),
                'ASN':       geo.get('as', '—'),
                'CDN':       cdn or '—',
            })

        # Findings
        if cdn_detected:
            findings.append(f("info", f"Behind {cdn_detected} CDN",
                               f"Real origin IP is hidden — direct IP may differ",
                               "Try DNS history, subdomain brute-force to find origin"))
        else:
            findings.append(f("info", "No CDN Detected",
                               f"Direct server IP exposed: {primary_ip}",
                               "Consider using Cloudflare or similar WAF/CDN"))

        if len(all_ips) > 1:
            findings.append(f("info", f"{len(all_ips)} IP Addresses Found",
                               "Load balancing or multiple A records detected", ""))

        if primary_geo.get('country'):
            findings.append(f("info",
                               f"Hosted in {primary_geo.get('city','?')}, {primary_geo.get('country','?')}",
                               f"ISP: {primary_geo.get('isp','?')} | ASN: {primary_geo.get('as','?')}", ""))

        if any(r['CDN'] == '—' for r in records):
            for r in records:
                if r['CDN'] == '—':
                    findings.append(f("low", f"Direct IP Exposed: {r['IP']}",
                                       f"Server IP visible — enables DDoS, bypass attempts",
                                       "Put server behind CDN/WAF to hide real IP"))
                    break

        summary = {
            'Domain':    domain,
            'Primary IP': primary_ip,
            'IPv4 Count': len(ips_v4),
            'IPv6 Count': len(ips_v6),
            'CDN':        cdn_detected or 'None',
            'Country':    primary_geo.get('country', '—'),
            'ISP':        primary_geo.get('isp', '—'),
        }

        return ok({
            'summary':        summary,
            'findings':       findings,
            'records':        records,
            'record_columns': ['IP', 'Type', 'Reverse DNS', 'Country', 'City', 'ISP', 'ASN', 'CDN'],
        })
    except Exception as e:
        return err(str(e))
