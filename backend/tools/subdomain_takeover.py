from __future__ import annotations
import asyncio
import dns.resolver
import dns.exception
from fastapi import APIRouter
from models import SubdomainReq
from tools.utils import clean_domain, http_get, f, ok, err, load_wordlist

router = APIRouter(tags=["recon"])

# Service fingerprints: cname_suffix -> (http_fingerprint, severity)
TAKEOVER_FINGERPRINTS = {
    'github.io':            ("There isn't a GitHub Pages site here",           'critical'),
    'githubusercontent.com': ("Invalid site",                                   'high'),
    'herokuapp.com':        ("No such app",                                     'critical'),
    'herokudns.com':        ("No such app",                                     'critical'),
    'azurewebsites.net':    ("Microsoft Azure App Service",                     'high'),
    'cloudapp.azure.com':   ("Microsoft Azure",                                 'high'),
    'trafficmanager.net':   ("NXDOMAIN",                                        'high'),
    's3.amazonaws.com':     ("NoSuchBucket",                                    'critical'),
    'amazonaws.com':        ("NoSuchBucket",                                    'high'),
    'cloudfront.net':       ("Bad Request",                                     'medium'),
    'netlify.com':          ("Not found - Request ID:",                         'critical'),
    'netlify.app':          ("Not found - Request ID:",                         'critical'),
    'shopify.com':          ("Sorry, this shop is currently unavailable",       'critical'),
    'myshopify.com':        ("Sorry, this shop is currently unavailable",       'critical'),
    'fastly.net':           ("Fastly error: unknown domain",                    'critical'),
    'ghost.io':             ("Domain is not configured",                        'high'),
    'surge.sh':             ("project not found",                               'critical'),
    'readme.io':            ("Project doesnt exist",                            'high'),
    'readme.com':           ("Project doesnt exist",                            'high'),
    'zendesk.com':          ("Help Center Closed",                              'medium'),
    'freshdesk.com':        ("May be this is still fresh!",                     'medium'),
    'freshservice.com':     ("We could not find what you're looking for",       'medium'),
    'wordpress.com':        ("Do you want to register",                         'high'),
    'pantheon.io':          ("The gods are wise, but do not know",              'high'),
    'webflow.io':           ("The page you are looking for doesn't exist",      'high'),
    'bitbucket.io':         ("The Page You're Looking For Isn't Here",         'high'),
    'strikingly.com':       ("page not found",                                  'high'),
    'tumblr.com':           ("There's nothing here.",                           'medium'),
    'squarespace.com':      ("No Such Account",                                 'high'),
    'desk.com':             ("Sorry, We Couldn't Find That Page",               'medium'),
    'intercom.io':          ("This page doesn't exist.",                        'medium'),
    'helpscoutdocs.com':    ("No settings were found",                          'medium'),
    'unbounce.com':         ("The requested URL was not found",                 'critical'),
    'kajabi.com':           ("The page you were looking for doesn't exist",     'high'),
    'launchrock.com':       ("It looks like you may have taken a wrong turn!",  'medium'),
}


def get_cname(domain: str) -> str | None:
    try:
        r = dns.resolver.Resolver()
        r.timeout = 5
        answers = r.resolve(domain, 'CNAME')
        return str(answers[0].target).rstrip('.')
    except Exception:
        return None


def domain_exists(domain: str) -> bool:
    try:
        r = dns.resolver.Resolver()
        r.timeout = 3
        r.resolve(domain, 'A')
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except Exception:
        return True  # uncertain — don't flag


@router.post("/subdomain_takeover")
async def subdomain_takeover(req: SubdomainReq):
    domain = clean_domain(req.target)
    if not domain:
        return err("Invalid domain")

    all_words = load_wordlist("subdomains.txt")
    sizes     = {"small": 50, "medium": 120, "large": len(all_words)}
    words     = all_words[:sizes.get(req.wordlist, 120)]

    findings  = []
    records   = []
    sem       = asyncio.Semaphore(20)

    async def check_subdomain(sub: str):
        async with sem:
            host = f"{sub}.{domain}"
            loop = __import__('asyncio').get_event_loop()

            # Check if it resolves at all
            try:
                import socket
                ip = await loop.run_in_executor(None, socket.gethostbyname, host)
            except Exception:
                # NXDOMAIN — still check CNAME for dangling
                ip = None

            # Check CNAME
            cname = await loop.run_in_executor(None, get_cname, host)
            if not cname:
                return None

            # Is the CNAME pointing to a known service?
            service = None
            fingerprint = None
            severity = 'medium'
            for svc_suffix, (fp, sev) in TAKEOVER_FINGERPRINTS.items():
                if cname.endswith(svc_suffix):
                    service     = svc_suffix
                    fingerprint = fp
                    severity    = sev
                    break

            if not service:
                return None  # Not a known takeover-vulnerable service

            # Verify by HTTP fingerprint
            vulnerable = False
            for scheme in ['https', 'http']:
                try:
                    r = await http_get(f"{scheme}://{host}/", timeout=6, follow_redirects=True)
                    if r['ok'] and fingerprint.lower() in r['body'].lower():
                        vulnerable = True
                        break
                except Exception:
                    pass

            return {
                'subdomain': host,
                'cname':     cname,
                'service':   service,
                'ip':        ip or 'NXDOMAIN',
                'vulnerable': vulnerable,
                'severity':  severity,
            }

    results = await asyncio.gather(*[check_subdomain(w) for w in words])
    vulnerable_count = 0

    for res in results:
        if res is None:
            continue
        records.append({
            'Subdomain': res['subdomain'],
            'CNAME':     res['cname'],
            'Service':   res['service'],
            'IP':        res['ip'],
            'Vulnerable': 'YES' if res['vulnerable'] else 'Possible',
        })
        if res['vulnerable']:
            vulnerable_count += 1
            findings.append(f(
                res['severity'],
                f"Subdomain Takeover: {res['subdomain']}",
                f"CNAME → {res['cname']} ({res['service']}) is unclaimed. HTTP fingerprint confirmed.",
                f"Claim the {res['service']} resource or remove the CNAME record"
            ))
        else:
            findings.append(f(
                'medium',
                f"Possible Takeover: {res['subdomain']}",
                f"CNAME → {res['cname']} ({res['service']}) — fingerprint not confirmed, manual check needed",
                f"Verify if {res['service']} resource is claimed"
            ))

    if not records:
        findings.append(f('pass', 'No Subdomain Takeover Vectors Found',
                           f'Checked {len(words)} subdomains — no dangling CNAMEs to vulnerable services', ''))

    return ok({
        'summary': {
            'Domain':     domain,
            'Checked':    len(words),
            'CNAME Found': len(records),
            'Vulnerable': vulnerable_count,
        },
        'findings':       findings,
        'records':        records,
        'record_columns': ['Subdomain', 'CNAME', 'Service', 'IP', 'Vulnerable'],
    })
