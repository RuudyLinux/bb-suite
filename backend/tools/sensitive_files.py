import re
import asyncio
from fastapi import APIRouter
from models import WordlistReq
from tools.utils import clean_url, http_get, f, ok, err, load_wordlist

router = APIRouter(tags=["scanning"])

CRITICAL_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.bak",
    "/.git/config", "/.git/HEAD", "/wp-config.php", "/config.php",
    "/config.json", "/config.yml", "/credentials.json", "/.aws/credentials",
    "/.ssh/id_rsa", "/id_rsa", "/secret.txt", "/api_keys.txt",
    "/database.sql", "/backup.sql", "/dump.sql", "/phpinfo.php"
]

HIGH_RISK = re.compile(
    r'\.env|\.git|phpinfo|backup\.|\.sql|private|credential|\.ssh|\.aws|id_rsa|secret|api_key|config\.',
    re.I
)

SECRET_PATTERNS = [
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key ID"),
    (re.compile(r'aws_secret_access_key\s*=\s*([^\s\n"\'#]+)', re.I), "AWS Secret Access Key"),
    (re.compile(r'ghp_[a-zA-Z0-9]{36}'), "GitHub Personal Access Token"),
    (re.compile(r'sk-[a-zA-Z0-9]{32,60}'), "OpenAI API Key"),
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "Google Cloud API Key"),
    (re.compile(r'xox[baprs]-[a-zA-Z0-9\-]{20,70}'), "Slack OAuth Token"),
    (re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'), "PEM Private Key"),
    (re.compile(r'(?:postgres|mysql|mongodb(?:\+srv)?):\/\/[^\s"\':]+:[^\s"\':]+@[^\s"\']+', re.I), "Database Connection URI with Credentials"),
    (re.compile(r'(?:DB_PASSWORD|SECRET_KEY|API_KEY|APP_KEY)\s*=\s*([^\s\n"\'#]+)', re.I), "Application Secret / Password"),
]


@router.post("/sensitive_files")
async def sensitive_files(req: WordlistReq):
    url = clean_url(req.target)
    all_paths = load_wordlist("common_paths.txt")
    if not all_paths:
        all_paths = []

    # Merge critical paths first to ensure top coverage
    combined = list(dict.fromkeys(CRITICAL_PATHS + all_paths))

    if req.wordlist == "small":
        paths = [p for p in combined if HIGH_RISK.search(p)][:40]
    elif req.wordlist == "full":
        paths = combined
    else:
        paths = combined[:150]

    findings = []
    records = []
    leaked_secrets = []
    semaphore = asyncio.Semaphore(20)

    async def check(path: str):
        async with semaphore:
            target = url.rstrip("/") + "/" + path.lstrip("/")
            r = await http_get(target, timeout=5, follow_redirects=False)
            return path, r["status"], len(r["body"]), r["body"]

    results = await asyncio.gather(*[check(p) for p in paths])
    found = 0

    for path, code, size, body in results:
        if code in [0, 404, 503] or (code >= 500 and code not in [500]):
            continue
        if code not in [200, 301, 302, 403]:
            continue

        found += 1
        is_high = bool(HIGH_RISK.search(path))
        label = {200: "ACCESSIBLE", 403: "FORBIDDEN (exists)", 301: "REDIRECT", 302: "REDIRECT"}.get(code, f"HTTP {code}")
        preview = body[:250].replace('\n', ' ').replace('\r', ' ')

        # Scan accessible responses for live secret tokens
        detected_secrets = []
        if code == 200 and len(body) > 10:
            for pat, sec_name in SECRET_PATTERNS:
                m = pat.search(body)
                if m:
                    match_val = m.group(0)[:40]
                    detected_secrets.append(sec_name)
                    leaked_secrets.append(f"{sec_name} in {path}")
                    findings.append(f(
                        "critical",
                        f"Secret Leaked in {path}: {sec_name}",
                        f"Matched signature '{sec_name}': {match_val}... in HTTP 200 response.",
                        "Immediately revoke and rotate the compromised credential, remove file from webroot."
                    ))

        if code == 200 and is_high and not detected_secrets:
            findings.append(f(
                "critical",
                f"Sensitive File Accessible: {path}",
                f"HTTP {code} ({size}B) — File readable. Preview: {preview[:120]}...",
                "Remove sensitive file from public webroot or restrict access via web server rules."
            ))
        elif is_high and not detected_secrets:
            findings.append(f(
                "high",
                f"High-Risk Path Present: {path}",
                f"HTTP {code} ({label}) — Resource exists on server.",
                "Review server routing to prevent unauthorized access."
            ))
        elif code == 403:
            findings.append(f(
                "medium",
                f"Restricted Resource Discovered: {path}",
                f"HTTP 403 Forbidden indicates this file/directory exists on server."
            ))

        records.append({
            "Path": path,
            "Status": code,
            "Label": label,
            "Size": f"{size}B",
            "Secrets Leaked": ", ".join(detected_secrets) if detected_secrets else "None"
        })

    if not found:
        findings.append(f("pass", "No Sensitive Files Found", f"Audited {len(paths)} sensitive paths."))

    return ok({
        "summary": {
            "URL": url,
            "Paths Checked": len(paths),
            "Exposed Files": found,
            "Secrets Leaked": len(leaked_secrets),
        },
        "findings": findings,
        "records": records,
        "record_columns": ["Path", "Status", "Label", "Size", "Secrets Leaked"]
    })
