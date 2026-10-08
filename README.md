# BB-SUITE v4.0 — Bug Bounty & Autonomous Security Testing Suite (Strix Enhanced)

> **⚠ AUTHORIZED TESTING ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorized testing is illegal.

---

## Overview

**BB-SUITE v4.0** is an enterprise-grade security testing and bug bounty platform inspired by autonomous penetration testing architectures like **Strix**. It combines active reconnaissance, web application vulnerability scanning, automated exploitation, AI-driven security analysis, asset tracking, and post-exploitation workflows into a single interface with one-click batch execution and report generation.

### Strix-Inspired Upgrades
- **Zero-False-Positive PoC Philosophy**: Vulnerability findings generate concrete, reproducible Proof-of-Concept exploits (cURL commands, Python `requests` scripts, or browser-executable HTML exfiltration harnesses).
- **Advanced Attack Surface Coverage**: Added targeted scanners for **Server-Side Request Forgery (SSRF)** across cloud metadata services, **Server-Side Template Injection (SSTI)** across 6 template engines, **GraphQL Introspection & Batch Amplification**, **Prototype Pollution & HTTP Parameter Pollution (HPP)**, and a dedicated **Exploit PoC Synthesizer**.
- **Consolidated Tool Architecture**: Eliminated toy/superficial tools by merging duplicate capabilities into superior scanners while retaining 100% backward compatibility via legacy API wrappers.
- **Interactive Exploit Viewer**: The results interface automatically surfaces copy-pasteable exploit code, automated reproduction steps, and developer remediation patches.

**Stack:** Python 3.8+ (FastAPI + Uvicorn) backend + React 18 (Vite + Tailwind CSS) cyberpunk frontend.

---

## Architecture

```
sql2/
├── backend/                  ← FastAPI Python backend (ASGI port 8000)
│   ├── main.py               ← App entry point, 54 API routes, legacy compatibility aliases
│   ├── models.py             ← Pydantic request models with strict validation
│   ├── database.py           ← Embedded SQLite persistence (reports/bbsuite.db)
│   ├── key_loader.py         ← API key parser for key.env
│   ├── requirements.txt      ← Python dependencies
│   └── tools/                ← 38 Security tool modules + utilities
│       ├── utils.py          ← Shared HTTP, port checking, and finding utilities
│       ├── whois.py          ← WHOIS domain registrar lookup
│       ├── dns_enum.py       ← Comprehensive DNS record enumeration
│       ├── subdomain.py      ← Subdomain brute-forcing engine
│       ├── subdomain_takeover.py ← Dangling CNAME takeover auditor
│       ├── portscan.py       ← TCP port scanner & service detector
│       ├── tls_inspect.py    ← SSL/TLS certificate & cipher inspector
│       ├── ip_finder.py      ← IP resolution, CDN/WAF detection, geolocation
│       ├── headers.py        ← Security header gap analyzer
│       ├── http_security.py  ← Tech stack fingerprinter & redirect checker
│       ├── security_files.py ← Standard security text file fetcher
│       ├── dns_security.py   ← SPF, DMARC, DKIM, and CAA email security auditor
│       ├── cors_check.py     ← CORS misconfiguration tester & HTML PoC generator
│       ├── cookies.py        ← Cookie security, session fixation & entropy auditor
│       ├── cloud.py          ← S3/Azure/GCP cloud storage exposure scanner
│       ├── js_intel.py       ← JavaScript secret & hidden endpoint extractor
│       ├── page_discover.py  ← Recursive crawler & admin portal finder
│       ├── sensitive_files.py← Sensitive files & regex secret token detector
│       ├── vuln_detection.py ← Info disclosure, directory listing, CVE marker scanner
│       ├── db_scanner.py     ← Exposed database port scanner (MySQL, PG, Mongo, Redis)
│       ├── api_security.py   ← OpenAPI / Swagger & API endpoint auditor
│       ├── graphql_scanner.py← [NEW] GraphQL introspection & batching DoS auditor
│       ├── jwt_analyzer.py   ← JWT decoder, secret cracker, and claims auditor
│       ├── xss_scanner.py    ← Reflected Cross-Site Scripting (XSS) scanner
│       ├── lfi_scanner.py    ← Local File Inclusion (LFI) & path traversal tester
│       ├── open_redirect.py  ← Open URL redirection vulnerability tester
│       ├── ssrf_scanner.py   ← [NEW] SSRF auditor (AWS/GCP/Azure metadata, IP bypasses)
│       ├── ssti_scanner.py   ← [NEW] Server-Side Template Injection engine tester
│       ├── proto_pollution.py← [NEW] Prototype Pollution & HTTP Parameter Pollution tester
│       ├── password_cracker.py← Offline hash cracker (MD5, SHA1, SHA256, NTLM)
│       ├── sqli.py           ← Error, boolean, and time-based SQL Injection scanner
│       ├── bruteforce.py     ← Dictionary login attack & credential stuffing engine
│       ├── auth_flaws.py     ← Authentication logic flaw tester
│       ├── rate_limit.py     ← Endpoint rate limit & concurrency tester
│       ├── poc_generator.py  ← [NEW] Exploit PoC synthesizer (cURL, Python, HTML, Patch)
│       ├── post_exploit.py   ← Post-compromise DB dumper & authenticated crawler
│       ├── vuln_map.py       ← Site-wide multi-vector vulnerability crawler
│       ├── ai_analysis.py    ← Local AI & built-in offline intelligence engine
│       ├── screenshots.py    ← Playwright headless screenshot engine
│       ├── zap_integration.py← OWASP ZAP REST API controller
│       └── reports.py        ← JSON & HTML report generation engine
│
├── frontend/                 ← React 18 + Vite + Tailwind CSS frontend
│   ├── src/
│   │   ├── App.jsx           ← Root component & view router
│   │   ├── index.css         ← Cyberpunk design system, scanlines, glow effects
│   │   ├── config/tools.js   ← 38 Tool definitions, metadata, inputs, categories
│   │   ├── hooks/
│   │   │   ├── useToolRunner.js  ← Single tool execution lifecycle manager
│   │   │   └── useRunAll.js      ← Parallel batch execution orchestrator
│   │   ├── lib/api.js        ← Fetch wrapper targeting backend API
│   │   └── components/
│   │       ├── Header.jsx        ← Target bar & execution stats
│   │       ├── Sidebar.jsx       ← Category navigation (38 tools)
│   │       ├── Dashboard.jsx     ← Live status grid & "Perform All" runner
│   │       ├── ToolPanel.jsx     ← Dynamic form renderer for tool inputs
│   │       ├── Results.jsx       ← Multi-tab results viewer with PoC display
│   │       ├── Findings.jsx      ← Color-coded severity cards
│   │       ├── DataTable.jsx     ← Paginated & searchable table viewer
│   │       ├── CrackBanner.jsx   ← Post-exploit alert banner for cracked logins
│   │       ├── ReportPanel.jsx   ← Saved scan report manager & viewer
│   │       └── Welcome.jsx       ← Interactive landing screen
│   ├── dist/                 ← Production React bundle (served by FastAPI)
│   └── package.json
│
├── wordlists/
│   ├── subdomains.txt        ← Common subdomain prefixes (~150 entries)
│   ├── common_paths.txt      ← Sensitive endpoints & directories (~200 entries)
│   └── passwords.txt         ← Common passwords for brute-force tests (~100 entries)
│
├── reports/                  ← Auto-generated reports & database
│   ├── bbsuite.db            ← SQLite scan history & findings database
│   └── report_<target>_<ts>.{json,html}
│
├── install.bat               ← Automated environment setup
├── start.bat                 ← Auto-build & launch backend + browser
└── key.env                   ← Local configuration store (ZAP, Local LLM)
```

---

## Tool Reference (38 Tools across 7 Categories)

### 🔍 Category 1: RECONNAISSANCE (RECON)
| Tool | Endpoint | Description |
|---|---|---|
| **IP Finder** | `POST /api/ip_finder` | Resolve IP addresses, detect CDN/WAF (Cloudflare, Akamai, CloudFront), ASN/ISP details, reverse DNS |
| **WHOIS Lookup** | `POST /api/whois` | Query domain registrar, registration/expiration dates, and contact data |
| **DNS Enumeration** | `POST /api/dns` | Query all DNS records: A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV |
| **Subdomain Enum** | `POST /api/subdomain` | Brute-force active subdomains via multi-threaded DNS resolution |
| **Subdomain Takeover** | `POST /api/subdomain_takeover` | Scan for dangling CNAME records pointing to unclaimed services (S3, Heroku, GitHub Pages, etc.) |
| **Port Scanning** | `POST /api/portscan` | Scan TCP ports and fingerprint services across common, web, DB, or extended port sets |
| **TLS Inspection** | `POST /api/tls` | Analyze SSL/TLS certificates, handshake protocol versions (TLS 1.2/1.3), cipher suites, expiry, SANs |

### 📊 Category 2: ANALYSIS (ANALYSIS)
| Tool | Endpoint | Description |
|---|---|---|
| **HTTP Headers** | `POST /api/headers` | Check missing security headers (HSTS, CSP, X-Frame-Options, Permissions-Policy) |
| **HTTP Security** | `POST /api/http_security` | Fingerprint technology stack, inspect redirect chains, detect server disclosures |
| **Security Files** | `POST /api/security_files` | Fetch `robots.txt`, `sitemap.xml`, `security.txt`, `.well-known/`, `crossdomain.xml` |
| **DNS Security** | `POST /api/dns_security` | Evaluate SPF records, DMARC policies, DKIM selector presence, and CAA records |
| **CORS Misconfig** | `POST /api/cors` | Test origin reflection, wildcard CORS, `null` origin, and generate browser data exfiltration PoCs |
| **Cookie Analyzer** | `POST /api/cookies` | Inspect Set-Cookie flags (`Secure`, `HttpOnly`, `SameSite`), prefix rules (`__Host-`, `__Secure-`), entropy & session fixation |
| **Cloud Exposure** | `POST /api/cloud` | Scan for exposed AWS S3 buckets, Azure Blob containers, and Google Cloud Storage buckets |
| **JS Intelligence** | `POST /api/js_intel` | Scrape target JavaScript bundles to extract hidden API routes, endpoints, and hardcoded API tokens |

### 🔎 Category 3: SCANNING (SCANNING)
| Tool | Endpoint | Description |
|---|---|---|
| **Page Discovery** | `POST /api/page_discover` | Recursive web crawler + wordlist brute-forcing to discover pages and administrative portals |
| **API Security** | `POST /api/api_security` | Discover OpenAPI/Swagger documentation, exposed REST endpoints, and unauthenticated routes |
| **GraphQL Auditor** | `POST /api/graphql` | **[NEW]** Probe GraphQL endpoints for Introspection schemas, sensitive types, field suggestions, and batching DoS |
| **JWT Analyzer** | `POST /api/jwt_analyzer` | Decode JWTs, test `alg: none` and key-confusion vulnerabilities, crack weak HMAC secrets |
| **Sensitive Files** | `POST /api/sensitive_files` | Detect exposed `.env`, `.git`, backups, database dumps, and live regex-matched API keys (AWS, Slack, Stripe) |
| **Vuln Detection** | `POST /api/vuln_detection` | Scan for debug error traces, directory listings, software version disclosures, and CVE markers |
| **DB Login Scanner** | `POST /api/db_scanner` | Probe database ports (MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch) for unauthenticated access |
| **XSS Scanner** | `POST /api/xss` | Audit reflected Cross-Site Scripting (XSS) with context-aware payloads and script tags |
| **LFI Scanner** | `POST /api/lfi` | Test Local File Inclusion & directory traversal payloads (`/etc/passwd`, `win.ini`, wrapper filters) |
| **Open Redirect** | `POST /api/open_redirect` | Probe parameters for unvalidated URL redirection to external domain targets |
| **SSRF Scanner** | `POST /api/ssrf` | **[NEW]** Strix-class SSRF auditor testing AWS/GCP/Azure/K8s cloud metadata, loopback bypasses (decimal/hex/IPv6), and internal services |
| **SSTI Scanner** | `POST /api/ssti` | **[NEW]** Server-Side Template Injection engine evaluator using polyglot arithmetic across Jinja2, Twig, Freemarker, Smarty, Ruby ERB |
| **Prototype Pollution** | `POST /api/proto_pollution` | **[NEW]** Client/Server Prototype Pollution and HTTP Parameter Pollution (HPP) auditor injecting `__proto__` and duplicate query keys |

### ⚡ Category 4: EXPLOITATION (EXPLOIT)
| Tool | Endpoint | Description |
|---|---|---|
| **Password Cracker** | `POST /api/password_cracker` | Offline hash identifier and dictionary cracker for MD5, SHA1, SHA256, and NTLM hashes |
| **SQL Injection** | `POST /api/sqli` | Test parameters against error-based, boolean-based blind, and time-based delay SQL injection |
| **Brute Force** | `POST /api/bruteforce` | Dictionary attack & credential stuffing engine with automatic CSRF token extraction and async workers |
| **Auth Logic Flaws** | `POST /api/auth_flaws` | Test authentication logic weaknesses: blank password submissions, SQLi bypass, default creds, type juggling |
| **Rate Limit Tester** | `POST /api/rate_limit` | Rapid concurrent request stress-tester detecting HTTP 429 throttling and rate-limit bypasses |
| **PoC Synthesizer** | `POST /api/poc` | **[NEW]** Exploit Proof-of-Concept synthesizer generating cURL commands, Python `requests` scripts, browser HTML harnesses, and code fixes |
| **Post-Exploit** | `POST /api/post_exploit` | Post-compromise pipeline: dumps MySQL/PostgreSQL schemas and crawls internal authenticated pages |

### 💀 Category 5: VULNERABILITY MAPPING (VULN MAP)
| Tool | Endpoint | Description |
|---|---|---|
| **Vuln Map** | `POST /api/vuln_map` | Crawls entire application and executes multi-vector security checks across all discovered endpoints |

### ◈ Category 6: INTELLIGENCE (INTELLIGENCE)
| Tool | Endpoint | Description |
|---|---|---|
| **AI Analysis** | `POST /api/ai_analysis` | 100% Local AI vulnerability intelligence (Built-in Offline Security Engine + Ollama/LM Studio support) |
| **Screenshots** | `POST /api/screenshots` | Captures high-resolution headless Chromium viewport or full-page scroll screenshots via Playwright |

### ⬡ Category 7: OWASP ZAP (ZAP)
| Tool | Endpoint | Description |
|---|---|---|
| **OWASP ZAP** | `POST /api/zap` | Triggers spidering, passive scanning, or full active vulnerability scanning via OWASP ZAP REST API |

---

## Legacy Tool Consolidation & Compatibility

To eliminate redundancy and maintain clean, high-impact modules, several older tools were consolidated:
1. **`stuffing.py`** → Consolidated into **`bruteforce.py`** (supports both single user dictionary attacks and `user:pass` combo lists).
2. **`session_hijack.py`** → Consolidated into **`cookies.py`** (includes cookie security flags, `__Host-` prefixes, entropy checks, and predictable session sequence tests).
3. **`credential_exposure.py`** → Consolidated into **`sensitive_files.py`** (combines sensitive path scanning with high-entropy regex secret pattern matching).
4. **`aitm.py`** → Removed (redundant with `headers.py` HSTS enforcement and `http_security.py` redirect inspection).
5. **`wordlist.py`** → Removed (redundant with `page_discover.py`, which provides both active crawling and dictionary-based endpoint discovery).

*All legacy endpoints (`/api/stuffing`, `/api/session_hijack`, `/api/credential_exposure`, `/api/wordlist`, `/api/aitm`) remain active as backward-compatible aliases in `backend/main.py`.*

---

## API Response Format

Every tool returns the same JSON structure:

```json
{
  "success": true,
  "data": {
    "summary": {
      "Key": "Value"
    },
    "findings": [
      {
        "severity": "critical | high | medium | low | info | pass",
        "title": "Finding title",
        "detail": "Detailed description",
        "recommendation": "How to fix"
      }
    ],
    "records": [
      { "Column1": "value", "Column2": "value" }
    ],
    "record_columns": ["Column1", "Column2"],
    "raw": "Raw output string (optional)"
  },
  "error": ""
}
```

### Severity Levels

| Severity | Color | Meaning |
|---|---|---|
| `critical` | 🔴 Red | Immediate risk — exploitable vulnerability |
| `high` | 🟠 Orange | Significant security issue |
| `medium` | 🟡 Yellow | Moderate risk — should be addressed |
| `low` | 🔵 Blue | Minor issue or informational risk |
| `info` | 🩵 Cyan | Informational — no direct risk |
| `pass` | 🟢 Green | Check passed — no issue found |

---

## Reports

Reports auto-save when "Perform All Tools" completes.

### Location
```
reports/
└── report_example_com_20241215_143022.json
└── report_example_com_20241215_143022.html
```

### HTML Report Contains
- Target + timestamp + scan duration
- Severity summary (Critical / High / Medium / Low counts)
- All findings sorted by severity
- Per-tool result summary table

### View Reports
- **In browser:** Dashboard → 📁 Reports Folder → click ↗ HTML
- **Direct URL:** `http://localhost:8000/api/reports/report_xxx.html`
- **Raw JSON:** `http://localhost:8000/api/reports/report_xxx.json`

---

## OWASP ZAP Setup

1. Download OWASP ZAP from https://zaproxy.org
2. Open ZAP → **Tools → Options → API**
3. Enable API
4. Note your API key (or set one)
5. ZAP runs on `http://localhost:8080` by default

In BB-SUITE: Sidebar → OWASP ZAP → enter target + API key → Launch ZAP.

---

## Post-Exploit (Login Cracked)

When brute force or credential stuffing cracks a password:

1. Red `██ LOGIN CRACKED ██` banner appears
2. Shows cracked `username:password`
3. Click **▶ DUMP DATABASE + SCAN AUTHENTICATED PAGES**
4. System attempts:
   - Connect to MySQL / PostgreSQL on target host with cracked credentials
   - Dump databases, tables, sample rows
   - Find `/phpmyadmin`, `/adminer`, `/pma` panels
   - Make authenticated HTTP session, scan accessible endpoints

> **Note:** DB dumping requires `pymysql` (MySQL) or `psycopg2-binary` (PostgreSQL):
> ```
> pip install pymysql psycopg2-binary
> ```

---

## Python Dependencies

```
fastapi==0.104.1        ← Web framework
uvicorn[standard]       ← ASGI server
httpx==0.25.2           ← Async HTTP client
dnspython==2.4.2        ← DNS queries
pydantic==2.5.0         ← Data validation
cryptography==41.0.7    ← TLS cert parsing
python-multipart        ← Form data parsing
```

Optional (for DB dumping):
```
pymysql                 ← MySQL connection
psycopg2-binary         ← PostgreSQL connection
```

---

## Adding a New Tool

### 1. Backend — `backend/tools/mytool.py`

```python
from __future__ import annotations
from fastapi import APIRouter
from models import TargetReq
from tools.utils import clean_url, http_get, f, ok, err

router = APIRouter(tags=["scanning"])

@router.post("/mytool")
async def my_tool(req: TargetReq):
    url = clean_url(req.target)
    findings = []
    records  = []

    # ... tool logic ...

    return ok({
        "summary":        {"Target": url},
        "findings":       findings,
        "records":        records,
        "record_columns": ["Column1", "Column2"],
    })
```

### 2. Register in `backend/main.py`

```python
from tools.mytool import router as mytool_r
# Add mytool_r to the router list
```

### 3. Frontend — `frontend/src/config/tools.js`

```javascript
my_tool: T(
  'My Tool', '🔧',
  'Tool description.',
  [{ name: 'target', label: 'URL', type: 'text', autofill: 'url' }]
),
```

Add `'my_tool'` to the relevant category in `CATEGORIES`.

### 4. Rebuild

```bat
cd frontend && npm run build
```

Restart backend. Done.

---

## Wordlists

| File | Size | Used By |
|---|---|---|
| `wordlists/subdomains.txt` | ~150 entries | Subdomain Enum |
| `wordlists/common_paths.txt` | ~200 entries | Sensitive Files, Page Discovery, Wordlist Discovery |
| `wordlists/passwords.txt` | ~100 entries | Brute Force (default list) |

Custom wordlists: replace files or paste custom passwords directly in the Brute Force tool form.

---

## Troubleshooting

### "localhost refused to connect" on port 8000
Backend is not running. Run `start.bat` or:
```bat
cd backend && python main.py
```

### Tools return HTTP 404
Old backend process still running with broken code. Run `start.bat` — it kills all Python processes first.

### Python TypeError on startup
Python version < 3.8 or missing `from __future__ import annotations`. All tool files already include this fix.

### ZAP returns "Cannot connect"
Start OWASP ZAP first. Enable API under Tools → Options → API.

### DB dump not working
Install optional drivers:
```
pip install pymysql psycopg2-binary
```

---

## Legal Notice

This tool is intended for:
- Authorized penetration testing
- Bug bounty programs (target must be in scope)
- Security research on systems you own
- CTF competitions

**Never use against systems without explicit written authorization.**
Unauthorized testing violates computer fraud laws (CFAA, Computer Misuse Act, etc.).
