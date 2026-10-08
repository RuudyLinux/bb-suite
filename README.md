# BB-SUITE v4.0 — Enterprise Authorized Penetration Testing & Bug Bounty Framework

> **⚠ AUTHORIZED TESTING ONLY** — This framework is designed strictly for authorized penetration testing, security assessments, CTF competitions, and bug bounty programs with explicit scope permission. Unauthorized scanning or testing of third-party systems is illegal.

---

## Overview

**BB-SUITE v4.0** is an enterprise-grade security testing and bug bounty assessment framework. It integrates active reconnaissance, web vulnerability scanning, automated exploitation, local AI security intelligence, asset tracking, and post-exploitation workflows into a unified, high-performance interface with one-click batch execution and report generation.

### Security Architecture & Philosophy
- **Centralized Security Boundary & SSRF Prevention**: All outbound HTTP and network probes flow through an authoritative security boundary (`backend/security/`). Scanning loopback addresses (`127.0.0.0/8`, `::1`), private networks (`RFC1918`), link-local/cloud metadata (`169.254.169.254`, `metadata.google.internal`), and carrier-grade NAT is blocked by default.
- **4-Tier Confidence Taxonomy**: Eliminates false positives by distinguishing evidence strength across every detector:
  - **CONFIRMED**: Direct, verified exploit proof (e.g. vendor SQL syntax error, reflected unescaped canary breakout, verified file signature, server arithmetic evaluation).
  - **LIKELY**: Strong differential or status evidence without direct code/data leak.
  - **POSSIBLE**: Heuristic variance or anomaly requiring manual verification.
  - **NOT DETECTED**: Negative result. Heuristic anomalies are **never** reported as confirmed vulnerabilities.
- **Operator Authentication & Role Boundary**: Sensitive tools (`/api/post_exploit`, `/api/bruteforce`, `/api/auto_login`, `/api/password_cracker`, etc.) require authentication via HMAC-SHA256 Bearer tokens or `X-API-Key` headers.
- **Safe Exploit PoC Synthesizer**: Generates reproducible Proof-of-Concept exploits with context-aware escaping (`shlex.quote` for shell commands, `repr()` for Python scripts, `html.escape()` for browser harnesses, and `json.dumps()` for JSON payloads).
- **Hardened Reporting & Database**: Stored XSS in report exports is completely mitigated by strict HTML entity escaping across all dynamic fields. SQLite persistence runs in Write-Ahead Logging (WAL) mode with a 5000ms busy timeout and transaction isolation.

**Stack:** Python 3.11+ (FastAPI + Uvicorn) backend + React 18 (Vite + Tailwind CSS) cyberpunk frontend. Compatible with Python 3.8+.

---

## System Architecture

```
sql2/
├── backend/                       ← FastAPI Python backend (ASGI port 8000)
│   ├── main.py                    ← App entry point, security headers middleware, CORS, error handling
│   ├── models.py                  ← Authoritative Pydantic request models with Field boundaries
│   ├── database.py                ← Embedded SQLite persistence with WAL mode & busy timeout
│   ├── key_loader.py              ← Standard .env and key.env environment loader
│   ├── requirements.txt           ← Pinned Python dependencies
│   ├── security/                  ← Centralized Security Boundary (Phases 1-4)
│   │   ├── config.py              ← Environment configuration & security flags
│   │   ├── confidence.py          ← 4-tier confidence taxonomy & standard response builder
│   │   ├── target_validator.py    ← Hostname RFC 1123, SSRF boundary & redirect validation
│   │   ├── http_client.py         ← Streaming HTTP client (timeouts, 5MB response cap, TLS verify)
│   │   ├── auth.py                ← HMAC-SHA256 token manager & dependency guards
│   │   ├── auth_router.py         ← Login (/api/auth/login), status, and logout endpoints
│   │   └── logger.py              ← Structured audit logger with credential scrubber
│   ├── tests/                     ← Automated Security Test Suite
│   │   ├── test_security_suite.py ← Target validator, auth, reports, PoC escaping, taxonomy tests
│   │   └── test_password_suite.py ← Multi-algorithm hash cracking, salted hashes, entropy tests
│   └── tools/                     ← 38 Security tool modules + utilities
│       ├── utils.py               ← Centralized http_get, port check, and finding wrappers
│       ├── whois.py               ← WHOIS domain registrar lookup
│       ├── dns_enum.py            ← DNS record enumeration (A, AAAA, MX, NS, TXT, SOA, CAA)
│       ├── subdomain.py           ← Subdomain discovery engine
│       ├── subdomain_takeover.py  ← Dangling CNAME takeover auditor
│       ├── portscan.py            ← TCP port scanner & service detector
│       ├── tls_inspect.py         ← SSL/TLS certificate & cipher inspector
│       ├── ip_finder.py           ← IP resolution, CDN/WAF detection, reverse DNS
│       ├── headers.py             ← Security header gap analyzer
│       ├── http_security.py       ← Tech stack fingerprinter & redirect checker
│       ├── security_files.py      ← robots.txt, sitemap.xml, security.txt, .well-known fetcher
│       ├── dns_security.py        ← SPF, DMARC, DKIM, and CAA email security auditor
│       ├── cors_check.py          ← CORS misconfiguration tester & HTML PoC generator
│       ├── cookies.py             ← Cookie security, Shannon entropy, prefix rules (__Host-, __Secure-)
│       ├── cloud.py               ← S3/Azure/GCP cloud storage exposure scanner
│       ├── js_intel.py            ← JavaScript secret & hidden endpoint extractor
│       ├── page_discover.py       ← Recursive crawler & admin portal finder
│       ├── sensitive_files.py     ← Sensitive files & regex secret token detector
│       ├── vuln_detection.py      ← Info disclosure, directory listing, CVE marker scanner
│       ├── db_scanner.py          ← Exposed database port scanner (MySQL, PG, Mongo, Redis, ES)
│       ├── api_security.py        ← OpenAPI / Swagger & API endpoint auditor
│       ├── graphql_scanner.py     ← GraphQL introspection & batching DoS auditor
│       ├── jwt_analyzer.py        ← JWT decoder, secret cracker, and claims auditor
│       ├── xss_scanner.py         ← Reflected XSS scanner with unique canary breakouts
│       ├── lfi_scanner.py         ← LFI & path traversal tester with exact file signature checks
│       ├── open_redirect.py       ← Open URL redirection vulnerability tester
│       ├── ssrf_scanner.py        ← SSRF auditor (cloud metadata, loopback, differential proofs)
│       ├── ssti_scanner.py        ← SSTI engine evaluator using dynamic prime arithmetic probes
│       ├── proto_pollution.py     ← Prototype Pollution & HTTP Parameter Pollution tester
│       ├── password_cracker.py    ← Offline hash cracker (MD5, SHA1, SHA256, NTLM, MySQL, bcrypt)
│       ├── sqli.py                ← SQL injection scanner (vendor errors, boolean & timing differentials)
│       ├── bruteforce.py          ← Rate-bounded dictionary attack & credential stuffing engine
│       ├── auth_flaws.py          ← Authentication logic flaw tester
│       ├── rate_limit.py          ← Endpoint rate limit & progressive throttling tester
│       ├── poc_generator.py       ← Exploit PoC synthesizer (cURL, Python, HTML, code fixes)
│       ├── post_exploit.py        ← Protected post-compromise pipeline with query boundaries
│       ├── vuln_map.py            ← Site-wide multi-vector vulnerability crawler
│       ├── ai_analysis.py         ← Local AI & built-in offline intelligence engine
│       ├── screenshots.py         ← Headless Chromium screenshot engine via Playwright
│       ├── zap_integration.py     ← OWASP ZAP REST API controller
│       ├── reports.py             ← Safe JSON & HTML report generation engine
│       └── auto_login.py          ← Authorized browser session bootstrap helper
│
├── frontend/                      ← React 18 + Vite + Tailwind CSS cyberpunk UI
│   ├── src/
│   │   ├── config/tools.js        ← 38 Tool definitions, metadata, inputs, categories
│   │   ├── hooks/                 ← useToolRunner.js, useRunAll.js lifecycle managers
│   │   ├── lib/api.js             ← Centralized fetch wrapper targeting backend API
│   │   └── components/            ← Cyberpunk dashboard, forms, tables, PoC modal
│   └── dist/                      ← Production bundle served by FastAPI
│
├── wordlists/                     ← Wordlists for subdomains, paths, and passwords
├── reports/                       ← Auto-generated reports and SQLite database
├── .env.example                   ← Template environment configuration
├── key.env                        ← Local configuration store
├── install.bat                    ← Automated setup script
└── start.bat                      ← Build & start launcher
```

---

## Security Boundaries & Defenses

### 1. Centralized Target Validation (SSRF Boundary)
All outbound target requests pass through `validate_target_url(url, allow_private=...)`:
- **Allowed Schemes**: Only `http` and `https` schemes are permitted. Schemes like `file://`, `gopher://`, `dict://`, or `ftp://` are immediately rejected.
- **Embedded Credentials**: URLs containing userinfo like `http://user:password@target.com` are strictly forbidden.
- **Prohibited Address Ranges**:
  - `127.0.0.0/8` (IPv4 Loopback) and `::1` (IPv6 Loopback)
  - `0.0.0.0/8` (Unspecified)
  - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918 Private)
  - `169.254.0.0/16` and `fd00:ec2::254` (Link-local & AWS/GCP/Azure Cloud Metadata)
  - `100.64.0.0/10` (Carrier-Grade NAT)
  - `224.0.0.0/4` and `240.0.0.0/4` (Multicast and Reserved)
- **DNS Rebinding Protection**: Resolved IPs are checked immediately before connection.
- **Redirect Re-validation**: In multi-hop redirects, every destination URL is re-validated to ensure a public site cannot redirect the scanner into an internal host.
- **Authorized Lab / CTF Mode**: Set `BB_ALLOW_PRIVATE_TARGETS=true` or `BB_LOCAL_LAB_MODE=true` in environment configuration when testing local Docker containers, CTF challenges, or private lab targets.

### 2. Centralized HTTP Client
Network probes use `safe_request()` from `backend/security/http_client.py`:
- **Connection Timeout**: 5 seconds
- **Read Timeout**: 10 seconds
- **Total Timeout**: 15 seconds
- **Maximum Redirects**: 5 hops (each inspected against the SSRF boundary)
- **Maximum Response Size**: 5 MB stream bounding (prevents denial-of-service from malicious multi-gigabyte responses)
- **TLS Verification**: Defaults strictly to `verify=True`. Insecure TLS for self-signed certificates must be explicitly configured via `BB_ALLOW_INSECURE_TLS=true`.

### 3. Operator Authentication & Authorization
Sensitive exploitation and scanning endpoints are protected:
- **Authentication Endpoints**:
  - `POST /api/auth/login`: Accepts credentials and returns an expiring HMAC-SHA256 token.
  - `GET /api/auth/status`: Validates the active session.
  - `POST /api/auth/logout`: Revokes the active token.
- **Bootstrap Credentials**: Set via environment variables:
  ```env
  BB_ADMIN_USERNAME=admin
  BB_ADMIN_PASSWORD=your_secure_password
  BB_SECRET_KEY=generate_a_random_32_byte_secret_key
  ```
- **Protected Endpoints**:
  - `/api/post_exploit`
  - `/api/bruteforce`
  - `/api/auto_login`
  - `/api/password_cracker`
  - `/api/rate_limit`
  - `/api/zap`

### 4. Detection Accuracy & 4-Tier Taxonomy
Every vulnerability scanner adheres to authoritative confidence levels:
- **SSRF Scanner**: Probes AWS (`169.254.169.254`), GCP (`metadata.google.internal`), and Azure endpoints. Only confirmed when explicit metadata headers or recognized hypervisor signatures are returned by the remote target server. Injected request headers are never interpreted as proof of SSRF.
- **SQL Injection**: Calibrates against a baseline response, tests vendor-specific syntax errors (MySQL, PostgreSQL, MSSQL, Oracle, SQLite), and requires repeatable boolean true/false differentials. Never triggers on arbitrary 50-byte length variations.
- **XSS Scanner**: Injects dynamic random canaries and evaluates whether the reflected input breaks out of HTML tags, attribute boundaries, or script blocks without sanitization or HTML entity encoding.
- **LFI / Path Traversal**: Verifies exact file signatures (e.g. `root:.*:0:0:` for `/etc/passwd`, `\[extensions\]` for `win.ini`, or decoded PHP base64 markers).
- **SSTI Scanner**: Evaluates dynamic random prime arithmetic (e.g. `{{41*73}}` expecting `2993`) to confirm server-side template execution versus naive parameter reflection.
- **JWT Analyzer**: Distinguishes theoretical token header properties (e.g. `alg: none` present in client token) from confirmed server-side acceptance of unsigned tokens.
- **Cookie Analyzer**: Computes Shannon entropy on token values (rather than mistaking token length for entropy) and validates modern security flags (`Secure`, `HttpOnly`, `SameSite`, `__Host-`, `__Secure-`).

### 5. Report Security & Escaping
- **Stored XSS Elimination**: All dynamic fields rendered in HTML reports (`target`, `title`, `detail`, `recommendation`, `evidence`, `tool`) are escaped via `html.escape()`.
- **Path Traversal Protection**: Report export filenames are sanitized against directory traversal attacks (`../`, `..\`).
- **Secret Redaction**: Passwords, API tokens, Authorization headers, and private keys are scrubbed by default before saving or displaying reports.

### 6. PoC Synthesizer Escaping
Context-aware escaping is enforced across all generated Proof-of-Concept formats:
- **cURL / Shell**: Parameters and headers are quoted with `shlex.quote()`.
- **Python Scripts**: Strings are wrapped with `repr()` and parsed to ensure safe constants.
- **HTML Harnesses**: Form action and input values are attribute-escaped.
- **JavaScript**: Payloads are serialized with `json.dumps()`.

---

## Tool Reference (38 Tools across 7 Categories)

### 🔍 Reconnaissance
| Tool | Endpoint | Description |
|---|---|---|
| **IP Finder** | `POST /api/ip_finder` | Resolve IP addresses, detect CDN/WAF (Cloudflare, Akamai, CloudFront), ASN details, reverse DNS |
| **WHOIS Lookup** | `POST /api/whois` | Query domain registrar, registration/expiration dates, and contact data |
| **DNS Enumeration** | `POST /api/dns` | Query all DNS records: A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV |
| **Subdomain Enum** | `POST /api/subdomain` | Discover active subdomains via multi-threaded DNS resolution |
| **Subdomain Takeover** | `POST /api/subdomain_takeover` | Scan for dangling CNAME records pointing to unclaimed services (S3, GitHub Pages, etc.) |
| **Port Scanning** | `POST /api/portscan` | Scan TCP ports and fingerprint services across common, web, DB, or extended port sets |
| **TLS Inspection** | `POST /api/tls` | Analyze SSL/TLS certificates, handshake protocol versions (TLS 1.2/1.3), cipher suites, expiry, SANs |

### 📊 Analysis
| Tool | Endpoint | Description |
|---|---|---|
| **HTTP Headers** | `POST /api/headers` | Check missing security headers (HSTS, CSP, X-Frame-Options, Permissions-Policy) |
| **HTTP Security** | `POST /api/http_security` | Fingerprint technology stack, inspect redirect chains, detect server disclosures |
| **Security Files** | `POST /api/security_files` | Fetch `robots.txt`, `sitemap.xml`, `security.txt`, `.well-known/`, `crossdomain.xml` |
| **DNS Security** | `POST /api/dns_security` | Evaluate SPF records, DMARC policies, DKIM selector presence, and CAA records |
| **CORS Misconfig** | `POST /api/cors` | Test origin reflection, wildcard CORS, `null` origin, and generate browser data exfiltration PoCs |
| **Cookie Analyzer** | `POST /api/cookies` | Inspect Set-Cookie flags (`Secure`, `HttpOnly`, `SameSite`), prefix rules (`__Host-`, `__Secure-`), entropy |
| **Cloud Exposure** | `POST /api/cloud` | Scan for exposed AWS S3 buckets, Azure Blob containers, and Google Cloud Storage buckets |
| **JS Intelligence** | `POST /api/js_intel` | Scrape target JavaScript bundles to extract hidden API routes, endpoints, and hardcoded API tokens |

### 🔎 Scanning
| Tool | Endpoint | Description |
|---|---|---|
| **Page Discovery** | `POST /api/page_discover` | Recursive web crawler + wordlist brute-forcing to discover pages and administrative portals |
| **API Security** | `POST /api/api_security` | Discover OpenAPI/Swagger documentation, exposed REST endpoints, and unauthenticated routes |
| **GraphQL Auditor** | `POST /api/graphql` | Probe GraphQL endpoints for Introspection schemas, sensitive types, field suggestions, and batching DoS |
| **JWT Analyzer** | `POST /api/jwt_analyzer` | Decode JWTs, test `alg: none` and key-confusion vulnerabilities, crack weak HMAC secrets |
| **Sensitive Files** | `POST /api/sensitive_files` | Detect exposed `.env`, `.git`, backups, database dumps, and live regex-matched API keys |
| **Vuln Detection** | `POST /api/vuln_detection` | Scan for debug error traces, directory listings, software version disclosures, and CVE markers |
| **DB Login Scanner** | `POST /api/db_scanner` | Probe database ports (MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch) for unauthenticated access |
| **XSS Scanner** | `POST /api/xss` | Audit reflected Cross-Site Scripting (XSS) with context-aware canary breakouts |
| **LFI Scanner** | `POST /api/lfi` | Test Local File Inclusion & directory traversal payloads with signature verification |
| **Open Redirect** | `POST /api/open_redirect` | Probe parameters for verified external URL redirection via Location headers |
| **SSRF Scanner** | `POST /api/ssrf` | SSRF auditor testing AWS/GCP/Azure cloud metadata, loopback bypasses, and internal services |
| **SSTI Scanner** | `POST /api/ssti` | Server-Side Template Injection evaluator using dynamic arithmetic across Jinja2, Twig, etc. |
| **Prototype Pollution** | `POST /api/proto_pollution` | Prototype Pollution and HTTP Parameter Pollution (HPP) auditor injecting `__proto__` and duplicate keys |

### ⚡ Exploitation
| Tool | Endpoint | Description |
|---|---|---|
| **Password Cracker** | `POST /api/password_cracker` | Offline hash identifier and dictionary cracker for MD5, SHA1, SHA256, NTLM, and salted hashes |
| **SQL Injection** | `POST /api/sqli` | Test parameters against error-based, boolean-based blind, and time-based delay SQL injection |
| **Brute Force** | `POST /api/bruteforce` | Rate-bounded dictionary attack & credential stuffing engine with automatic CSRF token extraction |
| **Auth Logic Flaws** | `POST /api/auth_flaws` | Test authentication logic weaknesses: blank password submissions, SQLi bypass, default creds |
| **Rate Limit Tester** | `POST /api/rate_limit` | Rapid concurrent request stress-tester detecting HTTP 429 throttling and progressive backoff |
| **PoC Synthesizer** | `POST /api/poc` | Exploit Proof-of-Concept synthesizer generating cURL, Python `requests`, HTML harnesses, and patches |
| **Post-Exploit** | `POST /api/post_exploit` | Protected post-compromise pipeline: dumps MySQL/PostgreSQL schemas and scans authenticated pages |
| **Auto-Login** | `POST /api/auto_login` | Single-use expiring token generator for authenticated test session orchestration |

### 💀 Vulnerability Mapping, Intelligence & Reporting
| Tool | Endpoint | Description |
|---|---|---|
| **Vuln Map** | `POST /api/vuln_map` | Crawls target application and executes multi-vector security checks across all discovered endpoints |
| **AI Analysis** | `POST /api/ai_analysis` | 100% Local AI vulnerability intelligence (Built-in Offline Security Engine + Ollama/LM Studio support) |
| **Screenshots** | `POST /api/screenshots` | Captures high-resolution headless Chromium viewport or full-page scroll screenshots via Playwright |
| **OWASP ZAP** | `POST /api/zap` | Triggers spidering, passive scanning, or full active vulnerability scanning via OWASP ZAP REST API |
| **Report Manager** | `POST /api/reports/save` | Generates and exports sanitized JSON and HTML security assessment reports |

---

## Configuration & Environment Variables

Copy `.env.example` to `.env` or update `key.env` using standard `KEY=value` syntax:

| Variable | Default | Purpose |
|---|---|---|
| `BB_ENV` | `production` | Deployment mode (`production` disables reload; `development` enables reload) |
| `BB_HOST` | `127.0.0.1` | Local listening IP (use `127.0.0.1` for local-only, `0.0.0.0` for LAN access) |
| `BB_PORT` | `8000` | Backend API port |
| `BB_ALLOW_PRIVATE_TARGETS` | `false` | Set to `true` to scan RFC1918, loopback, or private lab targets in CTFs |
| `BB_LOCAL_LAB_MODE` | `false` | Alias to permit internal target validation in authorized lab environments |
| `BB_ALLOW_INSECURE_TLS` | `false` | Set to `true` only when assessing targets with self-signed TLS certificates |
| `BB_MAX_RESPONSE_SIZE` | `5242880` | Maximum HTTP response size in bytes (5 MB stream bound) |
| `BB_ADMIN_USERNAME` | `admin` | Operator username for authentication |
| `BB_ADMIN_PASSWORD` | `admin` | Operator password for authentication |
| `BB_SECRET_KEY` | *(auto-generated)* | 32-byte secret key for signing authentication tokens |
| `BB_TOKEN_EXPIRE_HOURS` | `24` | Token lifespan in hours |
| `BB_CORS_ORIGINS` | `http://localhost:5173,...` | Comma-separated list of allowed CORS origins |
| `LOCAL_LLM_URL` | `http://127.0.0.1:11434` | Ollama or LM Studio endpoint for local AI analysis |
| `LOCAL_LLM_MODEL` | `deepseek-r1:latest` | Local LLM model identifier |
| `ZAP_URL` | `http://localhost:8080` | OWASP ZAP API base URL |
| `ZAP_API_KEY` | `""` | OWASP ZAP API key |

---

## Installation & Running

### Prerequisites
- Python 3.11+ recommended (Python 3.8+ supported)
- Node.js 18+ and npm

### 1. Setup Backend Virtual Environment
```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

pip install -r backend/requirements.txt
```

### 2. Setup Frontend
```bash
cd frontend
npm install
npm run build
cd ..
```

### 3. Run Automated Tests
```bash
# Run Centralized Security & Correctness Suite
.venv\Scripts\python backend/tests/test_security_suite.py

# Run Password & Brute-Force Testing Suite
.venv\Scripts\python backend/tests/test_password_suite.py
```

### 4. Start the Application
#### Development Mode
```bash
# Backend with hot-reloading
python backend/main.py --dev

# Frontend dev server in separate terminal
cd frontend && npm run dev
```

#### Production Mode (Secure Local Default)
```bash
# Binds to 127.0.0.1:8000 with reload disabled and production headers
python backend/main.py
```
Open your browser to: `http://localhost:8000` (or `http://localhost:5173` if running Vite dev server).

---

## Legal & Compliance Notice

This framework is built strictly for **authorized security testing**, research, and educational purposes. Ensure you have written authorization from system owners before performing any assessment.
