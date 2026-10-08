# BB-SUITE v4.0 — System Architecture & Technical Documentation (Strix Enhanced)

> **AUTHORIZATION NOTICE**: This platform is designed exclusively for authorized penetration testing, bug bounty programs, and security research on infrastructure you own or have explicit written authorization to test.

---

## 1. System Overview

**BB-SUITE v4.0** is an enterprise-grade automated security testing and bug bounty platform inspired by multi-agent autonomous penetration testing systems like **Strix**. It integrates active reconnaissance, web application vulnerability scanning, automated exploitation, AI-driven security analysis, asset tracking, post-exploitation pipelines, and verified Proof-of-Concept (PoC) generation into a single unified interface with one-click batch execution.

### Key Capabilities at a Glance
- **38 Security Tools** organized across 7 core domains with zero toy/superficial utilities.
- **Strix-Class Exploit PoC Verification**: Zero-false-positive philosophy generating copy-pasteable cURL commands, Python `requests` exploit scripts, browser-executable HTML exfiltration harnesses, and developer remediation patches.
- **Advanced Attack Surface Coverage**:
  - **SSRF Scanner**: Probes AWS, GCP, Azure, and Kubernetes cloud metadata APIs, loopback bypasses (decimal/hex/IPv6), and internal service ports.
  - **SSTI Scanner**: Evaluates mathematical polyglot injections across Jinja2, Twig, Freemarker, Smarty, Ruby ERB, and Spring EL.
  - **GraphQL Auditor**: Queries introspection schemas, identifies sensitive object types (`User`, `Admin`, `Token`), checks field suggestions, and audits batch query DoS amplification.
  - **Prototype Pollution & HPP**: Probes client/server prototype inheritance corruptions (`__proto__`, `constructor.prototype`) and HTTP Parameter Pollution precedence.
  - **PoC Synthesizer**: Automatically formats reproducible exploit chains with copy-paste execution instructions and defensive patches.
- **Consolidated Architecture**: Merged redundant modules (`stuffing` into `bruteforce`, `session_hijack` into `cookies`, `credential_exposure` into `sensitive_files`, `aitm` into `headers`/`http_security`, `wordlist` into `page_discover`) while maintaining 100% backward compatibility via legacy API wrappers.
- **One-Click Batch Execution ("Perform All Tools")**: Executes all security modules concurrently in rate-limited batches with live visual status tracking.
- **Local AI Vulnerability Intelligence**: Built-in Offline Security Intelligence Engine and local LLM connector (Ollama, LM Studio) for automated finding triage without cloud API keys, external dependencies, or token costs.
- **Post-Exploitation Pipeline**: Automatic database schema dumping (MySQL / PostgreSQL) and authenticated page crawling when login credentials are cracked.
- **SQLite Database Persistence**: History tracking, vulnerability findings store, and asset inventory repository (`reports/bbsuite.db`).
- **OWASP ZAP REST Integration**: Direct interface to trigger spidering and active scanning via OWASP ZAP.
- **Automated Reporting**: Auto-generates standalone JSON and dark-themed responsive HTML vulnerability reports.

---

## 2. Technical Stack & System Architecture

The platform follows a decoupled client-server architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│                React 18 + Tailwind CSS Frontend                 │
│   (Vite SPA with Cyberpunk Dark Theme & Interactive PoC Viewer) │
└────────────────────────────────┬────────────────────────────────┘
                                 │ HTTP REST API / JSON (54 Endpoints)
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FastAPI Python Backend                       │
│    (Async Uvicorn ASGI Server, Pydantic Validation Engine)      │
└────────┬───────────────────────┬────────────────────────┬───────┘
         │                       │                        │
         ▼                       ▼                        ▼
┌───────────────────┐ ┌────────────────────┐ ┌────────────────────┐
│ 38 Security Tools │ │ SQLite Database    │ │ AI & External APIs │
│ (Tools Directory) │ │ (reports/bbsuite.db│ │ (OpenRouter, ZAP,  │
│ + PoC Synthesizer │ │ Asset & Scan Store)│ │  Playwright)       │
└───────────────────┘ └────────────────────┘ └────────────────────┘
```

### Backend Architecture
- **Framework**: Python 3.8+ with [FastAPI](https://fastapi.tiangolo.com/)
- **Server**: [Uvicorn](https://www.uvicorn.org/) (ASGI Web Server) running on port `8000`
- **Asynchronous HTTP Client**: `httpx` for non-blocking network requests with timeout and redirection controls
- **Data Validation & Schemas**: `pydantic` request/response models in `backend/models.py`
- **Security Utilities**: `dnspython` (DNS queries), `cryptography` (X.509 TLS certificate parsing), `Playwright` (Headless browser automation)
- **Database Engine**: `sqlite3` embedded database (`reports/bbsuite.db`)

### Frontend Architecture
- **Framework**: [React 18](https://react.dev/) built with [Vite](https://vitejs.dev/)
- **Styling**: [Tailwind CSS](https://tailwindcss.com/) customized with cyberpunk aesthetics (dark mode background `#050508`, CRT scanline effects, glowing matrix color palette)
- **State & Hooks Management**: Custom React hooks:
  - `useToolRunner.js`: Handles single tool execution lifecycle, error catching, and state transitions.
  - `useRunAll.js`: Orchestrates parallel batch execution across all 38 tools in batches of 5.
- **API Client Layer**: Native `fetch` wrapper module (`lib/api.js`) targeting FastAPI endpoints.

---

## 3. Directory & Workspace Structure

```
c:\xampp\htdocs\sql2\
├── backend/                       ← FastAPI Python Server
│   ├── main.py                    ← App entry point, 54 API routes, backward compatibility aliases
│   ├── database.py                ← SQLite database manager (history, assets, findings)
│   ├── key_loader.py              ← API key parser for key.env
│   ├── models.py                  ← Pydantic request models
│   ├── requirements.txt           ← Python dependency manifest
│   └── tools/                     ← 38 Security tool modules + utilities
│       ├── utils.py               ← Shared utilities (URL cleaning, HTTP wrappers, finding generators)
│       ├── whois.py               ← WHOIS protocol client
│       ├── dns_enum.py            ← DNS record enumerator
│       ├── subdomain.py           ← Subdomain brute-forcer
│       ├── subdomain_takeover.py  ← Dangling CNAME takeover scanner
│       ├── portscan.py            ← TCP port scanner & service detector
│       ├── tls_inspect.py         ← SSL/TLS certificate inspector
│       ├── ip_finder.py           ← IP resolver, CDN/WAF detector, IP geolocator
│       ├── headers.py             ← Security header auditor
│       ├── http_security.py       ← Tech stack fingerprinter & redirect checker
│       ├── security_files.py      ← Standard security text file fetcher
│       ├── dns_security.py        ← SPF, DMARC, DKIM, CAA security validator
│       ├── cors_check.py          ← CORS misconfiguration tester & HTML exfiltration PoC generator
│       ├── cookies.py             ← Set-Cookie flags, __Host- prefixes, session entropy & fixation
│       ├── cloud.py               ← Cloud storage bucket exposure finder (S3, Azure, GCP)
│       ├── js_intel.py            ← JS secret scanner & endpoint extractor
│       ├── page_discover.py       ← Web crawler & admin panel locator + dictionary discovery
│       ├── api_security.py        ← Swagger/OpenAPI security tester
│       ├── graphql_scanner.py     ← [NEW] GraphQL schema introspection & batching DoS auditor
│       ├── jwt_analyzer.py        ← JWT decoder, secret cracker, and claims auditor
│       ├── sensitive_files.py     ← Sensitive files & regex secret token detector (AWS, Slack, GCP, PEM)
│       ├── vuln_detection.py      ← Information disclosure & CVE marker scanner
│       ├── db_scanner.py          ← Exposed DB port scanner (MySQL, PG, Mongo, Redis, Elasticsearch)
│       ├── xss_scanner.py         ← Reflected Cross-Site Scripting (XSS) scanner
│       ├── lfi_scanner.py         ← Local File Inclusion (LFI) & path traversal tester
│       ├── open_redirect.py       ← Open URL redirection vulnerability tester
│       ├── ssrf_scanner.py        ← [NEW] SSRF auditor (cloud metadata, IP bypasses, cURL PoCs)
│       ├── ssti_scanner.py        ← [NEW] Server-Side Template Injection engine tester
│       ├── proto_pollution.py     ← [NEW] Prototype Pollution & HTTP Parameter Pollution tester
│       ├── password_cracker.py    ← Offline hash identifier & cracker (MD5, SHA1, SHA256, NTLM)
│       ├── sqli.py                ← SQL Injection tester (error, boolean, time-based)
│       ├── bruteforce.py          ← Login brute-force & credential stuffing engine with CSRF support
│       ├── auth_flaws.py          ← Authentication logic flaw tester
│       ├── rate_limit.py          ← Endpoint rate limiting stress tester
│       ├── poc_generator.py       ← [NEW] Exploit PoC synthesizer (cURL, Python, HTML, Patch)
│       ├── post_exploit.py        ← Post-compromise DB dumper & auth crawler
│       ├── vuln_map.py            ← Site-wide vulnerability mapping crawler
│       ├── ai_analysis.py         ← Local AI & built-in offline intelligence engine
│       ├── screenshots.py         ← Playwright headless screenshot engine
│       ├── zap_integration.py     ← OWASP ZAP REST API controller
│       └── reports.py             ← Report generator (HTML & JSON formatting)
│
├── frontend/                      ← React + Tailwind Frontend Source & Build
│   ├── src/
│   │   ├── App.jsx                ← Root component & view router
│   │   ├── main.jsx               ← React DOM entry point
│   │   ├── index.css              ← Design system, scanlines, glow keyframes, Tailwind styles
│   │   ├── config/
│   │   │   └── tools.js           ← Tool definitions, metadata, inputs, categories (38 tools)
│   │   ├── hooks/
│   │   │   ├── useToolRunner.js   ← Execution state manager for single tools
│   │   │   └── useRunAll.js       ← Parallel execution orchestrator (batches of 5)
│   │   ├── lib/
│   │   │   └── api.js             ← API fetch layer
│   │   └── components/
│   │       ├── Header.jsx         ← Navigation header & global target selector
│   │       ├── Sidebar.jsx        ← Category & tool navigation panel
│   │       ├── Dashboard.jsx      ← Main dashboard, live status grid, "Perform All" button
│   │       ├── ToolPanel.jsx      ← Dynamic form renderer for tools
│   │       ├── Results.jsx        ← Multi-tab results viewer with dedicated PoC block & copy
│   │       ├── Findings.jsx       ← Color-coded severity cards
│   │       ├── DataTable.jsx      ← Paginated & searchable tabular data viewer
│   │       ├── CrackBanner.jsx    ← Alert panel for cracked credentials & DB dump triggers
│   │       ├── ReportPanel.jsx    ← Report history manager & viewer
│   │       └── Welcome.jsx        ← Landing screen with category stats & OWASP Top 10 links
│   ├── dist/                      ← Compiled static distribution served by FastAPI
│   ├── package.json               ← NPM dependencies & scripts
│   ├── vite.config.js             ← Vite build bundler configuration
│   ├── tailwind.config.js         ← Tailwind theme customization
│   └── postcss.config.js          ← PostCSS setup
│
├── wordlists/                     ← Wordlist repository for brute-forcing
│   ├── subdomains.txt             ← ~150 common subdomain prefixes
│   ├── common_paths.txt           ← ~200 sensitive paths & endpoints
│   └── passwords.txt              ← ~100 common passwords for brute-force tests
│
├── reports/                       ← Persistent storage for reports & database
│   ├── bbsuite.db                 ← SQLite database file (Targets, Scans, Findings, Assets)
│   └── report_<target>_<ts>.{json,html} ← Auto-generated scan reports
│
├── install.bat                    ← Environment initialization & dependency setup
├── start.bat                      ← Service launch script (process cleanup, build, backend start)
├── key.env                        ← API key configuration store (ZAP, OpenRouter)
└── README.md                      ← Quick start & architecture overview
```

---

## 4. Complete Tool Reference (38 Tools across 7 Categories)

### Category 1: Reconnaissance (RECON)
| Tool Name | API Endpoint | Description | Key Output / Indicators |
|---|---|---|---|
| **IP Finder** | `POST /api/ip_finder` | Resolves A/AAAA records, detects CDNs (Cloudflare, Akamai, CloudFront) & WAFs, geolocates server, fetches ISP/ASN details, performs reverse DNS lookups. | IP addresses, CDN/WAF presence, Country/City, ASN/ISP details. |
| **WHOIS Lookup** | `POST /api/whois` | Queries WHOIS servers for domain registration details, registrar name, creation/expiry dates, and name servers. | Domain registrar, expiration dates, contact details. |
| **DNS Enumeration** | `POST /api/dns` | Queries all major DNS record types: A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV. | Mail servers, nameservers, TXT verifications, CNAME records. |
| **Subdomain Enum** | `POST /api/subdomain` | Brute-forces subdomains via multi-threaded DNS resolution against configurable wordlists (small/medium/large). | Discovered live subdomains & IP mappings. |
| **Subdomain Takeover** | `POST /api/subdomain_takeover` | Scans for dangling CNAME records pointing to unclaimed third-party services (GitHub Pages, Heroku, AWS S3, Netlify, Azure, Shopify, Tumblr). | Vulnerable subdomains, target service name, CNAME target. |
| **Port Scanning** | `POST /api/portscan` | Scans TCP ports for open services using native sockets or Nmap fallback. Supports common (27), web, database, or extended (100) port sets. | Open ports, service names, protocol versions. |
| **TLS Inspection** | `POST /api/tls` | Inspects SSL/TLS certificates, handshake protocol versions (TLS 1.2/1.3), cipher suites, expiration dates, and Subject Alternative Names (SANs). | Cert validity, expiration warnings, weak ciphers, SAN domains. |

---

### Category 2: Analysis (ANALYSIS)
| Tool Name | API Endpoint | Description | Key Output / Indicators |
|---|---|---|---|
| **HTTP Headers** | `POST /api/headers` | Analyzes HTTP response headers for missing security protections (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy). | Security header gaps, misconfigurations, server disclosure headers. |
| **HTTP Security** | `POST /api/http_security` | Fingerprints target technology stack (web server, frameworks, OS), inspects HTTP redirect chains, and checks for verbose error messages. | Detected technologies, redirect paths, server signature leaks. |
| **Security Files** | `POST /api/security_files` | Fetches standard web security metadata files: `robots.txt`, `sitemap.xml`, `security.txt`, `.well-known/`, and `crossdomain.xml`. | Disallowed paths, sitemap endpoints, security contact details. |
| **DNS Security** | `POST /api/dns_security` | Evaluates email spoofing defenses by inspecting SPF records, DMARC policies, DKIM selector presence, and CAA records. | SPF syntax errors, DMARC `p=none` policies, email spoofing risk scores. |
| **CORS Misconfig** | `POST /api/cors` | Tests Access-Control-Allow-Origin headers with crafted requests (arbitrary origin, reflection, `null` origin, trusted prefix/suffix bypasses) and generates browser exfiltration PoCs. | Insecure CORS policies, credential reflection flags (`ACAC: true`), HTML PoC. |
| **Cookie Analyzer** | `POST /api/cookies` | Inspects Set-Cookie headers for security flags (`Secure`, `HttpOnly`, `SameSite=Strict/Lax/None`), `__Host-`/`__Secure-` prefixes, session token entropy, and predictable session sequence checks. | Missing security flags, vulnerable cookie scope settings, session fixation vectors. |
| **Cloud Exposure** | `POST /api/cloud` | Probes for publicly accessible cloud storage containers across Amazon Web Services (S3 Buckets), Microsoft Azure (Blob Containers), and Google Cloud Platform (GCP Storage). | Exposed cloud bucket URLs, read/write permissions status. |
| **JS Intelligence** | `POST /api/js_intel` | Scrapes target JavaScript files to discover internal API routes, hidden endpoints, hardcoded API keys/secrets, WebSocket URLs, and GraphQL endpoints. | Extracted endpoints, leaked credentials/tokens, developer comments. |

---

### Category 3: Scanning (SCANNING)
| Tool Name | API Endpoint | Description | Key Output / Indicators |
|---|---|---|---|
| **Page Discovery** | `POST /api/page_discover` | Recursive web crawler combined with wordlist brute-forcing to discover all site pages, administrative portals, and login interfaces. | Complete URL tree, status codes, identified admin panels. |
| **API Security** | `POST /api/api_security` | Probes for OpenAPI/Swagger documentation (`/swagger-ui.html`, `/api-docs`), exposed endpoints, and evaluates unauthenticated REST routes. | Exposed Swagger UIs, unauthenticated endpoints. |
| **GraphQL Auditor** | `POST /api/graphql` | Probes GraphQL endpoints (`/graphql`, `/api/graphql`) for enabled Introspection, sensitive object models (`User`, `Admin`, `Token`, `Payment`), field suggestion leaks, and batch query DoS amplification. | Introspection schema status, sensitive types list, suggestions enabled, batching risk. |
| **JWT Analyzer** | `POST /api/jwt_analyzer` | Decodes JSON Web Tokens (JWT), tests algorithm vulnerabilities (`alg: none`, HMAC/RSA key confusion), attempts offline secret cracking, and checks expiration/issuer claims. | Decoded header & payload, algorithm flaws, cracked secrets. |
| **Sensitive Files** | `POST /api/sensitive_files` | Checks for publicly accessible `.env`, `.git`, database backups (`.sql`, `.tar.gz`), configuration files, and audits accessible text for high-entropy regex tokens (AWS, Slack, GCP, PEM private keys, DB connection URIs). | Exposed configuration files, source code repositories, credential leaks. |
| **Vuln Detection** | `POST /api/vuln_detection` | Scans for verbose PHP/Python error messages, directory listing vulnerabilities, out-of-date software version disclosures, and known CVE markers. | Exposed error tracebacks, directory listing paths, software version alerts. |
| **DB Login Scanner** | `POST /api/db_scanner` | Probes database ports (MySQL 3306, PostgreSQL 5432, MongoDB 27017, Redis 6379, Elasticsearch 9200) for unauthenticated access or default credentials. | Accessible database services, unauthenticated DB prompts. |
| **XSS Scanner** | `POST /api/xss` | Tests input parameters for reflected Cross-Site Scripting (XSS) with context-aware polyglot payloads and unescaped script tag reflection. | Reflected payload evidence, vulnerable parameters, execution context. |
| **LFI Scanner** | `POST /api/lfi` | Tests parameters for Local File Inclusion and directory traversal using path traversal payloads (`/etc/passwd`, `C:\Windows\win.ini`, PHP wrappers). | Traversal confirmation, disclosed file contents, vulnerable parameters. |
| **Open Redirect** | `POST /api/open_redirect` | Injects redirection test URLs into redirection parameters (`next`, `return`, `redirect_to`) to detect open redirect vulnerabilities. | Redirection target verification, vulnerable parameter list. |
| **SSRF Scanner** | `POST /api/ssrf` | Tests URL parameters for Server-Side Request Forgery against AWS/GCP/Azure/Kubernetes metadata APIs, loopback representations (decimal dword, hex, IPv6), internal service ports, and protocol wrappers. | Cloud metadata leaks, internal loopback responses, cURL PoC commands. |
| **SSTI Scanner** | `POST /api/ssti` | Injects mathematical polyglot expressions (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `{{7*'7'}}`) to detect template evaluation and identify specific template engines (Jinja2, Twig, Freemarker, Smarty, Ruby ERB, Spring EL). | Evaluated arithmetic results, template engine identity, injection PoCs. |
| **Prototype Pollution** | `POST /api/proto_pollution` | Tests for client and server prototype pollution via `__proto__` and `constructor.prototype` query and JSON parameters, and audits HTTP Parameter Pollution (HPP) precedence. | Polluted properties, reflected object keys, HPP precedence behavior. |

---

### Category 4: Exploitation (EXPLOIT)
| Tool Name | API Endpoint | Description | Key Output / Indicators |
|---|---|---|---|
| **Password Cracker** | `POST /api/password_cracker` | Identifies hash algorithms and performs dictionary cracking for MD5, SHA1, SHA256, and NTLM hashes. | Identified hash types, plaintext cracked passwords. |
| **SQL Injection** | `POST /api/sqli` | Tests URL parameters against error-based, boolean-based blind, and time-based delay SQL injection payloads. | Vulnerable parameters, database engine type, payload confirmation. |
| **Brute Force** | `POST /api/bruteforce` | Performs dictionary attacks and credential stuffing (`user:pass` combo lists) against HTTP POST login forms with auto CSRF extraction. | Valid username/password combinations, login success confirmations. |
| **Auth Logic Flaws** | `POST /api/auth_flaws` | Tests authentication logic weaknesses: blank password submissions, SQLi authentication bypasses (`' OR '1'='1`), default credentials, and type juggling. | Authentication bypass vulnerabilities, default account access. |
| **Rate Limit Tester** | `POST /api/rate_limit` | Sends rapid concurrent requests to test endpoint rate limiting posture, detecting HTTP 429 status codes, `Retry-After` headers, and server stability under load. | Rate limit enforcement status, burst threshold, 429 responses. |
| **PoC Synthesizer** | `POST /api/poc` | Generates verified Proof-of-Concept exploit code: copy-paste cURL commands, standalone Python `requests` exploit scripts, browser HTML exfiltration harnesses, and developer remediation patches. | Ready-to-run exploit scripts, cURL commands, exfiltration HTML, patch code. |
| **Post-Exploit** | `POST /api/post_exploit` | Triggered upon successful credential cracking: dumps MySQL / PostgreSQL databases and crawls authenticated session pages. | Database schemas, dumped sample tables, internal authenticated endpoints. |

---

### Category 5: Vulnerability Mapping (VULN MAP)
| Tool Name | API Endpoint | Description | Key Output / Indicators |
|---|---|---|---|
| **Vuln Map** | `POST /api/vuln_map` | Crawls target web application and automatically executes multi-vector vulnerability checks across every discovered page. | Interactive site vulnerability map, page-by-page risk breakdown. |

---

### Category 6: Intelligence (INTELLIGENCE)
| Tool Name | API Endpoint | Description | Key Output / Indicators |
|---|---|---|---|
| **AI Analysis** | `POST /api/ai_analysis` | 100% Local AI vulnerability intelligence (Built-in Heuristic Engine + Ollama/LM Studio support) to generate executive summaries, attack graphs, and remediation roadmaps. | AI risk score, attack vector graphs, prioritized actions, remediation guide. |
| **Screenshots** | `POST /api/screenshots` | Uses Playwright headless Chromium browser to capture viewport or full-page scroll screenshots of web applications. | High-resolution PNG base64 screenshots. |

---

### Category 7: OWASP ZAP (ZAP)
| Tool Name | API Endpoint | Description | Key Output / Indicators |
|---|---|---|---|
| **OWASP ZAP** | `POST /api/zap` | Interfaces with OWASP ZAP REST API (`http://localhost:8080`) to trigger automated spidering, passive scanning, or full active vulnerability scanning. | ZAP alert summary, risk breakdown, passive/active scan IDs. |

---

## 5. Advanced Features & Workflows

### 5.1 One-Click Batch Execution ("Perform All Tools")
When a target URL (e.g., `https://example.com`) is set in the Header:
1. The user clicks **`▶▶ PERFORM ALL TOOLS`** on the Dashboard.
2. `useRunAll.js` splits all 38 tools into parallel execution batches (5 tools per batch).
3. The Dashboard updates a live progress grid showing tool states (`pending` ➔ `running` ➔ `completed` / `failed`).
4. Upon completion:
   - Severity counters (Critical, High, Medium, Low, Info, Pass) are recalculated.
   - The scan session is persisted to `reports/bbsuite.db`.
   - The full report is auto-saved as both `reports/report_<domain>_<timestamp>.json` and `reports/report_<domain>_<timestamp>.html`.

### 5.2 Automated Post-Exploitation Pipeline
When **Brute Force** or **Auth Logic Flaws** successfully crack credentials:
1. The UI displays a glowing alert banner: `██ LOGIN CRACKED ██` along with the cracked credentials (`user:pass`).
2. A button **`▶ DUMP DATABASE + SCAN AUTHENTICATED PAGES`** appears.
3. Upon clicking:
   - The backend attempts direct database connections (`pymysql` for MySQL, `psycopg2` for PostgreSQL) on the target host.
   - If successful, it dumps database names, table schemas, and sample records.
   - It searches for database administration panels (`/phpmyadmin`, `/adminer`, `/pma`).
   - It creates an authenticated HTTP session using the cracked credentials and crawls internal protected endpoints.

### 5.3 Local AI Security Intelligence Engine
The **AI Analysis** tool runs 100% locally with zero external API dependencies or cloud token limits. It features a built-in deterministic Offline Security Intelligence Engine that correlates findings, computes CVSS metrics, models multi-stage attack chains, and produces structured remediation roadmaps. It also natively supports local LLMs running via Ollama (`http://localhost:11434`) or LM Studio (`http://localhost:1234/v1`), falling back seamlessly to the built-in offline engine if the local LLM server is stopped.

### 5.4 Embedded SQLite Database Schema (`reports/bbsuite.db`)
Managed by `backend/database.py`, the database tracks scans across sessions:

```sql
CREATE TABLE targets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    url        TEXT NOT NULL UNIQUE,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER REFERENCES targets(id),
    started_at  TEXT,
    finished_at TEXT,
    duration_s  REAL DEFAULT 0,
    tool_count  INTEGER DEFAULT 0,
    sev_counts  TEXT DEFAULT '{}'
);

CREATE TABLE findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER REFERENCES scans(id),
    tool           TEXT,
    severity       TEXT,
    title          TEXT,
    detail         TEXT,
    recommendation TEXT,
    created_at     TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE assets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id     INTEGER REFERENCES targets(id),
    asset_type    TEXT,
    value         TEXT,
    extra         TEXT DEFAULT '{}',
    discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(target_id, asset_type, value)
);
```

### 5.5 Strix-Class Verified PoC Generation & Remediation Engine
Modeled after **Strix's zero-false-positive testing philosophy**, high-severity vulnerability findings are paired with concrete, reproducible Proof-of-Concept artifacts:
- **`poc_generator`**: Synthesizes standalone cURL commands, Python `requests` scripts, automated browser HTML CSRF/CORS exfiltration forms, and code-level remediation patches.
- **`cors_check`**: Automatically compiles an interactive browser HTML PoC with an embedded JavaScript fetch harness to prove cross-origin data exfiltration with credentials.
- **`ssrf_scanner` & `ssti_scanner`**: Attach exact cURL replication commands to findings so security analysts can reproduce responses directly from the CLI.
- **Interactive Results UI**: The React `Results.jsx` component automatically detects exploit code or cURL commands in tool outputs, expanding a dedicated `⚡ EXPLOIT PROOF-OF-CONCEPT (PoC) & CODE` terminal with a 1-click clipboard copy button.

### 5.6 Legacy Compatibility & Tool Consolidation
To prevent fragmentation while maintaining high-impact tooling:
1. **`stuffing.py`** was merged into **`bruteforce.py`** (adds `credentials` list support to dictionary attacks).
2. **`session_hijack.py`** was merged into **`cookies.py`** (adds `__Host-` prefixes, session ID entropy, and predictable sequence tests).
3. **`credential_exposure.py`** was merged into **`sensitive_files.py`** (adds regex scanning for AWS, Slack, GCP, PEM private keys, and DB URIs).
4. **`aitm.py`** was removed (fully covered by `headers.py` HSTS enforcement and `http_security.py` redirect inspection).
5. **`wordlist.py`** was removed (fully covered by `page_discover.py` crawling and dictionary wordlist probes).

*All 5 legacy endpoints (`/api/stuffing`, `/api/session_hijack`, `/api/credential_exposure`, `/api/wordlist`, `/api/aitm`) remain functional as backward-compatible wrapper routes in `backend/main.py`.*

---

## 6. Unified API Data Contract & Severity Matrix

### 6.1 Standard JSON Response Format
Every tool endpoint returns a standardized JSON structure:

```json
{
  "success": true,
  "data": {
    "summary": {
      "Target": "https://example.com",
      "Scan Time": "2026-08-01 22:30:00"
    },
    "findings": [
      {
        "severity": "critical",
        "title": "Exposed .env Configuration File",
        "detail": "Found accessible environment file containing DB passwords at https://example.com/.env",
        "recommendation": "Block access to .env files in web server rules."
      }
    ],
    "records": [
      { "URL": "https://example.com/.env", "Status": 200, "Size": "1.2 KB" }
    ],
    "record_columns": ["URL", "Status", "Size"],
    "raw": "RAW RESPONSE OR LOG TEXT"
  },
  "error": ""
}
```

### 6.2 Severity Level Classification

| Severity | UI Color | HEX Code | Definition |
|---|---|---|---|
| `critical` | 🔴 Red | `#ef4444` | Directly exploitable vulnerability leading to full system compromise or unauthenticated data leak. |
| `high` | 🟠 Orange | `#f97316` | Significant vulnerability requiring immediate remediation (e.g., SQLi, Auth Bypass, CORS reflection). |
| `medium` | 🟡 Yellow | `#eab308` | Moderate security flaw or missing defense-in-depth control (e.g., missing CSP, weak JWT secret). |
| `low` | 🔵 Blue | `#3b82f6` | Minor configuration issue or low-impact informational risk (e.g., missing HSTS, verbose server header). |
| `info` | 🩵 Cyan | `#06b6d4` | Informational intelligence asset (e.g., DNS record, open port, WHOIS registrant). |
| `pass` | 🟢 Green | `#22c55e` | Security check passed — control is correctly implemented. |

---

## 7. Operational Workflow & Developer Guide

### 7.1 First-Time Setup
Run `install.bat` from the root directory. It performs the following:
1. Verifies Python 3.8+ and Node.js 18+ installations.
2. Creates a Python virtual environment (`.venv`).
3. Installs Python packages from `backend/requirements.txt`.
4. Installs Node modules in `frontend/`.

### 7.2 Running the Application
Run `start.bat` from the root directory. The script executes the following automated workflow:
1. Cleans up stale Python processes listening on port `8000`.
2. Compiles the React frontend using `npm run build` into `frontend/dist/`.
3. Launches the FastAPI backend using `.venv\Scripts\python.exe main.py` in a separate process.
4. Polls `http://localhost:8000` until responsive.
5. Launches the default web browser targeting `http://localhost:8000`.

### 7.3 API Keys Configuration (`key.env`)
Place external API keys in `key.env` at the project root:

```env
ZAP API: fndorqfot05j2bg625a12uq0ag
OpenRouter Key: sk-or-v1-your-openrouter-key-here
```

### 7.4 How to Add a New Security Tool

#### Step 1: Create Backend Module (`backend/tools/my_new_tool.py`)
```python
from __future__ import annotations
from fastapi import APIRouter
from models import TargetReq
from tools.utils import clean_url, ok, f

router = APIRouter(tags=["custom"])

@router.post("/my_new_tool")
async def run_my_new_tool(req: TargetReq):
    url = clean_url(req.target)
    findings = []
    
    # Tool logic here
    findings.append(f("info", "Test Finding", f"Scanned {url}", "No action required"))
    
    return ok({
        "summary": {"Target": url},
        "findings": findings,
        "records": [],
        "record_columns": []
    })
```

#### Step 2: Register Endpoint (`backend/main.py`)
```python
from tools.my_new_tool import router as my_new_tool_r

# Append to ALL_ROUTERS list:
ALL_ROUTERS = [ ..., my_new_tool_r ]
```

#### Step 3: Add Frontend Config (`frontend/src/config/tools.js`)
```javascript
my_new_tool: T(
  'My New Tool', '🔧',
  'Description of what my new tool does.',
  [{ name: 'target', label: 'URL', type: 'text', autofill: 'url' }]
),

// Add 'my_new_tool' to the appropriate category in CATEGORIES array
```

#### Step 4: Build & Restart
Run `start.bat` to rebuild the frontend and launch the backend.

---

## 8. Compliance & Legal Notice

BB-SUITE is strictly intended for legal security testing, authorized penetration testing assessments, bug bounty testing within specified scope parameters, and educational cybersecurity research. Operating this platform against targets without explicit, written permission from the asset owner is strictly prohibited and illegal under applicable laws (e.g., Computer Fraud and Abuse Act, Computer Misuse Act).
