export const CATEGORIES = [
  {
    id: 'recon', label: 'RECON', icon: '◎',
    tools: ['ip_finder', 'whois', 'dns', 'subdomain', 'subdomain_takeover', 'portscan', 'tls'],
  },
  {
    id: 'analysis', label: 'ANALYSIS', icon: '◆',
    tools: ['headers', 'http_security', 'security_files', 'dns_security', 'cors', 'cookies', 'cloud', 'js_intel'],
  },
  {
    id: 'scanning', label: 'SCANNING', icon: '◇',
    tools: ['page_discover', 'api_security', 'graphql_scanner', 'jwt_analyzer', 'sensitive_files', 'vuln_detection', 'db_scanner', 'xss_scanner', 'lfi_scanner', 'open_redirect', 'ssrf_scanner', 'ssti_scanner', 'proto_pollution'],
  },
  {
    id: 'exploit', label: 'EXPLOITATION', icon: '▲',
    tools: ['password_cracker', 'sqli', 'bruteforce', 'auth_flaws', 'rate_limit', 'poc_generator'],
  },
  {
    id: 'vuln_map', label: 'VULN MAP', icon: '💀',
    tools: ['vuln_map'],
  },
  {
    id: 'intelligence', label: 'INTELLIGENCE', icon: '◈',
    tools: ['ai_analysis', 'screenshots'],
  },
  {
    id: 'zap', label: 'OWASP ZAP', icon: '⬡',
    tools: ['zap'],
  },
]

const T = (name, icon, desc, fields, endpoint) => ({ name, icon, desc, fields, endpoint: endpoint || name })

export const TOOL_CONFIGS = {
  // ── Strix-Inspired Advanced Security Tools ────────────────
  ssrf_scanner: T(
    'SSRF Scanner', '🎯',
    'Detect Server-Side Request Forgery vulnerabilities. Fuzzes query parameters for AWS/GCP/Azure cloud metadata leaks, loopback IP bypasses (decimal/hex), internal services (Redis, Docker), and protocol wrappers.',
    [
      { name: 'target', label: 'Target URL', placeholder: 'https://example.com/api/fetch?url=https://test.com', type: 'text', autofill: 'url' },
      { name: 'param', label: 'Parameter to Test (optional — auto-discovers if empty)', placeholder: 'url or dest', type: 'text' },
      { name: 'mode', label: 'Scan Mode', type: 'select',
        options: [
          { v: 'all',      l: 'All Vectors (Cloud + Loopback + Bypasses)', default: true },
          { v: 'cloud',    l: 'Cloud Metadata (AWS, GCP, Azure, K8s)' },
          { v: 'loopback', l: 'Internal Loopback (127.0.0.1, Localhost)' },
          { v: 'bypass',   l: 'Bypass Techniques (Dword, Hex, IPv6, Protocols)' },
        ],
      },
    ]
  ),
  ssti_scanner: T(
    'SSTI Scanner', '🧪',
    'Detect Server-Side Template Injection. Injects mathematical polyglots across Jinja2, Twig, Freemarker, Smarty, Ruby ERB, and Spring EL to verify code execution risk and isolate underlying template engines.',
    [
      { name: 'target', label: 'Target URL', placeholder: 'https://example.com/search?q=test', type: 'text', autofill: 'url' },
      { name: 'param', label: 'Parameter to Test (optional — auto-discovers if empty)', placeholder: 'q or template', type: 'text' },
      { name: 'method', label: 'HTTP Method', type: 'select',
        options: [
          { v: 'GET',  l: 'GET (URL Query Parameter)', default: true },
          { v: 'POST', l: 'POST (Form Data)' },
        ],
      },
    ]
  ),
  graphql_scanner: T(
    'GraphQL Auditor', '⚛',
    'Full GraphQL API Security Auditor. Discovers GraphQL endpoints, tests Introspection disclosure, identifies sensitive data models, audits field suggestion leakage, and tests batch query DoS amplification.',
    [
      { name: 'target', label: 'Base URL or Endpoint', placeholder: 'https://example.com', type: 'text', autofill: 'url' },
      { name: 'endpoint', label: 'Custom Endpoint Path (leave blank to auto-probe)', placeholder: '/graphql', type: 'text' },
    ]
  ),
  proto_pollution: T(
    'Prototype Pollution', '🧬',
    'Audit client-side & server-side JavaScript prototype pollution and HTTP Parameter Pollution (HPP). Injects __proto__ and constructor.prototype payloads, and evaluates duplicate parameter precedence for WAF bypass.',
    [
      { name: 'target', label: 'Target URL', placeholder: 'https://example.com/api/settings', type: 'text', autofill: 'url' },
      { name: 'method', label: 'Test Mode', type: 'select',
        options: [
          { v: 'ALL',  l: 'All Vectors (Query + JSON POST + HPP)', default: true },
          { v: 'GET',  l: 'Query String Only' },
          { v: 'POST', l: 'JSON Body Only' },
        ],
      },
    ]
  ),
  poc_generator: T(
    'PoC Generator', '⚡',
    'Instant Exploit Proof-of-Concept Synthesizer inspired by Strix verified findings methodology. Generates ready-to-run cURL reproduction commands, standalone Python exploit scripts, browser HTML PoCs, and developer remediation patches.',
    [
      { name: 'target', label: 'Target URL', placeholder: 'https://example.com/search', type: 'text', autofill: 'url' },
      { name: 'vuln_type', label: 'Vulnerability Type', type: 'select',
        options: [
          { v: 'xss',           l: 'Cross-Site Scripting (XSS)', default: true },
          { v: 'sqli',          l: 'SQL Injection (SQLi)' },
          { v: 'ssrf',          l: 'Server-Side Request Forgery (SSRF)' },
          { v: 'ssti',          l: 'Server-Side Template Injection (SSTI)' },
          { v: 'cors',          l: 'CORS Misconfiguration' },
          { v: 'open_redirect', l: 'Open Redirect' },
          { v: 'lfi',           l: 'Local File Inclusion (LFI)' },
          { v: 'proto',         l: 'Prototype Pollution' },
        ],
      },
      { name: 'parameter', label: 'Target Parameter', placeholder: 'q or id', defaultValue: 'q', type: 'text' },
      { name: 'http_method', label: 'HTTP Method', type: 'select',
        options: [{ v: 'GET', l: 'GET', default: true }, { v: 'POST', l: 'POST' }],
      },
      { name: 'custom_payload', label: 'Custom Payload (optional — auto-generates if empty)', placeholder: "<script>alert(1)</script>", type: 'text' },
    ]
  ),

  // ── Web Application Vulnerability Scanners ────────────────
  xss_scanner: T(
    'XSS Scanner', '🎯',
    'Detect Reflected, DOM-based, and Form-based Cross-Site Scripting (XSS) vulnerabilities using polyglot payloads across URL parameters, forms, and page source sinks.',
    [
      { name: 'target', label: 'Target URL', placeholder: 'https://example.com/page?q=test', type: 'text', autofill: 'url' },
      { name: 'mode', label: 'Scan Mode', type: 'select',
        options: [
          { v: 'all',       l: 'All Modes (Reflected + DOM + Forms)', default: true },
          { v: 'reflected', l: 'Reflected XSS (URL Params)' },
          { v: 'dom',       l: 'DOM XSS (Source Code Sinks)' },
          { v: 'forms',     l: 'Form XSS (POST Inputs)' },
        ],
      },
      { name: 'max_params', label: 'Max Params to Test', type: 'select',
        options: [{ v: '5', l: '5 params (fast)' }, { v: '10', l: '10 params', default: true }, { v: '20', l: '20 params (thorough)' }],
      },
    ]
  ),
  lfi_scanner: T(
    'LFI Scanner', '📁',
    'Test for Local File Inclusion (LFI) and Path Traversal vulnerabilities. Uses Unix/Windows payloads, PHP wrapper injection, null byte techniques, and response anomaly detection.',
    [
      { name: 'target', label: 'Target URL', placeholder: 'https://example.com/page?file=about', type: 'text', autofill: 'url' },
      { name: 'depth', label: 'Scan Depth', type: 'select',
        options: [
          { v: 'quick',  l: 'Quick — 5 payloads' },
          { v: 'medium', l: 'Medium — 12 payloads', default: true },
          { v: 'deep',   l: 'Deep — All payloads (thorough)' },
        ],
      },
    ]
  ),
  open_redirect: T(
    'Open Redirect', '↪',
    'Detect open redirect vulnerabilities across URL parameters, headers, and crawled links. Tests common bypass techniques (double-slash, URL encoding, null bytes).',
    [
      { name: 'target', label: 'Target URL', placeholder: 'https://example.com/login?next=/', type: 'text', autofill: 'url' },
      { name: 'depth', label: 'Scan Depth', type: 'select',
        options: [
          { v: 'quick',  l: 'Quick — 4 payloads' },
          { v: 'medium', l: 'Medium — 8 payloads', default: true },
          { v: 'deep',   l: 'Deep — All bypass payloads' },
        ],
      },
    ]
  ),

  // ── Password Cracking Suite ────────────────────────────────
  password_cracker: T(
    'Password Cracker', '⚡',
    'Industrial multi-algorithm password & hash cracking suite. Offline cracking (MD5, SHA1/256/512, NTLM, MySQL, Bcrypt, APR1), rule-based mutation engine, mask PIN brute-force, entropy & time-to-crack auditor, and targeted profiler.',
    [
      { name: 'mode', label: 'Operation Mode', type: 'select',
        options: [
          { v: 'hash_crack', l: 'Hash Cracker (MD5, SHA, NTLM, Bcrypt, APR1...)', default: true },
          { v: 'entropy_audit', l: 'Password Strength & Entropy Auditor' },
          { v: 'wordlist_generator', l: 'Targeted Wordlist Profiler (CUPP)' },
        ]
      },
      { name: 'hashes', label: 'Hashes / Passwords / Targets (one per line, e.g. hash, user:hash, or hash:salt)', type: 'textarea', rows: 4,
        placeholder: '5f4dcc3b5aa765d61d8327deb882cf99\nadmin:209c6174da490caeb422f3fa5a7ae634\n*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19'
      },
      { name: 'hash_type', label: 'Hash Algorithm', type: 'select',
        options: [
          { v: 'auto', l: 'Auto-Detect Algorithm (Recommended)', default: true },
          { v: 'md5', l: 'MD5 (mode 0)' },
          { v: 'ntlm', l: 'NTLM / Windows (mode 1000)' },
          { v: 'sha1', l: 'SHA-1 (mode 100)' },
          { v: 'sha256', l: 'SHA-256 (mode 1400)' },
          { v: 'sha512', l: 'SHA-512 (mode 1700)' },
          { v: 'mysql', l: 'MySQL 4.1+ (mode 300)' },
          { v: 'bcrypt', l: 'Bcrypt (mode 3200)' },
          { v: 'apr1', l: 'Apache APR1 / MD5 (mode 1600)' },
        ]
      },
      { name: 'attack_type', label: 'Attack Mode', type: 'select',
        options: [
          { v: 'all', l: 'All Attacks (Dict + Rules + Fast PINs)', default: true },
          { v: 'dictionary', l: 'Dictionary Attack Only (Fastest)' },
          { v: 'rules', l: 'Rule-Based Mangling (Leet, Years, Cases)' },
          { v: 'mask', l: 'Mask Brute-Force (PINs & Charsets)' },
        ]
      },
      { name: 'salt', label: 'Salt (optional for salted hashes)', placeholder: 'salt123', type: 'text' },
      { name: 'mask', label: 'Mask Pattern (for Mask Attack)', placeholder: '?d?d?d?d', defaultValue: '?d?d?d?d', type: 'text' },
      { name: 'target_info', label: 'Target Keywords (for Wordlist Generator)', placeholder: 'company, admin, 2026', type: 'text' },
      { name: 'custom_wordlist', label: 'Custom Wordlist (optional extra candidates, one per line)', type: 'textarea', rows: 3 },
    ]
  ),

  // ── Authentication & Exploitation Tools ────────────────────
  sqli: T(
    'SQL Injection', '💉',
    'Test URL parameters for error-based, boolean-based, and time-based SQLi.',
    [
      { name: 'target', label: 'URL with Parameter', placeholder: 'https://example.com/page?id=1', type: 'text' },
      { name: 'type', label: 'Test Type', type: 'select',
        options: [{ v: 'all', l: 'All types', default: true }, { v: 'error', l: 'Error-based' },
                  { v: 'boolean', l: 'Boolean-based' }, { v: 'time', l: 'Time-based' }] },
    ]
  ),
  bruteforce: T(
    'Brute Force & Stuffing', '🔨',
    'Multi-worker async login cracker with auto-CSRF token extraction, JSON/form payload support, and smart response diffing. Supports both single-user dictionary attacks and credential stuffing lists (user:pass).',
    [
      { name: 'target', label: 'Login URL', placeholder: 'https://example.com/login', type: 'text', autofill: 'url' },
      { name: 'username', label: 'Target Username (ignored if credentials list used)', placeholder: 'admin', type: 'text', defaultValue: 'admin' },
      { name: 'username_field', label: 'Username Field Name', placeholder: 'username', type: 'text', defaultValue: 'username' },
      { name: 'password_field', label: 'Password Field Name', placeholder: 'password', type: 'text', defaultValue: 'password' },
      { name: 'credentials', label: 'Credential Stuffing List (user:pass, one per line — overrides password list)', type: 'textarea', rows: 3,
        placeholder: 'admin:password123\nuser@example.com:letmein' },
      { name: 'payload_type', label: 'Payload Format', type: 'select',
        options: [{ v: 'form', l: 'Form (x-www-form-urlencoded)', default: true }, { v: 'json', l: 'JSON (application/json)' }] },
      { name: 'concurrency', label: 'Concurrency Workers', type: 'select',
        options: [{ v: '1', l: '1 (Stealth / Slow)' }, { v: '5', l: '5 (Balanced)', default: true },
                  { v: '10', l: '10 (Fast)' }, { v: '20', l: '20 (Burst / Turbo)' }] },
      { name: 'wordlist_size', label: 'Wordlist Preset', type: 'select',
        options: [{ v: 'small', l: 'Small (~50 passwords)' }, { v: 'medium', l: 'Medium (~250 passwords)', default: true },
                  { v: 'large', l: 'Large (~1000 passwords)' }, { v: 'custom', l: 'Custom List Below' }] },
      { name: 'success_indicator', label: 'Success Indicator (optional text in response)', placeholder: 'dashboard or logout', type: 'text' },
      { name: 'passwords', label: 'Custom Passwords (one/line — empty = uses wordlist preset)', type: 'textarea', rows: 3 },
    ]
  ),
  auth_flaws: T(
    'Auth Logic Flaws', '🔓',
    'Test blank password, SQLi bypass, username enum, default creds, and type juggling.',
    [
      { name: 'target', label: 'Login URL', placeholder: 'https://example.com/login', type: 'text', autofill: 'url' },
      { name: 'username_field', label: 'Username Field', type: 'text', defaultValue: 'username' },
      { name: 'password_field', label: 'Password Field', type: 'text', defaultValue: 'password' },
      { name: 'username', label: 'Test Username', type: 'text', defaultValue: 'admin' },
    ]
  ),
  rate_limit: T(
    'Rate Limit Tester', '⏱',
    'Fire rapid requests at an endpoint to check if your site enforces rate limiting. Detects 429 responses, Retry-After and X-RateLimit-* headers, and server stability under load.',
    [
      { name: 'target', label: 'URL to Test', placeholder: 'https://example.com/login', type: 'text', autofill: 'url' },
      { name: 'requests', label: 'Request Count', type: 'select',
        options: [{ v: '20', l: '20 requests (quick)' }, { v: '50', l: '50 requests', default: true },
                  { v: '100', l: '100 requests (thorough)' }, { v: '150', l: '150 requests (stress)' }] },
      { name: 'concurrency', label: 'Concurrency', type: 'select',
        options: [{ v: '2', l: '2 (slow, stealthy)' }, { v: '5', l: '5 (default)', default: true },
                  { v: '10', l: '10 (fast)' }, { v: '20', l: '20 (burst)' }] },
      { name: 'custom_header', label: 'Custom Header (optional)', placeholder: 'X-Forwarded-For: 1.2.3.4', type: 'text' },
    ]
  ),

  // ── Reconnaissance Tools ──────────────────────────────────
  ip_finder: T(
    'IP Finder', '🌐',
    'Resolve domain to IP addresses, detect CDN/WAF, geolocate server, get ISP/ASN, and reverse DNS.',
    [{ name: 'target', label: 'Domain', placeholder: 'example.com', type: 'text', autofill: 'domain' }]
  ),
  whois: T(
    'WHOIS Lookup', '◉',
    'Query WHOIS for domain registration, expiry, and registrant info.',
    [{ name: 'target', label: 'Domain', placeholder: 'example.com', type: 'text', autofill: 'domain' }]
  ),
  dns: T(
    'DNS Enumeration', '◈',
    'Enumerate A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV records.',
    [{ name: 'target', label: 'Domain', placeholder: 'example.com', type: 'text', autofill: 'domain' }]
  ),
  subdomain: T(
    'Subdomain Enum', '⬡',
    'Brute-force subdomains via DNS resolution against wordlists.',
    [
      { name: 'target', label: 'Domain', placeholder: 'example.com', type: 'text', autofill: 'domain' },
      { name: 'wordlist', label: 'Wordlist Size', type: 'select',
        options: [{ v: 'small', l: 'Small (~50)' }, { v: 'medium', l: 'Medium (~120)', default: true }, { v: 'large', l: 'Large (all)' }] },
    ]
  ),
  subdomain_takeover: T(
    'Subdomain Takeover', '⚑',
    'Detect subdomains with dangling CNAMEs pointing to unclaimed cloud services (GitHub Pages, Heroku, Netlify, S3, etc.).',
    [
      { name: 'target', label: 'Domain', placeholder: 'example.com', type: 'text', autofill: 'domain' },
      { name: 'wordlist', label: 'Wordlist', type: 'select',
        options: [{ v: 'small', l: 'Small (~50)' }, { v: 'medium', l: 'Medium (~120)', default: true }, { v: 'large', l: 'Large (all)' }] },
    ]
  ),
  portscan: T(
    'Port Scanning', '⬣',
    'Scan TCP ports and detect running services. Uses nmap if available.',
    [
      { name: 'target', label: 'Host / IP', placeholder: '192.168.1.1 or example.com', type: 'text', autofill: 'host' },
      { name: 'ports', label: 'Port Set', type: 'select',
        options: [{ v: 'common', l: 'Common (27 ports)', default: true }, { v: 'web', l: 'Web ports' },
                  { v: 'db', l: 'Database ports' }, { v: 'extended', l: 'Extended (100 ports)' }] },
    ]
  ),
  tls: T(
    'TLS Inspection', '🔒',
    'Inspect SSL/TLS certificate, cipher suite, protocol, and expiry.',
    [
      { name: 'target', label: 'Domain', placeholder: 'example.com', type: 'text', autofill: 'domain' },
      { name: 'port', label: 'Port', placeholder: '443', type: 'number', defaultValue: '443' },
    ]
  ),

  // ── Analysis & Security Posture Tools ──────────────────────
  headers: T(
    'HTTP Headers', '≡',
    'Check for missing or misconfigured security headers (HSTS, CSP, X-Frame-Options…).',
    [{ name: 'target', label: 'URL', placeholder: 'https://example.com', type: 'text', autofill: 'url' }]
  ),
  http_security: T(
    'HTTP Security', '⚡',
    'Fingerprint tech stack, check redirect chains, detect error messages and info leaks.',
    [{ name: 'target', label: 'URL', placeholder: 'https://example.com', type: 'text', autofill: 'url' }]
  ),
  security_files: T(
    'Security Files', '📄',
    'Fetch robots.txt, sitemap.xml, security.txt, and other standard files.',
    [{ name: 'target', label: 'Base URL', placeholder: 'https://example.com', type: 'text', autofill: 'url' }]
  ),
  dns_security: T(
    'DNS Security', '🛡',
    'Check SPF, DMARC, DKIM selectors, CAA, and email spoofing posture.',
    [{ name: 'target', label: 'Domain', placeholder: 'example.com', type: 'text', autofill: 'domain' }]
  ),
  cors: T(
    'CORS Misconfig', '↔',
    'Deep CORS audit testing origin reflection, null origin, subdomain trust, and credential exposure. Automatically generates data exfiltration HTML PoC.',
    [
      { name: 'target', label: 'URL', placeholder: 'https://example.com/api/', type: 'text', autofill: 'url' },
      { name: 'origin', label: 'Custom Origin (optional)', placeholder: 'https://evil.com', type: 'text' },
    ]
  ),
  cookies: T(
    'Cookie & Session Security', '🍪',
    'Deep cookie and session auditor. Analyzes Secure, HttpOnly, SameSite, cookie prefixes (__Host-), session ID entropy, predictability sequences, and JWT tokens.',
    [{ name: 'target', label: 'URL', placeholder: 'https://example.com', type: 'text', autofill: 'url' }]
  ),
  cloud: T(
    'Cloud Exposure', '☁',
    'Detect exposed S3 buckets, Azure Blob containers, and GCP Storage buckets.',
    [{ name: 'target', label: 'Domain or Company Name', placeholder: 'example.com or acmecorp', type: 'text', autofill: 'domain' }]
  ),
  js_intel: T(
    'JS Intelligence', '⟨/⟩',
    'Analyze JavaScript files for hidden API endpoints, hardcoded secrets, WebSocket URLs, GraphQL endpoints, and internal URLs.',
    [{ name: 'target', label: 'URL', placeholder: 'https://example.com', type: 'text', autofill: 'url' }]
  ),

  // ── Discovery & Scanning Tools ────────────────────────────
  page_discover: T(
    'Page Discovery', '🗺',
    'Crawl website pages + wordlist brute-force. Lists discovered URLs, internal API routes, and flags admin/management panels.',
    [
      { name: 'target', label: 'Base URL', placeholder: 'https://example.com', type: 'text', autofill: 'url' },
      { name: 'depth', label: 'Crawl Depth', type: 'select',
        options: [{ v: '1', l: 'Depth 1 (fast)' }, { v: '2', l: 'Depth 2 (recommended)', default: true }, { v: '3', l: 'Depth 3 (thorough)' }] },
      { name: 'max_pages', label: 'Max Pages', type: 'select',
        options: [{ v: '50', l: '50 pages' }, { v: '150', l: '150 pages', default: true }, { v: '300', l: '300 pages' }] },
      { name: 'wordlist', label: 'Wordlist', type: 'select',
        options: [{ v: 'small', l: 'Small' }, { v: 'medium', l: 'Medium', default: true }, { v: 'full', l: 'Full' }] },
    ]
  ),
  api_security: T(
    'API Security', '⇌',
    'Discover OpenAPI/Swagger docs, test GraphQL introspection, probe REST endpoints for missing auth, check rate limiting.',
    [{ name: 'target', label: 'URL', placeholder: 'https://example.com', type: 'text', autofill: 'url' }]
  ),
  jwt_analyzer: T(
    'JWT Analyzer', '🔑',
    'Decode and analyze JWT tokens: check algorithm (none/HS256), crack weak secrets, inspect claims (exp, iss, sub), detect sensitive data.',
    [
      { name: 'token', label: 'JWT Token (paste full token or Bearer header)', placeholder: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ...', type: 'textarea', rows: 3 },
    ]
  ),
  sensitive_files: T(
    'Sensitive Files & Secrets', '⚠',
    'Check for exposed .env, .git repos, config backups, credentials.json, and scans live response bodies for leaked API keys, tokens, and private keys.',
    [
      { name: 'target', label: 'Base URL', placeholder: 'https://example.com', type: 'text', autofill: 'url' },
      { name: 'wordlist', label: 'Wordlist', type: 'select',
        options: [{ v: 'small', l: 'Critical only' }, { v: 'medium', l: 'Medium', default: true }, { v: 'full', l: 'Full list' }] },
    ]
  ),
  vuln_detection: T(
    'Vuln Detection', '🐛',
    'Detect error messages, version disclosure, directory listing, and CVE markers.',
    [{ name: 'target', label: 'URL', placeholder: 'https://example.com', type: 'text', autofill: 'url' }]
  ),
  db_scanner: T(
    'DB Login Scanner', '🗄',
    'Check exposed DB ports (MySQL, PG, MongoDB, Redis…) for no-auth access.',
    [{ name: 'target', label: 'Host / IP', placeholder: '192.168.1.1 or example.com', type: 'text', autofill: 'host' }]
  ),

  // ── Vuln Map, AI & ZAP ─────────────────────────────────────
  vuln_map: T(
    'Vuln Map', '💀',
    'Crawl your site and test every discovered page for SQL injection, reflected XSS, open redirects, error disclosure, directory listing, and sensitive file exposure. Shows exactly which pages are cracked.',
    [
      { name: 'target', label: 'Base URL', placeholder: 'https://example.com', type: 'text', autofill: 'url' },
      { name: 'max_pages', label: 'Max Pages to Scan', type: 'select',
        options: [{ v: '20', l: '20 pages (fast)' }, { v: '40', l: '40 pages (default)', default: true },
                  { v: '60', l: '60 pages (thorough)' }, { v: '80', l: '80 pages (deep)' }] },
    ]
  ),
  ai_analysis: T(
    'Local AI Security Analysis', '🤖',
    'Analyze scan findings 100% locally using your own models. Supports Built-in Offline Security Engine (Zero setup), Ollama (localhost:11434), LM Studio (localhost:1234), or custom local endpoints. No external API keys or cloud credits required.',
    [
      { name: 'target', label: 'Target (for context)', type: 'text', autofill: 'url' },
      { name: 'engine', label: 'AI Engine', type: 'select',
        options: [
          { v: 'builtin',   l: '⚡ Built-in Offline Security Engine (Fast, No Setup Required)', default: true },
          { v: 'ollama',    l: '🦙 Ollama (Local LLM @ localhost:11434)' },
          { v: 'lm_studio', l: '🧠 LM Studio / LocalAI (@ localhost:1234)' },
          { v: 'custom',    l: '🌐 Custom Local Endpoint URL' },
        ]},
      { name: 'local_url', label: 'Local Endpoint URL (optional — leave empty for default)', placeholder: 'http://localhost:11434 or http://localhost:1234/v1', type: 'text' },
      { name: 'model', label: 'Local Model Name (for Ollama / LM Studio)', type: 'text', defaultValue: 'deepseek-r1', placeholder: 'deepseek-r1, llama3, mistral, qwen2.5...' },
      { name: 'findings', label: 'Paste findings JSON (from any tool result or run)', type: 'textarea', rows: 8,
        placeholder: '[{"severity":"high","title":"...","detail":"..."}]' },
    ]
  ),
  screenshots: T(
    'Screenshots', '📷',
    'Capture full-page screenshots of target using headless Chromium (Playwright). Requires: pip install playwright && playwright install chromium.',
    [
      { name: 'target', label: 'URL', placeholder: 'https://example.com', type: 'text', autofill: 'url' },
      { name: 'full_page', label: 'Capture Mode', type: 'select',
        options: [{ v: 'false', l: 'Viewport only', default: true }, { v: 'true', l: 'Full page (scroll)' }] },
    ]
  ),
  zap: T(
    'OWASP ZAP', '👁',
    'Automated spider and active scanning via ZAP REST API. Requires ZAP on localhost:8080.',
    [
      { name: 'target', label: 'Target URL', placeholder: 'https://example.com', type: 'text', autofill: 'url' },
      { name: 'scan_type', label: 'Scan Type', type: 'select',
        options: [{ v: 'spider', l: 'Spider Only' }, { v: 'active', l: 'Active Scan', default: true },
                  { v: 'passive', l: 'Passive Scan' }, { v: 'full', l: 'Full (Spider + Active)' }] },
      { name: 'api_key', label: 'ZAP API Key', type: 'text', defaultValue: 'fndorqfot05j2bg625a12uq0ag' },
      { name: 'zap_host', label: 'ZAP Host', placeholder: 'http://localhost:8080', type: 'text', defaultValue: 'http://localhost:8080' },
    ]
  ),
}
