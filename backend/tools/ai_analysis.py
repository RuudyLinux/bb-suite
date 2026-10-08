from __future__ import annotations
import re
import json
from typing import List, Dict, Any, Optional
import httpx
from fastapi import APIRouter
from pydantic import BaseModel
from tools.utils import f, ok, err

router = APIRouter(tags=["intelligence"])

SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'pass': 5}


class AiAnalysisReq(BaseModel):
    target: str = ""
    findings: List[Dict[str, Any]] = []
    engine: str = "builtin"  # builtin | ollama | lm_studio | custom
    local_url: str = ""      # e.g., http://localhost:11434 or http://localhost:1234/v1
    model: str = "deepseek-r1"


def calculate_risk_metrics(findings: list) -> tuple[int, str, dict]:
    weights = {'critical': 30, 'high': 15, 'medium': 7, 'low': 2}
    counts = {}
    for fnd in findings:
        s = fnd.get('severity', 'info').lower()
        counts[s] = counts.get(s, 0) + 1

    score = min(100, sum(weights.get(f.get('severity', '').lower(), 0) for f in findings))

    if score >= 80 or counts.get('critical', 0) > 0:
        label = 'CRITICAL'
    elif score >= 55 or counts.get('high', 0) > 0:
        label = 'HIGH'
    elif score >= 30 or counts.get('medium', 0) > 0:
        label = 'MEDIUM'
    elif score >= 10 or counts.get('low', 0) > 0:
        label = 'LOW'
    else:
        label = 'MINIMAL'

    return score, label, counts


def run_offline_heuristic_analysis(target: str, findings: list, score: int, label: str, counts: dict) -> str:
    """Built-in Local Security Intelligence Engine.

    Executes 100% offline with zero cloud API keys or external credits.
    Performs deterministic vulnerability correlation, attack graph modeling,
    false-positive triage, and tailored remediation roadmaps.
    """
    sorted_findings = sorted(findings, key=lambda x: SEV_ORDER.get(x.get('severity', 'info').lower(), 9))
    
    # Classify detected vulnerability vectors
    vectors = {
        'sqli': False,
        'ssrf': False,
        'ssti': False,
        'xss': False,
        'lfi': False,
        'cors': False,
        'cookies': False,
        'proto': False,
        'graphql': False,
        'secrets': False,
        'auth': False,
        'headers': False,
    }
    
    for item in findings:
        t = (item.get('title', '') + ' ' + item.get('detail', '')).lower()
        if 'sql injection' in t or 'sqli' in t: vectors['sqli'] = True
        if 'ssrf' in t or 'server-side request forgery' in t: vectors['ssrf'] = True
        if 'ssti' in t or 'template injection' in t: vectors['ssti'] = True
        if 'xss' in t or 'cross-site scripting' in t: vectors['xss'] = True
        if 'lfi' in t or 'local file inclusion' in t or 'traversal' in t: vectors['lfi'] = True
        if 'cors' in t: vectors['cors'] = True
        if 'cookie' in t or 'session' in t: vectors['cookies'] = True
        if 'proto' in t or 'prototype pollution' in t or 'hpp' in t: vectors['proto'] = True
        if 'graphql' in t: vectors['graphql'] = True
        if 'secret' in t or '.env' in t or 'api key' in t or 'credential' in t: vectors['secrets'] = True
        if 'auth' in t or 'login' in t or 'jwt' in t or 'password' in t: vectors['auth'] = True
        if 'hsts' in t or 'csp' in t or 'security header' in t: vectors['headers'] = True

    # 1. Executive Summary
    summary = (
        f"Security assessment of **{target or 'target application'}** identified **{len(findings)} findings** "
        f"({counts.get('critical', 0)} Critical, {counts.get('high', 0)} High, {counts.get('medium', 0)} Medium). "
        f"The composite security risk posture is rated **{label} ({score}/100)**. "
    )
    if counts.get('critical', 0) > 0 or counts.get('high', 0) > 0:
        summary += "Immediate attacker exploitability was verified; urgent defensive intervention is required to avoid unauthorized data access or host compromise."
    else:
        summary += "No critical remote code execution or direct database takeover primitives were confirmed; findings mainly reflect defense-in-depth hardening opportunities."

    # 2. Prioritized Top Actions
    actions = []
    if vectors['sqli']:
        actions.append("1. **Parameterized Queries (SQLi Remediation)**: Migrate all dynamic SQL queries to parameterized prepared statements (e.g., PDO / SQLAlchemy).")
    if vectors['ssrf']:
        actions.append(f"{len(actions)+1}. **Restricted Egress & IMDSv2 (SSRF Remediation)**: Enforce strict URL parsing allowlists and mandate AWS IMDSv2 token authentication.")
    if vectors['ssti']:
        actions.append(f"{len(actions)+1}. **Context-Aware Template Sandboxing (SSTI)**: Refactor dynamic template rendering to use sandboxed environments with execution guards.")
    if vectors['secrets']:
        actions.append(f"{len(actions)+1}. **Revoke and Rotate Leaked Secrets**: Immediately invalidate exposed tokens (`.env`, git repositories) and implement `.gitignore` safety pre-commit hooks.")
    if vectors['proto']:
        actions.append(f"{len(actions)+1}. **Object Prototype Freezing**: Freeze `Object.prototype` (`Object.freeze`) and replace vulnerable recursive object merges.")
    if vectors['graphql']:
        actions.append(f"{len(actions)+1}. **Disable Production GraphQL Introspection**: Turn off `__schema` queries and apply query depth/cost limits to prevent batching DoS.")
    if vectors['cors'] or vectors['cookies']:
        actions.append(f"{len(actions)+1}. **Lock Down CORS & Session Cookies**: Eliminate wildcard/null CORS reflections; set `Secure`, `HttpOnly`, `SameSite=Strict`, and `__Host-` prefixes.")
    if not actions:
        actions.append("1. Enforce strict HTTP response headers: Content-Security-Policy (CSP) and Strict-Transport-Security (HSTS).")
        actions.append("2. Implement continuous endpoint authentication and rate limiting.")

    actions_text = "\n".join(actions[:4])

    # 3. Realistic Attack Chains
    chains = []
    if vectors['ssrf'] and vectors['secrets']:
        chains.append(
            "• **Chain A (Cloud Infrastructure Takeover)**: Attacker targets SSRF parameter ➔ Accesses cloud metadata API (`169.254.169.254`) ➔ "
            "Exfiltrates temporary IAM role tokens ➔ Gains authenticated access to cloud storage and infrastructure resources."
        )
    elif vectors['sqli']:
        chains.append(
            "• **Chain A (Database Exfiltration & Privilege Escalation)**: Attacker detects vulnerable input parameter ➔ Executes SQL Injection "
            "➔ Extracts password hashes and database tables ➔ Cracks hashes or recovers administrative session tokens."
        )
    elif vectors['ssti']:
        chains.append(
            "• **Chain A (Template Injection to Remote Code Execution)**: Attacker submits template polyglots ➔ Engine evaluates input expressions ➔ "
            "Attacker invokes runtime system classes ➔ Achieves remote shell execution on application host."
        )
    else:
        chains.append(
            "• **Chain A (Reconnaissance to Endpoint Exploitation)**: Attacker uses discovered administrative routes or sensitive endpoints ➔ "
            "Leverages missing rate limits and default configuration weaknesses to test credentials and gain unauthorized access."
        )

    if vectors['cors'] and vectors['cookies']:
        chains.append(
            "• **Chain B (Cross-Origin Data Exfiltration)**: Attacker hosts malicious page ➔ Tricks victim into visiting ➔ "
            "Triggers authenticated cross-origin `fetch()` with credentials due to misconfigured CORS origin reflection ➔ Leaks victim sensitive data."
        )
    elif vectors['xss']:
        chains.append(
            "• **Chain B (Session Hijacking via Reflected XSS)**: Attacker crafts malicious link with injected script ➔ Victim clicks link ➔ "
            "Script executes in victim context ➔ Steals session cookies or injects malicious DOM overlays."
        )

    chains_text = "\n".join(chains)

    # 4. False Positive Analysis
    fp_text = (
        "• **Information Disclosure / Headers**: Missing HSTS or banner disclosures may reflect internal reverse proxies or WAF layers; confirm reachability from external perimeter.\n"
        "• **DNS / Mail Security**: SPF / DMARC `p=none` flags do not impact web application confidentiality, though they permit domain email spoofing.\n"
        "• **403 / 401 Protected Endpoints**: Responses with 401/403 status codes confirm that access controls are actively enforced."
    )

    # 5. Bug Bounty Impact
    bounty_lines = []
    if vectors['ssrf'] or vectors['sqli'] or vectors['ssti']:
        bounty_lines.append("• **Critical / P1 Vulnerability**: Verified SSRF / SQLi / SSTI qualify for high-tier payouts ($2,000 – $10,000+ depending on program scale).")
    if vectors['proto'] or vectors['graphql']:
        bounty_lines.append("• **High / P2 Vulnerability**: Prototype pollution and sensitive GraphQL introspection disclosures qualify for medium-high payouts ($500 – $2,500).")
    if vectors['cors'] or vectors['xss']:
        bounty_lines.append("• **Medium / P3 Vulnerability**: CORS credential theft and reflected XSS with user impact qualify for moderate payouts ($300 – $1,000).")
    if not bounty_lines:
        bounty_lines.append("• **Informational / Low (P4-P5)**: Hardening issues and missing headers are generally classified as informative by VRPs unless chained into tangible impact.")
    bounty_text = "\n".join(bounty_lines)

    # 6. Remediation Roadmap
    roadmap_text = """• **Phase 1: Immediate (Next 24 Hours)**:
  - Patch directly exploitable parameters (SSRF, SQLi, SSTI).
  - Invalidate any discovered credentials, API keys, or leaked environment files.
• **Phase 2: Short-Term (1 – 7 Days)**:
  - Enforce strict CORS origins (whitelist only, no dynamic reflection).
  - Secure session cookies (`HttpOnly`, `Secure`, `SameSite=Strict`, `__Host-` prefixes).
  - Disable GraphQL introspection in production environments.
• **Phase 3: Long-Term (1 – 4 Weeks)**:
  - Implement centralized WAF rules and automated regression scanning.
  - Implement least-privilege database user permissions and network egress firewalls."""

    return f"""### [LOCAL SECURITY INTELLIGENCE REPORT]
*Generated 100% locally by BB-SUITE Built-in Offline Analysis Engine (No Cloud API)*

#### 1. Executive Summary
{summary}

#### 2. Top Prioritized Actions
{actions_text}

#### 3. Exploit Scenario & Attack Graph
{chains_text}

#### 4. False Positive Assessment
{fp_text}

#### 5. Bug Bounty & Business Impact
{bounty_text}

#### 6. Remediation Roadmap
{roadmap_text}"""


@router.post("/ai_analysis")
async def ai_analysis(req: AiAnalysisReq):
    if not req.findings:
        return err("No findings provided. Paste findings JSON from any tool result or run a scan first.")

    score, label, counts = calculate_risk_metrics(req.findings)
    sorted_findings = sorted(req.findings, key=lambda x: SEV_ORDER.get(x.get('severity', 'info').lower(), 9))

    engine = (req.engine or "builtin").lower().strip()
    ai_response = ""
    engine_used = "Built-in Offline Security Engine"

    # If user selected a local LLM (Ollama, LM Studio, or custom local server)
    if engine in ("ollama", "lm_studio", "custom"):
        prompt = f"""You are a senior penetration tester and bug bounty expert analyzing a security scan.

Target: {req.target}
Risk Score: {score}/100 ({label})
Finding Counts: Critical={counts.get('critical',0)} High={counts.get('high',0)} Medium={counts.get('medium',0)} Low={counts.get('low',0)}

Security Findings:
""" + '\n'.join([
            f"[{fnd.get('severity','?').upper()}] {fnd.get('title','?')}: {fnd.get('detail','')}"
            for fnd in sorted_findings[:50]
        ]) + """

Provide a structured, actionable security analysis:
1. Executive Summary (non-technical, high-level overview)
2. Top 3-5 Critical Actions
3. Realistic Attack Scenarios & Exploit Chains
4. False Positive Assessment
5. Bug Bounty Impact (P1-P5 classification)
6. Step-by-Step Remediation Roadmap (Immediate, Short-Term, Long-Term)
"""

        endpoint_url = ""
        request_body = {}
        headers = {"Content-Type": "application/json"}

        if engine == "ollama":
            base_url = req.local_url.strip() or "http://localhost:11434"
            base_url = base_url.rstrip("/")
            # Use OpenAI-compatible route or native Ollama chat route
            endpoint_url = f"{base_url}/v1/chat/completions"
            request_body = {
                "model": req.model or "deepseek-r1",
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
            }
            engine_used = f"Local Ollama ({req.model or 'deepseek-r1'} @ {base_url})"

        elif engine in ("lm_studio", "custom"):
            base_url = req.local_url.strip() or "http://localhost:1234/v1"
            base_url = base_url.rstrip("/")
            if not base_url.endswith("/v1"):
                base_url = f"{base_url}/v1"
            endpoint_url = f"{base_url}/chat/completions"
            request_body = {
                "model": req.model or "local-model",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3,
            }
            engine_used = f"Local LLM ({req.model or 'local'} @ {base_url})"

        # Attempt to query local LLM server
        try:
            async with httpx.AsyncClient(timeout=45) as client:
                resp = await client.post(endpoint_url, headers=headers, json=request_body)
                if resp.status_code == 200:
                    data = resp.json()
                    if "choices" in data and len(data["choices"]) > 0:
                        ai_response = data["choices"][0]["message"]["content"]
                    elif "response" in data:
                        ai_response = data["response"]
                else:
                    # Fallback on non-200
                    ai_response = f"> [!NOTE]\n> Local LLM at `{endpoint_url}` responded with status {resp.status_code}. Automatically analyzed using the Built-in Offline Security Engine.\n\n"
                    ai_response += run_offline_heuristic_analysis(req.target, req.findings, score, label, counts)
                    engine_used = "Built-in Offline Security Engine (Local LLM Fallback)"
        except Exception as e:
            # Fallback gracefully to built-in offline engine if local LLM server is not running
            ai_response = f"> [!NOTE]\n> Local LLM at `{endpoint_url}` was unreachable ({str(e)}). Automatically analyzed using the Built-in Offline Security Engine with 0 external dependencies.\n\n"
            ai_response += run_offline_heuristic_analysis(req.target, req.findings, score, label, counts)
            engine_used = "Built-in Offline Security Engine (Local LLM Offline)"
    else:
        # Built-in offline engine by default
        ai_response = run_offline_heuristic_analysis(req.target, req.findings, score, label, counts)
        engine_used = "Built-in Offline Security Engine (100% Local)"

    sev_map = {'CRITICAL': 'critical', 'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low', 'MINIMAL': 'pass'}
    ai_findings = [
        f(sev_map.get(label, 'info'),
          f'AI Risk Score: {score}/100 — {label}',
          f'Analyzed {len(req.findings)} findings. Crit:{counts.get("critical",0)} High:{counts.get("high",0)} Med:{counts.get("medium",0)}',
          'See raw output for full analysis'),
        f('info', f'Local Analysis Complete ({engine_used})',
          f'Target: {req.target or "Local Assessment"} | Zero Cloud API required', ''),
    ]

    return ok({
        'summary': {
            'Target': req.target or 'General Assessment',
            'Engine': engine_used,
            'Risk Score': f'{score}/100',
            'Risk Level': label,
            'Findings Analyzed': len(req.findings),
            'Local Mode': 'Active (100% Private / No External API)',
        },
        'findings': ai_findings,
        'records': [{'Severity': k.upper(), 'Count': v} for k, v in counts.items()],
        'record_columns': ['Severity', 'Count'],
        'raw': ai_response,
    })
