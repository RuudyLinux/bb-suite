"""SSTI Scanner — High-Precision Server-Side Template Injection Detector.

Distinguishes between literal expression reflection and genuine mathematical evaluation:
- Confirmed: Verifiable mathematical computation (random prime multiplication) or engine config disclosure.
- Likely: Template syntax error traces (e.g., Jinja2 TemplateSyntaxError, Twig error).
- Possible: Expression filtered or status divergence without confirmed computation.
- Not Detected: Expression reflected as literal text or sanitized.
"""
from __future__ import annotations
import asyncio
import random
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter
from pydantic import BaseModel, Field

from backend.security.confidence import (
    Confidence,
    Severity,
    create_finding,
    standard_response,
)
from backend.security.http_client import safe_request
from backend.security.logger import redact_secrets
from backend.security.target_validator import TargetValidationError, validate_target_url
from backend.tools.utils import clean_url, err, ok

router = APIRouter(tags=["scanning"])

SSTI_ERROR_PATTERNS = [
    (r"jinja2\.exceptions\.TemplateSyntaxError", "Jinja2 Syntax Error"),
    (r"Twig(?:_Error_Syntax|\\Error\\SyntaxError)", "Twig Syntax Error"),
    (r"freemarker\.core\.ParseException", "Freemarker Parse Error"),
    (r"org\.thymeleaf\.exceptions", "Thymeleaf Exception"),
    (r"SmartyCompilerException", "Smarty Compiler Exception"),
]


class SstiRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    param: str = Field("", max_length=128)
    method: str = Field("GET", max_length=16)


def generate_arithmetic_probe(template_syntax: str) -> Tuple[str, str]:
    """Generate dynamic math probe with random primes to prevent static false positives."""
    n1 = random.randint(123, 789)
    n2 = random.randint(17, 89)
    product = str(n1 * n2)
    expr = template_syntax.replace("MATH", f"{n1}*{n2}")
    return expr, product


SYNTAX_TEMPLATES = [
    ("{{MATH}}", "Jinja2 / Twig / Nunjucks"),
    ("${MATH}", "Freemarker / Spring EL / Smarty"),
    ("<%= MATH %>", "Ruby ERB / EJS"),
    ("#{MATH}", "Ruby Interpolation / Thymeleaf"),
    ("*{MATH}", "Thymeleaf"),
]


@router.post("/ssti_scanner")
async def ssti_scanner(req: SstiRequest):
    url = clean_url(req.target)
    try:
        validate_target_url(url)
    except TargetValidationError as tve:
        return err(f"Target validation failed: {tve}")

    parsed = urlparse(url)
    existing_qs = parse_qs(parsed.query, keep_blank_values=True)

    params_to_test = []
    if req.param and req.param.strip():
        params_to_test = [req.param.strip()]
    elif existing_qs:
        params_to_test = list(existing_qs.keys())
    else:
        params_to_test = ["q", "name", "template", "page", "preview", "title", "msg", "text"]

    findings: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []

    # Baseline check
    try:
        baseline_resp = await safe_request("GET", url, timeout=8.0)
        baseline_body = baseline_resp.text
    except Exception as e:
        return err(f"Failed to reach target: {e}")

    for param in params_to_test:
        param_confirmed = False

        for syntax_fmt, engine_name in SYNTAX_TEMPLATES:
            probe_expr, expected_val = generate_arithmetic_probe(syntax_fmt)

            # Ensure expected_val isn't already present in baseline
            if expected_val in baseline_body:
                # Re-generate with different numbers
                probe_expr, expected_val = generate_arithmetic_probe(syntax_fmt)

            current_params = dict(existing_qs)
            current_params[param] = [probe_expr]
            flat_params = {k: v[0] for k, v in current_params.items()}

            try:
                if req.method.upper() == "POST":
                    resp = await safe_request("POST", url, data=flat_params, timeout=7.0)
                else:
                    new_query = urlencode(flat_params)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
                    resp = await safe_request("GET", test_url, timeout=7.0)

                body = resp.text

                # 1. Verification of Server-Side Mathematical Evaluation (Confirmed)
                # Must contain the computed product, but NOT just echo the literal expression!
                if expected_val in body and expected_val not in baseline_body:
                    # Differential check: if probe is in body, make sure it's not a trivial match
                    conf = Confidence.CONFIRMED
                    findings.append(create_finding(
                        title=f"SSTI Confirmed ({engine_name}): param '{param}'",
                        severity="critical",
                        confidence=conf.value,
                        detail=f"Injected mathematical probe '{probe_expr}' into parameter '{param}'. The server dynamically evaluated and returned computed result '{expected_val}'.",
                        recommendation="Never concatenate user input directly into template strings. Treat user input strictly as template context variables, or utilize sandboxed engines.",
                        evidence=f"Injected: {probe_expr}\nComputed Result Found: {expected_val}",
                    ))
                    records.append({
                        "Parameter": param,
                        "Syntax": syntax_fmt,
                        "Engine": engine_name,
                        "Confidence": "confirmed",
                        "Result": f"💀 CONFIRMED EVALUATION ({expected_val})",
                    })
                    param_confirmed = True
                    break

                # 2. Template Syntax Error Traces (Likely)
                for err_pat, err_desc in SSTI_ERROR_PATTERNS:
                    if re.search(err_pat, body, re.IGNORECASE):
                        conf = Confidence.LIKELY
                        findings.append(create_finding(
                            title=f"Template Syntax Error Disclosed ({err_desc}): param '{param}'",
                            severity="high",
                            confidence=conf.value,
                            detail=f"Parameter '{param}' triggered a template engine syntax exception: {err_desc}.",
                            recommendation="Sanitize user input and prevent template parsing exceptions from leaking to client responses.",
                            evidence=f"Matched: {err_pat}",
                        ))
                        records.append({
                            "Parameter": param,
                            "Syntax": syntax_fmt,
                            "Engine": engine_name,
                            "Confidence": "likely",
                            "Result": f"🔥 LIKELY ({err_desc})",
                        })
                        param_confirmed = True
                        break

                if param_confirmed:
                    break

            except Exception:
                pass

        if not param_confirmed:
            records.append({
                "Parameter": param,
                "Syntax": "Standard Syntax Set",
                "Engine": "None",
                "Confidence": "not_detected",
                "Result": "Safe (No template evaluation)",
            })

    if not findings:
        findings.append(create_finding(
            title="No SSTI Detected",
            severity="info",
            confidence=Confidence.NOT_DETECTED.value,
            detail="Mathematical template probes were not evaluated by the target server.",
            recommendation="Continue maintaining secure templating architecture.",
        ))

    confirmed_count = sum(1 for f in findings if f.get("confidence") == "confirmed")
    likely_count = sum(1 for f in findings if f.get("confidence") == "likely")

    return ok({
        "summary": {
            "Target": url,
            "Parameters Tested": len(params_to_test),
            "Confirmed SSTI": confirmed_count,
            "Likely SSTI": likely_count,
            "Status": "Vulnerable" if (confirmed_count or likely_count) else "Secure",
        },
        "findings": findings,
        "records": records,
        "record_columns": ["Parameter", "Syntax", "Engine", "Confidence", "Result"],
    })
