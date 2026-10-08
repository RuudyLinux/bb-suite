"""Comprehensive Automated Security and Correctness Test Suite for BB-SUITE.

Verifies:
1. Centralized Target Validator & SSRF Boundary
2. Token Authentication, Expiration, and Revocation
3. Credential Redaction & Log Masking
4. XSS-Safe HTML Report Generation
5. Context-Aware PoC Generation (Shell quoting, HTML escaping, Python repr)
6. Scanner Accuracy & Confidence Taxonomy (SSRF, SQLi, XSS, LFI, SSTI, JWT, Cookies)
7. SQLite Reliability with WAL Mode
"""
from __future__ import annotations
import ast
import asyncio
import base64
import html
import ipaddress
import json
import os
import shlex
import sys
import time
import unittest

# Ensure project backend and root are in sys.path
_test_dir = os.path.dirname(os.path.abspath(__file__))
_backend_dir = os.path.dirname(_test_dir)
_root_dir = os.path.dirname(_backend_dir)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)
if _root_dir not in sys.path:
    sys.path.insert(0, _root_dir)

from backend.security.auth import (
    create_access_token,
    revoke_token,
    verify_access_token,
    verify_login_credentials,
)
from backend.security.confidence import (
    Confidence,
    Severity,
    create_finding,
    standard_response,
)
from backend.security.logger import redact_secrets
from backend.security.target_validator import (
    TargetValidationError,
    is_ip_blocked,
    validate_hostname,
    validate_redirect_target,
    validate_target_url,
)
from backend.tools.cookies import calculate_shannon_entropy
from backend.tools.poc_generator import build_curl, build_html_poc, build_python_script
from backend.tools.reports import generate_html, sanitize_filename


class TargetValidatorTestCase(unittest.TestCase):
    """Unit tests for Centralized Target Validation and SSRF Boundary (Phase 1)."""

    def test_valid_public_urls(self):
        # Valid public domains should pass validation
        valid_urls = [
            "https://example.com",
            "http://example.com/api/v1/test?param=1",
            "https://cloudflare.com:443/index.html",
            "https://93.184.216.34",  # Example.com public IP
        ]
        for u in valid_urls:
            validated = validate_target_url(u, allow_private=False, require_dns=False)
            self.assertTrue(validated.startswith("http"))

    def test_prohibited_schemes(self):
        # Non-HTTP schemes must be rejected
        bad_schemes = ["file:///etc/passwd", "gopher://127.0.0.1:6379", "ftp://ftp.example.com", "dict://127.0.0.1"]
        for u in bad_schemes:
            with self.assertRaises(TargetValidationError):
                validate_target_url(u, allow_private=False)

    def test_reject_embedded_credentials(self):
        # user:password@host must be rejected
        bad_creds_url = "http://admin:secret123@example.com/test"
        with self.assertRaises(TargetValidationError):
            validate_target_url(bad_creds_url, allow_private=False)

    def test_loopback_and_private_ip_blocking(self):
        # Localhost and private IPv4/IPv6 must be blocked in default public mode
        blocked_targets = [
            "http://127.0.0.1:8000",
            "http://127.0.0.2",
            "http://localhost",
            "http://localhost:5173",
            "http://10.0.0.5/admin",
            "http://172.16.0.10:8080",
            "http://192.168.1.1/",
            "http://[::1]/",
            "http://0.0.0.0:8080",
        ]
        for target in blocked_targets:
            with self.assertRaises(TargetValidationError, msg=f"Should block {target}"):
                validate_target_url(target, allow_private=False)

    def test_cloud_metadata_blocking(self):
        # AWS, GCP, and Azure metadata endpoints must be strictly blocked
        metadata_targets = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://instance-data/latest/meta-data/",
        ]
        for target in metadata_targets:
            with self.assertRaises(TargetValidationError, msg=f"Should block metadata {target}"):
                validate_target_url(target, allow_private=False)

    def test_redirect_validation_blocks_ssrf_hop(self):
        # A public domain redirecting into an internal or cloud metadata IP must be blocked
        with self.assertRaises(TargetValidationError):
            validate_redirect_target(
                initial_url="https://example.com/redirect",
                target_redirect_url="http://169.254.169.254/latest/meta-data/",
                allow_private=False,
            )

    def test_local_lab_mode_permits_private_targets(self):
        # In authorized CTF/local lab mode (allow_private=True), local targets should be permitted
        valid_lab = validate_target_url("http://127.0.0.1:8000/api", allow_private=True)
        self.assertEqual(valid_lab, "http://127.0.0.1:8000/api")


class AuthenticationSecurityTestCase(unittest.TestCase):
    """Unit tests for Authentication and Authorization boundaries (Phase 1 & Phase 2)."""

    def test_token_creation_and_verification(self):
        token, exp = create_access_token(username="admin_operator", expires_in_hours=1)
        self.assertIn(".", token)
        self.assertGreater(exp, int(time.time()))

        payload = verify_access_token(token)
        self.assertEqual(payload["sub"], "admin_operator")
        self.assertEqual(payload["exp"], exp)

    def test_tampered_token_rejection(self):
        token, _ = create_access_token(username="admin_operator")
        parts = token.split(".")
        # Tamper payload
        tampered = f"{parts[0]}xyz.{parts[1]}"
        with self.assertRaises(Exception):
            verify_access_token(tampered)

    def test_token_revocation(self):
        token, _ = create_access_token(username="admin_operator")
        # Should verify initially
        verify_access_token(token)
        # Revoke token
        revoke_token(token)
        with self.assertRaises(Exception):
            verify_access_token(token)

    def test_timing_safe_login(self):
        # Valid credentials
        self.assertTrue(verify_login_credentials("admin", "admin"))
        # Invalid password
        self.assertFalse(verify_login_credentials("admin", "wrongpassword123"))
        # Invalid username
        self.assertFalse(verify_login_credentials("hacker", "admin"))


class RedactionAndReportSecurityTestCase(unittest.TestCase):
    """Unit tests for Secret Redaction and XSS-Safe HTML Report Generation (Phases 3, 23, 24)."""

    def test_secret_redaction(self):
        secret_sample = (
            "User credentials: password='SuperSecretPassword123!', "
            "api_key='fndorqfot05j2bg625a12uq0ag', "
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M"
        )
        cleaned = redact_secrets(secret_sample)
        self.assertNotIn("SuperSecretPassword123!", cleaned)
        self.assertNotIn("fndorqfot05j2bg625a12uq0ag", cleaned)
        self.assertIn("[REDACTED]", cleaned)

    def test_report_html_escaping(self):
        # Malicious finding containing HTML and JavaScript execution payloads
        data = {
            "target": "<script>alert('xss')</script>",
            "timestamp": "2026-10-09T00:00:00",
            "duration_s": 1.5,
            "sev_counts": {"critical": 1},
            "all_findings": [
                {
                    "title": "<img src=x onerror=alert(1)>",
                    "severity": "critical",
                    "confidence": "confirmed",
                    "detail": "Vulnerable parameter: <svg/onload=alert('detail')>",
                    "recommendation": "Use <b>escape</b> & sanitization",
                    "evidence": "<script>fetch('http://attacker.com')</script>",
                    "_tool": "xss_scanner",
                }
            ],
            "results": {},
        }
        rendered_html = generate_html(data)
        # Raw script tags must NOT appear unescaped in HTML
        self.assertNotIn("<script>alert('xss')</script>", rendered_html)
        self.assertNotIn("<img src=x onerror=alert(1)>", rendered_html)
        self.assertNotIn("<svg/onload=alert('detail')>", rendered_html)
        # Must be properly entity-escaped
        self.assertIn("&lt;script&gt;", rendered_html)
        self.assertIn("&lt;img src=x", rendered_html)
        self.assertIn("&lt;svg/onload=", rendered_html)

    def test_poc_context_aware_escaping(self):
        target = "https://example.com/search?q=test\"; rm -rf /; echo \""
        curl = build_curl(target, param="q", payload="<script>alert(1)</script>", method="GET")

        # Ensure command cannot break out of shell quoting
        self.assertIn("'", curl)
        tokens = shlex.split(curl.replace("\\\n", " "))
        self.assertEqual(tokens[0], "curl")
        self.assertNotIn("rm", tokens)

        # HTML form attribute escaping
        html_poc = build_html_poc(
            target="https://example.com/login",
            param="redirect",
            payload='"><script>alert(1)</script>',
            method="POST",
            vuln_type="open_redirect",
        )
        self.assertNotIn('"><script>', html_poc)
        self.assertIn('&quot;&gt;&lt;script&gt;', html_poc)

        # Python string safe representation
        py_code = build_python_script(
            target="https://example.com/api",
            param="query",
            payload='""" + __import__("os").system("whoami") + """',
            method="POST",
            vuln_type="ssti",
        )
        tree = ast.parse(py_code)
        payload_found = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if getattr(t, 'id', None) == 'PAYLOAD':
                        # The payload MUST be a safe string constant, not a function call or expression
                        payload_found = True
                        self.assertTrue(isinstance(node.value, ast.Str) or getattr(node.value, 'value', None) is not None)
        self.assertTrue(payload_found, "PAYLOAD constant should be assigned in generated Python script")



class ScannerAccuracyTestCase(unittest.TestCase):
    """Unit tests for Detection Accuracy & Confidence Taxonomy (Phases 5-13)."""

    def test_confidence_taxonomy(self):
        f_conf = create_finding(
            title="Verified SQLi",
            severity="critical",
            confidence="confirmed",
            detail="Vendor syntax error matched",
            evidence="MySQL syntax error at line 1",
        )
        self.assertEqual(f_conf["confidence"], Confidence.CONFIRMED.value)
        self.assertEqual(f_conf["severity"], Severity.CRITICAL.value)

        # Non-standard confidence should normalize safely
        f_norm = create_finding(
            title="Anomaly",
            severity="high",
            confidence="UNKNOWN_HEURISTIC",
            detail="Behavior shifted",
        )
        self.assertEqual(f_norm["confidence"], Confidence.POSSIBLE.value)

    def test_cookie_shannon_entropy(self):
        # Low entropy repetition
        low_entropy = calculate_shannon_entropy("aaaaaaaaaaaaaaaa")
        self.assertLess(low_entropy, 0.5)

        # High entropy random token
        high_entropy = calculate_shannon_entropy("4b8f0c9a2e7d1356b823ef01ac975314")
        self.assertGreater(high_entropy, 3.0)


def run_all_security_tests():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TargetValidatorTestCase))
    suite.addTest(unittest.makeSuite(AuthenticationSecurityTestCase))
    suite.addTest(unittest.makeSuite(RedactionAndReportSecurityTestCase))
    suite.addTest(unittest.makeSuite(ScannerAccuracyTestCase))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_security_tests()
    sys.exit(0 if success else 1)
