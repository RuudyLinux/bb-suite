"""BB-SUITE — Advanced Bug Bounty & Penetration Testing Suite.

Main Application Server with production security boundaries, centralized error handling,
security headers middleware, configurable CORS, and authentication.
"""
from __future__ import annotations
import logging
import os
import sys

# Ensure backend and root are on sys.path for both package and module execution
_backend_dir = os.path.dirname(os.path.abspath(__file__))
_root_dir = os.path.dirname(_backend_dir)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)
if _root_dir not in sys.path:
    sys.path.insert(0, _root_dir)

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.security.auth_router import auth_router
from backend.security.config import (
    BB_CORS_ORIGINS,
    BB_ENV,
    BB_HOST,
    BB_PORT,
    IS_DEVELOPMENT,
    is_private_allowed,
)
from backend.security.logger import audit_logger, setup_logger
from backend.security.target_validator import TargetValidationError

logger = setup_logger("bb_suite.server")

app = FastAPI(
    title="BugBounty Suite",
    version="4.0.0",
    description="Authorized Penetration Testing and Bug Bounty Assessment Framework",
    docs_url="/docs" if IS_DEVELOPMENT else None,
    redoc_url="/redoc" if IS_DEVELOPMENT else None,
)

# CORS Configuration with verified allowed origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=BB_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


# Security Headers Middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # API routes: disable aggressive caching to prevent token or result leakage
    if request.url.path.startswith("/api"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"

    return response


# Global Exception Handlers
@app.exception_handler(TargetValidationError)
async def target_validation_exception_handler(request: Request, exc: TargetValidationError):
    return JSONResponse(
        status_code=400,
        content={
            "success": False,
            "data": {"summary": {}, "findings": [], "records": [], "record_columns": [], "raw": ""},
            "error": f"Security Boundary Error: {str(exc)}",
        },
    )


@app.exception_handler(Exception)
async def global_unhandled_exception_handler(request: Request, exc: Exception):
    # Log exception traceback server-side only
    logger.exception("Unhandled server exception on %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "data": {"summary": {}, "findings": [], "records": [], "record_columns": [], "raw": ""},
            "error": "An internal server error occurred. Check server logs for details.",
        },
    )


# System Health Endpoint
@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "version": "4.0.0",
        "environment": BB_ENV,
        "private_targets_allowed": is_private_allowed(),
        "database": "sqlite_wal",
    }


# Include Authentication Router
app.include_router(auth_router, prefix="/api")

# Recon tools
from tools.whois import router as whois_r
from tools.dns_enum import router as dns_r
from tools.subdomain import router as sub_r
from tools.portscan import router as port_r
from tools.tls_inspect import router as tls_r
from tools.ip_finder import router as ip_r
from tools.subdomain_takeover import router as takeover_r

# Analysis tools
from tools.headers import router as hdr_r
from tools.http_security import router as httpsec_r
from tools.security_files import router as secf_r
from tools.dns_security import router as dnssec_r
from tools.cors_check import router as cors_r
from tools.cookies import router as cookie_r
from tools.cloud import router as cloud_r
from tools.js_intel import router as js_r

# Scanning tools
from tools.page_discover import router as page_r
from tools.sensitive_files import router as senf_r
from tools.vuln_detection import router as vuln_r
from tools.db_scanner import router as db_r
from tools.api_security import router as apisec_r
from tools.graphql_scanner import router as graphql_r
from tools.jwt_analyzer import router as jwt_r
from tools.xss_scanner import router as xss_r
from tools.lfi_scanner import router as lfi_r
from tools.open_redirect import router as redir_r
from tools.ssrf_scanner import router as ssrf_r
from tools.ssti_scanner import router as ssti_r
from tools.proto_pollution import router as proto_r

# Exploitation & Intelligence tools
from tools.password_cracker import router as pc_r
from tools.sqli import router as sqli_r
from tools.bruteforce import router as bf_r
from tools.auth_flaws import router as auth_r
from tools.rate_limit import router as rl_r
from tools.poc_generator import router as poc_r
from tools.post_exploit import router as pe_r
from tools.vuln_map import router as vm_r
from tools.ai_analysis import router as ai_r
from tools.screenshots import router as ss_r
from tools.zap_integration import router as zap_r
from tools.reports import router as report_r
from tools.auto_login import router as autologin_r

ALL_ROUTERS = [
    # Recon
    whois_r, dns_r, sub_r, port_r, tls_r, ip_r, takeover_r,
    # Analysis
    hdr_r, httpsec_r, secf_r, dnssec_r, cors_r, cookie_r, cloud_r, js_r,
    # Scanning
    page_r, senf_r, vuln_r, db_r, apisec_r, graphql_r, jwt_r,
    xss_r, lfi_r, redir_r, ssrf_r, ssti_r, proto_r,
    # Exploitation & PoC
    pc_r, sqli_r, bf_r, auth_r, rl_r, poc_r, pe_r,
    # Vuln Map, Intelligence & Reporting
    vm_r, ai_r, ss_r, zap_r, report_r, autologin_r,
]

for r in ALL_ROUTERS:
    app.include_router(r, prefix="/api")


# Backward-compatibility wrappers for consolidated tools
@app.post("/api/stuffing")
async def legacy_stuffing(req: dict):
    from tools.bruteforce import brute_force
    from models import BruteReq
    return await brute_force(BruteReq(
        target=req.get("target", ""),
        username_field=req.get("username_field", "username"),
        password_field=req.get("password_field", "password"),
        credentials=req.get("credentials", ""),
        success_indicator=req.get("success_indicator", "")
    ))


@app.post("/api/session_hijack")
async def legacy_session_hijack(req: dict):
    from tools.cookies import cookie_analyzer
    from models import TargetReq
    return await cookie_analyzer(TargetReq(target=req.get("target", "")))


@app.post("/api/credential_exposure")
async def legacy_credential_exposure(req: dict):
    from tools.sensitive_files import sensitive_files
    from models import WordlistReq
    return await sensitive_files(WordlistReq(target=req.get("target", ""), wordlist="small"))


@app.post("/api/wordlist")
async def legacy_wordlist(req: dict):
    from tools.page_discover import page_discovery
    from models import PageDiscoverReq
    return await page_discovery(PageDiscoverReq(
        target=req.get("target", ""),
        depth=1,
        max_pages=req.get("max_pages", 50),
        wordlist=req.get("wordlist", "medium")
    ))


@app.post("/api/aitm")
async def legacy_aitm(req: dict):
    from tools.http_security import http_security
    from models import TargetReq
    return await http_security(TargetReq(target=req.get("target", "")))


# Short name aliases for scanner & PoC endpoints
@app.post("/api/graphql")
async def alias_graphql(req: dict):
    from tools.graphql_scanner import graphql_scanner, GraphqlRequest
    return await graphql_scanner(GraphqlRequest(target=req.get("target", ""), endpoint=req.get("endpoint", "")))


@app.post("/api/ssrf")
async def alias_ssrf(req: dict):
    from tools.ssrf_scanner import ssrf_scanner, SsrfRequest
    return await ssrf_scanner(SsrfRequest(target=req.get("target", ""), param=req.get("param", ""), mode=req.get("mode", "all")))


@app.post("/api/ssti")
async def alias_ssti(req: dict):
    from tools.ssti_scanner import ssti_scanner, SstiRequest
    return await ssti_scanner(SstiRequest(target=req.get("target", ""), param=req.get("param", ""), method=req.get("method", "GET")))


@app.post("/api/poc")
async def alias_poc(req: dict):
    from tools.poc_generator import poc_generator, PocRequest
    return await poc_generator(PocRequest(
        target=req.get("target", ""),
        vuln_type=req.get("vuln_type", "xss"),
        parameter=req.get("parameter", "q"),
        custom_payload=req.get("custom_payload", req.get("payload", "")),
        http_method=req.get("http_method", req.get("method", "GET")),
    ))


@app.post("/api/xss")
async def alias_xss(req: dict):
    from tools.xss_scanner import xss_scanner, XSSRequest
    return await xss_scanner(XSSRequest(target=req.get("target", "")))


@app.post("/api/lfi")
async def alias_lfi(req: dict):
    from tools.lfi_scanner import lfi_scanner, LFIRequest
    return await lfi_scanner(LFIRequest(target=req.get("target", "")))


# Database history endpoint
@app.get("/api/history")
async def scan_history():
    try:
        from database import get_scan_history, get_top_findings
        return {"success": True, "data": {
            "scans": get_scan_history(20),
            "findings": get_top_findings(50),
        }}
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# Serve React build
_dist = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.exists(_dist):
    app.mount("/", StaticFiles(directory=_dist, html=True), name="spa")

if __name__ == "__main__":
    import uvicorn
    logger.info("Starting BB-SUITE on %s:%s (env=%s, reload=%s)", BB_HOST, BB_PORT, BB_ENV, IS_DEVELOPMENT)
    uvicorn.run("main:app", host=BB_HOST, port=BB_PORT, reload=IS_DEVELOPMENT)
