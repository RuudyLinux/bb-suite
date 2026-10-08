"""Auto-Login Helper — Single-Use Controlled Authentication Dispatcher.

Strictly bounded helper for security testing with authorized target validation:
- Requires authenticated operator session
- Validates destination target URL against SSRF boundary
- Sanitizes username and password form fields with strict HTML escaping
- Single-use, time-expiring (60 seconds) memory token
- Prevents unvalidated open redirects
"""
from __future__ import annotations
import html
import time
from typing import Any, Dict
from urllib.parse import urlparse
import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from backend.security.auth import get_current_user
from backend.security.logger import log_security_event
from backend.security.target_validator import TargetValidationError, validate_target_url
from backend.tools.utils import clean_url, err, ok

router = APIRouter(tags=["exploitation"])

# Token -> (html_content, created_timestamp)
_TOKEN_STORE: Dict[str, Tuple[str, float]] = {}


class AutoLoginReq(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)
    username: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=1, max_length=256)
    username_field: str = Field("username", max_length=128)
    password_field: str = Field("password", max_length=128)
    redirect_after: str = Field("", max_length=512)


@router.post("/auto_login")
async def create_auto_login(
    req: AutoLoginReq,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    target = clean_url(req.target)
    try:
        validate_target_url(target)
    except TargetValidationError as tve:
        return err(f"Target validation failed: {tve}")

    operator = current_user.get("sub", "admin")
    log_security_event(
        event_type="AUTO_LOGIN_REQUEST",
        target=target,
        user=operator,
        tool="auto_login",
        details={"username": req.username},
        level="info",
    )

    token = uuid.uuid4().hex
    e = html.escape

    extra_input = ""
    if req.redirect_after:
        # Validate redirect_after is either a relative path or points to the same target host
        red_parsed = urlparse(req.redirect_after)
        target_parsed = urlparse(target)
        if red_parsed.netloc and red_parsed.netloc != target_parsed.netloc:
            return err("redirect_after cannot point to an external domain (open redirect defense).")
        extra_input = f'<input type="hidden" name="redirect" value="{e(req.redirect_after, quote=True)}">\n'

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BB-SUITE // Controlled Auto-Login</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{
    background: #050508; color: #00ff41;
    font-family: 'Courier New', monospace;
    display: flex; align-items: center; justify-content: center;
    height: 100vh; overflow: hidden;
  }}
  .box {{ text-align: center; max-width: 420px; padding: 20px; }}
  .logo {{ font-size: 26px; font-weight: bold; letter-spacing: 4px; text-shadow: 0 0 20px #00ff41; margin-bottom: 20px; }}
  .info {{ color: #00cc33; font-size: 13px; margin-bottom: 8px; }}
  .cred {{ color: #ff6600; font-size: 12px; margin-bottom: 20px; word-break: break-all; }}
  .bar  {{ width: 280px; height: 3px; background: #001a00; margin: 0 auto 16px; border-radius: 2px; overflow: hidden; }}
  .fill {{ height: 100%; background: linear-gradient(90deg, #003300, #00ff41); animation: progress 0.8s ease-in forwards; }}
  @keyframes progress {{ from {{ width:0 }} to {{ width:100% }} }}
  .warning {{ color: #ff4444; font-size: 11px; margin-top: 20px; }}
</style>
</head>
<body>
<div class="box">
  <div class="logo">&#9632; BB-SUITE</div>
  <div class="info">Operator session dispatching login for <strong style="color:#fff">{e(req.username)}</strong></div>
  <div class="cred">Target: {e(target)}</div>
  <div class="bar"><div class="fill"></div></div>
  <div class="info">Submitting credentials...</div>
  <form id="loginForm" method="POST" action="{e(target, quote=True)}" style="display:none">
    <input name="{e(req.username_field, quote=True)}" value="{e(req.username, quote=True)}">
    <input type="password" name="{e(req.password_field, quote=True)}" value="{e(req.password, quote=True)}">
    {extra_input}
  </form>
  <script>
    setTimeout(function() {{ document.getElementById('loginForm').submit(); }}, 800);
  </script>
  <div class="warning">&#9888; Authorized penetration testing only. Single-use token.</div>
</div>
</body>
</html>"""

    # Cleanup expired tokens (> 60s)
    now = time.time()
    expired = [k for k, (_, ts) in _TOKEN_STORE.items() if now - ts > 60.0]
    for k in expired:
        _TOKEN_STORE.pop(k, None)

    _TOKEN_STORE[token] = (page, now)
    return ok({"url": f"/api/auto_login/{token}", "token": token, "target": target})


@router.get("/auto_login/{token}")
async def serve_auto_login(token: str):
    entry = _TOKEN_STORE.pop(token, None)  # Single-use: consumed immediately
    if not entry:
        return HTMLResponse(
            "<!DOCTYPE html><html><body style='background:#050508;color:#ff4444;font-family:monospace;padding:40px'>"
            "&#9888; Token expired or already consumed. Please request a new auto-login session in BB-SUITE."
            "</body></html>",
            status_code=404,
        )

    page, created_ts = entry
    if time.time() - created_ts > 60.0:
        return HTMLResponse(
            "<!DOCTYPE html><html><body style='background:#050508;color:#ff4444;font-family:monospace;padding:40px'>"
            "&#9888; Token expired (60-second validity window exceeded)."
            "</body></html>",
            status_code=410,
        )

    return HTMLResponse(page)
