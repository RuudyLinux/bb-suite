"""Auto-login: generate a one-time page that auto-submits cracked credentials."""
from __future__ import annotations
import html as _html
import uuid
from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Dict
from tools.utils import clean_url, ok

router = APIRouter(tags=["exploitation"])

# One-time token → HTML page (consumed on first GET)
_store: Dict[str, str] = {}


class AutoLoginReq(BaseModel):
    target: str
    username: str
    password: str
    username_field: str = "username"
    password_field: str = "password"
    redirect_after: str = ""


@router.post("/auto_login")
async def create_auto_login(req: AutoLoginReq):
    target = clean_url(req.target)
    token  = uuid.uuid4().hex[:20]
    e      = _html.escape

    extra_input = ""
    if req.redirect_after:
        extra_input += f'<input type="hidden" name="redirect" value="{e(req.redirect_after)}">\n'

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>BB-SUITE // Auto-Login</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{
    background: #050508; color: #00ff41;
    font-family: 'Courier New', monospace;
    display: flex; align-items: center; justify-content: center;
    height: 100vh; overflow: hidden;
  }}
  .box {{ text-align: center; }}
  .logo {{ font-size: 28px; font-weight: bold; letter-spacing: 4px;
           text-shadow: 0 0 20px #00ff41; margin-bottom: 20px; animation: glitch 3s infinite; }}
  .info {{ color: #00cc33; font-size: 14px; margin-bottom: 8px; }}
  .cred {{ color: #ff6600; font-size: 13px; margin-bottom: 20px; }}
  .bar  {{ width: 300px; height: 3px; background: #001a00; margin: 0 auto 16px; border-radius: 2px; overflow: hidden; }}
  .fill {{ height: 100%; background: linear-gradient(90deg, #003300, #00ff41);
           animation: progress 0.8s ease-in forwards; }}
  @keyframes progress {{ from {{ width:0 }} to {{ width:100% }} }}
  @keyframes glitch {{
    0%,90%,100% {{ text-shadow: 0 0 20px #00ff41; }}
    91% {{ text-shadow: 3px 0 #ff0000, -3px 0 #00ffff; transform: translateX(1px); }}
    92% {{ text-shadow: -3px 0 #ff0000, 3px 0 #00ffff; transform: translateX(-1px); }}
    93% {{ text-shadow: 0 0 20px #00ff41; transform: translateX(0); }}
  }}
  .warning {{ color: #ff4444; font-size: 10px; margin-top: 20px; }}
</style>
</head>
<body>
<div class="box">
  <div class="logo">⚡ BB-SUITE</div>
  <div class="info">Logging in as <strong style="color:#fff">{e(req.username)}</strong></div>
  <div class="cred">Target: {e(target)}</div>
  <div class="bar"><div class="fill"></div></div>
  <div class="info">Submitting credentials...</div>
  <form id="f" method="POST" action="{e(target)}" style="display:none">
    <input name="{e(req.username_field)}" value="{e(req.username)}">
    <input type="password" name="{e(req.password_field)}" value="{e(req.password)}">
    {extra_input}
  </form>
  <script>
    setTimeout(function() {{ document.getElementById('f').submit(); }}, 900);
  </script>
  <div class="warning">⚠ Authorized testing only</div>
</div>
</body>
</html>"""

    _store[token] = page
    return ok({"url": f"/api/auto_login/{token}", "token": token, "target": target})


@router.get("/auto_login/{token}")
async def serve_auto_login(token: str):
    page = _store.pop(token, None)  # single-use
    if not page:
        return HTMLResponse(
            "<html><body style='background:#050508;color:#ff4444;font-family:monospace;padding:40px'>"
            "⚠ Token expired or already used. Go back to BB-SUITE and click the button again."
            "</body></html>",
            status_code=404
        )
    return HTMLResponse(page)
