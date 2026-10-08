from __future__ import annotations
import asyncio
import base64
import os
from datetime import datetime
from fastapi import APIRouter
from fastapi.responses import FileResponse
from pydantic import BaseModel
from tools.utils import clean_url, f, ok, err

router = APIRouter(tags=["intelligence"])

SCREENSHOTS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..', 'reports', 'screenshots')
)
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)


class ScreenshotReq(BaseModel):
    target: str
    full_page: bool = False
    width: int = 1280
    height: int = 900


@router.post("/screenshots")
async def take_screenshot(req: ScreenshotReq):
    url = clean_url(req.target)
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return err("playwright not installed. Run: .venv\\Scripts\\pip install playwright && .venv\\Scripts\\playwright install chromium")

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-setuid-sandbox',
                      '--disable-dev-shm-usage', '--disable-gpu',
                      '--disable-web-security']
            )
            ctx = await browser.new_context(
                viewport={'width': req.width, 'height': req.height},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 BugBountySuite/3.0',
                ignore_https_errors=True,
            )
            page = await ctx.new_page()

            # Navigate with generous timeout
            try:
                await page.goto(url, wait_until='domcontentloaded', timeout=20000)
                await asyncio.sleep(2)  # let JS render
            except Exception:
                pass  # Screenshot whatever loaded

            png = await page.screenshot(full_page=req.full_page, type='png')
            await browser.close()

    except Exception as e:
        err_msg = str(e)
        if 'Executable doesn\'t exist' in err_msg or 'chromium' in err_msg.lower():
            project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
            venv_pw = os.path.join(project_root, '.venv', 'Scripts', 'playwright.exe')
            return err(
                "Chromium browser not found.\n"
                "Fix: run in terminal:\n"
                f"  {venv_pw} install chromium"
            )
        return err(f"Screenshot failed: {err_msg}")

    # Save file
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe     = url.replace('https://', '').replace('http://', '').replace('/', '_')[:50]
    filename = f"shot_{safe}_{ts}.png"
    filepath = os.path.join(SCREENSHOTS_DIR, filename)

    with open(filepath, 'wb') as fh:
        fh.write(png)

    b64 = base64.b64encode(png).decode()

    return ok({
        'summary': {
            'URL':        url,
            'File':       filename,
            'Size KB':    len(png) // 1024,
            'Full Page':  'YES' if req.full_page else 'No',
            'Resolution': f'{req.width}x{req.height}',
        },
        'findings': [f('pass', 'Screenshot Captured',
                        f'Saved: reports/screenshots/{filename} ({len(png)//1024}KB)', '')],
        'records':  [{'File': filename, 'Size': f'{len(png)//1024}KB',
                      'Resolution': f'{req.width}x{req.height}', 'Full Page': 'YES' if req.full_page else 'No'}],
        'record_columns':   ['File', 'Size', 'Resolution', 'Full Page'],
        'screenshot_b64':   b64,
        'screenshot_path':  f'/api/screenshots/{filename}',
    })


@router.get("/screenshots/{filename}")
async def get_screenshot(filename: str):
    import re
    if not re.match(r'^[a-zA-Z0-9_\-\.]+\.png$', filename):
        return {"error": "Invalid filename"}
    fp = os.path.join(SCREENSHOTS_DIR, filename)
    if not os.path.exists(fp):
        return {"error": "Not found"}
    return FileResponse(fp, media_type='image/png')
