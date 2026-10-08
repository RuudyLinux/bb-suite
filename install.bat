@echo off
title BB-SUITE v3.1 — First Time Setup
color 0A
echo.
echo  ██████████████████████████████████████████████████
echo  █  BB-SUITE v3.1 — First Time Setup              █
echo  ██████████████████████████████████████████████████
echo.
echo  New in v3.1:
echo    + Rate Limit Tester  (EXPLOIT category)
echo    + Vuln Map           (crawl + auto-test all pages)
echo.

REM ── Check Python ───────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found.
    echo  Download: https://python.org/downloads
    echo  Make sure to check "Add Python to PATH" during install.
    pause & exit /b 1
)
for /f "tokens=*" %%i in ('python --version 2^>^&1') do echo  Python: %%i

REM ── Check Node.js ──────────────────────────────────────
node --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Node.js not found.
    echo  Download: https://nodejs.org
    pause & exit /b 1
)
for /f "tokens=*" %%i in ('node --version 2^>^&1') do echo  Node.js: %%i

echo.
echo  [1/6] Creating Python virtual environment...
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    python -m venv .venv
    echo  venv created.
) else (
    echo  venv already exists.
)

echo.
echo  [2/6] Upgrading pip in venv...
.venv\Scripts\python -m pip install --upgrade pip -q

echo.
echo  [3/6] Installing Python packages...
.venv\Scripts\pip install ^
    fastapi==0.104.1 ^
    "uvicorn[standard]==0.24.0" ^
    httpx==0.25.2 ^
    dnspython==2.4.2 ^
    pydantic==2.5.0 ^
    python-multipart==0.0.6 ^
    cryptography==41.0.7 ^
    playwright ^
    anthropic ^
    pymysql ^
    -q
echo  Python packages installed.

echo.
echo  [4/6] Installing Playwright Chromium browser...
.venv\Scripts\playwright install chromium
echo  Chromium ready.

echo.
echo  [5/6] Installing Node packages...
cd /d "%~dp0frontend"
if not exist "node_modules" (
    npm install
) else (
    echo  node_modules already exists.
)

echo.
echo  [6/6] Building React frontend...
npm run build
echo  Frontend built.

echo.
echo  ██████████████████████████████████████████████████
echo  █  Setup complete!                               █
echo  █                                               █
echo  █  Run start.bat to launch BB-SUITE v3.1        █
echo  ██████████████████████████████████████████████████
echo.
pause
