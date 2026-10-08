@echo off
title BB-SUITE v3.1 — Security Testing Platform
color 0A
cd /d "%~dp0"

echo.
echo  ██████████████████████████████████████████████████
echo  █  BB-SUITE v3.1 // BugBounty Platform           █
echo  ██████████████████████████████████████████████████
echo.
echo  Tools: RECON / ANALYSIS / SCANNING / EXPLOIT
echo         INTELLIGENCE / OWASP ZAP / VULN MAP
echo.

REM ── Prereq checks ──────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found. Run install.bat first.
    pause & exit /b 1
)

node --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Node.js not found. Run install.bat first.
    pause & exit /b 1
)

if not exist "%~dp0.venv\Scripts\python.exe" (
    echo  [ERROR] Virtual environment not found.
    echo  Run install.bat first.
    pause & exit /b 1
)

REM ── Kill old Python processes on port 8000 ─────────────
echo  [*] Stopping old processes on port 8000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000 " ^| findstr "LISTENING" 2^>nul') do (
    taskkill /F /PID %%a >nul 2>&1
)
timeout /t 2 /nobreak >nul

REM ── Build frontend ─────────────────────────────────────
echo  [1/2] Building React frontend...
cd /d "%~dp0frontend"
if not exist "node_modules" (
    echo  Installing Node packages first...
    npm install
    if errorlevel 1 ( echo  [ERROR] npm install failed. & pause & exit /b 1 )
)
call npm run build
if errorlevel 1 (
    echo  [ERROR] Frontend build failed.
    pause & exit /b 1
)
echo  Frontend built OK.

REM ── Start backend in new window ────────────────────────
echo  [2/2] Starting backend on port 8000...
cd /d "%~dp0backend"
start "BB-SUITE v3.1 Backend" cmd /k "cd /d "%~dp0backend" && "..\\.venv\Scripts\python.exe" main.py"

REM ── Poll until backend responds (max 30s) ──────────────
echo  Waiting for backend to start...
set /a tries=0
:waitloop
timeout /t 2 /nobreak >nul
set /a tries+=1
curl -s -o nul -w "%%{http_code}" http://localhost:8000 2>nul | findstr "200 404 422" >nul 2>&1
if not errorlevel 1 goto :ready
if %tries% geq 15 (
    echo  [WARN] Backend slow to start. Opening browser anyway...
    goto :open
)
echo  Waiting... (%tries%/15)
goto :waitloop

:ready
echo  Backend is up!

:open
REM ── Open browser ───────────────────────────────────────
echo.
echo  ██████████████████████████████████████████████████
echo  █  BB-SUITE v3.1 is running!                     █
echo  █                                               █
echo  █  URL:  http://localhost:8000                  █
echo  █  API:  http://localhost:8000/docs             █
echo  █                                               █
echo  █  NEW:  Password & Hash Cracker (EXPLOIT)      █
echo  █        Modern Cyber SOC Command Deck          █
echo  █        Vuln Map — cracked pages map           █
echo  █        Rate Limit Tester (EXPLOIT)            █
echo  █                                               █
echo  █  Close the BB-SUITE Backend window to stop.   █
echo  ██████████████████████████████████████████████████
echo.

REM Open browser — try multiple methods
start "" "http://localhost:8000" 2>nul
if errorlevel 1 (
    rundll32 url.dll,FileProtocolHandler "http://localhost:8000" 2>nul
)

echo  Press any key to close this launcher window...
echo  (The backend keeps running in its own window)
pause >nul
