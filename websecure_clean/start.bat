@echo off
title WebSecure - Starting Up...
color 0B

echo.
echo  ================================================
echo   WebSecure - Web Vulnerability Scanner
echo  ================================================
echo.

:: ── Step 1: Check Python is installed ────────────────────────────────────────
echo  [1/5] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo.
    echo  ERROR: Python is not installed or not in PATH.
    echo  Please install Python from https://python.org
    echo.
    pause
    exit /b 1
)
echo        Python found OK
echo.

:: ── Step 2: Go to the correct folder ─────────────────────────────────────────
echo  [2/5] Setting up project directory...
cd /d "%~dp0"
echo        Directory: %cd%
echo.

:: ── Step 3: Install requirements ─────────────────────────────────────────────
echo  [3/5] Installing required packages...
echo        This may take a minute on first run...
echo.
pip install -r requirements.txt --quiet 2>&1
if %errorlevel% neq 0 (
    color 0E
    echo.
    echo  WARNING: Some packages may not have installed correctly.
    echo  Trying to continue anyway...
    echo.
)
echo        Packages ready
echo.

:: ── Step 4: Seed database if it does not exist ───────────────────────────────
echo  [4/5] Checking database...
if not exist "instance\websecure.db" (
    echo        Database not found - creating and seeding...
    python seed_db.py
    echo        Database created with sample data
) else (
    echo        Database found OK
)
echo.

:: ── Step 5: Launch the app ───────────────────────────────────────────────────
echo  [5/5] Starting WebSecure...
echo.
echo  ================================================
echo.
echo   App is running!
echo.
echo   Open your browser and go to:
echo   http://127.0.0.1:5000
echo.
echo   Login credentials:
echo   Email   : admin@websecure.dev
echo   Password: Password123!
echo.
echo   Press Ctrl+C to stop the app
echo  ================================================
echo.

:: Open browser automatically after 3 seconds
start "" timeout /t 3 /nobreak >nul
start "" "http://127.0.0.1:5000"

:: Start the Flask app
python run.py

:: If app stops or crashes
echo.
echo  App has stopped.
pause
