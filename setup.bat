@echo off
REM CyberNest - Quick Setup Script (Windows)

echo ==================================================
echo   CyberNest - SIEM + SOAR Platform Setup
echo ==================================================

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 3 is required. Install from https://python.org
    exit /b 1
)

echo [OK] Python found
python --version

REM Create virtual environment
echo [*] Creating virtual environment...
python -m venv venv
call venv\Scripts\activate.bat

REM Install dependencies
echo [*] Installing dependencies...
pip install -r backend\requirements.txt

REM Seed database
echo [*] Seeding demo data...
cd backend
python seed.py
cd ..

echo.
echo ==================================================
echo   Setup Complete!
echo ==================================================
echo.
echo   To start CyberNest:
echo     venv\Scripts\activate.bat
echo     cd backend
echo     python -m uvicorn main:app --reload
echo.
echo   Then open: http://localhost:8000
echo.
echo   Demo login:
echo     Admin:   admin / admin123
echo     Analyst: analyst / analyst123
echo ==================================================
