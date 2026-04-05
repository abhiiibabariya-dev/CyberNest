@echo off
REM CyberNest - Quick Run Script

if not exist "venv" (
    echo Run setup.bat first!
    exit /b 1
)

call venv\Scripts\activate.bat
cd backend
echo Starting CyberNest on http://localhost:8000 ...
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
