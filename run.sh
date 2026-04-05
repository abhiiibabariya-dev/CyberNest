#!/bin/bash
# CyberNest - Quick Run Script

if [ ! -d "venv" ]; then
    echo "Run ./setup.sh first!"
    exit 1
fi

source venv/bin/activate
cd backend
echo "Starting CyberNest on http://localhost:8000 ..."
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
