#!/bin/bash
# CyberNest - Quick Setup Script (Linux/macOS)

set -e

echo "=================================================="
echo "  CyberNest - SIEM + SOAR Platform Setup"
echo "=================================================="

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is required. Install from https://python.org"
    exit 1
fi

PYTHON=python3
echo "[OK] Python found: $($PYTHON --version)"

# Create virtual environment
echo "[*] Creating virtual environment..."
$PYTHON -m venv venv
source venv/bin/activate

# Install dependencies
echo "[*] Installing dependencies..."
pip install -r backend/requirements.txt

# Seed database
echo "[*] Seeding demo data..."
cd backend
$PYTHON seed.py
cd ..

echo ""
echo "=================================================="
echo "  Setup Complete!"
echo "=================================================="
echo ""
echo "  To start CyberNest:"
echo "    source venv/bin/activate"
echo "    cd backend"
echo "    python -m uvicorn main:app --reload"
echo ""
echo "  Then open: http://localhost:8000"
echo ""
echo "  Demo login:"
echo "    Admin:   admin / admin123"
echo "    Analyst: analyst / analyst123"
echo "=================================================="
