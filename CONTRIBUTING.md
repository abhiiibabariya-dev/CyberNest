# Contributing to CyberNest

Thanks for your interest in contributing to CyberNest! This guide will help you get started.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/CyberNest.git`
3. Create a branch: `git checkout -b feature/your-feature`
4. Run setup: `./setup.sh` (Linux/macOS) or `setup.bat` (Windows)

## Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate    # Windows

# Install dependencies
pip install -r backend/requirements.txt

# Seed demo data
cd backend && python seed.py && cd ..

# Run dev server
cd backend && python -m uvicorn main:app --reload
```

## Project Structure

- `backend/` - Python FastAPI backend
  - `siem/` - Log ingestion, parsing, detection engine
  - `soar/` - Playbook engine, case management, automated response
  - `core/` - Database models, auth, config
  - `api/` - REST API routes
- `frontend/` - HTML/CSS/JS dashboard
- `config/rules/` - YAML detection rules
- `config/playbooks/` - YAML SOAR playbooks

## How to Contribute

### Adding Detection Rules
Add YAML files to `config/rules/`. Follow the existing format:

```yaml
name: Your Rule Name
description: What it detects
severity: critical|high|medium|low
enabled: true
alert_title: "Alert Title"
mitre_tactic: MITRE Tactic
mitre_technique: T1234

logic: and|or
conditions:
  - field: message
    operator: contains|equals|regex|gt|lt|in
    value: "pattern"
```

### Adding SOAR Playbooks
Add YAML files to `config/playbooks/`. Available actions:
- `log` - Log a message
- `block_ip` - Block an IP address
- `isolate_host` - Isolate a host
- `send_notification` - Send notification
- `enrich_ioc` - Enrich IOC with threat intel
- `create_ticket` - Create a ticket
- `disable_user` - Disable a user account

### Adding Integrations
Extend action handlers in `backend/soar/playbook_engine.py` to connect with real tools (firewalls, EDR, SIEM, ticketing systems).

## Pull Request Process

1. Ensure your code works with `python -m uvicorn main:app --reload`
2. Test the frontend dashboard
3. Update README if you added new features
4. Submit a PR with a clear description

## Code Style

- Python: Follow PEP 8
- JavaScript: Use consistent formatting
- YAML: 2-space indentation

## Reporting Issues

Use GitHub Issues. Include:
- Steps to reproduce
- Expected vs actual behavior
- Python version and OS
- Error logs if applicable

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
