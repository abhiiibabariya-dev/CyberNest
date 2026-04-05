# CyberNest - SIEM + SOAR Platform

> A unified Security Information & Event Management (SIEM) and Security Orchestration, Automation & Response (SOAR) platform built for SOC teams.

## Features

### SIEM
- **Log Ingestion** — Collect logs from multiple sources (syslog, APIs, file-based, agents)
- **Log Parsing & Normalization** — Unified event schema across all sources
- **Detection Engine** — YAML-based correlation rules mapped to MITRE ATT&CK
- **Real-time Alerting** — Severity-based alerts with deduplication
- **Log Search** — Full-text search with filters and time-range queries
- **Dashboard** — SOC analyst overview with metrics, charts, and threat indicators

### SOAR
- **Playbook Engine** — YAML-defined automated response playbooks
- **Orchestration** — Trigger actions across integrated tools (firewall, EDR, email, ticketing)
- **Case Management** — Track incidents from detection to resolution
- **Automated Response** — Auto-block IPs, isolate hosts, disable accounts
- **Enrichment** — Auto-enrich IOCs with threat intelligence feeds

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.13 + FastAPI |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Task Queue | Celery + Redis |
| Frontend | HTML/CSS/JS Dashboard |
| Config | YAML-based rules & playbooks |
| API | RESTful + WebSocket (live alerts) |

## Quick Start

```bash
# Clone
git clone https://github.com/abhiiibabariya-dev/CyberNest.git
cd CyberNest

# Backend setup
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --reload

# Open dashboard
# Navigate to http://localhost:8000
```

## Project Structure

```
CyberNest/
├── backend/
│   ├── main.py              # FastAPI app entry point
│   ├── requirements.txt     # Python dependencies
│   ├── core/                # Auth, database, shared models
│   ├── siem/                # Log ingestion, parsing, detection engine
│   ├── soar/                # Playbook engine, orchestration, response
│   └── api/                 # REST API routes
├── frontend/
│   ├── index.html           # Main dashboard
│   ├── src/                 # JS components & pages
│   └── assets/              # CSS, images
├── agents/                  # Log collection agents
├── config/
│   ├── rules/               # SIEM detection rules (YAML)
│   └── playbooks/           # SOAR playbooks (YAML)
├── tests/                   # Test suite
└── docs/                    # Documentation
```

## License

MIT

---

**CyberNest** — Detect. Respond. Protect.
