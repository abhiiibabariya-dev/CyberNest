# CyberNest - SIEM + SOAR Platform

> A unified Security Information & Event Management (SIEM) and Security Orchestration, Automation & Response (SOAR) platform built for SOC teams.

![Python](https://img.shields.io/badge/Python-3.13-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active_Development-orange)

## Features

### SIEM
- **Log Ingestion** — Collect logs from multiple sources (syslog, CEF, APIs, file-based, agents)
- **Log Parsing & Normalization** — Auto-parse syslog, CEF, and extract IPs, hostnames, and metadata
- **Detection Engine** — YAML-based correlation rules mapped to MITRE ATT&CK framework
- **Real-time Alerting** — Severity-based alerts with WebSocket live streaming
- **Log Search** — Full-text search with severity, IP, and time-range filters
- **Dashboard** — SOC analyst overview with stats, charts, MITRE ATT&CK heatmap

### SOAR
- **Playbook Engine** — YAML-defined automated response playbooks with 7 action types
- **Orchestration** — Block IPs, isolate hosts, disable users, enrich IOCs, create tickets, send notifications
- **Case Management** — Full incident lifecycle with timeline tracking
- **Automated Response** — Alert-triggered or manual playbook execution
- **Enrichment** — IOC enrichment pipeline (extendable to VirusTotal, AbuseIPDB, Shodan)

## Screenshots

> Dashboard with live stats, alert timeline, severity charts, and MITRE ATT&CK heatmap

## Quick Start

### Option 1: Script Setup (Recommended)

```bash
git clone https://github.com/abhiiibabariya-dev/CyberNest.git
cd CyberNest

# Linux/macOS
chmod +x setup.sh run.sh
./setup.sh
./run.sh

# Windows
setup.bat
run.bat
```

### Option 2: Docker

```bash
git clone https://github.com/abhiiibabariya-dev/CyberNest.git
cd CyberNest
docker-compose up --build
```

### Option 3: Manual Setup

```bash
git clone https://github.com/abhiiibabariya-dev/CyberNest.git
cd CyberNest

# Create virtual environment
python -m venv venv
source venv/bin/activate      # Linux/macOS
# venv\Scripts\activate       # Windows

# Install dependencies
pip install -r backend/requirements.txt

# Seed demo data (100 events, 15 alerts, 5 incidents, 6 playbooks)
cd backend
python seed.py

# Start server
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Open http://localhost:8000** and explore the dashboard.

### Demo Credentials

| User | Password | Role |
|------|----------|------|
| `admin` | `admin123` | Admin |
| `analyst` | `analyst123` | Analyst |

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.13 + FastAPI |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Task Queue | Celery + Redis (optional) |
| Frontend | HTML/CSS/JS — Cyber-themed Dashboard |
| Config | YAML-based rules & playbooks |
| API | RESTful + WebSocket (live alerts) |
| Auth | JWT + bcrypt |
| Deployment | Docker / docker-compose |

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register` | Register new user |
| POST | `/api/v1/auth/login` | Login, get JWT token |

### SIEM
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/events/ingest` | Ingest a single log event |
| POST | `/api/v1/events/ingest/batch` | Ingest batch of logs |
| GET | `/api/v1/events` | Search/list events |
| GET | `/api/v1/alerts` | List alerts (filter by severity/status) |
| PATCH | `/api/v1/alerts/{id}` | Update alert status |
| GET | `/api/v1/rules` | List detection rules |
| POST | `/api/v1/rules` | Create detection rule |
| GET | `/api/v1/sources` | List log sources |

### SOAR
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/incidents` | List incidents |
| POST | `/api/v1/incidents` | Create incident |
| PATCH | `/api/v1/incidents/{id}` | Update incident |
| GET | `/api/v1/playbooks` | List playbooks |
| POST | `/api/v1/playbooks/{id}/run` | Execute a playbook |
| GET | `/api/v1/playbooks/runs` | List playbook run history |

### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/dashboard/stats` | Full dashboard statistics |
| WS | `/ws/alerts/live` | WebSocket live alert stream |

## Detection Rules

CyberNest uses YAML-based detection rules in `config/rules/`. Included rules:

| Rule | Severity | MITRE ATT&CK |
|------|----------|---------------|
| Brute Force Login | High | T1110 |
| SSH Brute Force | High | T1110.001 |
| Suspected C2 Communication | Critical | T1071 |
| Suspicious PowerShell | Critical | T1059.001 |
| Ransomware Indicators | Critical | T1486 |
| Port Scan Detection | Medium | T1046 |
| Data Exfiltration | High | T1048 |
| Lateral Movement | High | T1021 |
| Privilege Escalation | Critical | T1068 |
| New Admin Account | High | T1136 |

### Adding Custom Rules

```yaml
name: My Custom Rule
description: Detects something suspicious
severity: high
enabled: true
alert_title: "Custom Alert Title"
mitre_tactic: Execution
mitre_technique: T1059

logic: or
conditions:
  - field: message
    operator: contains
    value: "suspicious_keyword"
  - field: src_ip
    operator: equals
    value: "10.0.0.100"
```

## SOAR Playbooks

Pre-built playbooks in `config/playbooks/`:

| Playbook | Trigger | Actions |
|----------|---------|---------|
| Block Malicious IP | Auto (alert) | Enrich IOC, block IP, create ticket, notify SOC |
| Disable Compromised Account | Manual | Disable user, create ticket, notify team |
| Isolate Infected Host | Auto (critical) | Isolate host, enrich IOCs, create ticket, notify |

### Available Actions

| Action | Description |
|--------|-------------|
| `block_ip` | Block IP on firewall |
| `isolate_host` | Network-isolate endpoint |
| `disable_user` | Disable user account |
| `enrich_ioc` | Enrich IOC with threat intel |
| `create_ticket` | Create investigation ticket |
| `send_notification` | Send alert to Slack/email/PagerDuty |
| `log` | Log playbook action |

## Project Structure

```
CyberNest/
├── backend/
│   ├── main.py              # FastAPI app entry point
│   ├── seed.py              # Demo data seeder
│   ├── requirements.txt     # Python dependencies
│   ├── core/                # Auth, database, models, schemas, config
│   ├── siem/                # Log parser, detection engine, ingest service
│   ├── soar/                # Playbook engine, case manager
│   └── api/                 # REST API routes, WebSocket
├── frontend/
│   ├── index.html           # Dashboard (9 pages)
│   └── src/                 # CSS + JavaScript
├── config/
│   ├── rules/               # YAML detection rules
│   └── playbooks/           # YAML SOAR playbooks
├── Dockerfile               # Container build
├── docker-compose.yml       # One-command deployment
├── setup.sh / setup.bat     # Quick setup scripts
├── run.sh / run.bat         # Quick run scripts
└── LICENSE
```

## Roadmap

- [ ] Real syslog UDP/TCP listener
- [ ] Sigma rule import support
- [ ] VirusTotal / AbuseIPDB / Shodan integration
- [ ] Slack / PagerDuty / email notifications
- [ ] PostgreSQL production database
- [ ] Alert correlation engine
- [ ] Endpoint log collection agent
- [ ] PDF/CSV incident reports
- [ ] MITRE ATT&CK Navigator integration
- [ ] Role-based access control (frontend)
- [ ] Audit logging

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE)

---

**CyberNest** — Detect. Respond. Protect.
