```
   ______      __              _   __          __
  / ____/_  __/ /_  ___  _____/ | / /__  _____/ /_
 / /   / / / / __ \/ _ \/ ___/  |/ / _ \/ ___/ __/
/ /___/ /_/ / /_/ /  __/ /  / /|  /  __(__  ) /_
\____/\__, /_.___/\___/_/  /_/ |_/\___/____/\__/
     /____/
```

# CyberNest — SIEM + SOAR Platform

> Enterprise-grade Security Information & Event Management (SIEM) and Security Orchestration, Automation & Response (SOAR) platform. Open source. Self-hosted.

![Python](https://img.shields.io/badge/Python-3.13-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.11-005571?logo=elasticsearch)
![Kafka](https://img.shields.io/badge/Kafka-7.5-231F20?logo=apachekafka)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Features

| Category | Capabilities |
|----------|-------------|
| **Log Collection** | Cross-platform agent (Windows/Linux/macOS), Syslog (UDP/TCP), 13+ log format parsers |
| **Detection Engine** | 60+ built-in rules, Sigma rule support, YAML custom rules, ML anomaly detection (UEBA) |
| **Correlation** | Sliding window rules, threshold detection, sequence tracking, impossible travel |
| **Alert Management** | Deduplication, enrichment, risk scoring, SLA tracking, auto-escalation |
| **SOAR** | Playbook engine, 12+ action integrations, Jinja2 templates, auto/manual trigger |
| **Threat Intelligence** | OTX, Abuse.ch, Emerging Threats feeds, IOC database, real-time enrichment |
| **Case Management** | Full incident lifecycle, tasks, observables, timeline, evidence, PDF export |
| **Dashboard** | Real-time WebSocket feeds, MITRE ATT&CK heatmap, geo map, Splunk-like search |
| **Integrations** | Slack, Email, PagerDuty, Teams, JIRA, VirusTotal, AbuseIPDB, Shodan |

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        CyberNest Platform                            │
├──────────┬───────────┬────────────┬──────────┬──────────┬───────────┤
│  Agent   │  Syslog   │   Parser   │ Correlator│  Alert   │   SOAR   │
│ (endpoints)│ Receiver │  Service   │  Engine  │ Manager  │  Engine  │
├──────────┴───────────┴─────┬──────┴──────────┴──────────┴───────────┤
│                            │                                         │
│         ┌──────────────────▼──────────────────┐                     │
│         │         Apache Kafka                 │                     │
│         │  (raw.* → parsed.events → alerts)    │                     │
│         └──────────────────┬──────────────────┘                     │
│                            │                                         │
│  ┌────────────┐  ┌────────▼────────┐  ┌──────────────┐             │
│  │ PostgreSQL  │  │ Elasticsearch   │  │    Redis      │             │
│  │ (metadata)  │  │ (events/search) │  │ (cache/pubsub)│             │
│  └────────────┘  └─────────────────┘  └──────────────┘             │
├──────────────────────────────────────────────────────────────────────┤
│                   Manager API (FastAPI)                               │
│              REST + WebSocket + Agent Receiver                        │
├──────────────────────────────────────────────────────────────────────┤
│                  React Dashboard (TypeScript)                         │
│           Dark SOC UI — Tailwind CSS + Recharts                      │
├──────────────────────────────────────────────────────────────────────┤
│                       Nginx (Reverse Proxy)                          │
└──────────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Clone
git clone https://github.com/abhiiibabariya-dev/CyberNest.git
cd CyberNest

# Setup and start (one command)
bash scripts/setup.sh

# Or manually:
cp .env.example .env
docker-compose up -d
```

**Dashboard:** http://localhost
**API Docs:** http://localhost/docs

## Default Credentials

| User | Password | Role |
|------|----------|------|
| `admin` | `CyberNest@2025!` | Super Admin |
| `analyst` | `Analyst@2025!` | Analyst |
| `soc_lead` | `SocLead@2025!` | SOC Lead |

> Change these immediately in production!

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend API** | Python 3.13, FastAPI, SQLAlchemy (async), asyncpg |
| **Frontend** | React 18, TypeScript 5, TailwindCSS, Recharts, Zustand |
| **Message Bus** | Apache Kafka (Confluent 7.5) |
| **Search/Index** | Elasticsearch 8.11 |
| **Database** | PostgreSQL 15 |
| **Cache/PubSub** | Redis 7.2 |
| **Reverse Proxy** | Nginx |
| **Containers** | Docker Compose |

## Services

| Service | Port | Description |
|---------|------|-------------|
| `cybernest-manager` | 5000, 5601 | REST API + Agent receiver |
| `cybernest-dashboard` | 3000 | React web UI |
| `cybernest-parser` | — | Log parsing + enrichment |
| `cybernest-correlator` | — | Detection engine |
| `cybernest-alert-manager` | — | Alert lifecycle |
| `cybernest-soar` | — | Playbook execution |
| `cybernest-indexer` | — | Elasticsearch writer |
| `cybernest-threat-intel` | — | IOC feed ingestion |
| `cybernest-syslog` | 514/udp, 601/tcp | Syslog receiver |
| `nginx` | 80, 443 | Reverse proxy |

## Agent Installation

### Linux
```bash
curl -sSL https://raw.githubusercontent.com/abhiiibabariya-dev/CyberNest/master/scripts/install-agent.sh | \
  bash -s -- --manager-url https://YOUR_SERVER:5601 --api-key YOUR_KEY
```

### Windows (PowerShell)
```powershell
iwr -useb https://raw.githubusercontent.com/abhiiibabariya-dev/CyberNest/master/scripts/install-agent.ps1 | iex
```

## Detection Rules

CyberNest ships with 60+ built-in detection rules covering:

- **Windows:** Authentication, credential access, privilege escalation, execution
- **Linux:** Authentication, persistence, suspicious activity
- **Network:** Port scans, host sweeps, C2 beaconing, DNS tunneling
- **Cloud:** AWS CloudTrail anomalies

Custom rules use a simple YAML format. Sigma rules are also supported.

See [docs/rule-writing.md](docs/rule-writing.md) for the rule authoring guide.

## SOAR Playbooks

Pre-built automated response playbooks:

- **Brute Force Response** — Enrich IP, block if malicious, create case, notify SOC
- **Malware Response** — Isolate endpoint, kill process, enrich hash, create case
- **Phishing Response** — WHOIS lookup, URL/hash analysis, block domain
- **Insider Threat Response** — Block destination, disable user, isolate endpoint

## API Documentation

Full REST API with OpenAPI/Swagger docs available at `/docs` when running.

See [docs/api-reference.md](docs/api-reference.md) for the complete API reference.

## Development

```bash
# Backend (manager)
cd manager
pip install -r requirements.txt
uvicorn main:app --reload --port 5000

# Frontend (dashboard)
cd dashboard
npm install
npm run dev
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

**CyberNest** — Detect. Respond. Protect.
