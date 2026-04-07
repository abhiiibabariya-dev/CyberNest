# CyberNest Architecture

## System Overview

```
                    ┌─────────────┐
                    │   Agents    │  Windows / Linux / macOS
                    │  (Python)   │  FIM, Process, Network, Logs
                    └──────┬──────┘
                           │ TLS WebSocket (5601)
                    ┌──────▼──────┐
                    │   Manager   │  FastAPI REST API (5000)
                    │   (API)     │  Syslog Receiver (514/601)
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │   Kafka     │  Message broker (9092)
                    │  (9 topics) │  Raw → Parsed → Alerts
                    └──────┬──────┘
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──────┐ ┌──▼───┐ ┌──────▼──────┐
       │   Parser    │ │Indexer│ │ Correlator  │
       │ (11 formats)│ │(ES)  │ │(Sigma+UEBA) │
       └──────┬──────┘ └──┬───┘ └──────┬──────┘
              │           │            │
              │    ┌──────▼──────┐     │
              └────► Elasticsearch◄────┘
                   │   (9200)    │
                   └─────────────┘
              ┌──────────────────────┐
              │    Alert Manager     │  Dedup → Enrich → Notify
              │  Slack/Email/PD/Teams│
              └──────────┬───────────┘
                         │
              ┌──────────▼───────────┐
              │    SOAR Engine       │  Playbook Automation
              │ VT/AbuseIPDB/Shodan  │  Firewall Block, AD Disable
              └──────────────────────┘
              ┌──────────────────────┐
              │  React Dashboard     │  10 pages, WebSocket live
              │  (TypeScript/Tailwind│  Dark SOC theme
              └──────────────────────┘
```

## Services (13 total)

| Service | Port | Technology | Purpose |
|---------|------|------------|---------|
| Manager API | 5000 | FastAPI | Central REST API, agent receiver |
| Parser | — | Python/Kafka | Log format normalization to ECS |
| Correlator | — | Python/Redis | Rule matching + ML anomaly detection |
| Alert Manager | — | Python | Dedup, enrich, notify, lifecycle |
| SOAR Engine | — | Python | Playbook automation |
| Indexer | — | Python/ES | Elasticsearch bulk writer |
| Threat Intel | — | Python | IOC feed ingestion |
| UEBA | — | Python/sklearn | Behavioral anomaly detection |
| Dashboard | 3000 | React/TS | Enterprise SOC UI |
| Kafka | 9092 | Confluent | Message broker |
| Elasticsearch | 9200 | Elastic 8.x | Event/alert storage + search |
| PostgreSQL | 5432 | PG 15 | Users, rules, cases, IOCs |
| Redis | 6379 | Redis 7.x | Cache, sessions, sliding windows |

## Data Flow

1. **Agents** collect logs (Event Log, syslog, FIM, processes, network)
2. **Manager** receives via TLS WebSocket, routes to **Kafka** topics
3. **Parser** normalizes all formats to ECS, enriches with GeoIP + TI
4. **Correlator** evaluates Sigma rules + sliding windows + UEBA
5. **Alert Manager** deduplicates, persists, notifies (Slack/Email/PD)
6. **SOAR** executes automated playbooks (VT lookup, firewall block)
7. **Indexer** bulk-writes to **Elasticsearch** for fast search
8. **Dashboard** displays real-time alerts, search, cases, agents
