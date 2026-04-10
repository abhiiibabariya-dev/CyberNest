# CyberNest API Reference

Base URL: `http://localhost:5000/api/v1`

Interactive docs: `http://localhost/docs` (Swagger UI) or `http://localhost/redoc`

## Authentication

All endpoints (except `/auth/login` and `/auth/register`) require a JWT Bearer token:

```
Authorization: Bearer <token>
```

### POST /auth/login

Login and obtain JWT tokens.

**Request:**
```json
{
  "username": "admin",
  "password": "CyberNest@2025!",
  "totp_code": "123456"  // optional, required if MFA enabled
}
```

**Response:**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 3600,
  "user": {
    "id": "uuid",
    "username": "admin",
    "email": "admin@cybernest.local",
    "role": "super_admin"
  }
}
```

### POST /auth/register

Register a new user (admin only).

### POST /auth/refresh

Refresh an expired access token using a refresh token.

### POST /auth/logout

Blacklist the current token.

### POST /auth/mfa/setup

Generate TOTP secret and QR code URI.

### POST /auth/mfa/verify

Verify TOTP code and enable MFA.

### POST /auth/change-password

Change the current user's password.

---

## Alerts

### GET /alerts

List alerts with filtering and pagination.

**Query Parameters:**
| Param | Type | Description |
|-------|------|-------------|
| `severity` | string | Filter: info, low, medium, high, critical |
| `status` | string | Filter: new, in_progress, resolved, false_positive, escalated |
| `rule_id` | string | Filter by rule ID |
| `agent_id` | string | Filter by agent ID |
| `source_ip` | string | Filter by source IP |
| `date_from` | ISO8601 | Start date |
| `date_to` | ISO8601 | End date |
| `assignee` | string | Filter by assigned user ID |
| `mitre_technique` | string | Filter by MITRE technique ID |
| `page` | int | Page number (default: 1) |
| `per_page` | int | Items per page (default: 50) |

### GET /alerts/{id}

Get alert detail with related events (ES query for same source IP +/- 5 minutes).

### PATCH /alerts/{id}/status

Update alert status. Records `acknowledged_at` / `resolved_at`.

```json
{ "status": "in_progress" }
```

### PATCH /alerts/{id}/assign

Assign alert to an analyst.

```json
{ "assignee_id": "user-uuid" }
```

### POST /alerts/{id}/case

Create a case from this alert.

### GET /alerts/stats

Alert statistics: counts by severity, status, trend by hour (24h).

### WebSocket /alerts/live

Real-time alert stream via WebSocket. Sends new alerts as they arrive.

---

## Search

### GET /search

Elasticsearch query with Lucene syntax.

**Query Parameters:**
| Param | Type | Description |
|-------|------|-------------|
| `q` | string | Lucene query string |
| `from_time` | ISO8601 | Start time |
| `to_time` | ISO8601 | End time |
| `index` | string | `events` or `alerts` (default: events) |
| `size` | int | Results per page (1-1000, default: 50) |
| `sort` | string | Field:asc/desc |
| `fields` | string | Comma-separated field filter |

**Response:**
```json
{
  "total": 12543,
  "hits": [...],
  "took_ms": 45,
  "scroll_id": "..."
}
```

---

## Rules

### GET /rules

List all detection rules with hit counts.

### POST /rules

Create a new rule (YAML or XML content).

### PUT /rules/{id}

Update a rule.

### POST /rules/{id}/toggle

Enable or disable a rule.

### POST /rules/import/sigma

Upload a Sigma YAML file to import as a CyberNest rule.

### POST /rules/test

Test a rule against sample event data.

```json
{
  "rule_yaml": "...",
  "event": { ... }
}
```

---

## Cases

### GET /cases

List cases with filtering.

### POST /cases

Create a new case.

```json
{
  "title": "Incident Title",
  "description": "...",
  "severity": "high",
  "tags": ["brute-force", "T1110"],
  "tlp": "amber"
}
```

### GET /cases/{id}

Case detail.

### POST /cases/{id}/tasks

Add a task to a case.

### POST /cases/{id}/observables

Add an observable (IOC) to a case.

### POST /cases/{id}/comments

Add a comment.

### POST /cases/{id}/attachments

Upload evidence file (multipart/form-data).

### GET /cases/{id}/timeline

Chronological timeline of all case activities.

### POST /cases/{id}/merge/{target_id}

Merge two cases.

### POST /cases/{id}/export/pdf

Generate and download a PDF case report.

---

## Agents

### POST /agents/register

Register a new agent and get an API key.

### GET /agents

List all agents with status.

### GET /agents/{id}

Agent detail with recent event count.

### POST /agents/{id}/command

Send a remote command to an agent.

```json
{
  "command": "isolate",
  "params": {}
}
```

Commands: `isolate`, `unisolate`, `restart`, `update`, `get_processes`, `get_connections`

---

## Playbooks

### GET /playbooks

List all SOAR playbooks.

### POST /playbooks

Create a new playbook (YAML upload).

### POST /playbooks/{id}/trigger

Manually trigger a playbook.

```json
{
  "alert_id": "alert-uuid"
}
```

### GET /playbooks/{id}/history

Execution history with step-by-step logs.

---

## Threat Intelligence

### GET /threat-intel/lookup

Lookup a single IOC.

**Query Parameters:**
| Param | Type | Description |
|-------|------|-------------|
| `value` | string | IOC value (IP, domain, hash, etc.) |
| `type` | string | `ip`, `domain`, `hash_sha256`, `url`, `email` |

### POST /threat-intel/iocs/bulk

Import IOCs from CSV or STIX JSON.

### GET /threat-intel/feeds

List configured threat intelligence feeds.

### POST /threat-intel/feeds/{id}/refresh

Trigger immediate feed refresh.

---

## Dashboard

### GET /dashboard/stats

Full dashboard statistics:

```json
{
  "total_events_24h": 125000,
  "total_alerts_24h": 47,
  "alerts_by_severity": {"critical": 2, "high": 8, "medium": 15, "low": 12, "info": 10},
  "alerts_by_status": {"new": 20, "in_progress": 15, "resolved": 12},
  "top_rules": [{"rule_name": "...", "hit_count": 100}],
  "top_source_ips": [{"ip": "...", "count": 50, "country": "US"}],
  "events_per_hour": [{"hour": "2025-01-01T00:00:00Z", "count": 5000}],
  "agent_status": {"online": 25, "offline": 3, "degraded": 1, "total": 29},
  "mitre_techniques": [{"technique_id": "T1110", "name": "Brute Force", "count": 15}],
  "open_cases": 5,
  "mean_time_to_detect": 120.5,
  "mean_time_to_respond": 450.2,
  "active_playbooks": 4,
  "ioc_matches_24h": 12
}
```

### WebSocket /dashboard/live

Broadcasts updated dashboard stats every 30 seconds.

---

## Users

### GET /users (admin only)

List all users.

### GET /users/me

Current user profile.

### PATCH /users/me

Update own profile.

---

## Assets

### GET /assets

List all assets.

### POST /assets/discover

Trigger network discovery scan.

---

## Health

### GET /health

System health check for all dependencies.

```json
{
  "status": "healthy",
  "services": {
    "postgres": "ok",
    "elasticsearch": "ok",
    "redis": "ok",
    "kafka": "ok"
  },
  "version": "1.0.0",
  "uptime": 86400
}
```
