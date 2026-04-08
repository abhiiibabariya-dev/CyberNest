# CyberNest API Reference

Base URL: `http://localhost:5000/api`

All endpoints require authentication via JWT bearer token unless otherwise noted. Responses use JSON.

---

## Table of Contents

1. [Authentication](#authentication)
2. [Alerts](#alerts)
3. [Agents](#agents)
4. [Rules](#rules)
5. [Cases](#cases)
6. [Search](#search)
7. [Dashboard](#dashboard)
8. [Playbooks](#playbooks)
9. [Threat Intel](#threat-intel)
10. [Users](#users)
11. [Assets](#assets)
12. [Notification Channels](#notification-channels)
13. [Health](#health)
14. [Error Responses](#error-responses)

---

## Authentication

### Login

Obtain a JWT access token and refresh token.

**`POST /api/auth/login`**

Request:
```json
{
  "username": "admin",
  "password": "CyberNest@2025!"
}
```

Response `200`:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 3600,
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "admin",
    "email": "admin@cybernest.local",
    "role": "super_admin"
  }
}
```

```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "CyberNest@2025!"}'
```

### Refresh Token

**`POST /api/auth/refresh`**

Request:
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

Response `200`:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_in": 3600
}
```

```bash
curl -X POST http://localhost:5000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "YOUR_REFRESH_TOKEN"}'
```

### Logout

**`POST /api/auth/logout`**

```bash
curl -X POST http://localhost:5000/api/auth/logout \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

Response `200`:
```json
{
  "message": "Successfully logged out"
}
```

### Get Current User

**`GET /api/auth/me`**

```bash
curl http://localhost:5000/api/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

Response `200`:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "admin",
  "email": "admin@cybernest.local",
  "role": "super_admin",
  "is_active": true,
  "last_login_at": "2025-01-15T10:30:00Z",
  "created_at": "2025-01-01T00:00:00Z"
}
```

---

## Alerts

### List Alerts

**`GET /api/alerts`**

Query parameters:

| Parameter   | Type   | Default | Description                                      |
|-------------|--------|---------|--------------------------------------------------|
| `page`      | int    | 1       | Page number                                      |
| `per_page`  | int    | 25      | Items per page (max 100)                         |
| `status`    | string | -       | Filter: new, in_progress, resolved, false_positive, escalated |
| `severity`  | string | -       | Filter: info, low, medium, high, critical        |
| `sort`      | string | created_at | Sort field                                    |
| `order`     | string | desc    | Sort order: asc, desc                            |
| `search`    | string | -       | Full-text search in title and description        |
| `from`      | string | -       | Start date (ISO 8601)                            |
| `to`        | string | -       | End date (ISO 8601)                              |

```bash
curl "http://localhost:5000/api/alerts?status=new&severity=high&per_page=10" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `200`:
```json
{
  "items": [
    {
      "id": "a1b2c3d4-...",
      "alert_id": "ALT-20250115-001",
      "rule_id": "550e8400-...",
      "severity": "high",
      "status": "new",
      "title": "Brute Force Login Attempt",
      "description": "More than 5 failed login attempts...",
      "source_ip": "203.0.113.50",
      "destination_ip": "10.0.1.5",
      "username": "admin",
      "mitre_tactic": "TA0006",
      "mitre_technique": "T1110.001",
      "created_at": "2025-01-15T10:30:00Z",
      "updated_at": "2025-01-15T10:30:00Z"
    }
  ],
  "total": 142,
  "page": 1,
  "per_page": 10,
  "pages": 15
}
```

### Get Alert

**`GET /api/alerts/{alert_id}`**

```bash
curl http://localhost:5000/api/alerts/a1b2c3d4-... \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `200`:
```json
{
  "id": "a1b2c3d4-...",
  "alert_id": "ALT-20250115-001",
  "rule_id": "550e8400-...",
  "agent_id": "660e8400-...",
  "severity": "high",
  "status": "new",
  "title": "Brute Force Login Attempt",
  "description": "More than 5 failed login attempts from 203.0.113.50",
  "source_ip": "203.0.113.50",
  "destination_ip": "10.0.1.5",
  "username": "admin",
  "raw_log": "Jan 15 10:30:00 DC01 sshd[1234]: Failed password for admin...",
  "parsed_event": { "event": { "outcome": "failure" } },
  "mitre_tactic": "TA0006",
  "mitre_technique": "T1110.001",
  "assignee": null,
  "case_id": null,
  "created_at": "2025-01-15T10:30:00Z",
  "updated_at": "2025-01-15T10:30:00Z"
}
```

### Update Alert

**`PATCH /api/alerts/{alert_id}`**

Request:
```json
{
  "status": "in_progress",
  "assignee": "550e8400-...",
  "severity": "critical"
}
```

```bash
curl -X PATCH http://localhost:5000/api/alerts/a1b2c3d4-... \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status": "in_progress", "assignee": "550e8400-..."}'
```

Response `200`:
```json
{
  "id": "a1b2c3d4-...",
  "status": "in_progress",
  "assignee": "550e8400-...",
  "updated_at": "2025-01-15T11:00:00Z"
}
```

### Bulk Update Alerts

**`PATCH /api/alerts/bulk`**

Request:
```json
{
  "alert_ids": ["a1b2c3d4-...", "e5f6g7h8-..."],
  "status": "resolved"
}
```

```bash
curl -X PATCH http://localhost:5000/api/alerts/bulk \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"alert_ids": ["a1b2c3d4-...", "e5f6g7h8-..."], "status": "resolved"}'
```

Response `200`:
```json
{
  "updated": 2,
  "failed": 0
}
```

### Escalate Alert to Case

**`POST /api/alerts/{alert_id}/escalate`**

Request:
```json
{
  "case_title": "Investigation: Brute Force from 203.0.113.50",
  "case_severity": "high"
}
```

```bash
curl -X POST http://localhost:5000/api/alerts/a1b2c3d4-.../escalate \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"case_title": "Investigation: Brute Force", "case_severity": "high"}'
```

Response `201`:
```json
{
  "alert_id": "a1b2c3d4-...",
  "case_id": "c1d2e3f4-...",
  "case_case_id": "CASE-20250115-001",
  "status": "escalated"
}
```

---

## Agents

### List Agents

**`GET /api/agents`**

Query parameters: `page`, `per_page`, `status` (online, offline, degraded), `os`, `search`

```bash
curl "http://localhost:5000/api/agents?status=online" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `200`:
```json
{
  "items": [
    {
      "id": "660e8400-...",
      "agent_id": "agent-dc01-win",
      "hostname": "DC01",
      "ip": "10.0.1.5",
      "os": "windows",
      "os_version": "Windows Server 2022",
      "version": "1.2.0",
      "status": "online",
      "last_seen": "2025-01-15T10:29:55Z",
      "tags": ["domain-controller", "tier-0"],
      "enrolled_at": "2025-01-01T00:00:00Z"
    }
  ],
  "total": 45,
  "page": 1,
  "per_page": 25,
  "pages": 2
}
```

### Get Agent

**`GET /api/agents/{agent_id}`**

```bash
curl http://localhost:5000/api/agents/660e8400-... \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Enroll Agent

**`POST /api/agents/enroll`**

Request:
```json
{
  "hostname": "web-server-1",
  "ip": "10.0.2.10",
  "os": "linux",
  "os_version": "Ubuntu 22.04",
  "architecture": "amd64",
  "version": "1.2.0",
  "tags": ["web", "production"]
}
```

Response `201`:
```json
{
  "agent_id": "agent-web-server-1-linux",
  "api_key": "cn_agent_abc123def456ghi789",
  "message": "Agent enrolled successfully. Save the API key - it cannot be retrieved later."
}
```

```bash
curl -X POST http://localhost:5000/api/agents/enroll \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"hostname":"web-server-1","ip":"10.0.2.10","os":"linux","os_version":"Ubuntu 22.04","architecture":"amd64","version":"1.2.0"}'
```

### Update Agent

**`PATCH /api/agents/{agent_id}`**

Request:
```json
{
  "tags": ["web", "production", "patched"],
  "config_json": { "log_level": "debug" }
}
```

```bash
curl -X PATCH http://localhost:5000/api/agents/660e8400-... \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tags": ["web", "production", "patched"]}'
```

### Delete Agent

**`DELETE /api/agents/{agent_id}`**

```bash
curl -X DELETE http://localhost:5000/api/agents/660e8400-... \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `200`:
```json
{
  "message": "Agent deleted successfully"
}
```

### Download Agent Binary

**`GET /api/agents/download`**

Query parameters: `os` (linux, windows, darwin), `arch` (amd64, arm64), `version` (default: latest)

```bash
curl -o cybernest-agent \
  "http://localhost:5000/api/agents/download?os=linux&arch=amd64" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## Rules

### List Rules

**`GET /api/rules`**

Query parameters: `page`, `per_page`, `category`, `level`, `enabled` (true/false), `search`

```bash
curl "http://localhost:5000/api/rules?category=authentication&enabled=true" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `200`:
```json
{
  "items": [
    {
      "id": "770e8400-...",
      "rule_id": "CN-WIN-AUTH-001",
      "name": "Single Failed Login Attempt",
      "description": "A single failed login attempt...",
      "level": 1,
      "category": "authentication",
      "mitre_tactic": "TA0006",
      "mitre_technique": ["T1110"],
      "is_enabled": true,
      "hit_count": 1523,
      "false_positive_count": 12,
      "created_at": "2025-01-01T00:00:00Z"
    }
  ],
  "total": 63,
  "page": 1,
  "per_page": 25,
  "pages": 3
}
```

### Get Rule

**`GET /api/rules/{rule_id}`**

```bash
curl http://localhost:5000/api/rules/770e8400-... \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Create Rule

**`POST /api/rules`**

Request:
```json
{
  "rule_id": "CN-CUSTOM-001",
  "name": "Custom Detection Rule",
  "description": "Detects custom event pattern",
  "level": 3,
  "category": "custom",
  "mitre_tactic": "TA0002",
  "mitre_technique": ["T1059"],
  "content_yaml": "id: CN-CUSTOM-001\nname: Custom Detection Rule\n...",
  "is_enabled": true
}
```

```bash
curl -X POST http://localhost:5000/api/rules \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"rule_id":"CN-CUSTOM-001","name":"Custom Detection Rule","level":3,"category":"custom","content_yaml":"...","is_enabled":true}'
```

Response `201`:
```json
{
  "id": "880e8400-...",
  "rule_id": "CN-CUSTOM-001",
  "name": "Custom Detection Rule",
  "created_at": "2025-01-15T12:00:00Z"
}
```

### Update Rule

**`PUT /api/rules/{rule_id}`**

Request: same schema as Create.

```bash
curl -X PUT http://localhost:5000/api/rules/880e8400-... \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Updated Rule Name","level":4,"is_enabled":true,"content_yaml":"..."}'
```

### Delete Rule

**`DELETE /api/rules/{rule_id}`**

```bash
curl -X DELETE http://localhost:5000/api/rules/880e8400-... \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Test Rule

**`POST /api/rules/test`**

Request:
```json
{
  "rule_yaml": "id: CN-TEST-001\nname: Test\n...",
  "events": [
    { "event": { "outcome": "failure" } }
  ]
}
```

Response `200`:
```json
{
  "rule_id": "CN-TEST-001",
  "total_events": 1,
  "matched_events": 1,
  "matches": [{ "event_index": 0, "event": { "event": { "outcome": "failure" } } }]
}
```

### Validate Rule

**`POST /api/rules/validate`**

Request:
```json
{
  "content_yaml": "id: CN-TEST-001\n..."
}
```

Response `200`:
```json
{
  "valid": true,
  "warnings": [],
  "errors": []
}
```

### Import Sigma Rule

**`POST /api/rules/import/sigma`**

Content-Type: `application/yaml`

```bash
curl -X POST http://localhost:5000/api/rules/import/sigma \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/yaml" \
  --data-binary @sigma_rule.yml
```

Response `201`:
```json
{
  "imported": true,
  "rule_id": "CN-SIGMA-abc123",
  "sigma_id": "5af54681-df95-4c26-854f-2565e13cfab0",
  "name": "Imported Sigma Rule"
}
```

### Reload Rules

**`POST /api/rules/reload`**

```bash
curl -X POST http://localhost:5000/api/rules/reload \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `200`:
```json
{
  "message": "Rules reloaded",
  "total_rules": 63,
  "enabled_rules": 58
}
```

---

## Cases

### List Cases

**`GET /api/cases`**

Query parameters: `page`, `per_page`, `status` (open, in_progress, closed), `severity`, `assignee`, `search`

```bash
curl "http://localhost:5000/api/cases?status=open" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `200`:
```json
{
  "items": [
    {
      "id": "c1d2e3f4-...",
      "case_id": "CASE-20250115-001",
      "title": "Investigation: Brute Force from 203.0.113.50",
      "severity": "high",
      "status": "open",
      "assignee": "550e8400-...",
      "tags": ["brute-force", "authentication"],
      "tlp": "amber",
      "alert_count": 5,
      "task_count": 3,
      "created_at": "2025-01-15T10:35:00Z"
    }
  ],
  "total": 12,
  "page": 1,
  "per_page": 25,
  "pages": 1
}
```

### Get Case

**`GET /api/cases/{case_id}`**

```bash
curl http://localhost:5000/api/cases/c1d2e3f4-... \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `200`:
```json
{
  "id": "c1d2e3f4-...",
  "case_id": "CASE-20250115-001",
  "title": "Investigation: Brute Force from 203.0.113.50",
  "description": "Multiple failed login attempts detected...",
  "severity": "high",
  "status": "open",
  "assignee": { "id": "550e8400-...", "username": "analyst" },
  "tags": ["brute-force"],
  "tlp": "amber",
  "alerts": [ { "id": "a1b2c3d4-...", "title": "Brute Force Login Attempt" } ],
  "tasks": [ { "id": "t1u2v3w4-...", "title": "Block source IP", "status": "pending" } ],
  "observables": [ { "data_type": "ip", "value": "203.0.113.50", "is_ioc": true } ],
  "comments": [],
  "created_at": "2025-01-15T10:35:00Z",
  "updated_at": "2025-01-15T11:00:00Z"
}
```

### Create Case

**`POST /api/cases`**

Request:
```json
{
  "title": "Suspicious PowerShell Activity on DC01",
  "description": "Encoded PowerShell commands detected on domain controller",
  "severity": "high",
  "assignee": "550e8400-...",
  "tags": ["powershell", "execution"],
  "tlp": "amber"
}
```

```bash
curl -X POST http://localhost:5000/api/cases \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"Suspicious PowerShell Activity","severity":"high","tags":["powershell"]}'
```

Response `201`:
```json
{
  "id": "c2d3e4f5-...",
  "case_id": "CASE-20250115-002",
  "title": "Suspicious PowerShell Activity on DC01",
  "created_at": "2025-01-15T12:00:00Z"
}
```

### Update Case

**`PATCH /api/cases/{case_id}`**

```bash
curl -X PATCH http://localhost:5000/api/cases/c1d2e3f4-... \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status": "in_progress", "assignee": "550e8400-..."}'
```

### Close Case

**`POST /api/cases/{case_id}/close`**

Request:
```json
{
  "resolution": "True positive. Source IP blocked. User password reset.",
  "classification": "true_positive"
}
```

```bash
curl -X POST http://localhost:5000/api/cases/c1d2e3f4-.../close \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"resolution":"True positive. IP blocked.","classification":"true_positive"}'
```

### Add Task to Case

**`POST /api/cases/{case_id}/tasks`**

Request:
```json
{
  "title": "Block source IP at perimeter firewall",
  "description": "Add 203.0.113.50 to the block list on the edge firewall",
  "assignee": "550e8400-...",
  "due_date": "2025-01-15T18:00:00Z"
}
```

```bash
curl -X POST http://localhost:5000/api/cases/c1d2e3f4-.../tasks \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"Block source IP","assignee":"550e8400-..."}'
```

### Add Observable to Case

**`POST /api/cases/{case_id}/observables`**

Request:
```json
{
  "data_type": "ip",
  "value": "203.0.113.50",
  "description": "Brute force source",
  "is_ioc": true,
  "tlp": "amber",
  "tags": ["malicious", "brute-force"]
}
```

```bash
curl -X POST http://localhost:5000/api/cases/c1d2e3f4-.../observables \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data_type":"ip","value":"203.0.113.50","is_ioc":true}'
```

### Add Comment to Case

**`POST /api/cases/{case_id}/comments`**

Request:
```json
{
  "content": "Confirmed malicious IP from VirusTotal. 15/90 vendors flagged."
}
```

```bash
curl -X POST http://localhost:5000/api/cases/c1d2e3f4-.../comments \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"content":"Confirmed malicious IP from VirusTotal."}'
```

---

## Search

### Search Events (Elasticsearch)

**`POST /api/search/events`**

Request:
```json
{
  "query": "event.outcome:failure AND source.ip:203.0.113.50",
  "from": "2025-01-15T00:00:00Z",
  "to": "2025-01-15T23:59:59Z",
  "size": 50,
  "sort": [{ "@timestamp": "desc" }],
  "fields": ["@timestamp", "event.action", "source.ip", "user.name"]
}
```

```bash
curl -X POST http://localhost:5000/api/search/events \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"event.outcome:failure","from":"2025-01-15T00:00:00Z","to":"2025-01-15T23:59:59Z","size":50}'
```

Response `200`:
```json
{
  "total": 1523,
  "hits": [
    {
      "@timestamp": "2025-01-15T10:30:00Z",
      "event": { "action": "ssh_failed", "outcome": "failure" },
      "source": { "ip": "203.0.113.50" },
      "user": { "name": "admin" }
    }
  ],
  "aggregations": {}
}
```

### Search with Aggregation

**`POST /api/search/aggregate`**

Request:
```json
{
  "query": "event.category:authentication",
  "from": "2025-01-14T00:00:00Z",
  "to": "2025-01-15T23:59:59Z",
  "aggregations": {
    "by_outcome": {
      "field": "event.outcome",
      "type": "terms",
      "size": 10
    },
    "over_time": {
      "field": "@timestamp",
      "type": "date_histogram",
      "interval": "1h"
    }
  }
}
```

```bash
curl -X POST http://localhost:5000/api/search/aggregate \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"event.category:authentication","aggregations":{"by_outcome":{"field":"event.outcome","type":"terms","size":10}}}'
```

Response `200`:
```json
{
  "total": 50432,
  "aggregations": {
    "by_outcome": {
      "buckets": [
        { "key": "success", "doc_count": 45000 },
        { "key": "failure", "doc_count": 5432 }
      ]
    }
  }
}
```

---

## Dashboard

### Dashboard Summary

**`GET /api/dashboard/summary`**

Query parameters: `from`, `to` (default: last 24 hours)

```bash
curl "http://localhost:5000/api/dashboard/summary?from=2025-01-14T00:00:00Z" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `200`:
```json
{
  "alerts": {
    "total": 342,
    "new": 45,
    "in_progress": 23,
    "resolved": 250,
    "by_severity": {
      "critical": 5,
      "high": 28,
      "medium": 89,
      "low": 120,
      "info": 100
    }
  },
  "agents": {
    "total": 45,
    "online": 42,
    "offline": 2,
    "degraded": 1
  },
  "cases": {
    "total": 12,
    "open": 5,
    "in_progress": 4,
    "closed": 3
  },
  "events": {
    "total_24h": 2500000,
    "eps": 28.9
  },
  "top_rules": [
    { "rule_id": "CN-WIN-AUTH-001", "name": "Single Failed Login", "hit_count": 1523 }
  ],
  "top_sources": [
    { "ip": "203.0.113.50", "alert_count": 15 }
  ]
}
```

### Alert Trend

**`GET /api/dashboard/alerts/trend`**

Query parameters: `from`, `to`, `interval` (1h, 6h, 1d)

```bash
curl "http://localhost:5000/api/dashboard/alerts/trend?interval=1h" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `200`:
```json
{
  "interval": "1h",
  "data": [
    { "timestamp": "2025-01-15T00:00:00Z", "count": 12, "critical": 0, "high": 3, "medium": 5, "low": 4 },
    { "timestamp": "2025-01-15T01:00:00Z", "count": 8, "critical": 1, "high": 2, "medium": 3, "low": 2 }
  ]
}
```

### MITRE ATT&CK Heatmap

**`GET /api/dashboard/mitre/heatmap`**

Query parameters: `from`, `to`

```bash
curl "http://localhost:5000/api/dashboard/mitre/heatmap" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `200`:
```json
{
  "tactics": [
    {
      "id": "TA0006",
      "name": "Credential Access",
      "techniques": [
        { "id": "T1110", "name": "Brute Force", "count": 45 },
        { "id": "T1110.001", "name": "Password Guessing", "count": 30 }
      ]
    }
  ]
}
```

### Events Per Second

**`GET /api/dashboard/events/eps`**

```bash
curl http://localhost:5000/api/dashboard/events/eps \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `200`:
```json
{
  "current_eps": 28.9,
  "avg_eps_1h": 25.3,
  "peak_eps_24h": 150.2,
  "total_events_24h": 2500000
}
```

---

## Playbooks

### List Playbooks

**`GET /api/playbooks`**

Query parameters: `page`, `per_page`, `enabled` (true/false), `search`

```bash
curl "http://localhost:5000/api/playbooks" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `200`:
```json
{
  "items": [
    {
      "id": "p1q2r3s4-...",
      "name": "brute_force_response",
      "description": "Automated response to brute-force login attempts...",
      "trigger_type": "alert",
      "is_enabled": true,
      "run_count": 23,
      "created_at": "2025-01-01T00:00:00Z"
    }
  ],
  "total": 7,
  "page": 1,
  "per_page": 25,
  "pages": 1
}
```

### Get Playbook

**`GET /api/playbooks/{playbook_id}`**

```bash
curl http://localhost:5000/api/playbooks/p1q2r3s4-... \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Create Playbook

**`POST /api/playbooks`**

Request:
```json
{
  "name": "custom_response",
  "description": "Custom automated response playbook",
  "trigger_type": "manual",
  "trigger_conditions": {},
  "content_yaml": "name: custom_response\nsteps:\n  - name: step1\n    action: slack_notify\n    ...",
  "is_enabled": true
}
```

```bash
curl -X POST http://localhost:5000/api/playbooks \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"custom_response","trigger_type":"manual","content_yaml":"...","is_enabled":true}'
```

### Update Playbook

**`PUT /api/playbooks/{playbook_id}`**

```bash
curl -X PUT http://localhost:5000/api/playbooks/p1q2r3s4-... \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"updated_playbook","is_enabled":false}'
```

### Delete Playbook

**`DELETE /api/playbooks/{playbook_id}`**

```bash
curl -X DELETE http://localhost:5000/api/playbooks/p1q2r3s4-... \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Execute Playbook Manually

**`POST /api/playbooks/{playbook_id}/execute`**

Request:
```json
{
  "alert_id": "a1b2c3d4-...",
  "context": {
    "source_ip": "203.0.113.50",
    "username": "admin"
  }
}
```

```bash
curl -X POST http://localhost:5000/api/playbooks/p1q2r3s4-.../execute \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"alert_id":"a1b2c3d4-..."}'
```

Response `202`:
```json
{
  "execution_id": "x1y2z3-...",
  "playbook_id": "p1q2r3s4-...",
  "status": "pending",
  "started_at": "2025-01-15T12:00:00Z"
}
```

### Get Playbook Execution

**`GET /api/playbooks/executions/{execution_id}`**

```bash
curl http://localhost:5000/api/playbooks/executions/x1y2z3-... \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `200`:
```json
{
  "id": "x1y2z3-...",
  "playbook_id": "p1q2r3s4-...",
  "status": "success",
  "triggered_by": "manual",
  "steps_log": [
    { "step": "vt_lookup", "status": "success", "duration_ms": 1200, "output": { "malicious": 5 } },
    { "step": "block_source_ip", "status": "success", "duration_ms": 800, "output": { "message": "IP blocked" } }
  ],
  "started_at": "2025-01-15T12:00:00Z",
  "completed_at": "2025-01-15T12:00:05Z",
  "duration_ms": 5000
}
```

### List Playbook Executions

**`GET /api/playbooks/executions`**

Query parameters: `page`, `per_page`, `playbook_id`, `status` (pending, running, success, failure), `from`, `to`

```bash
curl "http://localhost:5000/api/playbooks/executions?status=success&per_page=10" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## Threat Intel

### List IOCs

**`GET /api/threat-intel/iocs`**

Query parameters: `page`, `per_page`, `ioc_type` (ip, domain, hash_sha256, etc.), `source`, `active` (true/false), `search`

```bash
curl "http://localhost:5000/api/threat-intel/iocs?ioc_type=ip&active=true" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `200`:
```json
{
  "items": [
    {
      "id": "i1o2c3-...",
      "ioc_type": "ip",
      "value": "203.0.113.50",
      "source": "AbuseIPDB",
      "confidence": 85,
      "tags": ["malware", "c2"],
      "is_active": true,
      "hit_count": 12,
      "first_seen_at": "2025-01-10T00:00:00Z",
      "last_seen_at": "2025-01-15T10:30:00Z",
      "expires_at": "2025-04-15T00:00:00Z"
    }
  ],
  "total": 15432,
  "page": 1,
  "per_page": 25,
  "pages": 618
}
```

### Create IOC

**`POST /api/threat-intel/iocs`**

Request:
```json
{
  "ioc_type": "ip",
  "value": "198.51.100.25",
  "source": "manual",
  "confidence": 90,
  "tags": ["c2", "apt"],
  "expires_at": "2025-06-01T00:00:00Z"
}
```

```bash
curl -X POST http://localhost:5000/api/threat-intel/iocs \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ioc_type":"ip","value":"198.51.100.25","source":"manual","confidence":90}'
```

### Bulk Import IOCs

**`POST /api/threat-intel/iocs/bulk`**

Request:
```json
{
  "iocs": [
    { "ioc_type": "ip", "value": "198.51.100.25", "source": "feed", "confidence": 80 },
    { "ioc_type": "domain", "value": "evil.example.com", "source": "feed", "confidence": 95 },
    { "ioc_type": "hash_sha256", "value": "a1b2c3...", "source": "feed", "confidence": 100 }
  ]
}
```

```bash
curl -X POST http://localhost:5000/api/threat-intel/iocs/bulk \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"iocs":[{"ioc_type":"ip","value":"198.51.100.25","source":"feed","confidence":80}]}'
```

Response `201`:
```json
{
  "imported": 3,
  "duplicates": 0,
  "errors": 0
}
```

### Delete IOC

**`DELETE /api/threat-intel/iocs/{ioc_id}`**

```bash
curl -X DELETE http://localhost:5000/api/threat-intel/iocs/i1o2c3-... \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Lookup IOC

**`GET /api/threat-intel/lookup`**

Query parameters: `value`, `type` (ip, domain, hash)

```bash
curl "http://localhost:5000/api/threat-intel/lookup?value=203.0.113.50&type=ip" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `200`:
```json
{
  "found": true,
  "ioc": {
    "ioc_type": "ip",
    "value": "203.0.113.50",
    "source": "AbuseIPDB",
    "confidence": 85,
    "tags": ["malware"],
    "hit_count": 12
  },
  "enrichments": {
    "virustotal": { "malicious": 5, "suspicious": 2, "total": 90 },
    "abuseipdb": { "score": 85, "reports": 42, "country": "RU" }
  }
}
```

### List Feeds

**`GET /api/threat-intel/feeds`**

```bash
curl http://localhost:5000/api/threat-intel/feeds \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `200`:
```json
{
  "items": [
    {
      "id": "f1e2d3-...",
      "name": "AbuseIPDB Blacklist",
      "feed_type": "abuse_ipdb",
      "url": "https://api.abuseipdb.com/api/v2/blacklist",
      "is_enabled": true,
      "last_fetched": "2025-01-15T06:00:00Z",
      "ioc_count": 10000,
      "fetch_interval_hours": 6
    }
  ]
}
```

### Create Feed

**`POST /api/threat-intel/feeds`**

Request:
```json
{
  "name": "Custom STIX Feed",
  "feed_type": "stix",
  "url": "https://feed.example.com/stix/taxii",
  "api_key": "feed-api-key",
  "is_enabled": true,
  "fetch_interval_hours": 12,
  "config_json": { "collection_id": "my-collection" }
}
```

```bash
curl -X POST http://localhost:5000/api/threat-intel/feeds \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Custom STIX Feed","feed_type":"stix","url":"https://feed.example.com/stix","is_enabled":true}'
```

### Trigger Feed Fetch

**`POST /api/threat-intel/feeds/{feed_id}/fetch`**

```bash
curl -X POST http://localhost:5000/api/threat-intel/feeds/f1e2d3-.../fetch \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `202`:
```json
{
  "message": "Feed fetch initiated",
  "feed_id": "f1e2d3-..."
}
```

---

## Users

### List Users

**`GET /api/users`** (admin only)

Query parameters: `page`, `per_page`, `role`, `active` (true/false), `search`

```bash
curl "http://localhost:5000/api/users" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `200`:
```json
{
  "items": [
    {
      "id": "550e8400-...",
      "username": "admin",
      "email": "admin@cybernest.local",
      "role": "super_admin",
      "is_active": true,
      "last_login_at": "2025-01-15T10:00:00Z",
      "created_at": "2025-01-01T00:00:00Z"
    }
  ],
  "total": 5,
  "page": 1,
  "per_page": 25,
  "pages": 1
}
```

### Create User

**`POST /api/users`** (admin only)

Request:
```json
{
  "username": "jdoe",
  "email": "jdoe@example.com",
  "password": "SecureP@ss2025!",
  "role": "analyst"
}
```

```bash
curl -X POST http://localhost:5000/api/users \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"jdoe","email":"jdoe@example.com","password":"SecureP@ss2025!","role":"analyst"}'
```

Response `201`:
```json
{
  "id": "990e8400-...",
  "username": "jdoe",
  "email": "jdoe@example.com",
  "role": "analyst",
  "created_at": "2025-01-15T12:00:00Z"
}
```

### Update User

**`PATCH /api/users/{user_id}`**

Request:
```json
{
  "role": "soc_lead",
  "is_active": true
}
```

```bash
curl -X PATCH http://localhost:5000/api/users/990e8400-... \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"soc_lead"}'
```

### Delete User

**`DELETE /api/users/{user_id}`** (super_admin only)

```bash
curl -X DELETE http://localhost:5000/api/users/990e8400-... \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Change Password

**`POST /api/users/{user_id}/change-password`**

Request:
```json
{
  "current_password": "OldP@ss",
  "new_password": "NewSecureP@ss2025!"
}
```

```bash
curl -X POST http://localhost:5000/api/users/550e8400-.../change-password \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"current_password":"OldP@ss","new_password":"NewSecureP@ss2025!"}'
```

---

## Assets

### List Assets

**`GET /api/assets`**

Query parameters: `page`, `per_page`, `criticality` (low, medium, high, critical), `os`, `search`

```bash
curl "http://localhost:5000/api/assets?criticality=critical" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `200`:
```json
{
  "items": [
    {
      "id": "as1-...",
      "hostname": "DC01",
      "ip": "10.0.1.5",
      "os": "Windows Server 2022",
      "owner": "IT Operations",
      "department": "Infrastructure",
      "criticality": "critical",
      "role": "Domain Controller",
      "risk_score": 25,
      "vulnerability_count": 3,
      "tags": ["tier-0", "domain-controller"]
    }
  ],
  "total": 150,
  "page": 1,
  "per_page": 25,
  "pages": 6
}
```

### Create Asset

**`POST /api/assets`**

Request:
```json
{
  "hostname": "web-server-1",
  "ip": "10.0.2.10",
  "os": "Ubuntu 22.04",
  "owner": "DevOps",
  "department": "Engineering",
  "criticality": "high",
  "role": "Web Server",
  "tags": ["production", "web"]
}
```

```bash
curl -X POST http://localhost:5000/api/assets \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"hostname":"web-server-1","ip":"10.0.2.10","os":"Ubuntu 22.04","criticality":"high"}'
```

### Update Asset

**`PATCH /api/assets/{asset_id}`**

```bash
curl -X PATCH http://localhost:5000/api/assets/as1-... \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"risk_score": 45, "vulnerability_count": 5}'
```

### Delete Asset

**`DELETE /api/assets/{asset_id}`**

```bash
curl -X DELETE http://localhost:5000/api/assets/as1-... \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## Notification Channels

### List Channels

**`GET /api/notifications/channels`**

```bash
curl http://localhost:5000/api/notifications/channels \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Create Channel

**`POST /api/notifications/channels`**

Request:
```json
{
  "name": "SOC Slack",
  "channel_type": "slack",
  "config_json": {
    "webhook_url": "https://hooks.slack.com/services/...",
    "channel": "#soc-alerts"
  },
  "is_enabled": true
}
```

```bash
curl -X POST http://localhost:5000/api/notifications/channels \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"SOC Slack","channel_type":"slack","config_json":{"webhook_url":"..."},"is_enabled":true}'
```

### Test Channel

**`POST /api/notifications/channels/{channel_id}/test`**

```bash
curl -X POST http://localhost:5000/api/notifications/channels/ch1-.../test \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Response `200`:
```json
{
  "success": true,
  "message": "Test notification sent successfully"
}
```

---

## Health

### Health Check (No auth required)

**`GET /api/health`**

```bash
curl http://localhost:5000/api/health
```

Response `200`:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_seconds": 86400,
  "services": {
    "postgres": "connected",
    "redis": "connected",
    "elasticsearch": "connected",
    "kafka": "connected"
  }
}
```

---

## Error Responses

All error responses follow this format:

```json
{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "Alert with ID 'xyz' not found",
    "status": 404
  }
}
```

### HTTP Status Codes

| Code | Meaning                                      |
|------|----------------------------------------------|
| 200  | Success                                      |
| 201  | Created                                      |
| 202  | Accepted (async operation started)           |
| 400  | Bad request (validation error)               |
| 401  | Unauthorized (missing or invalid token)      |
| 403  | Forbidden (insufficient permissions)         |
| 404  | Resource not found                           |
| 409  | Conflict (duplicate resource)                |
| 422  | Unprocessable entity (semantic error)        |
| 429  | Rate limited                                 |
| 500  | Internal server error                        |

### Common Error Codes

| Code                  | Description                              |
|-----------------------|------------------------------------------|
| `INVALID_CREDENTIALS` | Wrong username or password               |
| `TOKEN_EXPIRED`       | JWT token has expired                    |
| `TOKEN_INVALID`       | Malformed or tampered token              |
| `PERMISSION_DENIED`   | User role lacks required permission      |
| `RESOURCE_NOT_FOUND`  | Requested resource does not exist        |
| `DUPLICATE_RESOURCE`  | Resource with same unique key exists     |
| `VALIDATION_ERROR`    | Request body failed validation           |
| `RATE_LIMITED`        | Too many requests (default: 100/min)     |

### Rate Limiting

Default limits:
- Authentication endpoints: 10 requests/minute per IP
- API endpoints: 100 requests/minute per user
- Search endpoints: 30 requests/minute per user

Rate limit headers are included in every response:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705312800
```
