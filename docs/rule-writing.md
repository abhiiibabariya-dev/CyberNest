# CyberNest Detection Rule Writing Guide

This guide covers the CyberNest YAML rule format, all supported operators, threshold and sliding-window rules, MITRE ATT&CK mapping, testing, and Sigma rule import.

## Rule Format

CyberNest detection rules are written in YAML:

```yaml
id: CN-WIN-AUTH-002
name: Brute Force Login Attempt
description: Detects multiple failed login attempts from the same source IP
level: high
category: authentication
mitre_tactic: Credential Access
mitre_technique:
  - T1110
  - T1110.001
enabled: true

conditions:
  logic: and
  fields:
    - field: event.action
      operator: equals
      value: failed_login
    - field: event.module
      operator: equals
      value: windows.security

threshold:
  field: source.ip
  count: 5
  timeframe: 60

alert_title: "Brute Force: {{user.name}} from {{source.ip}}"
```

## Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique rule identifier (e.g., `CN-WIN-AUTH-002`) |
| `name` | string | Yes | Human-readable rule name |
| `description` | string | Yes | What this rule detects |
| `level` | string | Yes | `info`, `low`, `medium`, `high`, or `critical` |
| `category` | string | Yes | Rule category (authentication, execution, etc.) |
| `mitre_tactic` | string | No | MITRE ATT&CK tactic name |
| `mitre_technique` | list | No | MITRE ATT&CK technique IDs |
| `enabled` | bool | No | Whether the rule is active (default: true) |
| `conditions` | object | Yes | Detection logic |
| `threshold` | object | No | Count-based threshold |
| `alert_title` | string | No | Template for alert title |

## Condition Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `equals` | Exact match | `event.action equals "logon"` |
| `not_equals` | Not equal | `user.name not_equals "SYSTEM"` |
| `contains` | Substring match | `process.command_line contains "-enc"` |
| `not_contains` | Substring not present | `file.path not_contains "temp"` |
| `startswith` | String prefix | `file.path startswith "/tmp/"` |
| `endswith` | String suffix | `file.name endswith ".exe"` |
| `regex` | Regular expression | `process.name regex "^(cmd|powershell)\.exe$"` |
| `in` | Value in list | `event.code in [4624, 4625, 4634]` |
| `not_in` | Value not in list | `source.port not_in [80, 443, 8080]` |
| `exists` | Field exists | `file.hash.sha256 exists true` |
| `not_exists` | Field missing | `user.name not_exists true` |
| `gt` | Greater than | `event.severity gt 5` |
| `gte` | Greater than or equal | `network.bytes gte 1000000` |
| `lt` | Less than | `source.port lt 1024` |
| `lte` | Less than or equal | `event.duration lte 100` |
| `cidr` | IP in CIDR range | `source.ip cidr "10.0.0.0/8"` |

## Condition Logic

Combine conditions with `and` or `or`:

```yaml
conditions:
  logic: and
  fields:
    - field: event.action
      operator: equals
      value: process_created
    - field: process.name
      operator: in
      value: ["powershell.exe", "pwsh.exe"]
    - field: process.command_line
      operator: regex
      value: "(?i)(invoke-expression|iex|downloadstring|encodedcommand|-enc\\s)"
```

### Nested Logic

```yaml
conditions:
  logic: and
  fields:
    - field: event.module
      operator: equals
      value: windows.security
    - logic: or
      fields:
        - field: event.code
          operator: equals
          value: 4688
        - field: event.code
          operator: equals
          value: 4689
```

## Threshold Rules

Trigger when a count exceeds a threshold within a time window:

```yaml
threshold:
  field: source.ip          # Group by this field
  count: 10                 # Minimum count to trigger
  timeframe: 60             # Time window in seconds
```

Multiple group-by fields:

```yaml
threshold:
  field: "source.ip,user.name"
  count: 5
  timeframe: 300
```

## Sliding Window Correlation

For complex multi-event correlations, the correlator engine supports built-in patterns:

| Pattern | Description |
|---------|-------------|
| `brute_force` | >5 failed logins in 60s per (user, IP) |
| `password_spray` | >20 failures in 60s with >5 unique usernames |
| `port_scan` | >20 unique dest ports in 30s per source IP |
| `host_sweep` | >15 unique dest IPs in 60s per source IP |
| `lateral_movement` | >3 unique dest IPs with logon events in 300s |
| `data_exfiltration` | >100MB outbound in 300s per source IP |
| `c2_beaconing` | Regular HTTP intervals (CV < 0.1) to same external IP |
| `dns_tunneling` | >10 DNS queries with name length >50 in 60s |
| `impossible_travel` | Same user, different country, gap < 2 hours |

## MITRE ATT&CK Mapping

Always include MITRE ATT&CK references:

```yaml
mitre_tactic: Credential Access
mitre_technique:
  - T1110        # Brute Force
  - T1110.001    # Password Guessing
  - T1110.003    # Password Spraying
```

Common tactics: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact.

## Template Variables

Use `{{field.name}}` in `alert_title`:

```yaml
alert_title: "{{mitre_technique[0]}}: {{process.name}} executed by {{user.name}} on {{host.name}}"
```

Available variables: any field from the matched event's ECS schema.

## Testing Rules

### Via API

```bash
curl -X POST http://localhost:5000/api/v1/rules/test \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "rule_yaml": "id: TEST-001\nname: Test\nlevel: high\nconditions:\n  logic: and\n  fields:\n    - field: event.action\n      operator: equals\n      value: failed_login",
    "event": {
      "event": {"action": "failed_login", "module": "windows.security"},
      "source": {"ip": "192.168.1.100"},
      "user": {"name": "admin"}
    }
  }'
```

### Via Dashboard

1. Go to **Detection Rules** > click a rule
2. Switch to the **Test Rule** tab
3. Paste sample event JSON
4. Click **Test** — shows match/no-match result

## Importing Sigma Rules

### Via API

```bash
curl -X POST http://localhost:5000/api/v1/rules/import/sigma \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -F "file=@my_sigma_rule.yml"
```

### Via Dashboard

1. Go to **Detection Rules**
2. Click **Import Rule**
3. Select Sigma YAML file
4. Review converted rule
5. Click **Save**

## Best Practices

1. **Use descriptive IDs:** `CN-{PLATFORM}-{CATEGORY}-{NUMBER}` (e.g., `CN-WIN-CRED-003`)
2. **Set appropriate levels:** Don't over-alert. Use `info`/`low` for noisy detections.
3. **Include MITRE mappings:** Helps SOC analysts understand the attack context.
4. **Test before enabling:** Use the test API to validate against sample logs.
5. **Monitor false positives:** Check `false_positive_count` and tune conditions.
6. **Use thresholds for volume-based detections** rather than alerting on every event.
7. **Document exceptions** in the rule description.
