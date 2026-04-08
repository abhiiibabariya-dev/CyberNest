# CyberNest Detection Rule Writing Guide

This guide covers the CyberNest YAML rule format, all supported operators, threshold and sliding window rules, MITRE ATT&CK mapping, testing, and Sigma rule import.

---

## Table of Contents

1. [Rule Format](#rule-format)
2. [Field Reference](#field-reference)
3. [Operators](#operators)
4. [Threshold Rules](#threshold-rules)
5. [Sliding Window Rules](#sliding-window-rules)
6. [Correlation Chains](#correlation-chains)
7. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
8. [Rule Severity Levels](#rule-severity-levels)
9. [Testing Rules via API](#testing-rules-via-api)
10. [Importing Sigma Rules](#importing-sigma-rules)
11. [Examples](#examples)

---

## Rule Format

CyberNest detection rules use YAML. Each rule file can contain one or more rules under the `rules:` key.

```yaml
rules:
  - id: CN-WIN-AUTH-001
    name: Single Failed Login Attempt
    description: >
      A single failed login attempt was detected on a Windows host.
      May indicate a typo or unauthorized access attempt.
    level: informational
    category: authentication
    mitre_tactic: TA0006
    mitre_technique:
      - T1110
    enabled: true
    conditions:
      logic: and
      fields:
        - field: event.outcome
          operator: equals
          value: failure
        - field: event.category
          operator: contains
          value: authentication
        - field: host.os.platform
          operator: equals
          value: windows
```

### Required Fields

| Field         | Type     | Description                                        |
|---------------|----------|----------------------------------------------------|
| `id`          | string   | Unique rule ID (format: `CN-{CATEGORY}-{NUM}`)     |
| `name`        | string   | Human-readable rule name                            |
| `level`       | string   | Severity: informational, low, medium, high, critical|
| `conditions`  | object   | Match conditions (see below)                        |

### Optional Fields

| Field              | Type     | Description                                    |
|--------------------|----------|------------------------------------------------|
| `description`      | string   | Detailed description of what the rule detects  |
| `category`         | string   | Category: authentication, execution, etc.      |
| `mitre_tactic`     | string   | MITRE ATT&CK tactic ID (e.g., TA0006)         |
| `mitre_technique`  | list     | MITRE technique IDs (e.g., T1110, T1110.001)  |
| `enabled`          | boolean  | Whether the rule is active (default: true)     |
| `threshold`        | object   | Threshold/aggregation settings                 |
| `window`           | object   | Sliding window configuration                   |
| `tags`             | list     | Custom tags for grouping                       |
| `false_positives`  | list     | Known false positive scenarios                 |
| `references`       | list     | URLs to related documentation                  |

---

## Field Reference

CyberNest uses ECS (Elastic Common Schema) field names. Common fields:

| Field                     | Description                           | Example Values                    |
|---------------------------|---------------------------------------|-----------------------------------|
| `event.category`          | Event category                        | authentication, process, network  |
| `event.action`            | Specific action                       | logon, ssh_failed, process_create |
| `event.outcome`           | Result of the action                  | success, failure                  |
| `event.code`              | Event ID (Windows Event ID, etc.)     | 4624, 4625, 4688                  |
| `host.os.platform`        | Operating system                      | windows, linux, darwin            |
| `host.hostname`           | Host name                             | DC01, web-server-1                |
| `source.ip`               | Source IP address                     | 192.168.1.100                     |
| `destination.ip`          | Destination IP address                | 10.0.0.5                          |
| `source.port`             | Source port                           | 54321                             |
| `destination.port`        | Destination port                      | 443                               |
| `user.name`               | Username                              | jdoe, Administrator               |
| `user.domain`             | User domain                           | CORP                              |
| `user.roles`              | User roles                            | admin, user                       |
| `user.target.group.name`  | Target group name                     | Domain Admins                     |
| `process.name`            | Process name                          | powershell.exe, bash              |
| `process.command_line`    | Full command line                     | powershell -enc ...               |
| `process.parent.name`     | Parent process name                   | cmd.exe, explorer.exe             |
| `process.pid`             | Process ID                            | 1234                              |
| `file.path`               | File path                             | C:\Windows\Temp\payload.exe       |
| `file.hash.sha256`        | File SHA256 hash                      | a1b2c3...                         |
| `dns.question.name`       | DNS query name                        | evil.example.com                  |
| `network.protocol`        | Network protocol                      | tcp, udp, dns                     |
| `registry.path`           | Registry path                         | HKLM\Software\...                 |
| `cloud.provider`          | Cloud provider                        | aws, azure, gcp                   |
| `cloud.region`            | Cloud region                          | us-east-1                         |

---

## Operators

### `equals`

Exact match (case-sensitive).

```yaml
- field: event.outcome
  operator: equals
  value: failure
```

### `not_equals`

Inverse of equals.

```yaml
- field: host.os.platform
  operator: not_equals
  value: windows
```

### `contains`

Substring match (case-insensitive).

```yaml
- field: event.category
  operator: contains
  value: authentication
```

### `not_contains`

Inverse of contains.

```yaml
- field: user.roles
  operator: not_contains
  value: admin
```

### `starts_with`

String starts with the given prefix.

```yaml
- field: process.name
  operator: starts_with
  value: powershell
```

### `ends_with`

String ends with the given suffix.

```yaml
- field: file.path
  operator: ends_with
  value: .exe
```

### `in`

Field value matches any item in a list.

```yaml
- field: event.action
  operator: in
  value:
    - logon
    - logged-on
    - "4624"
```

### `not_in`

Field value does not match any item in the list.

```yaml
- field: user.name
  operator: not_in
  value:
    - SYSTEM
    - LOCAL SERVICE
    - NETWORK SERVICE
```

### `regex`

Perl-compatible regular expression match.

```yaml
- field: process.command_line
  operator: regex
  value: "(?i)(invoke-mimikatz|invoke-expression|iex\\s)"
```

### `exists`

Field is present (or absent when `value: false`).

```yaml
- field: source.ip
  operator: exists
  value: true
```

### `gt` (greater than)

Numeric comparison.

```yaml
- field: destination.port
  operator: gt
  value: 1024
```

### `gte` (greater than or equal)

```yaml
- field: event.risk_score
  operator: gte
  value: 75
```

### `lt` (less than)

```yaml
- field: destination.port
  operator: lt
  value: 1024
```

### `lte` (less than or equal)

```yaml
- field: process.pid
  operator: lte
  value: 4
```

### `cidr`

IP address is within a CIDR range.

```yaml
- field: source.ip
  operator: cidr
  value: "10.0.0.0/8"
```

### `not_cidr`

IP address is NOT within a CIDR range.

```yaml
- field: source.ip
  operator: not_cidr
  value: "192.168.0.0/16"
```

---

## Threshold Rules

Threshold rules fire only when an event matching the conditions occurs more than a specified number of times within a time window, grouped by a specific field.

```yaml
rules:
  - id: CN-WIN-AUTH-002
    name: Brute Force Login Attempt
    description: >
      More than 5 failed login attempts from the same source IP
      within 60 seconds targeting a single user account.
    level: high
    category: authentication
    mitre_tactic: TA0006
    mitre_technique:
      - T1110.001
    enabled: true
    conditions:
      logic: and
      fields:
        - field: event.outcome
          operator: equals
          value: failure
        - field: event.category
          operator: contains
          value: authentication
    threshold:
      field: user.name        # Group by this field
      count: 5                # Minimum occurrences to trigger
      timeframe: 60           # Window in seconds
```

### Threshold Parameters

| Parameter   | Type    | Description                                      |
|-------------|---------|--------------------------------------------------|
| `field`     | string  | Field to group events by                         |
| `count`     | integer | Minimum number of events to trigger the alert    |
| `timeframe` | integer | Time window in seconds                           |

### Multi-field Grouping

Group by multiple fields by using a list:

```yaml
threshold:
  field:
    - source.ip
    - user.name
  count: 10
  timeframe: 300
```

---

## Sliding Window Rules

Sliding window rules detect patterns across sequential events, such as a successful login following multiple failures.

```yaml
rules:
  - id: CN-WIN-AUTH-003
    name: Successful Login After Multiple Failures
    description: >
      Detects a successful login after 3+ failed attempts for the
      same user within a 5-minute window.
    level: high
    category: authentication
    mitre_tactic: TA0006
    mitre_technique:
      - T1110
    enabled: true
    window:
      timeframe: 300
      group_by: user.name
      sequence:
        - conditions:
            logic: and
            fields:
              - field: event.outcome
                operator: equals
                value: failure
              - field: event.category
                operator: contains
                value: authentication
          min_count: 3
        - conditions:
            logic: and
            fields:
              - field: event.outcome
                operator: equals
                value: success
              - field: event.category
                operator: contains
                value: authentication
          min_count: 1
```

### Window Parameters

| Parameter    | Type    | Description                                    |
|--------------|---------|------------------------------------------------|
| `timeframe`  | integer | Window duration in seconds                     |
| `group_by`   | string  | Field to correlate events by                   |
| `sequence`   | list    | Ordered list of event patterns                 |

Each sequence step has:
- `conditions`: same format as top-level conditions
- `min_count`: minimum number of events matching this step

---

## Correlation Chains

For complex multi-stage attacks, use correlation chains that link multiple rules:

```yaml
rules:
  - id: CN-CHAIN-001
    name: Lateral Movement Chain
    description: >
      Detects credential dumping followed by remote service creation
      on a different host within 15 minutes.
    level: critical
    category: lateral_movement
    mitre_tactic: TA0008
    mitre_technique:
      - T1021
    enabled: true
    correlation:
      timeframe: 900
      link_field: user.name
      rules:
        - CN-WIN-CRED-001    # Credential dump detection
        - CN-WIN-EXEC-003    # Remote service creation
      order: sequential
```

---

## MITRE ATT&CK Mapping

Every rule should include MITRE ATT&CK references for contextual alerting and dashboard visualization.

### Tactic IDs

| ID     | Tactic                    |
|--------|---------------------------|
| TA0001 | Initial Access            |
| TA0002 | Execution                 |
| TA0003 | Persistence               |
| TA0004 | Privilege Escalation      |
| TA0005 | Defense Evasion           |
| TA0006 | Credential Access         |
| TA0007 | Discovery                 |
| TA0008 | Lateral Movement          |
| TA0009 | Collection                |
| TA0010 | Exfiltration              |
| TA0011 | Command and Control       |
| TA0040 | Impact                    |
| TA0042 | Resource Development      |
| TA0043 | Reconnaissance            |

### Technique Mapping Example

```yaml
mitre_tactic: TA0006           # Credential Access
mitre_technique:
  - T1110                      # Brute Force (parent)
  - T1110.001                  # Password Guessing (sub-technique)
  - T1110.003                  # Password Spraying
```

---

## Rule Severity Levels

| Level          | DB Value | Use Case                                        |
|----------------|----------|--------------------------------------------------|
| informational  | 1        | Baseline events, audit trail                     |
| low            | 2        | Minor policy violations, reconnaissance          |
| medium         | 3        | Suspicious activity needing investigation        |
| high           | 4        | Likely malicious, requires prompt response       |
| critical       | 5        | Active breach, immediate action required         |

---

## Testing Rules via API

### Upload a Rule

```bash
curl -X POST http://localhost:5000/api/rules \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "rule_id": "CN-TEST-001",
    "name": "Test Rule",
    "description": "Testing rule creation via API",
    "level": 3,
    "category": "test",
    "mitre_tactic": "TA0002",
    "mitre_technique": ["T1059"],
    "content_yaml": "id: CN-TEST-001\nname: Test Rule\nlevel: medium\nconditions:\n  logic: and\n  fields:\n    - field: event.action\n      operator: equals\n      value: test",
    "is_enabled": false
  }'
```

### Test a Rule Against Sample Events

```bash
curl -X POST http://localhost:5000/api/rules/test \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "rule_yaml": "id: CN-TEST-001\nname: Test\nlevel: medium\nconditions:\n  logic: and\n  fields:\n    - field: event.outcome\n      operator: equals\n      value: failure",
    "events": [
      {
        "event": {"outcome": "failure", "category": "authentication"},
        "host": {"os": {"platform": "windows"}},
        "user": {"name": "admin"}
      },
      {
        "event": {"outcome": "success", "category": "authentication"},
        "host": {"os": {"platform": "windows"}},
        "user": {"name": "admin"}
      }
    ]
  }'
```

**Response:**

```json
{
  "rule_id": "CN-TEST-001",
  "total_events": 2,
  "matched_events": 1,
  "matches": [
    {
      "event_index": 0,
      "event": {
        "event": {"outcome": "failure", "category": "authentication"},
        "host": {"os": {"platform": "windows"}},
        "user": {"name": "admin"}
      }
    }
  ]
}
```

### Validate Rule Syntax

```bash
curl -X POST http://localhost:5000/api/rules/validate \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "content_yaml": "id: CN-TEST-001\nname: Test\nlevel: medium\nconditions:\n  logic: and\n  fields:\n    - field: event.outcome\n      operator: equals\n      value: failure"
  }'
```

**Response:**

```json
{
  "valid": true,
  "warnings": [],
  "errors": []
}
```

### List All Rules

```bash
curl http://localhost:5000/api/rules \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Toggle Rule Enabled/Disabled

```bash
curl -X PATCH http://localhost:5000/api/rules/CN-TEST-001 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"is_enabled": true}'
```

---

## Importing Sigma Rules

CyberNest supports importing [Sigma](https://github.com/SigmaHQ/sigma) rules directly.

### Import a Single Sigma Rule

```bash
curl -X POST http://localhost:5000/api/rules/import/sigma \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/yaml" \
  --data-binary @path/to/sigma_rule.yml
```

### Import Sigma Rules in Bulk

```bash
# Import an entire directory
for f in sigma_rules/*.yml; do
  echo "Importing $f..."
  curl -s -X POST http://localhost:5000/api/rules/import/sigma \
    -H "Authorization: Bearer YOUR_JWT_TOKEN" \
    -H "Content-Type: application/yaml" \
    --data-binary "@$f"
done
```

### Sigma to CyberNest Mapping

Sigma fields are automatically mapped to the CyberNest format:

| Sigma Field        | CyberNest Field          |
|--------------------|--------------------------|
| `logsource.product`| `host.os.platform`       |
| `EventID`          | `event.code`             |
| `User`             | `user.name`              |
| `SourceIP`         | `source.ip`              |
| `Image`            | `process.executable`     |
| `CommandLine`      | `process.command_line`   |
| `ParentImage`      | `process.parent.executable` |
| `TargetFilename`   | `file.path`              |
| `DestinationPort`  | `destination.port`       |
| `QueryName`        | `dns.question.name`      |

### Sigma Level Mapping

| Sigma Level    | CyberNest Level  |
|----------------|------------------|
| informational  | informational    |
| low            | low              |
| medium         | medium           |
| high           | high             |
| critical       | critical         |

---

## Examples

### Detect PowerShell Encoded Command Execution

```yaml
rules:
  - id: CN-WIN-EXEC-001
    name: PowerShell Encoded Command
    description: >
      Detects PowerShell execution with encoded command parameter,
      commonly used for obfuscation by attackers.
    level: high
    category: execution
    mitre_tactic: TA0002
    mitre_technique:
      - T1059.001
    enabled: true
    tags:
      - powershell
      - obfuscation
    false_positives:
      - Legitimate admin scripts using -EncodedCommand
    references:
      - https://attack.mitre.org/techniques/T1059/001/
    conditions:
      logic: and
      fields:
        - field: process.name
          operator: regex
          value: "(?i)powershell(\\.exe)?$"
        - field: process.command_line
          operator: regex
          value: "(?i)(-enc|-encodedcommand|-e\\s+[A-Za-z0-9+/=]{20,})"
        - field: host.os.platform
          operator: equals
          value: windows
```

### Detect SSH Brute Force from External IP

```yaml
rules:
  - id: CN-LNX-AUTH-010
    name: SSH Brute Force from External IP
    description: >
      More than 10 SSH failed logins from a non-RFC1918 IP
      within 120 seconds.
    level: high
    category: authentication
    mitre_tactic: TA0006
    mitre_technique:
      - T1110.001
    enabled: true
    conditions:
      logic: and
      fields:
        - field: event.outcome
          operator: equals
          value: failure
        - field: event.action
          operator: in
          value:
            - ssh_failed
            - sshd
            - failed-login
        - field: source.ip
          operator: not_cidr
          value: "10.0.0.0/8"
        - field: source.ip
          operator: not_cidr
          value: "172.16.0.0/12"
        - field: source.ip
          operator: not_cidr
          value: "192.168.0.0/16"
    threshold:
      field: source.ip
      count: 10
      timeframe: 120
```

### Detect DNS Beaconing

```yaml
rules:
  - id: CN-NET-C2-001
    name: DNS Beaconing Detected
    description: >
      High volume of DNS queries to the same domain within a short
      period, indicative of C2 beaconing activity.
    level: high
    category: command_and_control
    mitre_tactic: TA0011
    mitre_technique:
      - T1071.004
    enabled: true
    conditions:
      logic: and
      fields:
        - field: network.protocol
          operator: equals
          value: dns
        - field: dns.question.name
          operator: exists
          value: true
    threshold:
      field: dns.question.name
      count: 100
      timeframe: 300
```

### Detect AWS Root Account Login

```yaml
rules:
  - id: CN-CLOUD-AWS-001
    name: AWS Root Account Console Login
    description: >
      The AWS root account was used to log in to the console.
      Root account usage should be minimized.
    level: critical
    category: authentication
    mitre_tactic: TA0001
    mitre_technique:
      - T1078.004
    enabled: true
    conditions:
      logic: and
      fields:
        - field: cloud.provider
          operator: equals
          value: aws
        - field: event.action
          operator: equals
          value: ConsoleLogin
        - field: user.name
          operator: equals
          value: root
        - field: event.outcome
          operator: equals
          value: success
```

---

## Rule File Organization

Place rule files in the `correlator/rules/` directory, organized by category:

```
correlator/rules/
  windows/
    authentication.yml
    execution.yml
    credential_access.yml
    privilege_escalation.yml
  linux/
    authentication.yml
    persistence.yml
  network/
    c2.yml
    discovery.yml
  cloud/
    aws.yml
```

After adding or modifying rules, restart the correlator service:

```bash
docker compose restart cybernest-correlator
```

Or use the API to hot-reload rules:

```bash
curl -X POST http://localhost:5000/api/rules/reload \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```
