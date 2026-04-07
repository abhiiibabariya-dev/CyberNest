# CyberNest Detection Rule Writing Guide

## Sigma Rules (Recommended)

CyberNest natively supports Sigma rules. Place `.yml` files in `correlator/rules/sigma/`.

```yaml
title: Suspicious PowerShell Execution
id: sigma-powershell-suspicious
status: stable
level: high
description: Detects suspicious PowerShell command patterns
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - "-enc"
      - "-EncodedCommand"
      - "IEX"
      - "Invoke-Expression"
      - "bypass"
      - "downloadstring"
  condition: selection
tags:
  - attack.execution
  - attack.t1059.001
falsepositives:
  - Admin scripts
```

## CyberNest XML Rules

For threshold, frequency, and sequence rules:

```xml
<rule id="100002" level="10">
  <if_sid>100001</if_sid>
  <description>Brute force: >5 failed logins in 60s</description>
  <group>authentication_failures,brute_force</group>
  <mitre>
    <id>T1110.001</id>
    <tactic>credential_access</tactic>
  </mitre>
  <options>
    <frequency>5</frequency>
    <timeframe>60</timeframe>
    <group_by>source.ip</group_by>
  </options>
</rule>
```

## Rule Levels

| Level | Severity | Description |
|-------|----------|-------------|
| 0-3 | Info | Informational, no action needed |
| 4-6 | Low | Minor issue, review when time permits |
| 7-9 | Medium | Potential threat, investigate within 4h |
| 10-12 | High | Confirmed threat, investigate within 1h |
| 13-15 | Critical | Active attack, respond immediately |

## MITRE ATT&CK Mapping

Every rule MUST include MITRE technique IDs:
- `T1110` — Brute Force
- `T1059` — Command and Scripting Interpreter
- `T1003` — OS Credential Dumping
- Full list: https://attack.mitre.org/techniques/enterprise/
