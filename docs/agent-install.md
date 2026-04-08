# CyberNest Agent Installation Guide

The CyberNest agent collects security logs, system events, and telemetry from endpoints and forwards them to the CyberNest Manager for parsing, correlation, and alerting.

## Prerequisites

Before installing the agent, you need:

1. A running CyberNest Manager instance
2. An **Agent API Key** generated from the CyberNest dashboard:
   - Navigate to **Settings > Agents > Enroll New Agent**
   - Copy the generated API key
3. The Manager URL (e.g., `https://siem.example.com`)

---

## Linux Installation

### One-Liner (Recommended)

Run as root or with `sudo`:

```bash
curl -fsSL https://raw.githubusercontent.com/abhiiibabariya-dev/CyberNest/main/scripts/install-agent.sh | \
  sudo bash -s -- --manager-url https://siem.example.com --api-key YOUR_API_KEY
```

This single command will:
- Create a `cybernest` service user
- Install dependencies (curl, jq, auditd)
- Download the agent binary
- Write configuration to `/etc/cybernest/agent.yml`
- Create and start a systemd service

### Manual Installation

#### Step 1: Download the installer script

```bash
curl -fsSL -o install-agent.sh \
  https://raw.githubusercontent.com/abhiiibabariya-dev/CyberNest/main/scripts/install-agent.sh
chmod +x install-agent.sh
```

#### Step 2: Run with options

```bash
sudo bash install-agent.sh \
  --manager-url https://siem.example.com \
  --api-key YOUR_API_KEY \
  --version latest \
  --install-dir /opt/cybernest-agent \
  --port 9100
```

#### Step 3: Verify

```bash
systemctl status cybernest-agent
journalctl -u cybernest-agent -f
```

### Manual Installation (Without Script)

If you prefer full control:

```bash
# 1. Create service user
sudo groupadd --system cybernest
sudo useradd --system --gid cybernest --home-dir /opt/cybernest-agent \
  --shell /usr/sbin/nologin cybernest

# 2. Create directories
sudo mkdir -p /opt/cybernest-agent /etc/cybernest /var/log/cybernest

# 3. Download binary
sudo curl -fsSL -o /opt/cybernest-agent/cybernest-agent \
  -H "Authorization: Bearer YOUR_API_KEY" \
  "https://siem.example.com/api/agents/download?version=latest&os=linux&arch=amd64"
sudo chmod +x /opt/cybernest-agent/cybernest-agent

# 4. Create config (see Configuration section below)
sudo nano /etc/cybernest/agent.yml

# 5. Set permissions
sudo chown -R cybernest:cybernest /opt/cybernest-agent /etc/cybernest /var/log/cybernest
sudo chmod 750 /opt/cybernest-agent /etc/cybernest
sudo chmod 640 /etc/cybernest/agent.yml

# 6. Create systemd service (see Systemd Service section below)
sudo nano /etc/systemd/system/cybernest-agent.service

# 7. Start
sudo systemctl daemon-reload
sudo systemctl enable --now cybernest-agent
```

### Supported Linux Distributions

| Distribution          | Versions       | Package Manager |
|-----------------------|----------------|-----------------|
| Ubuntu                | 20.04, 22.04, 24.04 | apt       |
| Debian                | 11, 12         | apt             |
| CentOS / RHEL         | 8, 9           | dnf / yum       |
| Amazon Linux          | 2, 2023        | yum             |
| Alpine Linux          | 3.18+          | apk             |
| SUSE Linux Enterprise | 15             | zypper          |

---

## Windows Installation

### PowerShell One-Liner (Recommended)

Run in an **elevated PowerShell** (Administrator):

```powershell
irm https://raw.githubusercontent.com/abhiiibabariya-dev/CyberNest/main/scripts/install-agent.ps1 -OutFile install-agent.ps1; `
.\install-agent.ps1 -ManagerUrl https://siem.example.com -ApiKey YOUR_API_KEY
```

### PowerShell with Options

```powershell
.\scripts\install-agent.ps1 `
  -ManagerUrl https://siem.example.com `
  -ApiKey YOUR_API_KEY `
  -Version latest `
  -InstallDir "C:\Program Files\CyberNest\Agent" `
  -Port 9100
```

### Manual Installation (Without Script)

```powershell
# 1. Create directories
New-Item -ItemType Directory -Force -Path "C:\Program Files\CyberNest\Agent"
New-Item -ItemType Directory -Force -Path "C:\ProgramData\CyberNest\logs"

# 2. Download binary
$headers = @{ Authorization = "Bearer YOUR_API_KEY" }
Invoke-WebRequest -Uri "https://siem.example.com/api/agents/download?version=latest&os=windows&arch=amd64" `
  -OutFile "C:\Program Files\CyberNest\Agent\cybernest-agent.exe" -Headers $headers

# 3. Create config file (see Configuration section below)
notepad "C:\ProgramData\CyberNest\agent.yml"

# 4. Install as service (using sc.exe)
sc.exe create CyberNestAgent `
  binPath= """C:\Program Files\CyberNest\Agent\cybernest-agent.exe"" --config ""C:\ProgramData\CyberNest\agent.yml""" `
  DisplayName= "CyberNest SIEM Agent" `
  start= auto

# 5. Configure recovery
sc.exe failure CyberNestAgent reset= 86400 actions= restart/10000/restart/10000/restart/30000

# 6. Start
Start-Service CyberNestAgent
```

### Sysmon Integration (Recommended)

For enhanced Windows visibility, install [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) before the agent:

```powershell
# Download Sysmon
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath C:\Tools\Sysmon

# Install with SwiftOnSecurity config
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml `
  -OutFile C:\Tools\Sysmon\sysmonconfig.xml
C:\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\Tools\Sysmon\sysmonconfig.xml
```

The CyberNest agent automatically collects from `Microsoft-Windows-Sysmon/Operational` when Sysmon is installed.

---

## macOS Installation

### Using the Install Script

```bash
curl -fsSL https://raw.githubusercontent.com/abhiiibabariya-dev/CyberNest/main/scripts/install-agent.sh | \
  sudo bash -s -- --manager-url https://siem.example.com --api-key YOUR_API_KEY
```

The Linux install script detects macOS and adapts accordingly. On macOS, the agent uses a launchd plist instead of systemd.

### Manual Installation

```bash
# 1. Create directories
sudo mkdir -p /opt/cybernest-agent /etc/cybernest /var/log/cybernest

# 2. Download binary
sudo curl -fsSL -o /opt/cybernest-agent/cybernest-agent \
  -H "Authorization: Bearer YOUR_API_KEY" \
  "https://siem.example.com/api/agents/download?version=latest&os=darwin&arch=amd64"
sudo chmod +x /opt/cybernest-agent/cybernest-agent

# 3. Create config (see Configuration section below)
sudo nano /etc/cybernest/agent.yml

# 4. Create launchd plist
sudo tee /Library/LaunchDaemons/com.cybernest.agent.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.cybernest.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/cybernest-agent/cybernest-agent</string>
        <string>--config</string>
        <string>/etc/cybernest/agent.yml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/cybernest/agent-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/cybernest/agent-stderr.log</string>
    <key>ThrottleInterval</key>
    <integer>10</integer>
</dict>
</plist>
EOF

# 5. Load and start
sudo launchctl load /Library/LaunchDaemons/com.cybernest.agent.plist
sudo launchctl start com.cybernest.agent
```

### macOS Permissions

macOS requires granting Full Disk Access for log collection:

1. Open **System Settings > Privacy & Security > Full Disk Access**
2. Click the lock to make changes
3. Add `/opt/cybernest-agent/cybernest-agent`
4. Restart the agent: `sudo launchctl kickstart -k system/com.cybernest.agent`

---

## Configuration Reference

The agent configuration file (`agent.yml`) supports the following options:

### Linux Configuration Example

```yaml
manager:
  url: "https://siem.example.com"
  api_key: "cn_agent_abc123def456"
  tls_verify: true
  ca_cert: /etc/cybernest/ca.crt   # For self-signed certs

agent:
  id: ""                            # Auto-generated on first run
  port: 9100                        # Metrics/health endpoint
  log_level: info                   # debug, info, warn, error
  log_file: /var/log/cybernest/agent.log
  buffer_dir: /opt/cybernest-agent/buffer
  max_buffer_size_mb: 256           # Offline buffer before dropping

collectors:
  syslog:
    enabled: true
    paths:
      - /var/log/syslog
      - /var/log/messages
      - /var/log/auth.log
      - /var/log/secure

  auditd:
    enabled: true
    log_path: /var/log/audit/audit.log

  journald:
    enabled: true
    units:
      - sshd
      - sudo
      - systemd-logind
      - docker

  file:
    enabled: true
    paths:
      - path: /var/log/nginx/access.log
        type: nginx_access
      - path: /var/log/apache2/access.log
        type: apache_access

  process:
    enabled: true
    interval_seconds: 60

  network:
    enabled: true
    interfaces: []                  # Empty = all
    capture_dns: true
    capture_connections: true

heartbeat:
  interval_seconds: 30
  timeout_seconds: 10

output:
  batch_size: 100
  flush_interval_seconds: 5
  compression: gzip
  retry_max: 5
  retry_backoff_seconds: 10
```

### Windows Configuration Example

```yaml
manager:
  url: "https://siem.example.com"
  api_key: "cn_agent_abc123def456"
  tls_verify: true

agent:
  id: ""
  port: 9100
  log_level: info
  log_file: C:/ProgramData/CyberNest/logs/agent.log
  buffer_dir: C:/Program Files/CyberNest/Agent/buffer
  max_buffer_size_mb: 256

collectors:
  windows_event_log:
    enabled: true
    channels:
      - name: Security
        event_ids: []
      - name: System
        event_ids: []
      - name: Application
        event_ids: []
      - name: Microsoft-Windows-Sysmon/Operational
        event_ids: []
      - name: Microsoft-Windows-PowerShell/Operational
        event_ids: [4103, 4104, 4105, 4106]
      - name: Microsoft-Windows-Windows Defender/Operational
        event_ids: []

  process:
    enabled: true
    interval_seconds: 60
    track_command_line: true

  network:
    enabled: true
    capture_dns: true
    capture_connections: true

heartbeat:
  interval_seconds: 30
  timeout_seconds: 10

output:
  batch_size: 100
  flush_interval_seconds: 5
  compression: gzip
  retry_max: 5
  retry_backoff_seconds: 10
```

---

## Managing the Agent

### Linux (systemd)

```bash
systemctl status cybernest-agent       # Check status
systemctl restart cybernest-agent      # Restart
systemctl stop cybernest-agent         # Stop
journalctl -u cybernest-agent -f       # Follow logs
journalctl -u cybernest-agent --since "1 hour ago"  # Recent logs
```

### Windows (Services)

```powershell
Get-Service CyberNestAgent             # Check status
Restart-Service CyberNestAgent         # Restart
Stop-Service CyberNestAgent            # Stop
Get-Content C:\ProgramData\CyberNest\logs\agent.log -Tail 50  # View logs
```

### macOS (launchd)

```bash
sudo launchctl list | grep cybernest               # Check status
sudo launchctl kickstart -k system/com.cybernest.agent  # Restart
sudo launchctl bootout system/com.cybernest.agent   # Stop
tail -f /var/log/cybernest/agent.log                # Follow logs
```

---

## Uninstalling

### Linux

```bash
sudo systemctl stop cybernest-agent
sudo systemctl disable cybernest-agent
sudo rm /etc/systemd/system/cybernest-agent.service
sudo systemctl daemon-reload
sudo rm -rf /opt/cybernest-agent /etc/cybernest /var/log/cybernest
sudo userdel cybernest
sudo groupdel cybernest
```

### Windows

```powershell
Stop-Service CyberNestAgent
sc.exe delete CyberNestAgent
# Or if installed via NSSM: nssm remove CyberNestAgent confirm
Remove-Item -Recurse "C:\Program Files\CyberNest"
Remove-Item -Recurse "C:\ProgramData\CyberNest"
```

### macOS

```bash
sudo launchctl bootout system/com.cybernest.agent
sudo rm /Library/LaunchDaemons/com.cybernest.agent.plist
sudo rm -rf /opt/cybernest-agent /etc/cybernest /var/log/cybernest
```

---

## Troubleshooting

### Agent not connecting to Manager

1. Verify the Manager URL is reachable: `curl -sf https://siem.example.com/api/health`
2. Check the API key is valid in the dashboard under **Settings > Agents**
3. For self-signed certificates, set `tls_verify: false` or provide `ca_cert` path
4. Check firewall rules allow outbound HTTPS (443) from the agent host

### Agent not collecting logs

1. Verify the service user has read access to log files
2. On Linux: `sudo -u cybernest cat /var/log/auth.log`
3. On Windows: ensure the service runs as `LocalSystem` (has Event Log access)
4. Check the agent log for errors: `journalctl -u cybernest-agent --since "5 min ago"`

### High CPU or memory usage

1. Reduce collection frequency: increase `interval_seconds` in process/network collectors
2. Increase `batch_size` and `flush_interval_seconds` to reduce I/O
3. Disable collectors you don't need
4. Check `max_buffer_size_mb` isn't set too high
