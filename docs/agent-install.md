# CyberNest Agent Installation Guide

The CyberNest agent collects security logs, system events, file integrity data, process activity, and network connections from endpoints and forwards them to the CyberNest Manager for parsing, correlation, and alerting.

## Prerequisites

- Python 3.10+ (or use the Docker image)
- Network access to CyberNest Manager (port 5601)
- Root/Administrator privileges for full log access
- An API key from CyberNest Manager

## Quick Install

### Linux (One-Liner)

```bash
curl -sSL https://raw.githubusercontent.com/abhiiibabariya-dev/CyberNest/master/scripts/install-agent.sh | \
  bash -s -- --manager-url https://YOUR_SERVER:5601 --api-key YOUR_API_KEY
```

This will:
1. Install Python dependencies
2. Download the agent
3. Create a systemd service (`cybernest-agent`)
4. Auto-enroll with the manager
5. Start collecting logs

### Windows (PowerShell — Run as Administrator)

```powershell
$env:MANAGER_URL = "https://YOUR_SERVER:5601"
$env:API_KEY = "YOUR_API_KEY"
iwr -useb https://raw.githubusercontent.com/abhiiibabariya-dev/CyberNest/master/scripts/install-agent.ps1 | iex
```

### Docker

```bash
docker run -d \
  --name cybernest-agent \
  --restart unless-stopped \
  --privileged \
  -v /var/log:/var/log:ro \
  -v /etc:/etc:ro \
  -e MANAGER_URL=https://YOUR_SERVER:5601 \
  -e API_KEY=YOUR_API_KEY \
  ghcr.io/abhiiibabariya-dev/cybernest-agent:latest
```

## Manual Installation

### 1. Clone and install

```bash
git clone https://github.com/abhiiibabariya-dev/CyberNest.git
cd CyberNest/agent
pip install -r requirements.txt
```

### 2. Configure

Edit `cybernest-agent.yml`:

```yaml
manager:
  url: "wss://YOUR_SERVER:5601/ws/agent"
  api_key: "YOUR_API_KEY"

tls:
  enabled: true
  ca_cert: "/etc/cybernest/certs/ca.pem"
  client_cert: "/etc/cybernest/certs/agent.pem"
  client_key: "/etc/cybernest/certs/agent-key.pem"

collectors:
  windows_event:
    enabled: true  # Windows only
    channels: [Security, System, Application, PowerShell, Sysmon]

  linux_syslog:
    enabled: true  # Linux only
    paths:
      - /var/log/syslog
      - /var/log/auth.log
      - /var/log/secure
      - /var/log/messages

  fim:
    enabled: true
    paths:
      - /etc
      - /usr/bin
      - /usr/sbin
      - C:\Windows\System32
    exclude_patterns:
      - "*.log"
      - "*.tmp"
      - "*.cache"

  process_monitor:
    enabled: true
    interval_seconds: 10

  network_monitor:
    enabled: true
    interval_seconds: 15

  registry_monitor:
    enabled: true  # Windows only

heartbeat_interval: 30
batch_size: 50
batch_timeout: 1.0
log_level: INFO
```

### 3. Run

```bash
# Foreground
python cybernest_agent.py --config cybernest-agent.yml

# Background (Linux)
sudo systemctl start cybernest-agent

# Background (Windows — as service)
# Use NSSM or sc.exe to register as a service
```

## Obtaining an API Key

1. Log into the CyberNest Dashboard
2. Navigate to **Settings** > **Agents**
3. Click **Generate Install Script**
4. Select your OS
5. Copy the generated one-liner (includes the API key)

Or via the API:

```bash
curl -X POST https://YOUR_SERVER/api/v1/agents/register \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "my-server",
    "os": "linux",
    "os_version": "Ubuntu 22.04"
  }'
```

## Collectors

| Collector | Platform | Description |
|-----------|----------|-------------|
| `windows_event` | Windows | Windows Event Log (Security, System, PowerShell, Sysmon) |
| `linux_syslog` | Linux | Syslog file tailing with rotation detection |
| `macos_log` | macOS | Unified log stream |
| `fim` | All | File integrity monitoring with SHA256 hashing |
| `process_monitor` | All | New process detection with command-line capture |
| `network_monitor` | All | Connection tracking and listening port detection |
| `registry_monitor` | Windows | Registry key change monitoring (Run keys, Services) |

## Remote Commands

The manager can send commands to agents:

| Command | Description |
|---------|-------------|
| `isolate` | Drop all network traffic except to manager |
| `unisolate` | Restore normal network access |
| `get_processes` | Return current process list |
| `get_connections` | Return active network connections |
| `restart` | Restart the agent |
| `update` | Download and install new agent version |

## Troubleshooting

**Agent won't connect:**
- Verify the manager URL and port (5601) are accessible
- Check TLS certificate validity
- Ensure the API key is correct

**Missing logs:**
- Run agent with `--log-level DEBUG`
- Verify file permissions (agent needs read access to log files)
- Check collector configuration in `cybernest-agent.yml`

**High CPU/Memory:**
- Reduce `process_monitor` and `network_monitor` poll frequency
- Increase `batch_size` and `batch_timeout`
- Exclude noisy directories from FIM
