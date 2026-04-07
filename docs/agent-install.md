# CyberNest Agent Installation Guide

## Linux (Ubuntu/Debian)

```bash
# Download agent
curl -sO https://your-manager:5000/api/v1/agents/download/linux

# Install dependencies
pip3 install httpx pyyaml psutil watchdog

# Configure
cp cybernest-agent.yml /etc/cybernest/agent.yml
# Edit /etc/cybernest/agent.yml with your manager address

# Install as systemd service
sudo cp cybernest-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cybernest-agent
sudo systemctl start cybernest-agent

# Check status
sudo systemctl status cybernest-agent
journalctl -u cybernest-agent -f
```

## Windows

```powershell
# Download agent (run as Administrator)
Invoke-WebRequest -Uri "https://your-manager:5000/api/v1/agents/download/windows" -OutFile cybernest-agent.zip

# Extract and configure
Expand-Archive cybernest-agent.zip -DestinationPath C:\CyberNest\
# Edit C:\CyberNest\cybernest-agent.yml

# Install as Windows Service
python C:\CyberNest\cybernest-agent.py --install-service

# Or run directly
python C:\CyberNest\cybernest-agent.py
```

## macOS

```bash
pip3 install httpx pyyaml psutil watchdog
cp cybernest-agent.yml /usr/local/etc/cybernest/agent.yml
# Edit config, then run:
python3 cybernest-agent.py
```

## Auto-Enrollment

The agent automatically registers with the Manager on first run.
It receives an API key and agent ID which are stored locally.

No manual enrollment needed — just set the Manager address and start.
