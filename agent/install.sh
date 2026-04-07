#!/bin/bash
# CyberNest Agent — Linux/macOS Installer
# Usage: curl -s https://your-manager/install.sh | bash -s -- --manager https://manager:8000

set -e

MANAGER_URL="${1:-https://localhost:8000}"
INSTALL_DIR="/opt/cybernest-agent"
SERVICE_NAME="cybernest-agent"

echo "╔══════════════════════════════════════════╗"
echo "║       CyberNest Agent Installer          ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "Manager: $MANAGER_URL"
echo "Install: $INSTALL_DIR"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Please run as root (sudo)"
    exit 1
fi

# Create directories
mkdir -p "$INSTALL_DIR"/{config,data,logs}

# Install Python dependencies
pip3 install --quiet httpx pyyaml psutil

# Copy agent files
cp -r . "$INSTALL_DIR/"

# Update config with manager URL
sed -i "s|host: \"localhost\"|host: \"${MANAGER_URL#*://}\"|g" "$INSTALL_DIR/config/agent.yml"

# Create systemd service
cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=CyberNest Security Agent
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/main.py
Restart=always
RestartSec=10
Environment="CYBERNEST_AGENT_CONFIG=$INSTALL_DIR/config/agent.yml"

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

echo ""
echo "CyberNest Agent installed and running."
echo "Status: systemctl status $SERVICE_NAME"
echo "Logs:   journalctl -u $SERVICE_NAME -f"
