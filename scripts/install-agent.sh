#!/bin/bash
# =============================================================================
# CyberNest Agent Installer — Linux / macOS
# =============================================================================
# One-liner:
#   curl -sSL https://raw.githubusercontent.com/abhiiibabariya-dev/CyberNest/master/scripts/install-agent.sh | \
#     bash -s -- --manager-url https://YOUR_SERVER:5601 --api-key YOUR_KEY
# =============================================================================
set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

INSTALL_DIR="/opt/cybernest-agent"
CONFIG_DIR="/etc/cybernest"
SERVICE_NAME="cybernest-agent"
MANAGER_URL=""
API_KEY=""
REPO_URL="https://github.com/abhiiibabariya-dev/CyberNest.git"

log_info()  { echo -e "${CYAN}[INFO]${NC}  $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

usage() {
    echo "Usage: $0 --manager-url URL --api-key KEY [--install-dir DIR]"
    echo ""
    echo "Options:"
    echo "  --manager-url   CyberNest Manager WebSocket URL (required)"
    echo "  --api-key       Agent API key from CyberNest Manager (required)"
    echo "  --install-dir   Installation directory (default: /opt/cybernest-agent)"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --manager-url) MANAGER_URL="$2"; shift 2 ;;
        --api-key)     API_KEY="$2"; shift 2 ;;
        --install-dir) INSTALL_DIR="$2"; shift 2 ;;
        -h|--help)     usage ;;
        *)             echo "Unknown option: $1"; usage ;;
    esac
done

[ -z "$MANAGER_URL" ] && log_error "Missing --manager-url"
[ -z "$API_KEY" ] && log_error "Missing --api-key"

# Check root
[ "$(id -u)" -ne 0 ] && log_error "This script must be run as root (use sudo)"

echo ""
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║     CyberNest Agent Installer             ║"
echo "  ╚═══════════════════════════════════════════╝"
echo ""

# Check dependencies
log_info "Checking dependencies..."
command -v python3 &>/dev/null || {
    log_info "Installing Python 3..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq python3 python3-pip python3-venv
    elif command -v yum &>/dev/null; then
        yum install -y python3 python3-pip
    elif command -v dnf &>/dev/null; then
        dnf install -y python3 python3-pip
    elif command -v brew &>/dev/null; then
        brew install python3
    else
        log_error "Cannot install Python 3. Please install manually."
    fi
}
log_ok "Python 3 found: $(python3 --version)"

command -v git &>/dev/null || {
    log_info "Installing git..."
    if command -v apt-get &>/dev/null; then
        apt-get install -y -qq git
    elif command -v yum &>/dev/null; then
        yum install -y git
    fi
}

# Create directories
log_info "Creating directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p /var/log/cybernest

# Download agent
log_info "Downloading CyberNest agent..."
if [ -d "$INSTALL_DIR/.git" ]; then
    cd "$INSTALL_DIR" && git pull --quiet
else
    git clone --depth 1 --filter=blob:none --sparse "$REPO_URL" "$INSTALL_DIR/repo" 2>/dev/null || true
    if [ -d "$INSTALL_DIR/repo" ]; then
        cd "$INSTALL_DIR/repo"
        git sparse-checkout set agent 2>/dev/null || true
        cp -r agent/* "$INSTALL_DIR/"
        rm -rf "$INSTALL_DIR/repo"
    fi
fi

# Create virtual environment
log_info "Setting up Python environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt" 2>/dev/null || {
    "$INSTALL_DIR/venv/bin/pip" install --quiet psutil watchdog aiohttp pyyaml python-dateutil structlog
}
log_ok "Python dependencies installed"

# Write configuration
log_info "Writing configuration..."
cat > "$CONFIG_DIR/cybernest-agent.yml" <<AGENTCFG
manager:
  url: "${MANAGER_URL}"
  api_key: "${API_KEY}"

tls:
  enabled: false
  ca_cert: "${CONFIG_DIR}/certs/ca.pem"
  client_cert: "${CONFIG_DIR}/certs/agent.pem"
  client_key: "${CONFIG_DIR}/certs/agent-key.pem"

collectors:
  linux_syslog:
    enabled: true
    paths:
      - /var/log/syslog
      - /var/log/auth.log
      - /var/log/secure
      - /var/log/messages
      - /var/log/kern.log

  fim:
    enabled: true
    paths:
      - /etc
      - /usr/bin
      - /usr/sbin
      - /root
    exclude_patterns:
      - "*.log"
      - "*.tmp"
      - "*.cache"
      - "*.swp"

  process_monitor:
    enabled: true
    interval_seconds: 10

  network_monitor:
    enabled: true
    interval_seconds: 15

heartbeat_interval: 30
batch_size: 50
batch_timeout: 1.0
log_level: INFO
state_file: /var/lib/cybernest/agent-state.json
AGENTCFG

mkdir -p /var/lib/cybernest
log_ok "Configuration written to ${CONFIG_DIR}/cybernest-agent.yml"

# Create systemd service
if command -v systemctl &>/dev/null; then
    log_info "Creating systemd service..."
    cat > /etc/systemd/system/${SERVICE_NAME}.service <<SVCFILE
[Unit]
Description=CyberNest Security Agent
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python cybernest_agent.py --config ${CONFIG_DIR}/cybernest-agent.yml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cybernest-agent

# Security hardening
NoNewPrivileges=no
ProtectSystem=strict
ReadWritePaths=/var/log/cybernest /var/lib/cybernest ${CONFIG_DIR}
ReadOnlyPaths=/var/log /etc

[Install]
WantedBy=multi-user.target
SVCFILE

    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
    systemctl start ${SERVICE_NAME}
    log_ok "Service created and started"
else
    log_info "systemd not available — start manually:"
    echo "  ${INSTALL_DIR}/venv/bin/python ${INSTALL_DIR}/cybernest_agent.py --config ${CONFIG_DIR}/cybernest-agent.yml"
fi

echo ""
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║  CyberNest Agent installed successfully!  ║"
echo "  ╚═══════════════════════════════════════════╝"
echo ""
echo "  Install dir:  ${INSTALL_DIR}"
echo "  Config:       ${CONFIG_DIR}/cybernest-agent.yml"
echo "  Logs:         journalctl -u ${SERVICE_NAME} -f"
echo "  Status:       systemctl status ${SERVICE_NAME}"
echo ""
