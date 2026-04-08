#!/bin/bash
# =============================================================================
# CyberNest Agent Installer - Linux
# =============================================================================
# One-liner install:
#   curl -fsSL https://raw.githubusercontent.com/abhiiibabariya-dev/CyberNest/main/scripts/install-agent.sh | \
#     sudo bash -s -- --manager-url https://siem.example.com --api-key YOUR_API_KEY
#
# Manual:
#   sudo bash scripts/install-agent.sh --manager-url https://siem.example.com --api-key YOUR_API_KEY
# =============================================================================

set -euo pipefail

# ---------- Defaults ----------
MANAGER_URL=""
API_KEY=""
AGENT_VERSION="latest"
INSTALL_DIR="/opt/cybernest-agent"
CONFIG_DIR="/etc/cybernest"
LOG_DIR="/var/log/cybernest"
SERVICE_USER="cybernest"
SERVICE_GROUP="cybernest"
AGENT_BINARY_URL=""
AGENT_PORT=9100

# ---------- Colors ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ---------- Parse Arguments ----------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --manager-url)
            MANAGER_URL="$2"; shift 2 ;;
        --api-key)
            API_KEY="$2"; shift 2 ;;
        --version)
            AGENT_VERSION="$2"; shift 2 ;;
        --install-dir)
            INSTALL_DIR="$2"; shift 2 ;;
        --port)
            AGENT_PORT="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 --manager-url URL --api-key KEY [OPTIONS]"
            echo ""
            echo "Required:"
            echo "  --manager-url URL    CyberNest Manager URL (e.g., https://siem.example.com)"
            echo "  --api-key KEY        Agent API key from the CyberNest dashboard"
            echo ""
            echo "Optional:"
            echo "  --version VER        Agent version to install (default: latest)"
            echo "  --install-dir DIR    Installation directory (default: /opt/cybernest-agent)"
            echo "  --port PORT          Agent metrics port (default: 9100)"
            echo "  -h, --help           Show this help"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ---------- Validate ----------
if [ -z "$MANAGER_URL" ]; then
    log_error "--manager-url is required"
    echo "  Usage: $0 --manager-url URL --api-key KEY"
    exit 1
fi

if [ -z "$API_KEY" ]; then
    log_error "--api-key is required"
    echo "  Usage: $0 --manager-url URL --api-key KEY"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root (use sudo)"
    exit 1
fi

# ---------- Detect OS ----------
DISTRO=""
PKG_MGR=""
if command -v apt-get &>/dev/null; then
    DISTRO="debian"
    PKG_MGR="apt-get"
elif command -v yum &>/dev/null; then
    DISTRO="rhel"
    PKG_MGR="yum"
elif command -v dnf &>/dev/null; then
    DISTRO="rhel"
    PKG_MGR="dnf"
elif command -v apk &>/dev/null; then
    DISTRO="alpine"
    PKG_MGR="apk"
else
    log_warn "Could not detect package manager, assuming dependencies are installed"
fi

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    armv7l)  ARCH="armv7" ;;
esac

log_info "Detected: distro=$DISTRO arch=$ARCH"

# ---------- Construct download URL ----------
if [ -z "$AGENT_BINARY_URL" ]; then
    AGENT_BINARY_URL="${MANAGER_URL}/api/agents/download?version=${AGENT_VERSION}&os=linux&arch=${ARCH}"
fi

# ==========================================================================
# 1. Create service user
# ==========================================================================

log_info "Creating service user '${SERVICE_USER}'..."
if id "$SERVICE_USER" &>/dev/null; then
    log_info "User '${SERVICE_USER}' already exists"
else
    groupadd --system "$SERVICE_GROUP" 2>/dev/null || true
    useradd --system \
        --gid "$SERVICE_GROUP" \
        --home-dir "$INSTALL_DIR" \
        --shell /usr/sbin/nologin \
        --comment "CyberNest Agent" \
        "$SERVICE_USER"
    log_info "Created user '${SERVICE_USER}'"
fi

# ==========================================================================
# 2. Install dependencies
# ==========================================================================

log_info "Installing dependencies..."
case "$DISTRO" in
    debian)
        apt-get update -qq
        apt-get install -y -qq curl ca-certificates jq auditd audispd-plugins 2>/dev/null || true
        ;;
    rhel)
        $PKG_MGR install -y -q curl ca-certificates jq audit audit-libs 2>/dev/null || true
        ;;
    alpine)
        apk add --no-cache curl ca-certificates jq audit 2>/dev/null || true
        ;;
esac

# ==========================================================================
# 3. Download and install agent binary
# ==========================================================================

log_info "Downloading CyberNest agent (${AGENT_VERSION})..."
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"

TEMP_FILE=$(mktemp)
HTTP_CODE=$(curl -fsSL -o "$TEMP_FILE" -w "%{http_code}" \
    -H "Authorization: Bearer ${API_KEY}" \
    "$AGENT_BINARY_URL" 2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "200" ] && [ -s "$TEMP_FILE" ]; then
    # Detect if tarball or binary
    FILE_TYPE=$(file -b "$TEMP_FILE" 2>/dev/null || echo "unknown")
    if echo "$FILE_TYPE" | grep -qi "gzip\|tar"; then
        tar xzf "$TEMP_FILE" -C "$INSTALL_DIR"
    else
        cp "$TEMP_FILE" "${INSTALL_DIR}/cybernest-agent"
        chmod +x "${INSTALL_DIR}/cybernest-agent"
    fi
    rm -f "$TEMP_FILE"
    log_info "Agent installed to ${INSTALL_DIR}"
else
    rm -f "$TEMP_FILE"
    log_warn "Could not download agent binary (HTTP ${HTTP_CODE})"
    log_warn "Creating placeholder - download manually or build from source"
    cat > "${INSTALL_DIR}/cybernest-agent" << 'PLACEHOLDER'
#!/bin/bash
echo "[CyberNest Agent] Binary not yet installed. Download from your CyberNest Manager."
exit 1
PLACEHOLDER
    chmod +x "${INSTALL_DIR}/cybernest-agent"
fi

# ==========================================================================
# 4. Create configuration file
# ==========================================================================

log_info "Writing configuration to ${CONFIG_DIR}/agent.yml..."
cat > "${CONFIG_DIR}/agent.yml" << AGENTCFG
# CyberNest Agent Configuration
# Generated by install-agent.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")

manager:
  url: "${MANAGER_URL}"
  api_key: "${API_KEY}"
  tls_verify: true
  # ca_cert: /etc/cybernest/ca.crt  # Uncomment for self-signed certs

agent:
  id: ""  # Auto-generated on first run
  port: ${AGENT_PORT}
  log_level: info
  log_file: "${LOG_DIR}/agent.log"
  buffer_dir: "${INSTALL_DIR}/buffer"
  max_buffer_size_mb: 256

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

  file:
    enabled: true
    paths:
      - path: /var/log/nginx/access.log
        type: nginx_access
      - path: /var/log/apache2/access.log
        type: apache_access
      - path: /var/log/nginx/error.log
        type: nginx_error

  process:
    enabled: true
    interval_seconds: 60

  network:
    enabled: true
    interfaces: []  # Empty = all interfaces
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
AGENTCFG

# ==========================================================================
# 5. Create buffer directory
# ==========================================================================

mkdir -p "${INSTALL_DIR}/buffer"

# ==========================================================================
# 6. Set permissions
# ==========================================================================

log_info "Setting file permissions..."
chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
chmod 750 "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
chmod 640 "${CONFIG_DIR}/agent.yml"
chmod 755 "${INSTALL_DIR}/cybernest-agent"

# Allow agent to read system logs
usermod -aG adm "$SERVICE_USER" 2>/dev/null || true
usermod -aG systemd-journal "$SERVICE_USER" 2>/dev/null || true

# ==========================================================================
# 7. Create systemd service
# ==========================================================================

log_info "Creating systemd service..."
cat > /etc/systemd/system/cybernest-agent.service << SYSTEMD
[Unit]
Description=CyberNest SIEM Agent
Documentation=https://github.com/abhiiibabariya-dev/CyberNest
After=network-online.target auditd.service
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
ExecStart=${INSTALL_DIR}/cybernest-agent --config ${CONFIG_DIR}/agent.yml
Restart=always
RestartSec=10
StartLimitInterval=300
StartLimitBurst=5

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cybernest-agent

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${LOG_DIR} ${INSTALL_DIR}/buffer
ReadOnlyPaths=${CONFIG_DIR} /var/log
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096
MemoryMax=512M
CPUQuota=50%

# Capabilities needed for log reading and network capture
AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
SYSTEMD

# ==========================================================================
# 8. Enable and start service
# ==========================================================================

log_info "Enabling and starting CyberNest agent..."
systemctl daemon-reload
systemctl enable cybernest-agent
systemctl start cybernest-agent

# Wait for service to start
sleep 3

if systemctl is-active --quiet cybernest-agent; then
    log_info "CyberNest agent is running"
else
    log_warn "Agent service may not have started correctly"
    log_warn "Check: journalctl -u cybernest-agent -f"
fi

# ==========================================================================
# 9. Summary
# ==========================================================================

echo ""
echo "============================================================"
echo "  CyberNest Agent - Installation Complete"
echo "============================================================"
echo ""
echo "  Install dir:    ${INSTALL_DIR}"
echo "  Config:         ${CONFIG_DIR}/agent.yml"
echo "  Logs:           ${LOG_DIR}/agent.log"
echo "  Service:        cybernest-agent.service"
echo "  Manager URL:    ${MANAGER_URL}"
echo ""
echo "  Useful commands:"
echo "    systemctl status cybernest-agent     # Check status"
echo "    journalctl -u cybernest-agent -f     # Follow logs"
echo "    systemctl restart cybernest-agent    # Restart agent"
echo "    nano ${CONFIG_DIR}/agent.yml         # Edit config"
echo ""
echo "  To uninstall:"
echo "    systemctl stop cybernest-agent"
echo "    systemctl disable cybernest-agent"
echo "    rm /etc/systemd/system/cybernest-agent.service"
echo "    rm -rf ${INSTALL_DIR} ${CONFIG_DIR} ${LOG_DIR}"
echo "    userdel ${SERVICE_USER}"
echo ""
