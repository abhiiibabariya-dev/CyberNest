#!/bin/bash
# =============================================================================
# CyberNest SIEM + SOAR Platform - TLS Certificate Generator
# =============================================================================
# Generates a self-signed CA, server certificate, and agent certificate
# for secure communication between CyberNest components.
#
# Usage: ./scripts/generate-certs.sh [--days 365] [--domain cybernest.local]
# =============================================================================

set -euo pipefail

# ---------- Configuration ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CERT_DIR="${PROJECT_DIR}/deploy/certs"

DAYS=365
DOMAIN="cybernest.local"
COUNTRY="US"
STATE="California"
CITY="San Francisco"
ORG="CyberNest"
ORG_UNIT="Security Operations"
CA_KEY_BITS=4096
CERT_KEY_BITS=2048

# ---------- Parse Arguments ----------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --days)
            DAYS="$2"
            shift 2
            ;;
        --domain)
            DOMAIN="$2"
            shift 2
            ;;
        --country)
            COUNTRY="$2"
            shift 2
            ;;
        --org)
            ORG="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --days NUM       Certificate validity in days (default: 365)"
            echo "  --domain NAME    Domain name for server cert (default: cybernest.local)"
            echo "  --country CODE   Country code (default: US)"
            echo "  --org NAME       Organization name (default: CyberNest)"
            echo "  -h, --help       Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ---------- Colors ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ---------- Prerequisites ----------
if ! command -v openssl &>/dev/null; then
    log_error "openssl is not installed. Please install it first."
    exit 1
fi

# ---------- Prepare Output Directory ----------
if [ -d "$CERT_DIR" ] && [ "$(ls -A "$CERT_DIR" 2>/dev/null)" ]; then
    log_warn "Certificate directory already contains files: $CERT_DIR"
    read -rp "Overwrite existing certificates? [y/N]: " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        log_info "Aborted."
        exit 0
    fi
fi

mkdir -p "$CERT_DIR"

log_info "Generating certificates in: $CERT_DIR"
log_info "Domain: $DOMAIN | Validity: $DAYS days | CA key: ${CA_KEY_BITS}-bit"

# ==========================================================================
# 1. Certificate Authority (CA)
# ==========================================================================

log_info "Generating CA private key..."
openssl genrsa -out "${CERT_DIR}/ca.key" "$CA_KEY_BITS" 2>/dev/null

log_info "Generating CA certificate..."
openssl req -new -x509 \
    -key "${CERT_DIR}/ca.key" \
    -sha256 \
    -days "$DAYS" \
    -out "${CERT_DIR}/ca.crt" \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${CITY}/O=${ORG}/OU=${ORG_UNIT}/CN=${ORG} Root CA"

# ==========================================================================
# 2. Server Certificate (for manager, nginx, inter-service TLS)
# ==========================================================================

log_info "Generating server private key..."
openssl genrsa -out "${CERT_DIR}/server.key" "$CERT_KEY_BITS" 2>/dev/null

log_info "Creating server CSR..."

# Server extensions config (SAN)
cat > "${CERT_DIR}/server_ext.cnf" <<EXTEOF
[req]
default_bits = ${CERT_KEY_BITS}
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
C = ${COUNTRY}
ST = ${STATE}
L = ${CITY}
O = ${ORG}
OU = ${ORG_UNIT}
CN = ${DOMAIN}

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${DOMAIN}
DNS.2 = *.${DOMAIN}
DNS.3 = localhost
DNS.4 = cybernest-manager
DNS.5 = cybernest-nginx
DNS.6 = cybernest-syslog
IP.1 = 127.0.0.1
IP.2 = 0.0.0.0
EXTEOF

openssl req -new \
    -key "${CERT_DIR}/server.key" \
    -out "${CERT_DIR}/server.csr" \
    -config "${CERT_DIR}/server_ext.cnf"

log_info "Signing server certificate with CA..."
openssl x509 -req \
    -in "${CERT_DIR}/server.csr" \
    -CA "${CERT_DIR}/ca.crt" \
    -CAkey "${CERT_DIR}/ca.key" \
    -CAcreateserial \
    -out "${CERT_DIR}/server.crt" \
    -days "$DAYS" \
    -sha256 \
    -extensions v3_req \
    -extfile "${CERT_DIR}/server_ext.cnf" \
    2>/dev/null

# ==========================================================================
# 3. Agent Certificate (for agent <-> manager mTLS)
# ==========================================================================

log_info "Generating agent private key..."
openssl genrsa -out "${CERT_DIR}/agent.key" "$CERT_KEY_BITS" 2>/dev/null

log_info "Creating agent CSR..."

cat > "${CERT_DIR}/agent_ext.cnf" <<EXTEOF
[req]
default_bits = ${CERT_KEY_BITS}
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
C = ${COUNTRY}
ST = ${STATE}
L = ${CITY}
O = ${ORG}
OU = Agents
CN = ${ORG} Agent

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EXTEOF

openssl req -new \
    -key "${CERT_DIR}/agent.key" \
    -out "${CERT_DIR}/agent.csr" \
    -config "${CERT_DIR}/agent_ext.cnf"

log_info "Signing agent certificate with CA..."
openssl x509 -req \
    -in "${CERT_DIR}/agent.csr" \
    -CA "${CERT_DIR}/ca.crt" \
    -CAkey "${CERT_DIR}/ca.key" \
    -CAcreateserial \
    -out "${CERT_DIR}/agent.crt" \
    -days "$DAYS" \
    -sha256 \
    -extensions v3_req \
    -extfile "${CERT_DIR}/agent_ext.cnf" \
    2>/dev/null

# ==========================================================================
# 4. Create combined PEM bundle (useful for some services)
# ==========================================================================

log_info "Creating certificate bundles..."
cat "${CERT_DIR}/server.crt" "${CERT_DIR}/ca.crt" > "${CERT_DIR}/server-chain.crt"
cat "${CERT_DIR}/agent.crt" "${CERT_DIR}/ca.crt" > "${CERT_DIR}/agent-chain.crt"

# ==========================================================================
# 5. Set permissions
# ==========================================================================

log_info "Setting file permissions..."
chmod 644 "${CERT_DIR}"/*.crt "${CERT_DIR}"/*.cnf
chmod 600 "${CERT_DIR}"/*.key
chmod 644 "${CERT_DIR}"/*.csr 2>/dev/null || true

# ==========================================================================
# 6. Clean up temporary files
# ==========================================================================

rm -f "${CERT_DIR}/server.csr" "${CERT_DIR}/agent.csr"
rm -f "${CERT_DIR}/ca.srl"

# ==========================================================================
# 7. Verify
# ==========================================================================

log_info "Verifying certificates..."

echo ""
echo "--- CA Certificate ---"
openssl x509 -in "${CERT_DIR}/ca.crt" -noout -subject -issuer -dates

echo ""
echo "--- Server Certificate ---"
openssl x509 -in "${CERT_DIR}/server.crt" -noout -subject -issuer -dates
openssl verify -CAfile "${CERT_DIR}/ca.crt" "${CERT_DIR}/server.crt"

echo ""
echo "--- Agent Certificate ---"
openssl x509 -in "${CERT_DIR}/agent.crt" -noout -subject -issuer -dates
openssl verify -CAfile "${CERT_DIR}/ca.crt" "${CERT_DIR}/agent.crt"

echo ""
log_info "All certificates generated successfully."
echo ""
echo "Files created in ${CERT_DIR}/:"
echo "  ca.key              - CA private key (KEEP SECRET)"
echo "  ca.crt              - CA certificate (distribute to agents)"
echo "  server.key          - Server private key"
echo "  server.crt          - Server certificate"
echo "  server-chain.crt    - Server cert + CA cert bundle"
echo "  agent.key           - Agent private key"
echo "  agent.crt           - Agent certificate"
echo "  agent-chain.crt     - Agent cert + CA cert bundle"
echo "  server_ext.cnf      - Server certificate extensions"
echo "  agent_ext.cnf       - Agent certificate extensions"
echo ""
log_warn "These are self-signed certificates for development/internal use."
log_warn "For production, use certificates from a trusted CA."
