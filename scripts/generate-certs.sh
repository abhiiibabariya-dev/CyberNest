#!/bin/bash
# =============================================================================
# CyberNest — TLS Certificate Generator
# =============================================================================
# Generates a self-signed CA, server certificate, and agent certificate
# for securing agent-to-manager communication.
# Output: deploy/certs/
# =============================================================================
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")/.." && pwd)/deploy/certs"
DAYS_CA=3650
DAYS_CERT=365
KEY_SIZE=4096
COUNTRY="US"
STATE="California"
CITY="San Francisco"
ORG="CyberNest"
OU="Security"

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo "================================================================"
echo "  CyberNest TLS Certificate Generator"
echo "================================================================"
echo "  Output directory: $CERT_DIR"
echo ""

# ─── Certificate Authority ─────────────────────────────────
if [ ! -f ca.pem ]; then
    echo "[1/3] Generating Certificate Authority..."
    openssl genrsa -out ca-key.pem $KEY_SIZE 2>/dev/null

    openssl req -new -x509 -sha256 \
        -key ca-key.pem \
        -out ca.pem \
        -days $DAYS_CA \
        -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/OU=$OU/CN=CyberNest CA" \
        2>/dev/null

    echo "  [ok] CA certificate generated (valid $DAYS_CA days)"
else
    echo "[1/3] CA certificate already exists, skipping"
fi

# ─── Server Certificate ────────────────────────────────────
if [ ! -f server.pem ]; then
    echo "[2/3] Generating Server certificate..."

    # Create server extensions config
    cat > server-ext.cnf <<EXTCNF
[req]
distinguished_name = req_dn
req_extensions = v3_req

[req_dn]

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = cybernest-manager
DNS.2 = localhost
DNS.3 = *.cybernest.local
IP.1 = 127.0.0.1
IP.2 = 0.0.0.0
EXTCNF

    openssl genrsa -out server-key.pem $KEY_SIZE 2>/dev/null

    openssl req -new -sha256 \
        -key server-key.pem \
        -out server.csr \
        -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/OU=$OU/CN=cybernest-manager" \
        -config server-ext.cnf \
        2>/dev/null

    openssl x509 -req -sha256 \
        -in server.csr \
        -CA ca.pem \
        -CAkey ca-key.pem \
        -CAcreateserial \
        -out server.pem \
        -days $DAYS_CERT \
        -extensions v3_req \
        -extfile server-ext.cnf \
        2>/dev/null

    rm -f server.csr server-ext.cnf
    echo "  [ok] Server certificate generated (valid $DAYS_CERT days)"
else
    echo "[2/3] Server certificate already exists, skipping"
fi

# ─── Agent Certificate ─────────────────────────────────────
if [ ! -f agent.pem ]; then
    echo "[3/3] Generating Agent certificate..."

    cat > agent-ext.cnf <<EXTCNF
[req]
distinguished_name = req_dn
req_extensions = v3_req

[req_dn]

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EXTCNF

    openssl genrsa -out agent-key.pem $KEY_SIZE 2>/dev/null

    openssl req -new -sha256 \
        -key agent-key.pem \
        -out agent.csr \
        -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/OU=$OU/CN=cybernest-agent" \
        -config agent-ext.cnf \
        2>/dev/null

    openssl x509 -req -sha256 \
        -in agent.csr \
        -CA ca.pem \
        -CAkey ca-key.pem \
        -CAcreateserial \
        -out agent.pem \
        -days $DAYS_CERT \
        -extensions v3_req \
        -extfile agent-ext.cnf \
        2>/dev/null

    rm -f agent.csr agent-ext.cnf
    echo "  [ok] Agent certificate generated (valid $DAYS_CERT days)"
else
    echo "[3/3] Agent certificate already exists, skipping"
fi

# Cleanup
rm -f ca.srl

# Set permissions
chmod 600 *-key.pem 2>/dev/null || true
chmod 644 ca.pem server.pem agent.pem 2>/dev/null || true

echo ""
echo "================================================================"
echo "  Certificates generated in: $CERT_DIR"
echo ""
echo "  Files:"
echo "    ca.pem          - Certificate Authority (distribute to agents)"
echo "    ca-key.pem      - CA private key (keep secure!)"
echo "    server.pem      - Manager server certificate"
echo "    server-key.pem  - Manager server private key"
echo "    agent.pem       - Agent client certificate"
echo "    agent-key.pem   - Agent client private key"
echo "================================================================"
