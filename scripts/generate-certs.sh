#!/bin/bash
# CyberNest — Generate TLS certificates for agent ↔ manager communication

set -e

CERT_DIR="${1:-/etc/cybernest/ssl}"
mkdir -p "$CERT_DIR"

echo "Generating CyberNest CA certificate..."
openssl genrsa -out "$CERT_DIR/ca.key" 4096
openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" -sha256 -days 3650 \
    -out "$CERT_DIR/ca.crt" \
    -subj "/C=US/ST=Security/L=SOC/O=CyberNest/CN=CyberNest CA"

echo "Generating Manager server certificate..."
openssl genrsa -out "$CERT_DIR/server.key" 2048
openssl req -new -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" \
    -subj "/C=US/ST=Security/O=CyberNest/CN=cybernest-manager"
openssl x509 -req -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -out "$CERT_DIR/server.crt" -days 365 -sha256
rm "$CERT_DIR/server.csr"

echo "Generating Agent certificate..."
openssl genrsa -out "$CERT_DIR/agent.key" 2048
openssl req -new -key "$CERT_DIR/agent.key" \
    -out "$CERT_DIR/agent.csr" \
    -subj "/C=US/ST=Security/O=CyberNest/CN=cybernest-agent"
openssl x509 -req -in "$CERT_DIR/agent.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -out "$CERT_DIR/agent.crt" -days 365 -sha256
rm "$CERT_DIR/agent.csr"

echo "Certificates generated in $CERT_DIR"
ls -la "$CERT_DIR"
