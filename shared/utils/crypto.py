"""CyberNest — Cryptographic utilities for TLS cert management and hashing.

Used by the agent enrollment process and inter-service TLS communication.
"""

import hashlib
import secrets
import subprocess
import os
from pathlib import Path

from shared.utils.logger import get_logger

logger = get_logger(__name__)


def generate_api_key() -> tuple[str, str]:
    """Generate a random API key and its SHA-256 hash.

    Returns:
        Tuple of (plaintext_key, sha256_hash) — store only the hash in DB.
    """
    key = secrets.token_urlsafe(48)
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    return key, key_hash


def hash_api_key(key: str) -> str:
    """Hash an API key with SHA-256 for database storage."""
    return hashlib.sha256(key.encode()).hexdigest()


def generate_ca_cert(output_dir: str = "/etc/cybernest/ssl") -> tuple[str, str]:
    """Generate a self-signed CA certificate and private key.

    Args:
        output_dir: Directory to write ca.crt and ca.key.

    Returns:
        Tuple of (ca_cert_path, ca_key_path).
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    ca_key = os.path.join(output_dir, "ca.key")
    ca_cert = os.path.join(output_dir, "ca.crt")

    # Generate CA private key
    subprocess.run([
        "openssl", "genrsa", "-out", ca_key, "4096"
    ], check=True, capture_output=True)

    # Generate self-signed CA certificate
    subprocess.run([
        "openssl", "req", "-x509", "-new", "-nodes",
        "-key", ca_key, "-sha256", "-days", "3650",
        "-out", ca_cert,
        "-subj", "/C=US/ST=Security/L=SOC/O=CyberNest/CN=CyberNest CA"
    ], check=True, capture_output=True)

    logger.info("CA certificate generated", extra={"event": "ca_cert_generated"})
    return ca_cert, ca_key


def generate_server_cert(
    ca_cert: str, ca_key: str,
    hostname: str = "cybernest-manager",
    output_dir: str = "/etc/cybernest/ssl"
) -> tuple[str, str]:
    """Generate a server certificate signed by the CA.

    Args:
        ca_cert: Path to CA certificate.
        ca_key: Path to CA private key.
        hostname: Server hostname for the CN and SAN.
        output_dir: Directory to write server.crt and server.key.

    Returns:
        Tuple of (server_cert_path, server_key_path).
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    srv_key = os.path.join(output_dir, "server.key")
    srv_csr = os.path.join(output_dir, "server.csr")
    srv_cert = os.path.join(output_dir, "server.crt")

    # Generate server key
    subprocess.run(["openssl", "genrsa", "-out", srv_key, "2048"],
                   check=True, capture_output=True)

    # Generate CSR
    subprocess.run([
        "openssl", "req", "-new", "-key", srv_key, "-out", srv_csr,
        "-subj", f"/C=US/ST=Security/O=CyberNest/CN={hostname}"
    ], check=True, capture_output=True)

    # Sign with CA
    subprocess.run([
        "openssl", "x509", "-req", "-in", srv_csr,
        "-CA", ca_cert, "-CAkey", ca_key, "-CAcreateserial",
        "-out", srv_cert, "-days", "365", "-sha256"
    ], check=True, capture_output=True)

    os.remove(srv_csr)
    logger.info("Server certificate generated", extra={"event": "server_cert_generated"})
    return srv_cert, srv_key
