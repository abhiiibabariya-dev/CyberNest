"""
CyberNest Cryptographic Utilities.

Provides password hashing (bcrypt), JWT token creation/verification
(python-jose with HS256), and API key generation/hashing for agent
authentication and inter-service communication.

Usage:
    from shared.utils.crypto import (
        hash_password, verify_password,
        create_jwt_token, decode_jwt_token,
        generate_api_key, hash_api_key,
    )
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
from jose import ExpiredSignatureError, JWTError, jwt


# ---------------------------------------------------------------------------
# Password hashing (bcrypt)
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt.

    Args:
        password: The plaintext password to hash.

    Returns:
        The bcrypt hash string (includes salt, algorithm, and cost factor).
    """
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash.

    Args:
        password: The plaintext password to check.
        hashed: The bcrypt hash string to check against.

    Returns:
        True if the password matches, False otherwise.
    """
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            hashed.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# JWT tokens (python-jose, HS256)
# ---------------------------------------------------------------------------

def create_jwt_token(
    data: dict[str, Any],
    secret: str,
    expires_minutes: int = 60,
) -> str:
    """Create a signed JWT token with HS256.

    The token payload includes:
    - All key-value pairs from ``data``
    - ``sub``: set to data["sub"] if present, else ""
    - ``iat``: issued-at timestamp (UTC)
    - ``exp``: expiration timestamp (UTC, now + expires_minutes)

    Args:
        data: Claims to embed in the token payload.
        secret: HMAC secret key for signing.
        expires_minutes: Token lifetime in minutes (default 60).

    Returns:
        Encoded JWT string.
    """
    now = datetime.now(timezone.utc)
    payload = {
        **data,
        "sub": data.get("sub", ""),
        "iat": now,
        "exp": now + timedelta(minutes=expires_minutes),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_jwt_token(token: str, secret: str) -> dict[str, Any]:
    """Decode and verify a JWT token.

    Verifies the signature and checks that the token has not expired.

    Args:
        token: The encoded JWT string.
        secret: HMAC secret key used during signing.

    Returns:
        The decoded payload as a dict.

    Raises:
        ExpiredSignatureError: If the token has expired.
        JWTError: If the token is invalid or signature verification fails.
    """
    return jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        options={"verify_exp": True},
    )


# ---------------------------------------------------------------------------
# API key generation and hashing
# ---------------------------------------------------------------------------

def generate_api_key() -> str:
    """Generate a cryptographically secure API key.

    Returns:
        A 32-byte (64 hex character) random token string.
    """
    return secrets.token_hex(32)


def hash_api_key(key: str) -> str:
    """Hash an API key with SHA-256 for secure database storage.

    Args:
        key: The plaintext API key.

    Returns:
        Hex-encoded SHA-256 hash of the key.
    """
    return hashlib.sha256(key.encode("utf-8")).hexdigest()
