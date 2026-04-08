"""Emerging Threats compromised IP feed."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import aiohttp
import structlog

logger = structlog.get_logger("threat_intel.feeds.emergingthreats")

ET_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=30)
DEFAULT_CONFIDENCE = 70
DEFAULT_EXPIRY_DAYS = 14


async def fetch() -> list[dict[str, Any]]:
    """Download the Emerging Threats compromised-IP blocklist and parse it."""
    iocs: list[dict[str, Any]] = []
    expires_at = datetime.now(timezone.utc) + timedelta(days=DEFAULT_EXPIRY_DAYS)

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(ET_URL, timeout=REQUEST_TIMEOUT) as resp:
                resp.raise_for_status()
                text = await resp.text()

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Basic IPv4 validation
            parts = line.split(".")
            if len(parts) != 4:
                continue
            try:
                if not all(0 <= int(p) <= 255 for p in parts):
                    continue
            except ValueError:
                continue

            iocs.append(
                {
                    "type": "ip",
                    "value": line,
                    "source": "emergingthreats",
                    "confidence": DEFAULT_CONFIDENCE,
                    "tags": ["compromised"],
                    "expires_at": expires_at,
                }
            )

    except aiohttp.ClientError as exc:
        logger.error("emergingthreats.request_failed", error=str(exc))
    except Exception:
        logger.exception("emergingthreats.unexpected_error")

    logger.info("emergingthreats.fetched", ioc_count=len(iocs))
    return iocs
