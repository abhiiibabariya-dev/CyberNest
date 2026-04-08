"""AlienVault OTX feed integration."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import aiohttp
import structlog

logger = structlog.get_logger("threat_intel.feeds.otx")

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
DEFAULT_LIMIT = 100

# Map OTX indicator types to CyberNest canonical types
OTX_TYPE_MAP: dict[str, str] = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "URI": "url",
    "email": "email",
    "FileHash-MD5": "hash_md5",
    "FileHash-SHA1": "hash_sha1",
    "FileHash-SHA256": "hash_sha256",
    "CIDR": "cidr",
    "CVE": "cve",
    "MUTEX": "mutex",
    "FilePath": "filepath",
}

# OTX types we know but skip
OTX_SKIP_TYPES: set[str] = {"SSLCertFingerprint", "YARA"}


def _map_type(otx_type: str) -> str | None:
    """Return CyberNest IOC type or None if unmapped."""
    if otx_type in OTX_SKIP_TYPES:
        return None
    return OTX_TYPE_MAP.get(otx_type)


def _confidence_from_pulse(pulse: dict[str, Any]) -> int:
    """Derive a confidence score from pulse metadata (0-100)."""
    adversary = pulse.get("adversary")
    tlp = (pulse.get("tlp") or "").lower()
    subscriber_count = pulse.get("subscriber_count", 0)

    score = 50
    if adversary:
        score += 15
    if tlp in ("red", "amber"):
        score += 10
    if subscriber_count and subscriber_count > 100:
        score += 10
    elif subscriber_count and subscriber_count > 20:
        score += 5
    return min(score, 100)


async def fetch(api_key: str, limit: int = DEFAULT_LIMIT) -> list[dict[str, Any]]:
    """Fetch subscribed pulses from OTX and return a flat list of IOC dicts."""
    if not api_key:
        logger.warning("otx_feed.no_api_key")
        return []

    url = f"{OTX_BASE_URL}/pulses/subscribed"
    headers = {"X-OTX-API-KEY": api_key}
    params = {"limit": limit, "modified_since": ""}

    iocs: list[dict[str, Any]] = []

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            page_url: str | None = url
            pages_fetched = 0
            max_pages = 5  # safety cap

            while page_url and pages_fetched < max_pages:
                async with session.get(
                    page_url, params=params if pages_fetched == 0 else None, timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status == 403:
                        logger.error("otx_feed.auth_failed", status=resp.status)
                        return []
                    resp.raise_for_status()
                    data = await resp.json()

                pulses = data.get("results", [])
                for pulse in pulses:
                    confidence = _confidence_from_pulse(pulse)
                    pulse_name = pulse.get("name", "unknown")
                    pulse_tags = pulse.get("tags", [])
                    expires_at = (
                        datetime.now(timezone.utc) + timedelta(days=30)
                    )

                    for indicator in pulse.get("indicators", []):
                        otx_type = indicator.get("type", "")
                        cn_type = _map_type(otx_type)
                        if cn_type is None:
                            continue

                        value = (indicator.get("indicator") or "").strip()
                        if not value:
                            continue

                        iocs.append(
                            {
                                "type": cn_type,
                                "value": value,
                                "source": "otx",
                                "confidence": confidence,
                                "tags": list(
                                    set(pulse_tags + [f"pulse:{pulse_name[:80]}"])
                                ),
                                "expires_at": expires_at,
                            }
                        )

                page_url = data.get("next")
                pages_fetched += 1
                # Clear params for subsequent pages (URL already has them)
                params = {}

    except aiohttp.ClientError as exc:
        logger.error("otx_feed.request_failed", error=str(exc))
    except Exception:
        logger.exception("otx_feed.unexpected_error")

    logger.info("otx_feed.fetched", ioc_count=len(iocs))
    return iocs
