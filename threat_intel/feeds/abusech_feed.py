"""Abuse.ch feed integrations — URLhaus, MalwareBazaar, ThreatFox, FeodoTracker."""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone
from typing import Any

import aiohttp
import structlog

logger = structlog.get_logger("threat_intel.feeds.abusech")

URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/text_recent/"
MALWAREBAZAAR_URL = "https://bazaar.abuse.ch/export/csv/recent/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"

REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=60)
DEFAULT_EXPIRY_DAYS = 30


def _default_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=DEFAULT_EXPIRY_DAYS)


# ── URLhaus ─────────────────────────────────────────────────────────────────

async def fetch_urlhaus() -> list[dict[str, Any]]:
    """Fetch recently added malicious URLs from URLhaus (plain-text list)."""
    iocs: list[dict[str, Any]] = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(URLHAUS_URL, timeout=REQUEST_TIMEOUT) as resp:
                resp.raise_for_status()
                text = await resp.text()

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            iocs.append(
                {
                    "type": "url",
                    "value": line,
                    "source": "urlhaus",
                    "confidence": 80,
                    "tags": ["malware-distribution"],
                    "expires_at": _default_expiry(),
                }
            )
    except aiohttp.ClientError as exc:
        logger.error("urlhaus.request_failed", error=str(exc))
    except Exception:
        logger.exception("urlhaus.unexpected_error")

    logger.info("urlhaus.fetched", ioc_count=len(iocs))
    return iocs


# ── MalwareBazaar ───────────────────────────────────────────────────────────

async def fetch_malwarebazaar() -> list[dict[str, Any]]:
    """Fetch recent malware samples from MalwareBazaar CSV export."""
    iocs: list[dict[str, Any]] = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(MALWAREBAZAAR_URL, timeout=REQUEST_TIMEOUT) as resp:
                resp.raise_for_status()
                text = await resp.text()

        # MalwareBazaar CSV starts with comment lines prefixed by '#'
        lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
        if not lines:
            return iocs

        reader = csv.reader(io.StringIO("\n".join(lines)))
        for row in reader:
            # Expected columns (0-indexed):
            #  0: first_seen_utc, 1: sha256_hash, 2: md5_hash, 3: sha1_hash,
            #  4: reporter, 5: file_name, 6: file_type_guess, 7: mime_type,
            #  8: signature, 9: clamav, 10: vtpercent, 11: imphash, 12: ssdeep,
            #  13: tlsh
            if len(row) < 4:
                continue

            sha256 = row[1].strip().strip('"')
            md5 = row[2].strip().strip('"')
            sha1 = row[3].strip().strip('"')
            signature = row[8].strip().strip('"') if len(row) > 8 else ""
            tags = ["malware"]
            if signature:
                tags.append(f"family:{signature}")

            if sha256 and len(sha256) == 64:
                iocs.append(
                    {
                        "type": "hash_sha256",
                        "value": sha256,
                        "source": "malwarebazaar",
                        "confidence": 90,
                        "tags": tags,
                        "expires_at": _default_expiry(),
                    }
                )
            if md5 and len(md5) == 32:
                iocs.append(
                    {
                        "type": "hash_md5",
                        "value": md5,
                        "source": "malwarebazaar",
                        "confidence": 90,
                        "tags": tags,
                        "expires_at": _default_expiry(),
                    }
                )
            if sha1 and len(sha1) == 40:
                iocs.append(
                    {
                        "type": "hash_sha1",
                        "value": sha1,
                        "source": "malwarebazaar",
                        "confidence": 90,
                        "tags": tags,
                        "expires_at": _default_expiry(),
                    }
                )

    except aiohttp.ClientError as exc:
        logger.error("malwarebazaar.request_failed", error=str(exc))
    except Exception:
        logger.exception("malwarebazaar.unexpected_error")

    logger.info("malwarebazaar.fetched", ioc_count=len(iocs))
    return iocs


# ── ThreatFox ───────────────────────────────────────────────────────────────

THREATFOX_TYPE_MAP: dict[str, str] = {
    "ip:port": "ip",
    "domain": "domain",
    "url": "url",
    "md5_hash": "hash_md5",
    "sha256_hash": "hash_sha256",
    "sha1_hash": "hash_sha1",
}


async def fetch_threatfox() -> list[dict[str, Any]]:
    """Fetch IOCs from ThreatFox API (last 24 hours)."""
    iocs: list[dict[str, Any]] = []
    try:
        payload = {"query": "get_iocs", "days": 1}
        async with aiohttp.ClientSession() as session:
            async with session.post(
                THREATFOX_URL, json=payload, timeout=REQUEST_TIMEOUT
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()

        if data.get("query_status") != "ok":
            logger.warning("threatfox.bad_query_status", status=data.get("query_status"))
            return iocs

        for entry in data.get("data", []) or []:
            raw_type = (entry.get("ioc_type") or "").strip()
            cn_type = THREATFOX_TYPE_MAP.get(raw_type)
            if cn_type is None:
                continue

            value = (entry.get("ioc") or "").strip()
            if not value:
                continue

            # For ip:port entries, strip the port
            if raw_type == "ip:port" and ":" in value:
                value = value.rsplit(":", 1)[0]

            malware = entry.get("malware_printable", "")
            threat_type = entry.get("threat_type", "")
            confidence_level = entry.get("confidence_level", 50)
            tags_raw = entry.get("tags") or []
            tags = [t for t in tags_raw if t] if isinstance(tags_raw, list) else []
            if malware:
                tags.append(f"family:{malware}")
            if threat_type:
                tags.append(threat_type)

            iocs.append(
                {
                    "type": cn_type,
                    "value": value,
                    "source": "threatfox",
                    "confidence": min(int(confidence_level), 100),
                    "tags": tags,
                    "expires_at": _default_expiry(),
                }
            )

    except aiohttp.ClientError as exc:
        logger.error("threatfox.request_failed", error=str(exc))
    except Exception:
        logger.exception("threatfox.unexpected_error")

    logger.info("threatfox.fetched", ioc_count=len(iocs))
    return iocs


# ── FeodoTracker ────────────────────────────────────────────────────────────

async def fetch_feodotracker() -> list[dict[str, Any]]:
    """Fetch botnet C2 IPs from FeodoTracker recommended blocklist."""
    iocs: list[dict[str, Any]] = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(FEODO_URL, timeout=REQUEST_TIMEOUT) as resp:
                resp.raise_for_status()
                text = await resp.text()

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Validate it looks like an IP
            parts = line.split(".")
            if len(parts) != 4:
                continue
            iocs.append(
                {
                    "type": "ip",
                    "value": line,
                    "source": "feodotracker",
                    "confidence": 85,
                    "tags": ["botnet", "c2"],
                    "expires_at": _default_expiry(),
                }
            )

    except aiohttp.ClientError as exc:
        logger.error("feodotracker.request_failed", error=str(exc))
    except Exception:
        logger.exception("feodotracker.unexpected_error")

    logger.info("feodotracker.fetched", ioc_count=len(iocs))
    return iocs


# ── Aggregate ───────────────────────────────────────────────────────────────

async def fetch_all() -> list[dict[str, Any]]:
    """Fetch from all four Abuse.ch sources and merge results."""
    import asyncio

    results = await asyncio.gather(
        fetch_urlhaus(),
        fetch_malwarebazaar(),
        fetch_threatfox(),
        fetch_feodotracker(),
        return_exceptions=True,
    )

    merged: list[dict[str, Any]] = []
    names = ["urlhaus", "malwarebazaar", "threatfox", "feodotracker"]
    for name, result in zip(names, results):
        if isinstance(result, BaseException):
            logger.error("abusech.feed_error", feed=name, error=str(result))
        else:
            merged.extend(result)

    logger.info("abusech.total_fetched", ioc_count=len(merged))
    return merged
