"""CyberNest Threat Intel — Abuse.ch feed providers.

Fetches IOCs from Abuse.ch free feeds:
  - URLhaus: Malicious URLs used for malware distribution
  - MalwareBazaar: Malware file hashes with family classification
  - ThreatFox: IOCs (IPs, domains, URLs) from malware C2 infrastructure
  - FeodoTracker: Botnet C2 server IPs (Dridex, Emotet, TrickBot, QakBot)

All feeds are free, no API key required.
Reference: https://abuse.ch/
"""

import csv
import io
from datetime import datetime, timezone

import httpx
import structlog

from app.feeds.base import IOC

logger = structlog.get_logger()


class URLhausFeed:
    """URLhaus — malicious URL feed from Abuse.ch.

    Provides URLs actively distributing malware.
    Updated every 5 minutes. CSV format.
    """
    name = "abuse_ch_urlhaus"
    feed_type = "abuse_ch"
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"

    async def fetch(self) -> list[IOC]:
        logger.info("Fetching URLhaus feed")
        iocs: list[IOC] = []

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(self.url)
            resp.raise_for_status()

        # Skip comment lines (start with #)
        lines = [l for l in resp.text.splitlines() if l and not l.startswith("#")]
        reader = csv.reader(lines)

        for row in reader:
            if len(row) < 8:
                continue
            try:
                # Columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
                url_value = row[2].strip('"')
                threat = row[5].strip('"')
                tags = [t.strip() for t in row[6].strip('"').split(",") if t.strip()]

                iocs.append(IOC(
                    ioc_type="url",
                    value=url_value,
                    threat_type="malware_distribution",
                    threat_score=75.0,
                    confidence=85.0,
                    source=self.name,
                    tags=tags + [threat] if threat else tags,
                    malware_family=tags[0] if tags else None,
                    description=f"URLhaus: {threat}",
                    ttl_days=30,
                ))
            except (IndexError, ValueError) as e:
                logger.debug("URLhaus parse error", error=str(e))

        logger.info("URLhaus fetch complete", ioc_count=len(iocs))
        return iocs


class MalwareBazaarFeed:
    """MalwareBazaar — recent malware hash feed from Abuse.ch.

    Provides SHA256 hashes of recently submitted malware samples.
    """
    name = "abuse_ch_malwarebazaar"
    feed_type = "abuse_ch"
    url = "https://mb-api.abuse.ch/api/v1/"

    async def fetch(self) -> list[IOC]:
        logger.info("Fetching MalwareBazaar feed")
        iocs: list[IOC] = []

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(self.url, data={"query": "get_recent", "selector": "100"})
            resp.raise_for_status()

        data = resp.json()
        if data.get("query_status") != "ok":
            logger.warning("MalwareBazaar query failed", status=data.get("query_status"))
            return iocs

        for entry in data.get("data", []):
            iocs.append(IOC(
                ioc_type="hash_sha256",
                value=entry.get("sha256_hash", ""),
                threat_type="malware",
                threat_score=90.0,
                confidence=95.0,
                source=self.name,
                tags=entry.get("tags", []) or [],
                malware_family=entry.get("signature", None),
                description=f"MalwareBazaar: {entry.get('file_type', '')} — {entry.get('signature', 'unknown')}",
                ttl_days=180,
            ))

        logger.info("MalwareBazaar fetch complete", ioc_count=len(iocs))
        return iocs


class ThreatFoxFeed:
    """ThreatFox — IOC feed from Abuse.ch covering C2 infrastructure.

    Provides IPs, domains, and URLs associated with malware command & control.
    """
    name = "abuse_ch_threatfox"
    feed_type = "abuse_ch"
    url = "https://threatfox-api.abuse.ch/api/v1/"

    async def fetch(self) -> list[IOC]:
        logger.info("Fetching ThreatFox feed")
        iocs: list[IOC] = []

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(self.url, json={"query": "get_iocs", "days": 7})
            resp.raise_for_status()

        data = resp.json()
        if data.get("query_status") != "ok":
            return iocs

        type_map = {
            "ip:port": "ip",
            "domain": "domain",
            "url": "url",
            "md5_hash": "hash_md5",
            "sha256_hash": "hash_sha256",
        }

        for entry in data.get("data", []):
            ioc_type_raw = entry.get("ioc_type", "")
            ioc_type = type_map.get(ioc_type_raw, ioc_type_raw)
            value = entry.get("ioc", "")

            # Strip port from ip:port
            if ioc_type == "ip" and ":" in value:
                value = value.split(":")[0]

            confidence_level = entry.get("confidence_level", 50)

            iocs.append(IOC(
                ioc_type=ioc_type,
                value=value,
                threat_type=entry.get("threat_type", "c2"),
                threat_score=float(confidence_level),
                confidence=float(confidence_level),
                source=self.name,
                tags=entry.get("tags", []) or [],
                malware_family=entry.get("malware", None),
                description=f"ThreatFox: {entry.get('malware', 'unknown')} — {entry.get('threat_type', '')}",
                ttl_days=60,
            ))

        logger.info("ThreatFox fetch complete", ioc_count=len(iocs))
        return iocs


class FeodoTrackerFeed:
    """Feodo Tracker — botnet C2 server IP feed from Abuse.ch.

    Tracks C2 infrastructure for banking trojans:
    Dridex, Emotet, TrickBot, QakBot, BazarLoader.
    """
    name = "abuse_ch_feodotracker"
    feed_type = "abuse_ch"
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"

    async def fetch(self) -> list[IOC]:
        logger.info("Fetching FeodoTracker feed")
        iocs: list[IOC] = []

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(self.url)
            resp.raise_for_status()

        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            iocs.append(IOC(
                ioc_type="ip",
                value=line,
                threat_type="c2",
                threat_score=95.0,
                confidence=95.0,
                source=self.name,
                tags=["botnet", "c2", "banking_trojan"],
                description="FeodoTracker: Known botnet C2 server",
                ttl_days=30,
            ))

        logger.info("FeodoTracker fetch complete", ioc_count=len(iocs))
        return iocs
