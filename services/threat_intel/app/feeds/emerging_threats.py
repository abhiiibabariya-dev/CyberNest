"""CyberNest Threat Intel — EmergingThreats and PhishTank feed providers.

EmergingThreats: IP blocklist of known compromised/malicious hosts.
PhishTank: Database of verified phishing URLs.

Both are free, no API key required.
"""

import httpx
import structlog

from app.feeds.base import IOC

logger = structlog.get_logger()


class EmergingThreatsFeed:
    """EmergingThreats — compromised IP blocklist.

    Proofpoint's ET intelligence feed. Covers:
    - Known C2 servers
    - Compromised hosts
    - Malware distribution IPs
    - Scanning/brute force sources

    Attacker perspective: IPs used in active campaigns.
    Defender perspective: High confidence blocklist — low false positive rate.
    """
    name = "emerging_threats"
    feed_type = "txt"
    url = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"

    async def fetch(self) -> list[IOC]:
        logger.info("Fetching EmergingThreats IP blocklist")
        iocs: list[IOC] = []

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(self.url)
            resp.raise_for_status()

        for line in resp.text.splitlines():
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue
            # Some lines may contain CIDR notation — extract IP
            ip = line.split("/")[0].strip()
            if not ip or not all(p.isdigit() for p in ip.split(".")):
                continue

            iocs.append(IOC(
                ioc_type="ip",
                value=ip,
                threat_type="malicious_host",
                threat_score=80.0,
                confidence=80.0,
                source=self.name,
                tags=["blocklist", "emerging_threats"],
                description="EmergingThreats: Known malicious IP",
                ttl_days=14,
            ))

        logger.info("EmergingThreats fetch complete", ioc_count=len(iocs))
        return iocs


class PhishTankFeed:
    """PhishTank — verified phishing URL database.

    Community-driven database of verified phishing sites.
    Uses the PhishTank data download API (JSON format).

    Attacker perspective: Active phishing campaigns targeting organizations.
    Defender perspective: Verified by community — high confidence for URL blocking.
    """
    name = "phishtank"
    feed_type = "json"
    url = "http://data.phishtank.com/data/online-valid.json"

    async def fetch(self) -> list[IOC]:
        logger.info("Fetching PhishTank feed")
        iocs: list[IOC] = []

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.get(self.url)
                resp.raise_for_status()

            data = resp.json()
            # Limit to most recent entries to avoid overwhelming DB
            for entry in data[:5000]:
                url = entry.get("url", "")
                target = entry.get("target", "")
                verified = entry.get("verified") == "yes"

                if not url:
                    continue

                iocs.append(IOC(
                    ioc_type="url",
                    value=url,
                    threat_type="phishing",
                    threat_score=90.0 if verified else 60.0,
                    confidence=95.0 if verified else 50.0,
                    source=self.name,
                    tags=["phishing", target] if target else ["phishing"],
                    description=f"PhishTank: Phishing targeting {target}" if target else "PhishTank: Verified phishing URL",
                    ttl_days=7,
                ))

        except Exception as e:
            logger.warning("PhishTank fetch failed", error=str(e))

        logger.info("PhishTank fetch complete", ioc_count=len(iocs))
        return iocs
