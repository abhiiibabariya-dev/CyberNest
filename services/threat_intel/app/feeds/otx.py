"""CyberNest Threat Intel — AlienVault OTX feed provider.

Fetches pulses (threat reports) from AlienVault OTX API.
Extracts IOCs (IPs, domains, URLs, hashes) from subscribed pulses.
Requires an OTX API key (free tier available).

Reference: https://otx.alienvault.com/api
"""

import httpx
import structlog

from app.feeds.base import IOC

logger = structlog.get_logger()

# OTX indicator type → CyberNest IOC type mapping
OTX_TYPE_MAP = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "URI": "url",
    "FileHash-MD5": "hash_md5",
    "FileHash-SHA1": "hash_sha1",
    "FileHash-SHA256": "hash_sha256",
    "email": "email",
    "CVE": "cve",
    "YARA": "yara",
    "filepath": "filename",
}


class OTXFeed:
    """AlienVault OTX (Open Threat Exchange) feed provider.

    Subscribes to pulses and extracts indicators.
    OTX provides community-driven threat intelligence.

    Attacker perspective: Covers broad TTP indicators from community reports.
    Defender perspective: High volume — use threat_score filtering to reduce FPs.
    """
    name = "alienvault_otx"
    feed_type = "otx"
    base_url = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str):
        self.api_key = api_key

    async def fetch(self) -> list[IOC]:
        """Fetch subscribed pulses and extract all indicators."""
        if not self.api_key:
            logger.info("OTX API key not configured, skipping")
            return []

        logger.info("Fetching AlienVault OTX pulses")
        iocs: list[IOC] = []
        headers = {"X-OTX-API-KEY": self.api_key}

        async with httpx.AsyncClient(timeout=30, headers=headers) as client:
            # Get subscribed pulses (last 7 days)
            page = 1
            max_pages = 5  # Limit to avoid rate limiting

            while page <= max_pages:
                resp = await client.get(
                    f"{self.base_url}/pulses/subscribed",
                    params={"page": page, "limit": 50, "modified_since": "7 days ago"},
                )
                if resp.status_code != 200:
                    logger.warning("OTX API error", status=resp.status_code)
                    break

                data = resp.json()
                results = data.get("results", [])
                if not results:
                    break

                for pulse in results:
                    pulse_name = pulse.get("name", "")
                    pulse_tags = pulse.get("tags", [])
                    adversary = pulse.get("adversary", "")

                    # Extract indicators from each pulse
                    for indicator in pulse.get("indicators", []):
                        ioc_type_raw = indicator.get("type", "")
                        ioc_type = OTX_TYPE_MAP.get(ioc_type_raw)
                        if not ioc_type:
                            continue

                        value = indicator.get("indicator", "")
                        if not value:
                            continue

                        # MITRE ATT&CK extraction from pulse
                        mitre_tags = []
                        for attack_id in pulse.get("attack_ids", []):
                            if attack_id.get("id"):
                                mitre_tags.append(attack_id["id"])

                        iocs.append(IOC(
                            ioc_type=ioc_type,
                            value=value,
                            threat_type=self._classify_threat(pulse_tags),
                            threat_score=70.0,
                            confidence=65.0,
                            source=self.name,
                            tags=pulse_tags[:10] + mitre_tags,
                            malware_family=adversary or None,
                            description=f"OTX Pulse: {pulse_name}",
                            ttl_days=60,
                        ))

                page += 1
                if not data.get("next"):
                    break

        logger.info("OTX fetch complete", ioc_count=len(iocs))
        return iocs

    def _classify_threat(self, tags: list[str]) -> str:
        """Classify threat type from pulse tags."""
        tag_set = {t.lower() for t in tags}
        if tag_set & {"malware", "trojan", "ransomware", "backdoor"}:
            return "malware"
        if tag_set & {"phishing", "credential", "spearphishing"}:
            return "phishing"
        if tag_set & {"c2", "command and control", "c&c", "rat"}:
            return "c2"
        if tag_set & {"botnet", "ddos"}:
            return "botnet"
        if tag_set & {"apt", "targeted"}:
            return "apt"
        if tag_set & {"scanning", "recon", "enumeration"}:
            return "scanner"
        return "unknown"
