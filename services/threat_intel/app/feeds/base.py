"""CyberNest Threat Intel — Base feed interface and IOC data model."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol


@dataclass
class IOC:
    """Indicator of Compromise — normalized structure from any feed source.

    Attributes:
        ioc_type: Type of indicator (ip, domain, url, hash_md5, hash_sha256, email)
        value: The indicator value itself
        threat_type: Category (malware, c2, phishing, botnet, scanner, etc.)
        threat_score: Confidence/severity score 0-100
        source: Name of the feed that produced this IOC
        tags: Additional classification tags
        malware_family: Associated malware family name if known
        first_seen: When this IOC was first observed
        ttl_days: How many days this IOC remains valid before expiry
    """
    ioc_type: str
    value: str
    threat_type: str = "unknown"
    threat_score: float = 50.0
    confidence: float = 50.0
    source: str = ""
    tags: list[str] = field(default_factory=list)
    malware_family: str | None = None
    description: str | None = None
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ttl_days: int = 90
    raw_data: dict | None = None


class ThreatFeedProvider(Protocol):
    """Protocol interface for all threat intelligence feed providers.

    Each feed provider must implement:
        name: Human-readable feed name
        feed_type: Category (abuse_ch, otx, taxii, csv, etc.)
        fetch(): Async method that returns a list of normalized IOCs
    """
    name: str
    feed_type: str

    async def fetch(self) -> list[IOC]:
        """Fetch IOCs from this feed source. Returns normalized IOC list."""
        ...
