"""
CyberNest GeoIP Enricher.

Enriches source.ip and destination.ip with geographic and ASN data
using MaxMind GeoLite2 databases. Uses Redis cache with 1-hour TTL.
"""

from __future__ import annotations

import ipaddress
import json
import os
from typing import Any, Optional

import redis.asyncio as redis

from shared.utils.logger import get_logger

logger = get_logger("parser.enricher.geoip")

GEOIP_CITY_DB = os.environ.get("GEOIP_CITY_DB", "/app/data/GeoLite2-City.mmdb")
GEOIP_ASN_DB = os.environ.get("GEOIP_ASN_DB", "/app/data/GeoLite2-ASN.mmdb")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
GEOIP_CACHE_TTL = int(os.environ.get("GEOIP_CACHE_TTL", "3600"))  # 1 hour
GEOIP_CACHE_PREFIX = "cybernest:geoip:"

# Private/reserved IP ranges that should not be looked up
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/reserved."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except (ValueError, TypeError):
        return True


class GeoIPEnricher:
    """GeoIP enrichment using MaxMind databases with Redis caching."""

    def __init__(self) -> None:
        self._city_reader: Any = None
        self._asn_reader: Any = None
        self._redis: Optional[redis.Redis] = None
        self._initialized = False
        self._available = False

    async def initialize(self) -> None:
        """Initialize MaxMind readers and Redis connection."""
        if self._initialized:
            return

        self._initialized = True

        # Initialize Redis
        try:
            self._redis = redis.from_url(
                REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=5,
            )
            await self._redis.ping()
            logger.info("geoip redis connected", url=REDIS_URL)
        except Exception as exc:
            logger.warning("geoip redis unavailable, proceeding without cache", error=str(exc))
            self._redis = None

        # Initialize MaxMind databases
        try:
            import maxminddb
            if os.path.exists(GEOIP_CITY_DB):
                self._city_reader = maxminddb.open_database(GEOIP_CITY_DB)
                logger.info("geoip city db loaded", path=GEOIP_CITY_DB)
            else:
                logger.warning("geoip city db not found", path=GEOIP_CITY_DB)

            if os.path.exists(GEOIP_ASN_DB):
                self._asn_reader = maxminddb.open_database(GEOIP_ASN_DB)
                logger.info("geoip asn db loaded", path=GEOIP_ASN_DB)
            else:
                logger.warning("geoip asn db not found", path=GEOIP_ASN_DB)

            self._available = self._city_reader is not None or self._asn_reader is not None
        except ImportError:
            logger.warning("maxminddb not installed, geoip enrichment disabled")
            self._available = False
        except Exception as exc:
            logger.warning("geoip db initialization failed", error=str(exc))
            self._available = False

    async def close(self) -> None:
        """Clean up resources."""
        if self._city_reader:
            self._city_reader.close()
        if self._asn_reader:
            self._asn_reader.close()
        if self._redis:
            await self._redis.close()

    def _lookup_city(self, ip: str) -> Optional[dict[str, Any]]:
        """Look up city data for an IP."""
        if not self._city_reader:
            return None
        try:
            return self._city_reader.get(ip)
        except Exception:
            return None

    def _lookup_asn(self, ip: str) -> Optional[dict[str, Any]]:
        """Look up ASN data for an IP."""
        if not self._asn_reader:
            return None
        try:
            return self._asn_reader.get(ip)
        except Exception:
            return None

    def _build_geo_data(self, ip: str) -> Optional[dict[str, Any]]:
        """Build ECS geo data from MaxMind lookups."""
        city_data = self._lookup_city(ip)
        asn_data = self._lookup_asn(ip)

        if not city_data and not asn_data:
            return None

        result: dict[str, Any] = {}

        if city_data:
            country = city_data.get("country", {})
            city = city_data.get("city", {})
            location = city_data.get("location", {})
            continent = city_data.get("continent", {})

            geo: dict[str, Any] = {}
            if country.get("iso_code"):
                geo["country_iso_code"] = country["iso_code"]
            if country.get("names", {}).get("en"):
                geo["country_name"] = country["names"]["en"]
            if city.get("names", {}).get("en"):
                geo["city_name"] = city["names"]["en"]
            if continent.get("code"):
                geo["continent_code"] = continent["code"]
            if continent.get("names", {}).get("en"):
                geo["continent_name"] = continent["names"]["en"]
            if location.get("latitude") is not None and location.get("longitude") is not None:
                geo["location"] = {
                    "lat": location["latitude"],
                    "lon": location["longitude"],
                }
            if location.get("time_zone"):
                geo["timezone"] = location["time_zone"]

            subdivisions = city_data.get("subdivisions", [])
            if subdivisions:
                sub = subdivisions[0]
                if sub.get("iso_code"):
                    geo["region_iso_code"] = sub["iso_code"]
                if sub.get("names", {}).get("en"):
                    geo["region_name"] = sub["names"]["en"]

            postal = city_data.get("postal", {})
            if postal.get("code"):
                geo["postal_code"] = postal["code"]

            if geo:
                result["geo"] = geo

        if asn_data:
            as_info: dict[str, Any] = {}
            if asn_data.get("autonomous_system_number"):
                as_info["number"] = asn_data["autonomous_system_number"]
            if asn_data.get("autonomous_system_organization"):
                as_info["organization_name"] = asn_data["autonomous_system_organization"]
            if as_info:
                result["as"] = as_info

        return result if result else None

    async def _get_cached(self, ip: str) -> Optional[dict[str, Any]]:
        """Get cached geo data from Redis."""
        if not self._redis:
            return None
        try:
            cached = await self._redis.get(f"{GEOIP_CACHE_PREFIX}{ip}")
            if cached:
                return json.loads(cached)
        except Exception:
            pass
        return None

    async def _set_cached(self, ip: str, data: Optional[dict[str, Any]]) -> None:
        """Cache geo data in Redis."""
        if not self._redis:
            return
        try:
            value = json.dumps(data) if data else '{"_empty": true}'
            await self._redis.setex(
                f"{GEOIP_CACHE_PREFIX}{ip}",
                GEOIP_CACHE_TTL,
                value,
            )
        except Exception:
            pass

    async def enrich_ip(self, ip: str) -> Optional[dict[str, Any]]:
        """Enrich a single IP with GeoIP data.

        Returns dict with 'geo' and/or 'as' keys, or None.
        """
        if not ip or _is_private_ip(ip):
            return None

        if not self._available:
            return None

        # Check cache
        cached = await self._get_cached(ip)
        if cached is not None:
            if "_empty" in cached:
                return None
            return cached

        # Lookup
        data = self._build_geo_data(ip)

        # Cache result (including None to avoid repeated lookups)
        await self._set_cached(ip, data)

        return data

    async def enrich_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Enrich an ECS event with GeoIP data for source and destination IPs.

        Modifies the event in place and returns it.
        """
        if not self._available:
            return event

        # Enrich source IP
        src_ip = (event.get("source") or {}).get("ip")
        if src_ip:
            geo_data = await self.enrich_ip(src_ip)
            if geo_data:
                src = event.setdefault("source", {})
                if "geo" in geo_data:
                    src["geo"] = geo_data["geo"]
                if "as" in geo_data:
                    src["as"] = geo_data["as"]

        # Enrich destination IP
        dst_ip = (event.get("destination") or {}).get("ip")
        if dst_ip:
            geo_data = await self.enrich_ip(dst_ip)
            if geo_data:
                dst = event.setdefault("destination", {})
                if "geo" in geo_data:
                    dst["geo"] = geo_data["geo"]
                if "as" in geo_data:
                    dst["as"] = geo_data["as"]

        return event
