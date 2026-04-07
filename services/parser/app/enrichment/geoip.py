"""CyberNest Parser — GeoIP enrichment using MaxMind GeoLite2."""

import os
import structlog

logger = structlog.get_logger()

_reader = None
_PRIVATE_RANGES = [
    ("10.", "10."),
    ("172.16.", "172.31."),
    ("192.168.", "192.168."),
    ("127.", "127."),
    ("169.254.", "169.254."),
]


def _is_private(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix, _ in _PRIVATE_RANGES)


def init_geoip():
    global _reader
    db_path = os.environ.get("MAXMIND_DB_PATH", "/app/data/GeoLite2-City.mmdb")
    if os.path.exists(db_path):
        try:
            import geoip2.database
            _reader = geoip2.database.Reader(db_path)
            logger.info("GeoIP database loaded", path=db_path)
        except Exception as e:
            logger.warning("Failed to load GeoIP database", error=str(e))
    else:
        logger.info("GeoIP database not found, enrichment disabled", path=db_path)


def lookup_ip(ip: str) -> dict | None:
    """Return geo data for an IP, or None if not found / private."""
    if not ip or _is_private(ip) or _reader is None:
        return None

    try:
        resp = _reader.city(ip)
        return {
            "country_iso_code": resp.country.iso_code,
            "country_name": resp.country.name,
            "city_name": resp.city.name,
            "region_name": resp.subdivisions.most_specific.name if resp.subdivisions else None,
            "latitude": resp.location.latitude,
            "longitude": resp.location.longitude,
            "timezone": resp.location.time_zone,
            "asn": None,  # Requires separate ASN database
        }
    except Exception:
        return None


def enrich_event(event: dict) -> dict:
    """Add GeoIP data to source and destination IPs."""
    src_ip = event.get("source", {}).get("ip")
    if src_ip:
        geo = lookup_ip(src_ip)
        if geo:
            event.setdefault("source", {})["geo"] = geo

    dst_ip = event.get("destination", {}).get("ip")
    if dst_ip:
        geo = lookup_ip(dst_ip)
        if geo:
            event.setdefault("destination", {})["geo"] = geo

    return event
