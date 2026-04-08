"""
CyberNest SOAR Action -- WHOIS Lookup.

Performs WHOIS lookups on domains using the python-whois library and
returns registration, registrar, name server, and expiration data.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from functools import partial
from typing import Any

import whois

from soar.actions import BaseAction, register_action


def _normalize_date(value: Any) -> str | None:
    """Convert a date value to ISO string, handling lists."""
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value) if value else None


def _normalize_list(value: Any) -> list[str]:
    """Ensure a value is a list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value if v]
    return [str(value)]


def _sync_whois(domain: str) -> dict[str, Any]:
    """Run the blocking whois query and extract structured data."""
    w = whois.whois(domain)

    registrar = w.registrar or ""
    creation_date = _normalize_date(w.creation_date)
    expiration_date = _normalize_date(w.expiration_date)
    updated_date = _normalize_date(w.updated_date)
    name_servers = _normalize_list(w.name_servers)
    status = _normalize_list(w.status)
    emails = _normalize_list(w.emails)
    org = w.org or ""
    country = w.country or ""
    registrant = w.get("registrant_name", "") or ""
    dnssec = w.get("dnssec", "") or ""

    # Determine if the domain is registered
    is_registered = bool(w.domain_name)

    return {
        "domain": domain,
        "is_registered": is_registered,
        "registrar": registrar,
        "creation_date": creation_date,
        "expiration_date": expiration_date,
        "updated_date": updated_date,
        "name_servers": [ns.lower() for ns in name_servers],
        "status": status,
        "emails": emails,
        "org": org,
        "country": country,
        "registrant": registrant,
        "dnssec": str(dnssec),
    }


@register_action
class WhoisLookup(BaseAction):
    """Perform a WHOIS lookup on a domain name."""

    name = "whois_lookup"
    description = (
        "Query WHOIS data for a domain and return registrar, creation date, "
        "expiration date, name servers, country, and organization."
    )

    async def execute(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        domain: str = params.get("domain", "")

        if not domain:
            return self.result(False, error="Missing required parameter 'domain'")

        # Strip protocol prefixes if present
        domain = domain.replace("https://", "").replace("http://", "")
        domain = domain.split("/")[0]  # Remove path
        domain = domain.split("@")[-1]  # Handle email-style input

        try:
            loop = asyncio.get_running_loop()
            whois_data = await loop.run_in_executor(
                None, partial(_sync_whois, domain)
            )
        except whois.parser.PywhoisError as exc:
            error_msg = str(exc).lower()
            if "no match" in error_msg or "not found" in error_msg:
                return self.result(
                    True,
                    output={
                        "domain": domain,
                        "is_registered": False,
                        "message": "Domain not found in WHOIS database",
                    },
                )
            return self.result(False, error=f"WHOIS lookup failed: {exc}")
        except Exception as exc:
            return self.result(False, error=f"WHOIS lookup error: {exc}")

        return self.result(True, output=whois_data)
