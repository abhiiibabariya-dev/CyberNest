"""
CyberNest SOAR Action -- Shodan Host Lookup.

Queries the Shodan API for host information including open ports,
vulnerabilities, OS, organization, and geolocation data.
"""

from __future__ import annotations

import os
from typing import Any

import aiohttp

from soar.actions import BaseAction, register_action


SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
SHODAN_BASE_URL = "https://api.shodan.io"


@register_action
class ShodanLookup(BaseAction):
    """Look up an IP address on Shodan for host intelligence."""

    name = "shodan_lookup"
    description = (
        "Query Shodan for a host IP and return open ports, known "
        "vulnerabilities, OS, organization, ISP, and country."
    )

    async def execute(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        ip: str = params.get("ip", "")
        api_key: str = (
            params.get("api_key")
            or context.get("config", {}).get("shodan_api_key")
            or SHODAN_API_KEY
        )

        if not ip:
            return self.result(False, error="Missing required parameter 'ip'")
        if not api_key:
            return self.result(False, error="Shodan API key not configured")

        url = f"{SHODAN_BASE_URL}/shodan/host/{ip}"
        query_params = {"key": api_key}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    params=query_params,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 404:
                        return self.result(
                            True,
                            output={
                                "found": False,
                                "ip": ip,
                                "message": "Host not found in Shodan",
                            },
                        )
                    if resp.status == 401:
                        return self.result(False, error="Shodan API key is invalid or expired")
                    if resp.status == 429:
                        return self.result(False, error="Shodan API rate limit exceeded")
                    if resp.status != 200:
                        body = await resp.text()
                        return self.result(
                            False,
                            error=f"Shodan API returned HTTP {resp.status}: {body[:500]}",
                        )

                    data = await resp.json()

        except aiohttp.ClientError as exc:
            return self.result(False, error=f"HTTP request failed: {exc}")
        except Exception as exc:
            return self.result(False, error=f"Unexpected error: {exc}")

        # Extract open ports from service banners
        ports: list[int] = data.get("ports", [])

        # Collect all CVEs across services
        vulns: list[str] = data.get("vulns", [])

        # Extract service details
        services: list[dict[str, Any]] = []
        for service in data.get("data", []):
            services.append({
                "port": service.get("port"),
                "transport": service.get("transport", "tcp"),
                "product": service.get("product", ""),
                "version": service.get("version", ""),
                "banner": (service.get("data", "") or "")[:200],
            })

        return self.result(
            True,
            output={
                "found": True,
                "ip": ip,
                "ports": sorted(ports),
                "vulns": vulns,
                "vuln_count": len(vulns),
                "org": data.get("org", ""),
                "os": data.get("os", ""),
                "country_code": data.get("country_code", ""),
                "country_name": data.get("country_name", ""),
                "city": data.get("city", ""),
                "isp": data.get("isp", ""),
                "asn": data.get("asn", ""),
                "hostnames": data.get("hostnames", []),
                "domains": data.get("domains", []),
                "last_update": data.get("last_update", ""),
                "services": services,
            },
        )
