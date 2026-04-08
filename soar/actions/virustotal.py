"""
CyberNest SOAR Action -- VirusTotal Lookup.

Queries the VirusTotal v3 API for IP addresses, domains, file hashes, or URLs
and returns structured reputation data including malicious/suspicious counts.
"""

from __future__ import annotations

import os
from typing import Any

import aiohttp

from soar.actions import BaseAction, register_action


VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Map friendly type names to VT API resource paths
_RESOURCE_MAP: dict[str, str] = {
    "ip": "ip_addresses",
    "ip_address": "ip_addresses",
    "domain": "domains",
    "hash": "files",
    "file": "files",
    "url": "urls",
}


@register_action
class VirusTotalLookup(BaseAction):
    """Look up an indicator on VirusTotal and return reputation data."""

    name = "virustotal_lookup"
    description = (
        "Query VirusTotal v3 API for an IP, domain, hash, or URL and "
        "return malicious/suspicious/undetected counts plus permalink."
    )

    async def execute(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        target: str = params.get("target", "")
        indicator_type: str = params.get("type", "ip")
        api_key: str = params.get("api_key") or context.get("config", {}).get("vt_api_key") or VT_API_KEY

        if not target:
            return self.result(False, error="Missing required parameter 'target'")
        if not api_key:
            return self.result(False, error="VirusTotal API key not configured")

        resource = _RESOURCE_MAP.get(indicator_type.lower())
        if resource is None:
            return self.result(
                False,
                error=f"Unsupported indicator type '{indicator_type}'. "
                      f"Supported: {', '.join(_RESOURCE_MAP.keys())}",
            )

        url = f"{VT_BASE_URL}/{resource}/{target}"
        headers = {"x-apikey": api_key, "Accept": "application/json"}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 404:
                        return self.result(
                            True,
                            output={
                                "found": False,
                                "target": target,
                                "type": indicator_type,
                                "message": "Indicator not found in VirusTotal",
                            },
                        )
                    if resp.status == 429:
                        return self.result(False, error="VirusTotal API rate limit exceeded")
                    if resp.status != 200:
                        body = await resp.text()
                        return self.result(
                            False,
                            error=f"VirusTotal API returned HTTP {resp.status}: {body[:500]}",
                        )

                    data = await resp.json()

        except aiohttp.ClientError as exc:
            return self.result(False, error=f"HTTP request failed: {exc}")
        except Exception as exc:
            return self.result(False, error=f"Unexpected error: {exc}")

        attributes = data.get("data", {}).get("attributes", {})
        analysis = attributes.get("last_analysis_stats", {})
        reputation = attributes.get("reputation", 0)

        malicious = analysis.get("malicious", 0)
        suspicious = analysis.get("suspicious", 0)
        undetected = analysis.get("undetected", 0)
        harmless = analysis.get("harmless", 0)
        total = malicious + suspicious + undetected + harmless

        permalink = f"https://www.virustotal.com/gui/{resource.rstrip('s')}/{target}"

        return self.result(
            True,
            output={
                "found": True,
                "target": target,
                "type": indicator_type,
                "malicious": malicious,
                "suspicious": suspicious,
                "undetected": undetected,
                "harmless": harmless,
                "total": total,
                "reputation": reputation,
                "permalink": permalink,
                "tags": attributes.get("tags", []),
                "last_analysis_date": attributes.get("last_analysis_date"),
                "country": attributes.get("country"),
                "as_owner": attributes.get("as_owner"),
                "network": attributes.get("network"),
            },
        )
