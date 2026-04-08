"""
CyberNest SOAR Action -- AbuseIPDB Lookup.

Checks an IP address against the AbuseIPDB database and returns the
abuse confidence score, report count, country, and ISP information.
"""

from __future__ import annotations

import os
from typing import Any

import aiohttp

from soar.actions import BaseAction, register_action


ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


@register_action
class AbuseIPDBLookup(BaseAction):
    """Check an IP address reputation on AbuseIPDB."""

    name = "abuseipdb_lookup"
    description = (
        "Query AbuseIPDB for an IP address and return abuse confidence score, "
        "country, total reports, and last reported timestamp."
    )

    async def execute(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        ip: str = params.get("ip", "")
        max_age_days: int = int(params.get("max_age_days", 90))
        api_key: str = (
            params.get("api_key")
            or context.get("config", {}).get("abuseipdb_api_key")
            or ABUSEIPDB_API_KEY
        )

        if not ip:
            return self.result(False, error="Missing required parameter 'ip'")
        if not api_key:
            return self.result(False, error="AbuseIPDB API key not configured")

        headers = {
            "Key": api_key,
            "Accept": "application/json",
        }
        query_params = {
            "ipAddress": ip,
            "maxAgeInDays": str(max_age_days),
            "verbose": "",
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    ABUSEIPDB_URL,
                    headers=headers,
                    params=query_params,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 429:
                        return self.result(False, error="AbuseIPDB API rate limit exceeded")
                    if resp.status == 422:
                        body = await resp.json()
                        errors = body.get("errors", [])
                        msg = errors[0].get("detail", "Validation error") if errors else "Validation error"
                        return self.result(False, error=f"AbuseIPDB validation error: {msg}")
                    if resp.status != 200:
                        body = await resp.text()
                        return self.result(
                            False,
                            error=f"AbuseIPDB API returned HTTP {resp.status}: {body[:500]}",
                        )

                    data = await resp.json()

        except aiohttp.ClientError as exc:
            return self.result(False, error=f"HTTP request failed: {exc}")
        except Exception as exc:
            return self.result(False, error=f"Unexpected error: {exc}")

        report_data = data.get("data", {})

        abuse_score = report_data.get("abuseConfidenceScore", 0)
        country_code = report_data.get("countryCode", "")
        total_reports = report_data.get("totalReports", 0)
        last_reported = report_data.get("lastReportedAt")
        isp = report_data.get("isp", "")
        domain = report_data.get("domain", "")
        usage_type = report_data.get("usageType", "")
        is_tor = report_data.get("isTor", False)
        is_whitelisted = report_data.get("isWhitelisted", False)
        is_public = report_data.get("isPublic", True)

        return self.result(
            True,
            output={
                "ip": ip,
                "score": abuse_score,
                "abuse_confidence_score": abuse_score,
                "country_code": country_code,
                "total_reports": total_reports,
                "last_reported_at": last_reported,
                "isp": isp,
                "domain": domain,
                "usage_type": usage_type,
                "is_tor": is_tor,
                "is_whitelisted": is_whitelisted,
                "is_public": is_public,
                "is_malicious": abuse_score > 50,
            },
        )
