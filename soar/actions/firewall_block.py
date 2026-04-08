"""
CyberNest SOAR Action -- Firewall Block IP.

Blocks an IP address on a firewall appliance.  Supports pfSense (REST API),
Fortinet FortiGate (REST API), Palo Alto Networks (XML API), and a generic
fallback that records the block request in the database for manual application.
"""

from __future__ import annotations

import os
import ssl
from typing import Any

import aiohttp

from soar.actions import BaseAction, register_action


# Environment-based defaults
PFSENSE_URL = os.environ.get("PFSENSE_URL", "")
PFSENSE_API_KEY = os.environ.get("PFSENSE_API_KEY", "")
PFSENSE_API_SECRET = os.environ.get("PFSENSE_API_SECRET", "")

FORTINET_URL = os.environ.get("FORTINET_URL", "")
FORTINET_API_KEY = os.environ.get("FORTINET_API_KEY", "")

PALOALTO_URL = os.environ.get("PALOALTO_URL", "")
PALOALTO_API_KEY = os.environ.get("PALOALTO_API_KEY", "")


def _no_verify_ssl() -> ssl.SSLContext:
    """Create an SSL context that does not verify certificates.

    Firewall management interfaces often use self-signed certs.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


@register_action
class FirewallBlockIP(BaseAction):
    """Block an IP address on a firewall appliance."""

    name = "firewall_block_ip"
    description = (
        "Block an IP on a firewall.  Supports pfsense, fortinet, paloalto, "
        "and generic (database record) modes."
    )

    async def execute(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        ip: str = params.get("ip", "")
        duration: int = int(params.get("duration", 3600))  # seconds
        firewall_type: str = params.get("firewall_type", "generic").lower()
        reason: str = params.get("reason", "Blocked by CyberNest SOAR")

        if not ip:
            return self.result(False, error="Missing required parameter 'ip'")

        handler = {
            "pfsense": self._block_pfsense,
            "fortinet": self._block_fortinet,
            "paloalto": self._block_paloalto,
            "generic": self._block_generic,
        }.get(firewall_type)

        if handler is None:
            return self.result(
                False,
                error=f"Unsupported firewall_type '{firewall_type}'. "
                      f"Supported: pfsense, fortinet, paloalto, generic",
            )

        return await handler(ip, duration, reason, params, context)

    # ------------------------------------------------------------------
    # pfSense via pfSense-FauxAPI or pfSense REST API
    # ------------------------------------------------------------------
    async def _block_pfsense(
        self, ip: str, duration: int, reason: str,
        params: dict[str, Any], context: dict[str, Any],
    ) -> dict[str, Any]:
        base_url = params.get("firewall_url") or context.get("config", {}).get("pfsense_url") or PFSENSE_URL
        api_key = params.get("api_key") or context.get("config", {}).get("pfsense_api_key") or PFSENSE_API_KEY
        api_secret = params.get("api_secret") or context.get("config", {}).get("pfsense_api_secret") or PFSENSE_API_SECRET

        if not base_url or not api_key:
            return self.result(False, error="pfSense URL and API key are required")

        url = f"{base_url.rstrip('/')}/api/v1/firewall/rule"
        headers = {
            "Authorization": f"{api_key} {api_secret}",
            "Content-Type": "application/json",
        }
        payload = {
            "type": "block",
            "interface": "wan",
            "ipprotocol": "inet",
            "src": ip,
            "srcmask": "32",
            "dst": "any",
            "descr": f"[CyberNest] {reason} (auto-expire: {duration}s)",
            "top": True,
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    headers=headers,
                    ssl=_no_verify_ssl(),
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    body = await resp.json()
                    if resp.status in (200, 201):
                        return self.result(
                            True,
                            output={
                                "firewall": "pfsense",
                                "ip": ip,
                                "action": "block",
                                "duration": duration,
                                "rule_id": body.get("data", {}).get("tracker", ""),
                                "message": "IP blocked on pfSense",
                            },
                        )
                    return self.result(
                        False,
                        error=f"pfSense API error HTTP {resp.status}: {body}",
                    )
        except Exception as exc:
            return self.result(False, error=f"pfSense request failed: {exc}")

    # ------------------------------------------------------------------
    # Fortinet FortiGate REST API
    # ------------------------------------------------------------------
    async def _block_fortinet(
        self, ip: str, duration: int, reason: str,
        params: dict[str, Any], context: dict[str, Any],
    ) -> dict[str, Any]:
        base_url = params.get("firewall_url") or context.get("config", {}).get("fortinet_url") or FORTINET_URL
        api_key = params.get("api_key") or context.get("config", {}).get("fortinet_api_key") or FORTINET_API_KEY

        if not base_url or not api_key:
            return self.result(False, error="Fortinet URL and API key are required")

        # Step 1: Create address object
        address_name = f"CyberNest-Block-{ip.replace('.', '_')}"
        addr_url = f"{base_url.rstrip('/')}/api/v2/cmdb/firewall/address"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        addr_payload = {
            "name": address_name,
            "type": "ipmask",
            "subnet": f"{ip}/32",
            "comment": f"[CyberNest] {reason}",
        }

        try:
            async with aiohttp.ClientSession() as session:
                # Create the address object
                async with session.post(
                    addr_url,
                    json=addr_payload,
                    headers=headers,
                    ssl=_no_verify_ssl(),
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status not in (200, 201, 409):  # 409 = already exists
                        body = await resp.text()
                        return self.result(
                            False,
                            error=f"Fortinet address creation failed HTTP {resp.status}: {body[:500]}",
                        )

                # Step 2: Add to block address group
                group_url = f"{base_url.rstrip('/')}/api/v2/cmdb/firewall/addrgrp/CyberNest-Blocklist"
                async with session.get(
                    group_url,
                    headers=headers,
                    ssl=_no_verify_ssl(),
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        group_data = await resp.json()
                        members = group_data.get("results", [{}])[0].get("member", [])
                        members.append({"name": address_name})
                        async with session.put(
                            group_url,
                            json={"member": members},
                            headers=headers,
                            ssl=_no_verify_ssl(),
                            timeout=aiohttp.ClientTimeout(total=15),
                        ) as put_resp:
                            if put_resp.status not in (200, 201):
                                body = await put_resp.text()
                                return self.result(
                                    False,
                                    error=f"Fortinet group update failed HTTP {put_resp.status}: {body[:500]}",
                                )

                return self.result(
                    True,
                    output={
                        "firewall": "fortinet",
                        "ip": ip,
                        "action": "block",
                        "duration": duration,
                        "address_name": address_name,
                        "message": "IP blocked on FortiGate",
                    },
                )
        except Exception as exc:
            return self.result(False, error=f"Fortinet request failed: {exc}")

    # ------------------------------------------------------------------
    # Palo Alto Networks XML API
    # ------------------------------------------------------------------
    async def _block_paloalto(
        self, ip: str, duration: int, reason: str,
        params: dict[str, Any], context: dict[str, Any],
    ) -> dict[str, Any]:
        base_url = params.get("firewall_url") or context.get("config", {}).get("paloalto_url") or PALOALTO_URL
        api_key = params.get("api_key") or context.get("config", {}).get("paloalto_api_key") or PALOALTO_API_KEY

        if not base_url or not api_key:
            return self.result(False, error="Palo Alto URL and API key are required")

        # Use the Dynamic Address Group (DAG) tag-based approach
        # Register the IP with a blocking tag so the DAG policy catches it
        register_url = f"{base_url.rstrip('/')}/api/"
        tag_name = "CyberNest-Block"

        # XML command to register the IP with the block tag
        xml_cmd = (
            f"<uid-message>"
            f"<version>2.0</version>"
            f"<type>update</type>"
            f"<payload>"
            f"<register>"
            f'<entry ip="{ip}" persistent="1">'
            f"<tag><member>{tag_name}</member></tag>"
            f"</entry>"
            f"</register>"
            f"</payload>"
            f"</uid-message>"
        )

        query_params = {
            "type": "user-id",
            "key": api_key,
            "cmd": xml_cmd,
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    register_url,
                    params=query_params,
                    ssl=_no_verify_ssl(),
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    body = await resp.text()
                    if resp.status == 200 and "<response status=\"success\">" in body:
                        return self.result(
                            True,
                            output={
                                "firewall": "paloalto",
                                "ip": ip,
                                "action": "block",
                                "duration": duration,
                                "tag": tag_name,
                                "message": "IP registered with block tag on Palo Alto",
                            },
                        )
                    return self.result(
                        False,
                        error=f"Palo Alto API error HTTP {resp.status}: {body[:500]}",
                    )
        except Exception as exc:
            return self.result(False, error=f"Palo Alto request failed: {exc}")

    # ------------------------------------------------------------------
    # Generic -- store in database for manual review / external tooling
    # ------------------------------------------------------------------
    async def _block_generic(
        self, ip: str, duration: int, reason: str,
        params: dict[str, Any], context: dict[str, Any],
    ) -> dict[str, Any]:
        db_pool = context.get("db_pool")

        if db_pool is not None:
            try:
                async with db_pool.acquire() as conn:
                    await conn.execute(
                        """
                        INSERT INTO firewall_blocks
                            (ip_address, duration_seconds, reason, status, created_by)
                        VALUES ($1, $2, $3, 'pending', 'soar_engine')
                        ON CONFLICT (ip_address)
                        DO UPDATE SET
                            duration_seconds = EXCLUDED.duration_seconds,
                            reason = EXCLUDED.reason,
                            status = 'pending',
                            updated_at = NOW()
                        """,
                        ip, duration, reason,
                    )
            except Exception as exc:
                return self.result(
                    False,
                    error=f"Database insert failed: {exc}",
                )

        return self.result(
            True,
            output={
                "firewall": "generic",
                "ip": ip,
                "action": "block",
                "duration": duration,
                "message": (
                    "Block request recorded in database"
                    if db_pool
                    else "Block request logged (no database connection)"
                ),
            },
        )
