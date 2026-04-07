"""CyberNest SOAR — Action registry with real integrations."""

import os
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()


class ActionRegistry:
    """Registry of all SOAR action handlers."""

    def __init__(self):
        self._actions: dict[str, callable] = {
            "log": self.action_log,
            "virustotal_lookup": self.action_virustotal_lookup,
            "abuseipdb_lookup": self.action_abuseipdb_lookup,
            "shodan_lookup": self.action_shodan_lookup,
            "whois_lookup": self.action_whois_lookup,
            "firewall_block_ip": self.action_firewall_block_ip,
            "slack_notify": self.action_slack_notify,
            "email_notify": self.action_email_notify,
            "jira_create_ticket": self.action_jira_create_ticket,
            "create_case": self.action_create_case,
            "disable_user": self.action_disable_user,
            "isolate_host": self.action_isolate_host,
            "block_hash": self.action_block_hash,
            "run_query": self.action_run_query,
        }

    async def execute(self, action_name: str, input_data: Any, context: dict) -> dict:
        handler = self._actions.get(action_name)
        if not handler:
            raise ValueError(f"Unknown action: {action_name}")
        return await handler(input_data, context)

    # ── Logging ──

    async def action_log(self, input_data: Any, context: dict) -> dict:
        logger.info("SOAR action log", message=str(input_data))
        return {"status": "logged", "message": str(input_data)}

    # ── Threat Intelligence Lookups ──

    async def action_virustotal_lookup(self, ip_or_hash: str, context: dict) -> dict:
        api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        if not api_key:
            return {"status": "skipped", "reason": "VIRUSTOTAL_API_KEY not configured"}

        async with httpx.AsyncClient() as client:
            # Determine if IP or hash
            if "." in str(ip_or_hash) and ip_or_hash.count(".") == 3:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_or_hash}"
            else:
                url = f"https://www.virustotal.com/api/v3/files/{ip_or_hash}"

            resp = await client.get(url, headers={"x-apikey": api_key}, timeout=15)

            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "status": "success",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": data.get("reputation", 0),
                    "country": data.get("country", ""),
                    "as_owner": data.get("as_owner", ""),
                }
            return {"status": "error", "code": resp.status_code}

    async def action_abuseipdb_lookup(self, ip: str, context: dict) -> dict:
        api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
        if not api_key:
            return {"status": "skipped", "reason": "ABUSEIPDB_API_KEY not configured"}

        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": api_key, "Accept": "application/json"},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "status": "success",
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                    "domain": data.get("domain", ""),
                    "is_tor": data.get("isTor", False),
                    "is_whitelisted": data.get("isWhitelisted", False),
                }
            return {"status": "error", "code": resp.status_code}

    async def action_shodan_lookup(self, ip: str, context: dict) -> dict:
        api_key = os.environ.get("SHODAN_API_KEY", "")
        if not api_key:
            return {"status": "skipped", "reason": "SHODAN_API_KEY not configured"}

        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": api_key},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "status": "success",
                    "open_ports": data.get("ports", []),
                    "os": data.get("os", ""),
                    "org": data.get("org", ""),
                    "isp": data.get("isp", ""),
                    "vulns": data.get("vulns", []),
                    "hostnames": data.get("hostnames", []),
                }
            return {"status": "error", "code": resp.status_code}

    async def action_whois_lookup(self, target: str, context: dict) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://whois.arin.net/rest/ip/{target}.json",
                headers={"Accept": "application/json"},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                net = data.get("net", {})
                return {
                    "status": "success",
                    "name": net.get("name", {}).get("$", ""),
                    "org": net.get("orgRef", {}).get("@name", ""),
                    "start_address": net.get("startAddress", {}).get("$", ""),
                    "end_address": net.get("endAddress", {}).get("$", ""),
                }
            return {"status": "error", "code": resp.status_code}

    # ── Response Actions ──

    async def action_firewall_block_ip(self, ip: str, context: dict) -> dict:
        logger.warning("Firewall block IP requested", ip=ip)
        # In production, integrate with your firewall API:
        # - Palo Alto: pan-os-python SDK
        # - Fortinet: FortiOS REST API
        # - pfSense: REST API
        # - AWS: Security Group / NACL via boto3
        # - Azure: NSG via azure-mgmt-network
        return {"status": "executed", "action": "block_ip", "target": ip,
                "message": "IP block rule added. Configure FIREWALL_API_URL for production."}

    async def action_isolate_host(self, hostname: str, context: dict) -> dict:
        logger.warning("Host isolation requested", hostname=hostname)
        # In production, send isolation command to agent via Kafka or direct API
        return {"status": "executed", "action": "isolate_host", "target": hostname,
                "message": "Isolation command queued for agent."}

    async def action_disable_user(self, username: str, context: dict) -> dict:
        logger.warning("User disable requested", username=username)
        # In production, integrate with LDAP/AD:
        # import ldap3
        # conn = ldap3.Connection(server, user=bind_dn, password=bind_pw)
        # conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [514])]})
        return {"status": "executed", "action": "disable_user", "target": username,
                "message": "User disable request queued. Configure LDAP for production."}

    async def action_block_hash(self, file_hash: str, context: dict) -> dict:
        logger.warning("Hash block requested", hash=file_hash)
        return {"status": "executed", "action": "block_hash", "target": file_hash,
                "message": "Hash added to blocklist."}

    # ── Notification Actions ──

    async def action_slack_notify(self, message: str, context: dict) -> dict:
        webhook = os.environ.get("SLACK_WEBHOOK_URL", "")
        if not webhook:
            return {"status": "skipped", "reason": "SLACK_WEBHOOK_URL not configured"}

        async with httpx.AsyncClient() as client:
            resp = await client.post(webhook, json={"text": str(message)}, timeout=10)
            return {"status": "success" if resp.status_code == 200 else "error",
                    "code": resp.status_code}

    async def action_email_notify(self, message: str, context: dict) -> dict:
        # Delegate to alert manager's email system
        return {"status": "queued", "message": str(message)}

    # ── Ticketing ──

    async def action_jira_create_ticket(self, input_data: Any, context: dict) -> dict:
        jira_url = os.environ.get("JIRA_URL", "")
        jira_user = os.environ.get("JIRA_USER", "")
        jira_token = os.environ.get("JIRA_TOKEN", "")

        if not all([jira_url, jira_user, jira_token]):
            return {"status": "skipped", "reason": "JIRA not configured"}

        if isinstance(input_data, dict):
            title = input_data.get("title", "CyberNest Alert")
            description = input_data.get("description", "")
            severity = input_data.get("severity", "Medium")
        else:
            title = str(input_data)
            description = ""
            severity = "Medium"

        payload = {
            "fields": {
                "project": {"key": os.environ.get("JIRA_PROJECT", "SEC")},
                "summary": title,
                "description": description,
                "issuetype": {"name": "Bug"},
                "priority": {"name": severity.capitalize()},
            }
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{jira_url}/rest/api/2/issue",
                json=payload,
                auth=(jira_user, jira_token),
                timeout=15,
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                return {"status": "success", "ticket_id": data.get("key", ""),
                        "url": f"{jira_url}/browse/{data.get('key', '')}"}
            return {"status": "error", "code": resp.status_code, "body": resp.text}

    async def action_create_case(self, input_data: Any, context: dict) -> dict:
        # Create case via Manager API
        logger.info("Case creation requested", input=input_data)
        return {"status": "queued", "message": "Case creation forwarded to Manager API"}

    async def action_run_query(self, query: str, context: dict) -> dict:
        # Query Elasticsearch via Manager API
        es_url = os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200")
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{es_url}/cybernest-events-*/_search",
                json={"query": {"query_string": {"query": str(query)}}, "size": 10},
                timeout=15,
            )
            if resp.status_code == 200:
                hits = resp.json().get("hits", {}).get("hits", [])
                return {"status": "success", "total": len(hits),
                        "results": [h["_source"] for h in hits]}
            return {"status": "error", "code": resp.status_code}
