"""
CyberNest Alert Enricher.

Enriches alerts with asset information, user context, IOC reputation data,
MITRE ATT&CK technique descriptions, and computes a composite risk score.
"""

from __future__ import annotations

from typing import Any, Optional

import asyncpg

from shared.utils.logger import get_logger

logger = get_logger("alert_manager")

# ---------------------------------------------------------------------------
# MITRE ATT&CK Technique Mapping (50+ techniques)
# ---------------------------------------------------------------------------

MITRE_TECHNIQUES: dict[str, dict[str, str]] = {
    "T1001": {"name": "Data Obfuscation", "description": "Adversaries may obfuscate command and control traffic to make it more difficult to detect."},
    "T1003": {"name": "OS Credential Dumping", "description": "Adversaries may attempt to dump credentials to obtain account login information."},
    "T1003.001": {"name": "LSASS Memory", "description": "Adversaries may attempt to access credential material stored in LSASS process memory."},
    "T1003.003": {"name": "NTDS", "description": "Adversaries may attempt to access or create a copy of the Active Directory domain database (NTDS.dit)."},
    "T1005": {"name": "Data from Local System", "description": "Adversaries may search local system sources to find files of interest and sensitive data."},
    "T1007": {"name": "System Service Discovery", "description": "Adversaries may try to get information about registered services."},
    "T1012": {"name": "Query Registry", "description": "Adversaries may interact with the Windows Registry to gather information about the system."},
    "T1018": {"name": "Remote System Discovery", "description": "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier."},
    "T1021": {"name": "Remote Services", "description": "Adversaries may use valid accounts to log into a service specifically designed to accept remote connections."},
    "T1021.001": {"name": "Remote Desktop Protocol", "description": "Adversaries may use RDP to log into a computer using valid accounts."},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "description": "Adversaries may use valid accounts to interact with a remote network share using SMB."},
    "T1027": {"name": "Obfuscated Files or Information", "description": "Adversaries may attempt to make payloads difficult to discover and analyze by obfuscating their content."},
    "T1036": {"name": "Masquerading", "description": "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate."},
    "T1041": {"name": "Exfiltration Over C2 Channel", "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel."},
    "T1046": {"name": "Network Service Discovery", "description": "Adversaries may attempt to get a listing of services running on remote hosts."},
    "T1047": {"name": "Windows Management Instrumentation", "description": "Adversaries may abuse WMI to execute malicious commands and payloads."},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "description": "Adversaries may steal data by exfiltrating it over a different protocol than the existing C2 channel."},
    "T1053": {"name": "Scheduled Task/Job", "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code."},
    "T1053.005": {"name": "Scheduled Task", "description": "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution."},
    "T1055": {"name": "Process Injection", "description": "Adversaries may inject code into processes to evade process-based defenses and elevate privileges."},
    "T1057": {"name": "Process Discovery", "description": "Adversaries may attempt to get information about running processes on a system."},
    "T1059": {"name": "Command and Scripting Interpreter", "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries."},
    "T1059.001": {"name": "PowerShell", "description": "Adversaries may abuse PowerShell commands and scripts for execution."},
    "T1059.003": {"name": "Windows Command Shell", "description": "Adversaries may abuse the Windows command shell (cmd.exe) for execution."},
    "T1059.005": {"name": "Visual Basic", "description": "Adversaries may abuse Visual Basic (VB) for execution, including VBScript and VBA macros."},
    "T1059.007": {"name": "JavaScript", "description": "Adversaries may abuse JavaScript for execution."},
    "T1068": {"name": "Exploitation for Privilege Escalation", "description": "Adversaries may exploit software vulnerabilities to escalate privileges."},
    "T1070": {"name": "Indicator Removal", "description": "Adversaries may delete or modify artifacts generated on a host system to remove evidence."},
    "T1070.001": {"name": "Clear Windows Event Logs", "description": "Adversaries may clear Windows Event Logs to hide the activity of an intrusion."},
    "T1070.004": {"name": "File Deletion", "description": "Adversaries may delete files left behind by the actions of their intrusion activity."},
    "T1071": {"name": "Application Layer Protocol", "description": "Adversaries may communicate using application layer protocols to avoid detection."},
    "T1071.001": {"name": "Web Protocols", "description": "Adversaries may communicate using application layer protocols associated with web traffic."},
    "T1078": {"name": "Valid Accounts", "description": "Adversaries may obtain and abuse credentials of existing accounts to gain access."},
    "T1078.001": {"name": "Default Accounts", "description": "Adversaries may obtain and abuse credentials of a default account to gain access."},
    "T1078.002": {"name": "Domain Accounts", "description": "Adversaries may obtain and abuse credentials of a domain account to gain access."},
    "T1078.003": {"name": "Local Accounts", "description": "Adversaries may obtain and abuse credentials of a local account to gain access."},
    "T1082": {"name": "System Information Discovery", "description": "An adversary may attempt to get detailed information about the operating system and hardware."},
    "T1083": {"name": "File and Directory Discovery", "description": "Adversaries may enumerate files and directories or search for specific information within a file system."},
    "T1087": {"name": "Account Discovery", "description": "Adversaries may attempt to get a listing of valid accounts, usernames, or email addresses."},
    "T1090": {"name": "Proxy", "description": "Adversaries may use a connection proxy to direct network traffic between systems or act as intermediary."},
    "T1098": {"name": "Account Manipulation", "description": "Adversaries may manipulate accounts to maintain access to victim systems."},
    "T1105": {"name": "Ingress Tool Transfer", "description": "Adversaries may transfer tools or other files from an external system into a compromised environment."},
    "T1110": {"name": "Brute Force", "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown."},
    "T1110.001": {"name": "Password Guessing", "description": "Adversaries may guess passwords to attempt access to accounts."},
    "T1110.003": {"name": "Password Spraying", "description": "Adversaries may use a single or small list of commonly used passwords against many accounts."},
    "T1112": {"name": "Modify Registry", "description": "Adversaries may interact with the Windows Registry to hide configuration information or remove evidence."},
    "T1133": {"name": "External Remote Services", "description": "Adversaries may leverage external-facing remote services to gain access to a network."},
    "T1134": {"name": "Access Token Manipulation", "description": "Adversaries may modify access tokens to operate under a different user or system security context."},
    "T1135": {"name": "Network Share Discovery", "description": "Adversaries may look for folders and drives shared on remote systems."},
    "T1140": {"name": "Deobfuscate/Decode Files", "description": "Adversaries may use obfuscated files or information to hide artifacts of an intrusion."},
    "T1190": {"name": "Exploit Public-Facing Application", "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or program."},
    "T1197": {"name": "BITS Jobs", "description": "Adversaries may abuse BITS jobs to persistently execute or clean up after malicious payloads."},
    "T1199": {"name": "Trusted Relationship", "description": "Adversaries may breach or leverage organizations who have access to intended victims."},
    "T1204": {"name": "User Execution", "description": "An adversary may rely upon specific actions by a user in order to gain execution."},
    "T1218": {"name": "System Binary Proxy Execution", "description": "Adversaries may bypass process or signature-based defenses by proxying execution of malicious content."},
    "T1486": {"name": "Data Encrypted for Impact", "description": "Adversaries may encrypt data on target systems to interrupt availability to system and network resources."},
    "T1490": {"name": "Inhibit System Recovery", "description": "Adversaries may delete or remove built-in OS data and disable services designed to aid in recovery."},
    "T1505": {"name": "Server Software Component", "description": "Adversaries may abuse legitimate extensible development features of server applications."},
    "T1505.003": {"name": "Web Shell", "description": "Adversaries may backdoor web servers with web shells to establish persistent access."},
    "T1543": {"name": "Create or Modify System Process", "description": "Adversaries may create or modify system-level processes to repeatedly execute malicious payloads."},
    "T1543.003": {"name": "Windows Service", "description": "Adversaries may create or modify Windows services to repeatedly execute malicious payloads."},
    "T1547": {"name": "Boot or Logon Autostart Execution", "description": "Adversaries may configure system settings to automatically execute a program during system boot or logon."},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder", "description": "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key."},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "description": "Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions."},
    "T1548.002": {"name": "Bypass User Account Control", "description": "Adversaries may bypass UAC mechanisms to elevate process privileges on system."},
    "T1552": {"name": "Unsecured Credentials", "description": "Adversaries may search compromised systems to find and obtain insecurely stored credentials."},
    "T1558": {"name": "Steal or Forge Kerberos Tickets", "description": "Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets."},
    "T1558.003": {"name": "Kerberoasting", "description": "Adversaries may abuse a valid Kerberos TGT or sniff Kerberos traffic to request service tickets for cracking."},
    "T1562": {"name": "Impair Defenses", "description": "Adversaries may maliciously modify components of a victim environment to hinder or disable defensive mechanisms."},
    "T1562.001": {"name": "Disable or Modify Tools", "description": "Adversaries may disable security tools to avoid possible detection of their tools and activities."},
    "T1566": {"name": "Phishing", "description": "Adversaries may send phishing messages to gain access to victim systems."},
    "T1566.001": {"name": "Spearphishing Attachment", "description": "Adversaries may send spearphishing emails with a malicious attachment to gain access to victim systems."},
    "T1566.002": {"name": "Spearphishing Link", "description": "Adversaries may send spearphishing emails with a malicious link to gain access to victim systems."},
    "T1569": {"name": "System Services", "description": "Adversaries may abuse system services or daemons to execute commands or programs."},
    "T1569.002": {"name": "Service Execution", "description": "Adversaries may abuse the Windows service control manager to execute malicious commands or payloads."},
    "T1570": {"name": "Lateral Tool Transfer", "description": "Adversaries may transfer tools or other files between systems in a compromised environment."},
    "T1574": {"name": "Hijack Execution Flow", "description": "Adversaries may execute their own payloads by hijacking the way an OS loads programs."},
    "T1574.001": {"name": "DLL Search Order Hijacking", "description": "Adversaries may execute their own malicious payloads by hijacking the search order used to load DLLs."},
    "T1588": {"name": "Obtain Capabilities", "description": "Adversaries may buy, steal, or download capabilities for use during targeting."},
    "T1595": {"name": "Active Scanning", "description": "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting."},
    "T1595.001": {"name": "Scanning IP Blocks", "description": "Adversaries may scan IP blocks to gather victim network information."},
}

# Severity to numeric base score mapping
SEVERITY_BASE_SCORES: dict[str, float] = {
    "informational": 10.0,
    "low": 20.0,
    "medium": 40.0,
    "high": 60.0,
    "critical": 80.0,
}

# Asset criticality bonus
CRITICALITY_BONUSES: dict[str, float] = {
    "low": 0.0,
    "medium": 5.0,
    "high": 10.0,
    "critical": 15.0,
}


class AlertEnricher:
    """Enriches alerts with contextual data from databases and IOC feeds."""

    def __init__(self, pg_pool: asyncpg.Pool) -> None:
        self._pg_pool = pg_pool

    async def enrich(self, alert_data: dict[str, Any]) -> dict[str, Any]:
        """Run all enrichment steps on an alert dict.

        Modifies the alert in-place and returns it.
        """
        # 1. Asset enrichment
        await self._enrich_asset_info(alert_data)

        # 2. User enrichment
        await self._enrich_user_info(alert_data)

        # 3. IOC reputation check
        await self._enrich_ioc_reputation(alert_data)

        # 4. MITRE ATT&CK technique descriptions
        self._enrich_mitre(alert_data)

        # 5. Calculate risk score
        self._calculate_risk_score(alert_data)

        return alert_data

    async def _enrich_asset_info(self, alert_data: dict[str, Any]) -> None:
        """Fetch asset information for source and destination IPs from the DB."""
        source_ip = alert_data.get("source_ip")
        dest_ip = alert_data.get("destination_ip")
        ips_to_check = [ip for ip in [source_ip, dest_ip] if ip]

        if not ips_to_check:
            return

        try:
            async with self._pg_pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT ip_address, hostname, asset_type, criticality,
                           department, owner, os, location, tags
                    FROM assets
                    WHERE ip_address = ANY($1::text[])
                    """,
                    ips_to_check,
                )

            asset_map: dict[str, dict[str, Any]] = {}
            for row in rows:
                asset_map[row["ip_address"]] = {
                    "hostname": row["hostname"],
                    "asset_type": row["asset_type"],
                    "criticality": row["criticality"],
                    "department": row["department"],
                    "owner": row["owner"],
                    "os": row["os"],
                    "location": row["location"],
                    "tags": row["tags"],
                }

            if asset_map:
                alert_data["asset_info"] = asset_map
                # Set the highest criticality found for risk scoring
                criticalities = [
                    a.get("criticality", "low") for a in asset_map.values()
                ]
                alert_data["_asset_criticality"] = max(
                    criticalities,
                    key=lambda c: list(CRITICALITY_BONUSES.keys()).index(c)
                    if c in CRITICALITY_BONUSES
                    else 0,
                )

        except Exception as exc:
            logger.warning(
                "asset enrichment failed",
                alert_id=alert_data.get("alert_id"),
                error=str(exc),
            )

    async def _enrich_user_info(self, alert_data: dict[str, Any]) -> None:
        """Fetch user information for the username associated with the alert."""
        username = alert_data.get("username")
        if not username:
            return

        try:
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT user_id, username, full_name, email, department,
                           role, is_privileged, is_service_account,
                           last_login, risk_level
                    FROM users
                    WHERE username = $1
                    LIMIT 1
                    """,
                    username,
                )

            if row:
                user_info = {
                    "user_id": row["user_id"],
                    "username": row["username"],
                    "full_name": row["full_name"],
                    "email": row["email"],
                    "department": row["department"],
                    "role": row["role"],
                    "is_privileged": row["is_privileged"],
                    "is_service_account": row["is_service_account"],
                    "last_login": str(row["last_login"]) if row["last_login"] else None,
                    "risk_level": row["risk_level"],
                }
                alert_data.setdefault("enrichment", {})["user_info"] = user_info

                # Privileged accounts get a risk boost
                if row.get("is_privileged"):
                    alert_data["_user_privileged"] = True

        except Exception as exc:
            logger.warning(
                "user enrichment failed",
                alert_id=alert_data.get("alert_id"),
                username=username,
                error=str(exc),
            )

    async def _enrich_ioc_reputation(self, alert_data: dict[str, Any]) -> None:
        """Check IP addresses, domains, and file hashes against IOC database."""
        indicators: list[tuple[str, str]] = []

        # Collect IPs
        for field in ("source_ip", "destination_ip"):
            val = alert_data.get(field)
            if val:
                indicators.append(("ip", val))

        # Collect domains from parsed event
        parsed_event = alert_data.get("parsed_event", {}) or {}
        dns_question = (parsed_event.get("dns") or {}).get("question") or {}
        if dns_question.get("name"):
            indicators.append(("domain", dns_question["name"]))
        url_domain = (parsed_event.get("url") or {}).get("domain")
        if url_domain:
            indicators.append(("domain", url_domain))

        # Collect file hashes
        file_hash = (parsed_event.get("file") or {}).get("hash") or {}
        for hash_type in ("sha256", "md5", "sha1"):
            val = file_hash.get(hash_type)
            if val:
                indicators.append(("hash", val))

        if not indicators:
            return

        ioc_matches: list[dict[str, Any]] = []
        try:
            async with self._pg_pool.acquire() as conn:
                for ioc_type, ioc_value in indicators:
                    rows = await conn.fetch(
                        """
                        SELECT indicator_type, indicator_value, threat_type,
                               confidence, source, severity, first_seen,
                               last_seen, description, tags
                        FROM threat_indicators
                        WHERE indicator_type = $1 AND indicator_value = $2
                          AND is_active = true
                        """,
                        ioc_type,
                        ioc_value,
                    )
                    for row in rows:
                        ioc_matches.append({
                            "indicator_type": row["indicator_type"],
                            "indicator_value": row["indicator_value"],
                            "threat_type": row["threat_type"],
                            "confidence": row["confidence"],
                            "source": row["source"],
                            "severity": row["severity"],
                            "first_seen": str(row["first_seen"]) if row["first_seen"] else None,
                            "last_seen": str(row["last_seen"]) if row["last_seen"] else None,
                            "description": row["description"],
                            "tags": row["tags"],
                        })

            if ioc_matches:
                alert_data.setdefault("enrichment", {})["ioc_matches"] = ioc_matches
                alert_data["threat_intel"] = {
                    "matched_indicators": len(ioc_matches),
                    "highest_confidence": max(
                        (m.get("confidence", 0) for m in ioc_matches),
                        default=0,
                    ),
                    "threat_types": list(
                        {m.get("threat_type", "") for m in ioc_matches if m.get("threat_type")}
                    ),
                }
                alert_data["_has_ioc_match"] = True

        except Exception as exc:
            logger.warning(
                "ioc reputation check failed",
                alert_id=alert_data.get("alert_id"),
                error=str(exc),
            )

    @staticmethod
    def _enrich_mitre(alert_data: dict[str, Any]) -> None:
        """Add MITRE ATT&CK technique name and description from built-in mapping."""
        techniques = alert_data.get("mitre_technique", [])
        if not techniques:
            return

        enriched_techniques: list[dict[str, str]] = []
        for tech_id in techniques:
            info = MITRE_TECHNIQUES.get(tech_id)
            if info:
                enriched_techniques.append({
                    "id": tech_id,
                    "name": info["name"],
                    "description": info["description"],
                })
            else:
                enriched_techniques.append({
                    "id": tech_id,
                    "name": "Unknown Technique",
                    "description": f"No description available for {tech_id}.",
                })

        alert_data.setdefault("enrichment", {})["mitre_techniques"] = enriched_techniques

    @staticmethod
    def _calculate_risk_score(alert_data: dict[str, Any]) -> None:
        """Calculate composite risk score.

        Formula: base(severity * 10) + criticality_bonus + ioc_bonus + privileged_bonus
        Capped at 100.0.
        """
        severity = str(alert_data.get("severity", "medium")).lower()
        base_score = SEVERITY_BASE_SCORES.get(severity, 40.0)

        # Asset criticality bonus
        asset_criticality = alert_data.pop("_asset_criticality", "low")
        criticality_bonus = CRITICALITY_BONUSES.get(str(asset_criticality), 0.0)

        # IOC match bonus
        ioc_bonus = 0.0
        if alert_data.pop("_has_ioc_match", False):
            threat_intel = alert_data.get("threat_intel", {})
            matched = threat_intel.get("matched_indicators", 0)
            confidence = threat_intel.get("highest_confidence", 0)
            # Scale: up to 15 points based on matches and confidence
            ioc_bonus = min(15.0, matched * 3.0 + (confidence / 100.0) * 5.0)

        # Privileged user bonus
        privileged_bonus = 0.0
        if alert_data.pop("_user_privileged", False):
            privileged_bonus = 5.0

        total = min(100.0, base_score + criticality_bonus + ioc_bonus + privileged_bonus)
        alert_data["risk_score"] = round(total, 2)

        logger.debug(
            "risk score calculated",
            alert_id=alert_data.get("alert_id"),
            base=base_score,
            criticality_bonus=criticality_bonus,
            ioc_bonus=round(ioc_bonus, 2),
            privileged_bonus=privileged_bonus,
            total=total,
        )
