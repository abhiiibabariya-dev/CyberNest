"""SOAR Playbook Engine - executes automated response playbooks."""

import yaml
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from loguru import logger

from core.config import settings
from core.models import PlaybookStatus


def load_playbooks_from_yaml() -> list[dict]:
    """Load playbook definitions from config/playbooks/."""
    playbooks = []
    playbooks_dir = settings.PLAYBOOKS_DIR
    if not playbooks_dir.exists():
        logger.warning(f"Playbooks directory not found: {playbooks_dir}")
        return playbooks

    for pb_file in playbooks_dir.glob("*.yml"):
        try:
            with open(pb_file) as f:
                doc = yaml.safe_load(f)
                if doc:
                    playbooks.append(doc)
        except Exception as e:
            logger.error(f"Failed to load playbook {pb_file}: {e}")
    return playbooks


# ─── Action Handlers ───

async def action_log(params: dict, context: dict) -> dict:
    """Log a message."""
    message = params.get("message", "No message")
    logger.info(f"[Playbook Action] LOG: {message}")
    return {"status": "logged", "message": message}


async def action_block_ip(params: dict, context: dict) -> dict:
    """Block an IP address (simulated - integrate with firewall API)."""
    ip = params.get("ip") or context.get("src_ip")
    if not ip:
        return {"status": "skipped", "reason": "No IP to block"}
    logger.warning(f"[Playbook Action] BLOCK IP: {ip}")
    # TODO: Integrate with actual firewall API (iptables, pfsense, cloud security groups)
    return {"status": "blocked", "ip": ip, "note": "simulated"}


async def action_isolate_host(params: dict, context: dict) -> dict:
    """Isolate a host (simulated - integrate with EDR API)."""
    hostname = params.get("hostname") or context.get("hostname")
    if not hostname:
        return {"status": "skipped", "reason": "No hostname"}
    logger.warning(f"[Playbook Action] ISOLATE HOST: {hostname}")
    # TODO: Integrate with EDR (CrowdStrike, SentinelOne, etc.)
    return {"status": "isolated", "hostname": hostname, "note": "simulated"}


async def action_send_notification(params: dict, context: dict) -> dict:
    """Send a notification (simulated - integrate with Slack/email/PagerDuty)."""
    channel = params.get("channel", "default")
    message = params.get("message", "CyberNest Alert")
    logger.info(f"[Playbook Action] NOTIFY [{channel}]: {message}")
    # TODO: Integrate with Slack, email, PagerDuty, Teams
    return {"status": "notified", "channel": channel}


async def action_enrich_ioc(params: dict, context: dict) -> dict:
    """Enrich IOC with threat intelligence (simulated)."""
    ioc = params.get("ioc") or context.get("src_ip")
    logger.info(f"[Playbook Action] ENRICH IOC: {ioc}")
    # TODO: Integrate with VirusTotal, AbuseIPDB, Shodan, OTX
    return {
        "status": "enriched",
        "ioc": ioc,
        "reputation": "unknown",
        "note": "simulated - integrate TI feeds",
    }


async def action_create_ticket(params: dict, context: dict) -> dict:
    """Create a ticket in external system (simulated)."""
    title = params.get("title", "CyberNest Incident")
    logger.info(f"[Playbook Action] CREATE TICKET: {title}")
    # TODO: Integrate with Jira, ServiceNow, TheHive
    return {"status": "created", "title": title, "ticket_id": "SIM-001", "note": "simulated"}


async def action_disable_user(params: dict, context: dict) -> dict:
    """Disable a user account (simulated)."""
    username = params.get("username") or context.get("user")
    if not username:
        return {"status": "skipped", "reason": "No username"}
    logger.warning(f"[Playbook Action] DISABLE USER: {username}")
    # TODO: Integrate with Active Directory, Okta, etc.
    return {"status": "disabled", "username": username, "note": "simulated"}


# Action registry
ACTIONS = {
    "log": action_log,
    "block_ip": action_block_ip,
    "isolate_host": action_isolate_host,
    "send_notification": action_send_notification,
    "enrich_ioc": action_enrich_ioc,
    "create_ticket": action_create_ticket,
    "disable_user": action_disable_user,
}


async def execute_playbook(playbook: dict, context: dict) -> dict:
    """Execute a playbook's steps sequentially."""
    results = []
    playbook_name = playbook.get("name", "Unknown")
    steps = playbook.get("steps", [])

    logger.info(f"Executing playbook: {playbook_name} ({len(steps)} steps)")

    for i, step in enumerate(steps):
        step_name = step.get("name", f"Step {i+1}")
        action_type = step.get("action")
        params = step.get("params", {})

        handler = ACTIONS.get(action_type)
        if not handler:
            result = {"step": step_name, "status": "error", "reason": f"Unknown action: {action_type}"}
        else:
            try:
                result = await handler(params, context)
                result["step"] = step_name
            except Exception as e:
                result = {"step": step_name, "status": "error", "reason": str(e)}
                logger.error(f"Playbook step failed: {step_name} - {e}")

                if step.get("on_failure") == "abort":
                    results.append(result)
                    return {
                        "playbook": playbook_name,
                        "status": "failed",
                        "steps_completed": i,
                        "results": results,
                    }

        results.append(result)

    return {
        "playbook": playbook_name,
        "status": "completed",
        "steps_completed": len(steps),
        "results": results,
    }
