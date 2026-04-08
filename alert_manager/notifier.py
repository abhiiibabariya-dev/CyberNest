"""
CyberNest Alert Notification Dispatcher.

Sends alert notifications through multiple channels:
- Slack (Block Kit)
- Email (HTML via SMTP)
- PagerDuty (Events API v2)
- Microsoft Teams (Adaptive Cards)
- Generic Webhook (HMAC-signed)
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Optional

import aiohttp
import aiosmtplib
from jinja2 import Template

from shared.utils.logger import get_logger

logger = get_logger("alert_manager")

# ---------------------------------------------------------------------------
# Severity color mapping
# ---------------------------------------------------------------------------

SEVERITY_COLORS: dict[str, str] = {
    "informational": "#17a2b8",
    "low": "#28a745",
    "medium": "#ffc107",
    "high": "#fd7e14",
    "critical": "#dc3545",
}

SEVERITY_COLORS_HEX_NO_HASH: dict[str, str] = {
    k: v.lstrip("#") for k, v in SEVERITY_COLORS.items()
}

SEVERITY_EMOJI: dict[str, str] = {
    "informational": "info",
    "low": "large_green_circle",
    "medium": "warning",
    "high": "large_orange_circle",
    "critical": "red_circle",
}

PAGERDUTY_SEVERITY_MAP: dict[str, str] = {
    "informational": "info",
    "low": "warning",
    "medium": "warning",
    "high": "error",
    "critical": "critical",
}

DASHBOARD_BASE_URL = "http://localhost:3000"


def _get_dashboard_url(alert_id: str) -> str:
    return f"{DASHBOARD_BASE_URL}/alerts/{alert_id}"


def _format_timestamp(ts: Any) -> str:
    if isinstance(ts, datetime):
        return ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    if isinstance(ts, str):
        return ts
    return str(ts)


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------

async def send_slack(alert: dict[str, Any], webhook_url: str) -> bool:
    """Send a Slack notification using Block Kit formatting.

    Args:
        alert: Alert data dict.
        webhook_url: Slack incoming webhook URL.

    Returns:
        True if sent successfully, False otherwise.
    """
    severity = str(alert.get("severity", "medium")).lower()
    alert_id = alert.get("alert_id", "unknown")
    title = alert.get("title", "Untitled Alert")
    rule_name = alert.get("rule_name", "Unknown Rule")
    source_ip = alert.get("source_ip", "N/A")
    dest_ip = alert.get("destination_ip", "N/A")
    username = alert.get("username", "N/A")
    hostname = alert.get("hostname", "N/A")
    risk_score = alert.get("risk_score", 0)
    created_at = _format_timestamp(alert.get("created_at", ""))
    dashboard_url = _get_dashboard_url(alert_id)
    color = SEVERITY_COLORS.get(severity, "#808080")
    emoji = SEVERITY_EMOJI.get(severity, "bell")

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f":{emoji}: CyberNest Alert: {title}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                {"type": "mrkdwn", "text": f"*Rule:*\n{rule_name}"},
                {"type": "mrkdwn", "text": f"*Source IP:*\n`{source_ip}`"},
                {"type": "mrkdwn", "text": f"*Destination IP:*\n`{dest_ip}`"},
                {"type": "mrkdwn", "text": f"*Username:*\n{username}"},
                {"type": "mrkdwn", "text": f"*Hostname:*\n{hostname}"},
                {"type": "mrkdwn", "text": f"*Risk Score:*\n{risk_score}"},
                {"type": "mrkdwn", "text": f"*Time:*\n{created_at}"},
            ],
        },
        {"type": "divider"},
    ]

    # Description section
    description = alert.get("description", "")
    if description:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Description:*\n{description[:500]}",
            },
        })

    # MITRE techniques
    techniques = alert.get("mitre_technique", [])
    if techniques:
        tech_str = ", ".join(techniques)
        blocks.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"*MITRE ATT&CK:* {tech_str}"},
            ],
        })

    # Action buttons
    blocks.append({
        "type": "actions",
        "elements": [
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "View in Dashboard"},
                "url": dashboard_url,
                "style": "primary",
            },
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Acknowledge"},
                "action_id": f"ack_alert_{alert_id}",
                "value": alert_id,
            },
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Escalate"},
                "action_id": f"escalate_alert_{alert_id}",
                "value": alert_id,
                "style": "danger",
            },
        ],
    })

    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": blocks,
            }
        ],
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                webhook_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    logger.info("slack notification sent", alert_id=alert_id)
                    return True
                else:
                    body = await resp.text()
                    logger.error(
                        "slack notification failed",
                        alert_id=alert_id,
                        status=resp.status,
                        response=body[:200],
                    )
                    return False
    except Exception as exc:
        logger.error("slack notification error", alert_id=alert_id, error=str(exc))
        return False


# ---------------------------------------------------------------------------
# Email (HTML via SMTP)
# ---------------------------------------------------------------------------

EMAIL_HTML_TEMPLATE = Template("""
<!DOCTYPE html>
<html>
<head>
<style>
  body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f4f4f4; }
  .container { max-width: 600px; margin: 20px auto; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
  .header { background: {{ color }}; color: #fff; padding: 20px; text-align: center; }
  .header h1 { margin: 0; font-size: 20px; }
  .header .severity { font-size: 14px; text-transform: uppercase; margin-top: 5px; }
  .body-content { padding: 20px; }
  table { width: 100%; border-collapse: collapse; margin: 15px 0; }
  table td { padding: 8px 12px; border-bottom: 1px solid #eee; }
  table td:first-child { font-weight: bold; width: 40%; color: #555; }
  .description { background: #f8f9fa; padding: 12px; border-left: 4px solid {{ color }}; margin: 15px 0; }
  .btn { display: inline-block; padding: 10px 20px; background: {{ color }}; color: #fff; text-decoration: none; border-radius: 4px; margin-top: 15px; }
  .footer { padding: 15px 20px; background: #f8f9fa; text-align: center; font-size: 12px; color: #888; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>CyberNest Alert</h1>
    <div class="severity">{{ severity | upper }}</div>
  </div>
  <div class="body-content">
    <h2>{{ title }}</h2>
    <table>
      <tr><td>Alert ID</td><td>{{ alert_id }}</td></tr>
      <tr><td>Rule</td><td>{{ rule_name }}</td></tr>
      <tr><td>Severity</td><td>{{ severity | upper }}</td></tr>
      <tr><td>Risk Score</td><td>{{ risk_score }}</td></tr>
      <tr><td>Source IP</td><td>{{ source_ip }}</td></tr>
      <tr><td>Destination IP</td><td>{{ destination_ip }}</td></tr>
      <tr><td>Username</td><td>{{ username }}</td></tr>
      <tr><td>Hostname</td><td>{{ hostname }}</td></tr>
      <tr><td>Time</td><td>{{ created_at }}</td></tr>
      {% if mitre_techniques %}
      <tr><td>MITRE ATT&CK</td><td>{{ mitre_techniques }}</td></tr>
      {% endif %}
    </table>
    {% if description %}
    <div class="description">{{ description }}</div>
    {% endif %}
    <a href="{{ dashboard_url }}" class="btn">View in Dashboard</a>
  </div>
  <div class="footer">
    CyberNest SIEM &mdash; Automated Alert Notification
  </div>
</div>
</body>
</html>
""")


async def send_email(
    alert: dict[str, Any],
    smtp_config: dict[str, Any],
) -> bool:
    """Send an HTML email alert notification.

    Args:
        alert: Alert data dict.
        smtp_config: Dict with keys: host, port, username, password,
                     from_addr, to_addrs (list), use_tls (bool).

    Returns:
        True if sent successfully, False otherwise.
    """
    alert_id = alert.get("alert_id", "unknown")
    severity = str(alert.get("severity", "medium")).lower()
    color = SEVERITY_COLORS.get(severity, "#808080")

    html_body = EMAIL_HTML_TEMPLATE.render(
        color=color,
        severity=severity,
        title=alert.get("title", "Untitled Alert"),
        alert_id=alert_id,
        rule_name=alert.get("rule_name", "Unknown"),
        risk_score=alert.get("risk_score", 0),
        source_ip=alert.get("source_ip", "N/A"),
        destination_ip=alert.get("destination_ip", "N/A"),
        username=alert.get("username", "N/A"),
        hostname=alert.get("hostname", "N/A"),
        created_at=_format_timestamp(alert.get("created_at", "")),
        description=alert.get("description", ""),
        mitre_techniques=", ".join(alert.get("mitre_technique", [])),
        dashboard_url=_get_dashboard_url(alert_id),
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[CyberNest] [{severity.upper()}] {alert.get('title', 'Alert')}"
    msg["From"] = smtp_config.get("from_addr", "cybernest@localhost")
    to_addrs = smtp_config.get("to_addrs", [])
    msg["To"] = ", ".join(to_addrs)

    # Plain text fallback
    plain_text = (
        f"CyberNest Alert: {alert.get('title', '')}\n"
        f"Severity: {severity.upper()}\n"
        f"Rule: {alert.get('rule_name', '')}\n"
        f"Source IP: {alert.get('source_ip', 'N/A')}\n"
        f"Alert ID: {alert_id}\n"
        f"Dashboard: {_get_dashboard_url(alert_id)}\n"
    )
    msg.attach(MIMEText(plain_text, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        smtp = aiosmtplib.SMTP(
            hostname=smtp_config.get("host", "localhost"),
            port=smtp_config.get("port", 587),
            use_tls=smtp_config.get("use_tls", True),
        )
        await smtp.connect()
        if smtp_config.get("username") and smtp_config.get("password"):
            await smtp.login(smtp_config["username"], smtp_config["password"])
        await smtp.send_message(msg)
        await smtp.quit()
        logger.info("email notification sent", alert_id=alert_id, to=to_addrs)
        return True

    except Exception as exc:
        logger.error("email notification error", alert_id=alert_id, error=str(exc))
        return False


# ---------------------------------------------------------------------------
# PagerDuty (Events API v2)
# ---------------------------------------------------------------------------

async def send_pagerduty(alert: dict[str, Any], api_key: str) -> bool:
    """Send a PagerDuty alert via Events API v2.

    Args:
        alert: Alert data dict.
        api_key: PagerDuty Events API integration/routing key.

    Returns:
        True if sent successfully, False otherwise.
    """
    alert_id = alert.get("alert_id", "unknown")
    severity = str(alert.get("severity", "medium")).lower()
    pd_severity = PAGERDUTY_SEVERITY_MAP.get(severity, "warning")

    payload = {
        "routing_key": api_key,
        "event_action": "trigger",
        "dedup_key": f"cybernest-{alert_id}",
        "payload": {
            "summary": f"[CyberNest] {alert.get('title', 'Security Alert')} "
                       f"[{severity.upper()}]",
            "severity": pd_severity,
            "source": alert.get("hostname") or alert.get("source_ip") or "cybernest",
            "component": alert.get("rule_name", "detection-engine"),
            "group": "cybernest-siem",
            "class": severity,
            "timestamp": (
                alert.get("created_at").isoformat()
                if isinstance(alert.get("created_at"), datetime)
                else str(alert.get("created_at", ""))
            ),
            "custom_details": {
                "alert_id": alert_id,
                "rule_id": alert.get("rule_id", ""),
                "rule_name": alert.get("rule_name", ""),
                "source_ip": alert.get("source_ip", ""),
                "destination_ip": alert.get("destination_ip", ""),
                "username": alert.get("username", ""),
                "risk_score": alert.get("risk_score", 0),
                "mitre_techniques": alert.get("mitre_technique", []),
                "event_count": alert.get("event_count", 1),
                "description": alert.get("description", "")[:1000],
                "dashboard_url": _get_dashboard_url(alert_id),
            },
        },
        "links": [
            {
                "href": _get_dashboard_url(alert_id),
                "text": "View in CyberNest Dashboard",
            }
        ],
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status in (200, 202):
                    body = await resp.json()
                    logger.info(
                        "pagerduty notification sent",
                        alert_id=alert_id,
                        dedup_key=f"cybernest-{alert_id}",
                        status=body.get("status"),
                    )
                    return True
                else:
                    body = await resp.text()
                    logger.error(
                        "pagerduty notification failed",
                        alert_id=alert_id,
                        status=resp.status,
                        response=body[:200],
                    )
                    return False
    except Exception as exc:
        logger.error("pagerduty notification error", alert_id=alert_id, error=str(exc))
        return False


# ---------------------------------------------------------------------------
# Microsoft Teams (Adaptive Card)
# ---------------------------------------------------------------------------

async def send_teams(alert: dict[str, Any], webhook_url: str) -> bool:
    """Send a Microsoft Teams notification using Adaptive Card format.

    Args:
        alert: Alert data dict.
        webhook_url: Teams incoming webhook URL.

    Returns:
        True if sent successfully, False otherwise.
    """
    alert_id = alert.get("alert_id", "unknown")
    severity = str(alert.get("severity", "medium")).lower()
    color = SEVERITY_COLORS_HEX_NO_HASH.get(severity, "808080")
    title = alert.get("title", "Untitled Alert")

    facts = [
        {"title": "Severity", "value": severity.upper()},
        {"title": "Rule", "value": alert.get("rule_name", "Unknown")},
        {"title": "Source IP", "value": alert.get("source_ip", "N/A")},
        {"title": "Destination IP", "value": alert.get("destination_ip", "N/A")},
        {"title": "Username", "value": alert.get("username", "N/A")},
        {"title": "Hostname", "value": alert.get("hostname", "N/A")},
        {"title": "Risk Score", "value": str(alert.get("risk_score", 0))},
        {"title": "Time", "value": _format_timestamp(alert.get("created_at", ""))},
    ]

    techniques = alert.get("mitre_technique", [])
    if techniques:
        facts.append({"title": "MITRE ATT&CK", "value": ", ".join(techniques)})

    card_body = [
        {
            "type": "TextBlock",
            "size": "Large",
            "weight": "Bolder",
            "text": f"CyberNest Alert: {title}",
            "color": "Attention" if severity in ("high", "critical") else "Default",
        },
        {
            "type": "ColumnSet",
            "columns": [
                {
                    "type": "Column",
                    "width": "auto",
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": severity.upper(),
                            "weight": "Bolder",
                            "color": "Attention" if severity in ("high", "critical") else "Warning" if severity == "medium" else "Good",
                            "size": "Medium",
                        }
                    ],
                },
                {
                    "type": "Column",
                    "width": "stretch",
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": f"Alert ID: {alert_id}",
                            "isSubtle": True,
                            "size": "Small",
                        }
                    ],
                },
            ],
        },
        {
            "type": "FactSet",
            "facts": facts,
        },
    ]

    description = alert.get("description", "")
    if description:
        card_body.append({
            "type": "TextBlock",
            "text": description[:500],
            "wrap": True,
            "isSubtle": True,
        })

    card = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": card_body,
                    "actions": [
                        {
                            "type": "Action.OpenUrl",
                            "title": "View in Dashboard",
                            "url": _get_dashboard_url(alert_id),
                        },
                    ],
                    "msteams": {
                        "width": "Full",
                    },
                },
            }
        ],
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                webhook_url,
                json=card,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status in (200, 202):
                    logger.info("teams notification sent", alert_id=alert_id)
                    return True
                else:
                    body = await resp.text()
                    logger.error(
                        "teams notification failed",
                        alert_id=alert_id,
                        status=resp.status,
                        response=body[:200],
                    )
                    return False
    except Exception as exc:
        logger.error("teams notification error", alert_id=alert_id, error=str(exc))
        return False


# ---------------------------------------------------------------------------
# Generic Webhook (HMAC-signed)
# ---------------------------------------------------------------------------

async def send_webhook(
    alert: dict[str, Any],
    url: str,
    secret: str,
) -> bool:
    """Send alert as JSON to a webhook URL with HMAC-SHA256 signature.

    The signature is sent in the X-CyberNest-Signature header as
    sha256=<hex_digest>.

    Args:
        alert: Alert data dict.
        url: Webhook endpoint URL.
        secret: HMAC secret for signature generation.

    Returns:
        True if sent successfully, False otherwise.
    """
    alert_id = alert.get("alert_id", "unknown")

    # Serialize payload
    payload_bytes = json.dumps(alert, default=str, ensure_ascii=False).encode("utf-8")

    # Compute HMAC-SHA256 signature
    signature = hmac.new(
        secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-CyberNest-Signature": f"sha256={signature}",
        "X-CyberNest-Event": "alert",
        "X-CyberNest-Alert-ID": alert_id,
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                data=payload_bytes,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if 200 <= resp.status < 300:
                    logger.info(
                        "webhook notification sent",
                        alert_id=alert_id,
                        url=url,
                        status=resp.status,
                    )
                    return True
                else:
                    body = await resp.text()
                    logger.error(
                        "webhook notification failed",
                        alert_id=alert_id,
                        url=url,
                        status=resp.status,
                        response=body[:200],
                    )
                    return False
    except Exception as exc:
        logger.error(
            "webhook notification error",
            alert_id=alert_id,
            url=url,
            error=str(exc),
        )
        return False


# ---------------------------------------------------------------------------
# Dispatcher convenience
# ---------------------------------------------------------------------------

class NotificationDispatcher:
    """Routes alert notifications to configured channels based on severity."""

    def __init__(self, config: dict[str, Any]) -> None:
        """Initialize with notification channel configuration.

        Config format:
        {
            "slack": {"enabled": True, "webhook_url": "...", "min_severity": "medium"},
            "email": {"enabled": True, "smtp": {...}, "min_severity": "high"},
            "pagerduty": {"enabled": True, "api_key": "...", "min_severity": "critical"},
            "teams": {"enabled": True, "webhook_url": "...", "min_severity": "medium"},
            "webhooks": [
                {"enabled": True, "url": "...", "secret": "...", "min_severity": "low"},
            ],
        }
        """
        self._config = config

    _SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]

    def _meets_severity(self, alert_severity: str, min_severity: str) -> bool:
        alert_idx = self._SEVERITY_ORDER.index(alert_severity) if alert_severity in self._SEVERITY_ORDER else 0
        min_idx = self._SEVERITY_ORDER.index(min_severity) if min_severity in self._SEVERITY_ORDER else 0
        return alert_idx >= min_idx

    async def dispatch(self, alert: dict[str, Any]) -> dict[str, bool]:
        """Send notifications to all applicable channels.

        Returns dict of channel_name -> success boolean.
        """
        severity = str(alert.get("severity", "medium")).lower()
        results: dict[str, bool] = {}

        # Slack
        slack_cfg = self._config.get("slack", {})
        if slack_cfg.get("enabled") and self._meets_severity(
            severity, slack_cfg.get("min_severity", "medium")
        ):
            results["slack"] = await send_slack(alert, slack_cfg["webhook_url"])

        # Email
        email_cfg = self._config.get("email", {})
        if email_cfg.get("enabled") and self._meets_severity(
            severity, email_cfg.get("min_severity", "high")
        ):
            results["email"] = await send_email(alert, email_cfg.get("smtp", {}))

        # PagerDuty
        pd_cfg = self._config.get("pagerduty", {})
        if pd_cfg.get("enabled") and self._meets_severity(
            severity, pd_cfg.get("min_severity", "critical")
        ):
            results["pagerduty"] = await send_pagerduty(alert, pd_cfg["api_key"])

        # Teams
        teams_cfg = self._config.get("teams", {})
        if teams_cfg.get("enabled") and self._meets_severity(
            severity, teams_cfg.get("min_severity", "medium")
        ):
            results["teams"] = await send_teams(alert, teams_cfg["webhook_url"])

        # Generic webhooks
        for i, wh_cfg in enumerate(self._config.get("webhooks", [])):
            if wh_cfg.get("enabled") and self._meets_severity(
                severity, wh_cfg.get("min_severity", "low")
            ):
                result = await send_webhook(
                    alert, wh_cfg["url"], wh_cfg.get("secret", "")
                )
                results[f"webhook_{i}"] = result

        return results
