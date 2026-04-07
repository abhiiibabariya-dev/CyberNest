"""CyberNest — Notification dispatcher for alerts (Slack, Email, PagerDuty, Teams, Webhook)."""

import os
from email.mime.text import MIMEText

import httpx
import structlog

logger = structlog.get_logger()


class NotificationDispatcher:
    """Dispatches alert notifications to configured channels."""

    def __init__(self):
        self.slack_webhook = os.environ.get("SLACK_WEBHOOK_URL", "")
        self.teams_webhook = os.environ.get("TEAMS_WEBHOOK_URL", "")
        self.pagerduty_key = os.environ.get("PAGERDUTY_API_KEY", "")
        self.smtp_host = os.environ.get("SMTP_HOST", "")
        self.smtp_port = int(os.environ.get("SMTP_PORT", "587"))
        self.smtp_user = os.environ.get("SMTP_USER", "")
        self.smtp_password = os.environ.get("SMTP_PASSWORD", "")
        self.email_recipients = os.environ.get("ALERT_EMAIL_RECIPIENTS", "").split(",")

    async def dispatch(self, alert: dict):
        """Send alert to all configured notification channels."""
        tasks = []

        if self.slack_webhook:
            tasks.append(self._send_slack(alert))
        if self.teams_webhook:
            tasks.append(self._send_teams(alert))
        if self.pagerduty_key:
            tasks.append(self._send_pagerduty(alert))
        if self.smtp_host and any(self.email_recipients):
            tasks.append(self._send_email(alert))

        if not tasks:
            logger.debug("No notification channels configured")
            return

        import asyncio
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error("Notification failed", error=str(result))

    async def _send_slack(self, alert: dict):
        severity = alert.get("severity", "medium").upper()
        emoji = {"CRITICAL": ":rotating_light:", "HIGH": ":warning:", "MEDIUM": ":large_yellow_circle:", "LOW": ":information_source:"}.get(severity, ":bell:")

        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"{emoji} CyberNest Alert: {alert.get('title', '')}"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Severity:* {severity}"},
                        {"type": "mrkdwn", "text": f"*Rule:* {alert.get('rule_name', 'N/A')}"},
                        {"type": "mrkdwn", "text": f"*Source IP:* {alert.get('source_ip', 'N/A')}"},
                        {"type": "mrkdwn", "text": f"*Host:* {alert.get('hostname', 'N/A')}"},
                        {"type": "mrkdwn", "text": f"*User:* {alert.get('username', 'N/A')}"},
                        {"type": "mrkdwn", "text": f"*MITRE:* {', '.join(alert.get('mitre_techniques', []))}"},
                    ]
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"```{alert.get('description', '')}```"}
                }
            ]
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(self.slack_webhook, json=payload, timeout=10)
            resp.raise_for_status()
            logger.info("Slack notification sent", alert_title=alert.get("title"))

    async def _send_teams(self, alert: dict):
        severity = alert.get("severity", "medium").upper()
        color = {"CRITICAL": "FF0000", "HIGH": "FF8C00", "MEDIUM": "FFD700", "LOW": "0078D7"}.get(severity, "808080")

        payload = {
            "@type": "MessageCard",
            "themeColor": color,
            "summary": f"CyberNest Alert: {alert.get('title', '')}",
            "sections": [{
                "activityTitle": f"CyberNest Alert — {severity}",
                "facts": [
                    {"name": "Title", "value": alert.get("title", "")},
                    {"name": "Rule", "value": alert.get("rule_name", "N/A")},
                    {"name": "Source IP", "value": alert.get("source_ip", "N/A")},
                    {"name": "Host", "value": alert.get("hostname", "N/A")},
                    {"name": "User", "value": alert.get("username", "N/A")},
                    {"name": "MITRE", "value": ", ".join(alert.get("mitre_techniques", []))},
                ],
                "text": alert.get("description", ""),
            }]
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(self.teams_webhook, json=payload, timeout=10)
            resp.raise_for_status()
            logger.info("Teams notification sent", alert_title=alert.get("title"))

    async def _send_pagerduty(self, alert: dict):
        severity_map = {"critical": "critical", "high": "error", "medium": "warning", "low": "info"}
        payload = {
            "routing_key": self.pagerduty_key,
            "event_action": "trigger",
            "payload": {
                "summary": alert.get("title", "CyberNest Alert"),
                "source": alert.get("hostname", "cybernest"),
                "severity": severity_map.get(alert.get("severity", "medium"), "warning"),
                "custom_details": {
                    "rule_id": alert.get("rule_id"),
                    "source_ip": alert.get("source_ip"),
                    "username": alert.get("username"),
                    "mitre": alert.get("mitre_techniques"),
                },
            }
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload, timeout=10,
            )
            resp.raise_for_status()
            logger.info("PagerDuty notification sent", alert_title=alert.get("title"))

    async def _send_email(self, alert: dict):
        try:
            import aiosmtplib

            severity = alert.get("severity", "medium").upper()
            subject = f"[CyberNest {severity}] {alert.get('title', 'Alert')}"
            body = (
                f"CyberNest Security Alert\n"
                f"{'=' * 50}\n\n"
                f"Title: {alert.get('title', '')}\n"
                f"Severity: {severity}\n"
                f"Rule: {alert.get('rule_name', 'N/A')}\n"
                f"Source IP: {alert.get('source_ip', 'N/A')}\n"
                f"Hostname: {alert.get('hostname', 'N/A')}\n"
                f"User: {alert.get('username', 'N/A')}\n"
                f"MITRE: {', '.join(alert.get('mitre_techniques', []))}\n\n"
                f"Description:\n{alert.get('description', '')}\n\n"
                f"Raw Log (truncated):\n{alert.get('raw_log', '')[:500]}\n"
            )

            message = MIMEText(body)
            message["Subject"] = subject
            message["From"] = self.smtp_user
            message["To"] = ", ".join(r for r in self.email_recipients if r)

            await aiosmtplib.send(
                message,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_user,
                password=self.smtp_password,
                use_tls=True,
            )
            logger.info("Email notification sent", alert_title=alert.get("title"))
        except Exception as e:
            logger.error("Email send failed", error=str(e))
