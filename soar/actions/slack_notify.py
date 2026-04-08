"""
CyberNest SOAR Action -- Slack Notification.

Sends a formatted notification to a Slack channel via an incoming webhook.
Supports Jinja2 template variable substitution in the message body.
"""

from __future__ import annotations

import os
import re
from typing import Any

import aiohttp

from soar.actions import BaseAction, register_action


SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")


def _render_template(template: str, variables: dict[str, Any]) -> str:
    """Replace {{variable}} placeholders with values from the context.

    Supports dotted paths like {{alert.source_ip}} by walking the dict tree.
    """
    def _resolve(match: re.Match) -> str:
        path = match.group(1).strip()
        parts = path.split(".")
        value: Any = variables
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part, "")
            else:
                value = getattr(value, part, "")
        if value is None:
            return ""
        return str(value)

    return re.sub(r"\{\{(.+?)\}\}", _resolve, template)


@register_action
class SlackNotify(BaseAction):
    """Send a notification to Slack via incoming webhook."""

    name = "slack_notify"
    description = (
        "Send a formatted notification to a Slack channel using an incoming "
        "webhook. Supports {{template}} variable substitution."
    )

    async def execute(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        webhook_url: str = (
            params.get("webhook_url")
            or context.get("config", {}).get("slack_webhook_url")
            or SLACK_WEBHOOK_URL
        )
        channel: str = params.get("channel", "")
        message: str = params.get("message", "")
        title: str = params.get("title", "CyberNest SOAR Alert")
        severity: str = params.get("severity", "medium")
        mention: str = params.get("mention", "")  # e.g. "@here", "@channel", "<@U12345>"

        if not webhook_url:
            return self.result(False, error="Slack webhook URL not configured")
        if not message:
            return self.result(False, error="Missing required parameter 'message'")

        # Build template context from alert data and step outputs
        template_vars = {
            "alert": context.get("alert", {}),
            "playbook": context.get("playbook_name", ""),
            "execution_id": context.get("execution_id", ""),
            **context.get("step_outputs", {}),
        }

        rendered_message = _render_template(message, template_vars)
        rendered_title = _render_template(title, template_vars)

        # Map severity to Slack color
        severity_colors = {
            "critical": "#FF0000",
            "high": "#FF6600",
            "medium": "#FFAA00",
            "low": "#00AA00",
            "informational": "#0066FF",
        }
        color = severity_colors.get(severity.lower(), "#CCCCCC")

        # Build Slack Block Kit payload
        blocks = []
        if mention:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": mention},
            })

        blocks.append({
            "type": "header",
            "text": {"type": "plain_text", "text": rendered_title[:150], "emoji": True},
        })

        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": rendered_message[:3000]},
        })

        # Add alert metadata fields
        alert = context.get("alert", {})
        fields = []
        if alert.get("rule_name"):
            fields.append({"type": "mrkdwn", "text": f"*Rule:*\n{alert['rule_name']}"})
        if alert.get("severity"):
            fields.append({"type": "mrkdwn", "text": f"*Severity:*\n{alert['severity']}"})
        if alert.get("source_ip"):
            fields.append({"type": "mrkdwn", "text": f"*Source IP:*\n{alert['source_ip']}"})
        if alert.get("hostname"):
            fields.append({"type": "mrkdwn", "text": f"*Host:*\n{alert['hostname']}"})

        if fields:
            blocks.append({"type": "section", "fields": fields[:10]})

        blocks.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"Playbook: *{context.get('playbook_name', 'N/A')}* | Execution: {context.get('execution_id', 'N/A')[:12]}"},
            ],
        })

        payload: dict[str, Any] = {
            "blocks": blocks,
            "attachments": [{"color": color, "blocks": []}],
        }
        if channel:
            payload["channel"] = channel

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    body = await resp.text()
                    if resp.status == 200 and body == "ok":
                        return self.result(
                            True,
                            output={
                                "channel": channel or "webhook-default",
                                "message_preview": rendered_message[:200],
                                "message": "Slack notification sent successfully",
                            },
                        )
                    return self.result(
                        False,
                        error=f"Slack API error HTTP {resp.status}: {body[:500]}",
                    )
        except Exception as exc:
            return self.result(False, error=f"Slack request failed: {exc}")
