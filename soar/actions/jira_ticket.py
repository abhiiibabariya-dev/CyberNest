"""
CyberNest SOAR Action -- Create Jira Ticket.

Creates a new issue in Jira Cloud or Server via the REST API v3
using Basic authentication (email + API token for Cloud).
"""

from __future__ import annotations

import base64
import os
import re
from typing import Any

import aiohttp

from soar.actions import BaseAction, register_action


JIRA_URL = os.environ.get("JIRA_URL", "")
JIRA_USER = os.environ.get("JIRA_USER", "")
JIRA_API_TOKEN = os.environ.get("JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY = os.environ.get("JIRA_PROJECT_KEY", "SEC")


def _render_template(template: str, variables: dict[str, Any]) -> str:
    """Replace {{variable}} placeholders with context values."""
    def _resolve(match: re.Match) -> str:
        path = match.group(1).strip()
        parts = path.split(".")
        value: Any = variables
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part, "")
            else:
                value = getattr(value, part, "")
        return str(value) if value is not None else ""

    return re.sub(r"\{\{(.+?)\}\}", _resolve, template)


def _basic_auth_header(user: str, token: str) -> str:
    """Build a Basic authentication header value."""
    credentials = f"{user}:{token}"
    encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"


@register_action
class CreateJiraTicket(BaseAction):
    """Create a Jira issue linked to a CyberNest alert."""

    name = "create_jira_ticket"
    description = (
        "Create a new Jira issue (task/bug/story) via the REST API v3. "
        "Supports Basic auth and template variable substitution."
    )

    async def execute(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        config = context.get("config", {})
        alert = context.get("alert", {})

        jira_url: str = params.get("jira_url") or config.get("jira_url") or JIRA_URL
        jira_user: str = params.get("jira_user") or config.get("jira_user") or JIRA_USER
        jira_token: str = params.get("jira_api_token") or config.get("jira_api_token") or JIRA_API_TOKEN
        project_key: str = params.get("project_key") or config.get("jira_project_key") or JIRA_PROJECT_KEY

        summary: str = params.get("summary", "") or f"[CyberNest] {alert.get('title', 'Security Alert')}"
        description_text: str = params.get("description", "")
        issue_type: str = params.get("issue_type", "Task")
        priority: str = params.get("priority", "")
        labels: list[str] = params.get("labels", ["cybernest", "soar"])
        assignee: str = params.get("assignee", "")
        components: list[str] = params.get("components", [])

        if not jira_url:
            return self.result(False, error="Jira URL not configured")
        if not jira_user or not jira_token:
            return self.result(False, error="Jira credentials not configured")
        if not project_key:
            return self.result(False, error="Jira project key not configured")

        # Template rendering context
        template_vars = {
            "alert": alert,
            "playbook": context.get("playbook_name", ""),
            "execution_id": context.get("execution_id", ""),
            **context.get("step_outputs", {}),
        }

        rendered_summary = _render_template(summary, template_vars)[:255]

        # Build Atlassian Document Format (ADF) description
        if not description_text:
            description_text = self._build_description(alert, context)
        else:
            description_text = _render_template(description_text, template_vars)

        # Map severity to Jira priority
        if not priority:
            severity_priority = {
                "critical": "Highest",
                "high": "High",
                "medium": "Medium",
                "low": "Low",
                "informational": "Lowest",
            }
            priority = severity_priority.get(alert.get("severity", "medium"), "Medium")

        # Build the issue payload (Jira REST API v3 with ADF)
        issue_payload: dict[str, Any] = {
            "fields": {
                "project": {"key": project_key},
                "summary": rendered_summary,
                "issuetype": {"name": issue_type},
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {"type": "text", "text": description_text},
                            ],
                        },
                    ],
                },
                "priority": {"name": priority},
                "labels": labels,
            },
        }

        if assignee:
            issue_payload["fields"]["assignee"] = {"accountId": assignee}
        if components:
            issue_payload["fields"]["components"] = [{"name": c} for c in components]

        url = f"{jira_url.rstrip('/')}/rest/api/3/issue"
        headers = {
            "Authorization": _basic_auth_header(jira_user, jira_token),
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=issue_payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    body = await resp.json()

                    if resp.status in (200, 201):
                        issue_key = body.get("key", "")
                        issue_id = body.get("id", "")
                        issue_url = f"{jira_url.rstrip('/')}/browse/{issue_key}"

                        return self.result(
                            True,
                            output={
                                "issue_key": issue_key,
                                "issue_id": issue_id,
                                "issue_url": issue_url,
                                "project": project_key,
                                "summary": rendered_summary,
                                "priority": priority,
                                "message": f"Jira ticket {issue_key} created",
                            },
                        )

                    errors = body.get("errors", {})
                    error_messages = body.get("errorMessages", [])
                    error_detail = "; ".join(error_messages) if error_messages else str(errors)
                    return self.result(
                        False,
                        error=f"Jira API error HTTP {resp.status}: {error_detail}",
                    )

        except aiohttp.ClientError as exc:
            return self.result(False, error=f"Jira request failed: {exc}")
        except Exception as exc:
            return self.result(False, error=f"Unexpected error: {exc}")

    @staticmethod
    def _build_description(alert: dict[str, Any], context: dict[str, Any]) -> str:
        """Build a default issue description from alert data."""
        lines = [
            "CyberNest SOAR Automated Ticket",
            "",
            f"Alert ID: {alert.get('alert_id', 'N/A')}",
            f"Rule: {alert.get('rule_name', 'N/A')} ({alert.get('rule_id', '')})",
            f"Severity: {alert.get('severity', 'N/A')}",
            f"Source IP: {alert.get('source_ip', 'N/A')}",
            f"Destination IP: {alert.get('destination_ip', 'N/A')}",
            f"Hostname: {alert.get('hostname', 'N/A')}",
            f"Username: {alert.get('username', 'N/A')}",
            "",
            f"Description: {alert.get('description', 'N/A')}",
            "",
            f"MITRE Tactic: {alert.get('mitre_tactic', 'N/A')}",
            f"MITRE Techniques: {', '.join(alert.get('mitre_technique', []))}",
            f"Risk Score: {alert.get('risk_score', 'N/A')}",
            "",
            f"Playbook: {context.get('playbook_name', 'N/A')}",
            f"Execution ID: {context.get('execution_id', 'N/A')}",
        ]

        # Add step output summaries
        step_outputs = context.get("step_outputs", {})
        if step_outputs:
            lines.append("")
            lines.append("--- Playbook Step Results ---")
            for step_name, output in step_outputs.items():
                if isinstance(output, dict):
                    status = "OK" if output.get("success") else "FAILED"
                    msg = output.get("output", {}).get("message", output.get("error", ""))
                    lines.append(f"  {step_name}: [{status}] {msg}")

        return "\n".join(lines)
