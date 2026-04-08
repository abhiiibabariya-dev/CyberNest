"""
CyberNest SOAR Action -- Create Case.

Creates a new investigation case either by calling the CyberNest internal
REST API or by inserting directly into the PostgreSQL database.
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Any

import aiohttp

from soar.actions import BaseAction, register_action


CYBERNEST_API_URL = os.environ.get("CYBERNEST_API_URL", "http://localhost:8000")
CYBERNEST_API_KEY = os.environ.get("CYBERNEST_API_KEY", "")


@register_action
class CreateCase(BaseAction):
    """Create an investigation case in CyberNest."""

    name = "create_case"
    description = (
        "Create a new investigation case via the CyberNest internal API "
        "or by direct database insert. Links the case to the triggering alert."
    )

    async def execute(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        config = context.get("config", {})
        alert = context.get("alert", {})

        title: str = params.get("title", "") or f"[SOAR] {alert.get('title', 'Automated Case')}"
        description: str = params.get("description", "") or alert.get("description", "")
        severity: str = params.get("severity", "") or alert.get("severity", "medium")
        assignee: str = params.get("assignee", "")
        tags: list[str] = params.get("tags", [])
        alert_id: str = params.get("alert_id", "") or alert.get("alert_id", "")

        api_url = params.get("api_url") or config.get("cybernest_api_url") or CYBERNEST_API_URL
        api_key = params.get("api_key") or config.get("cybernest_api_key") or CYBERNEST_API_KEY

        # Gather evidence from previous step outputs
        step_outputs = context.get("step_outputs", {})
        evidence: list[dict[str, Any]] = []
        for step_name, output in step_outputs.items():
            if isinstance(output, dict) and output.get("success"):
                evidence.append({
                    "step": step_name,
                    "data": output.get("output", {}),
                })

        case_payload = {
            "title": title,
            "description": description,
            "severity": severity,
            "status": "open",
            "assignee": assignee,
            "alert_ids": [alert_id] if alert_id else [],
            "tags": tags or self._auto_tags(alert),
            "source": "soar_engine",
            "playbook": context.get("playbook_name", ""),
            "execution_id": context.get("execution_id", ""),
            "evidence": evidence,
            "source_ip": alert.get("source_ip"),
            "hostname": alert.get("hostname"),
            "username": alert.get("username"),
            "rule_id": alert.get("rule_id"),
            "rule_name": alert.get("rule_name"),
            "mitre_tactic": alert.get("mitre_tactic"),
            "mitre_techniques": alert.get("mitre_technique", []),
        }

        # Try API first, fall back to direct DB insert
        result = await self._create_via_api(api_url, api_key, case_payload)
        if result is not None:
            return result

        # Fallback: direct database insert
        return await self._create_via_db(case_payload, context)

    async def _create_via_api(
        self, api_url: str, api_key: str, payload: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Attempt to create a case via the REST API."""
        url = f"{api_url.rstrip('/')}/api/v1/cases"
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status in (200, 201):
                        data = await resp.json()
                        case_id = data.get("case_id") or data.get("id") or ""
                        return self.result(
                            True,
                            output={
                                "case_id": case_id,
                                "title": payload["title"],
                                "severity": payload["severity"],
                                "status": "open",
                                "method": "api",
                                "message": f"Case '{case_id}' created via API",
                            },
                        )
                    # API not available or errored -- fall through to DB
                    return None
        except Exception:
            return None

    async def _create_via_db(
        self, payload: dict[str, Any], context: dict[str, Any],
    ) -> dict[str, Any]:
        """Create a case directly in the database."""
        db_pool = context.get("db_pool")
        case_id = uuid.uuid4().hex

        if db_pool is not None:
            try:
                async with db_pool.acquire() as conn:
                    await conn.execute(
                        """
                        INSERT INTO cases
                            (case_id, title, description, severity, status,
                             assignee, tags, source, playbook, execution_id,
                             alert_ids, evidence, source_ip, hostname, username,
                             rule_id, rule_name, created_at)
                        VALUES
                            ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                             $11, $12, $13, $14, $15, $16, $17, NOW())
                        """,
                        case_id,
                        payload["title"],
                        payload["description"],
                        payload["severity"],
                        "open",
                        payload.get("assignee", ""),
                        payload.get("tags", []),
                        "soar_engine",
                        payload.get("playbook", ""),
                        payload.get("execution_id", ""),
                        payload.get("alert_ids", []),
                        str(payload.get("evidence", [])),
                        payload.get("source_ip"),
                        payload.get("hostname"),
                        payload.get("username"),
                        payload.get("rule_id"),
                        payload.get("rule_name"),
                    )
            except Exception as exc:
                return self.result(False, error=f"Database insert failed: {exc}")

            return self.result(
                True,
                output={
                    "case_id": case_id,
                    "title": payload["title"],
                    "severity": payload["severity"],
                    "status": "open",
                    "method": "database",
                    "message": f"Case '{case_id}' created via direct DB insert",
                },
            )

        # No DB pool available -- return case_id anyway for logging
        return self.result(
            True,
            output={
                "case_id": case_id,
                "title": payload["title"],
                "severity": payload["severity"],
                "status": "pending",
                "method": "none",
                "message": "Case ID generated but no backend was available to persist it",
            },
        )

    @staticmethod
    def _auto_tags(alert: dict[str, Any]) -> list[str]:
        """Generate automatic tags from alert data."""
        tags = ["soar-generated"]
        if alert.get("severity"):
            tags.append(f"severity:{alert['severity']}")
        if alert.get("mitre_tactic"):
            tags.append(f"mitre:{alert['mitre_tactic']}")
        if alert.get("rule_id"):
            tags.append(f"rule:{alert['rule_id']}")
        return tags
