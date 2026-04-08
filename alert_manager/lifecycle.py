"""
CyberNest Alert Lifecycle Manager.

Handles automated alert lifecycle operations:
- Auto-escalation of stale critical alerts (>15 min still NEW)
- Auto-case creation for critical severity alerts
- SLA tracking (acknowledged_at, resolved_at, time_to_detect, TTR)
- Alert aging (alerts >7 days still NEW get escalated)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import uuid4

import asyncpg

from shared.utils.logger import get_logger

logger = get_logger("alert_manager")

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

AUTO_ESCALATE_MINUTES = 15
ALERT_AGING_DAYS = 7


class AlertLifecycleManager:
    """Manages alert state transitions, SLA tracking, and auto-escalation."""

    def __init__(
        self,
        pg_pool: asyncpg.Pool,
        notify_callback: Optional[Any] = None,
    ) -> None:
        """Initialize the lifecycle manager.

        Args:
            pg_pool: PostgreSQL connection pool.
            notify_callback: Optional async callable(alert_dict, reason) for
                             sending notifications on lifecycle events.
        """
        self._pg_pool = pg_pool
        self._notify_callback = notify_callback

    # -----------------------------------------------------------------
    # SLA Tracking
    # -----------------------------------------------------------------

    @staticmethod
    def track_sla(alert_data: dict[str, Any]) -> dict[str, Any]:
        """Calculate SLA metrics on an alert and add them to the dict.

        - time_to_detect = alert.created_at - event.timestamp
        - time_to_acknowledge = acknowledged_at - created_at
        - time_to_resolve = resolved_at - created_at
        """
        now = datetime.now(timezone.utc)

        # Time to detect
        event_timestamp = None
        parsed_event = alert_data.get("parsed_event") or {}
        ts_raw = parsed_event.get("@timestamp") or parsed_event.get("timestamp")
        if ts_raw:
            if isinstance(ts_raw, str):
                try:
                    event_timestamp = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    pass
            elif isinstance(ts_raw, datetime):
                event_timestamp = ts_raw

        created_at = alert_data.get("created_at")
        if isinstance(created_at, str):
            try:
                created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                created_at = now
        elif not isinstance(created_at, datetime):
            created_at = now

        if event_timestamp and created_at:
            ttd = (created_at - event_timestamp).total_seconds()
            alert_data["time_to_detect_seconds"] = max(0.0, ttd)

        # Time to acknowledge
        ack_at = alert_data.get("acknowledged_at")
        if ack_at:
            if isinstance(ack_at, str):
                try:
                    ack_at = datetime.fromisoformat(ack_at.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    ack_at = None
            if isinstance(ack_at, datetime):
                tta = (ack_at - created_at).total_seconds()
                alert_data["time_to_acknowledge_seconds"] = max(0.0, tta)

        # Time to resolve
        resolved_at = alert_data.get("resolved_at")
        if resolved_at:
            if isinstance(resolved_at, str):
                try:
                    resolved_at = datetime.fromisoformat(resolved_at.replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    resolved_at = None
            if isinstance(resolved_at, datetime):
                ttr = (resolved_at - created_at).total_seconds()
                alert_data["time_to_resolve_seconds"] = max(0.0, ttr)

        return alert_data

    # -----------------------------------------------------------------
    # Status transitions with SLA recording
    # -----------------------------------------------------------------

    async def update_status(
        self,
        alert_id: str,
        new_status: str,
        updated_by: str = "system",
    ) -> Optional[dict[str, Any]]:
        """Update alert status and record SLA timestamps.

        On first transition from NEW: record acknowledged_at.
        On RESOLVED or CLOSED: record resolved_at.

        Returns updated alert dict or None if not found.
        """
        now = datetime.now(timezone.utc)

        try:
            async with self._pg_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM alerts WHERE alert_id = $1", alert_id
                )
                if not row:
                    logger.warning("alert not found for status update", alert_id=alert_id)
                    return None

                old_status = row["status"]
                updates: dict[str, Any] = {
                    "status": new_status,
                    "updated_at": now,
                }

                # First status change from NEW -> record acknowledged_at
                if old_status == "new" and new_status != "new" and not row.get("acknowledged_at"):
                    updates["acknowledged_at"] = now

                # Resolution
                if new_status in ("resolved", "closed") and not row.get("resolved_at"):
                    updates["resolved_at"] = now

                set_clauses = ", ".join(
                    f"{k} = ${i + 2}" for i, k in enumerate(updates.keys())
                )
                values = [alert_id] + list(updates.values())

                await conn.execute(
                    f"UPDATE alerts SET {set_clauses} WHERE alert_id = $1",
                    *values,
                )

                logger.info(
                    "alert status updated",
                    alert_id=alert_id,
                    old_status=old_status,
                    new_status=new_status,
                    updated_by=updated_by,
                )

                # Return updated alert data
                updated_row = await conn.fetchrow(
                    "SELECT * FROM alerts WHERE alert_id = $1", alert_id
                )
                return dict(updated_row) if updated_row else None

        except Exception as exc:
            logger.error(
                "failed to update alert status",
                alert_id=alert_id,
                error=str(exc),
            )
            return None

    # -----------------------------------------------------------------
    # Auto-escalation: Critical alerts still NEW after 15 minutes
    # -----------------------------------------------------------------

    async def check_auto_escalation(self) -> list[str]:
        """Find and escalate critical alerts that are still NEW after the threshold.

        Returns list of escalated alert IDs.
        """
        threshold = datetime.now(timezone.utc) - timedelta(minutes=AUTO_ESCALATE_MINUTES)
        escalated: list[str] = []

        try:
            async with self._pg_pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT alert_id, title, severity, rule_name,
                           source_ip, username, created_at
                    FROM alerts
                    WHERE severity = 'critical'
                      AND status = 'new'
                      AND created_at <= $1
                    """,
                    threshold,
                )

                for row in rows:
                    alert_id = row["alert_id"]

                    # Update status to escalated (acknowledged)
                    now = datetime.now(timezone.utc)
                    await conn.execute(
                        """
                        UPDATE alerts
                        SET status = 'acknowledged',
                            acknowledged_at = $2,
                            updated_at = $2,
                            comments = comments || $3::jsonb
                        WHERE alert_id = $1
                        """,
                        alert_id,
                        now,
                        json_comment(
                            "system",
                            f"Auto-escalated: critical alert was still NEW after "
                            f"{AUTO_ESCALATE_MINUTES} minutes.",
                        ),
                    )

                    escalated.append(alert_id)

                    logger.warning(
                        "auto-escalated critical alert",
                        alert_id=alert_id,
                        title=row["title"],
                        age_minutes=AUTO_ESCALATE_MINUTES,
                    )

                    # Notify SOC lead
                    if self._notify_callback:
                        alert_dict = dict(row)
                        alert_dict["status"] = "acknowledged"
                        try:
                            await self._notify_callback(
                                alert_dict,
                                f"Auto-escalated: critical alert NEW for >{AUTO_ESCALATE_MINUTES}min",
                            )
                        except Exception as exc:
                            logger.error(
                                "escalation notification failed",
                                alert_id=alert_id,
                                error=str(exc),
                            )

        except Exception as exc:
            logger.error("auto-escalation check failed", error=str(exc))

        return escalated

    # -----------------------------------------------------------------
    # Auto-case creation for critical alerts
    # -----------------------------------------------------------------

    async def auto_create_case(self, alert_data: dict[str, Any]) -> Optional[str]:
        """Automatically create a case for critical severity alerts.

        Returns the new case_id or None if not applicable.
        """
        severity = str(alert_data.get("severity", "")).lower()
        if severity != "critical":
            return None

        alert_id = alert_data.get("alert_id", "")
        case_id = uuid4().hex

        try:
            async with self._pg_pool.acquire() as conn:
                # Check if a case already exists for this alert
                existing = await conn.fetchval(
                    "SELECT incident_id FROM alerts WHERE alert_id = $1",
                    alert_id,
                )
                if existing:
                    logger.debug(
                        "case already exists for alert",
                        alert_id=alert_id,
                        case_id=existing,
                    )
                    return existing

                now = datetime.now(timezone.utc)

                # Create the case
                await conn.execute(
                    """
                    INSERT INTO cases (
                        case_id, title, description, severity, status,
                        created_at, updated_at, alert_ids
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    ON CONFLICT (case_id) DO NOTHING
                    """,
                    case_id,
                    f"[Auto] {alert_data.get('title', 'Critical Alert')}",
                    f"Automatically created case for critical alert {alert_id}. "
                    f"Rule: {alert_data.get('rule_name', 'Unknown')}. "
                    f"Source: {alert_data.get('source_ip', 'N/A')}.",
                    "critical",
                    "open",
                    now,
                    now,
                    [alert_id],
                )

                # Link alert to case
                await conn.execute(
                    """
                    UPDATE alerts
                    SET incident_id = $2, updated_at = $3,
                        comments = comments || $4::jsonb
                    WHERE alert_id = $1
                    """,
                    alert_id,
                    case_id,
                    now,
                    json_comment(
                        "system",
                        f"Auto-created case {case_id} for critical alert.",
                    ),
                )

                logger.info(
                    "auto-created case for critical alert",
                    alert_id=alert_id,
                    case_id=case_id,
                )
                return case_id

        except Exception as exc:
            logger.error(
                "auto-case creation failed",
                alert_id=alert_id,
                error=str(exc),
            )
            return None

    # -----------------------------------------------------------------
    # Alert aging: alerts >7 days still NEW -> escalate
    # -----------------------------------------------------------------

    async def check_alert_aging(self) -> list[str]:
        """Find and escalate alerts that have been NEW for more than 7 days.

        Returns list of escalated alert IDs.
        """
        threshold = datetime.now(timezone.utc) - timedelta(days=ALERT_AGING_DAYS)
        escalated: list[str] = []

        try:
            async with self._pg_pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT alert_id, title, severity, rule_name, created_at
                    FROM alerts
                    WHERE status = 'new'
                      AND created_at <= $1
                    """,
                    threshold,
                )

                now = datetime.now(timezone.utc)
                for row in rows:
                    alert_id = row["alert_id"]

                    await conn.execute(
                        """
                        UPDATE alerts
                        SET status = 'acknowledged',
                            acknowledged_at = $2,
                            updated_at = $2,
                            comments = comments || $3::jsonb
                        WHERE alert_id = $1
                        """,
                        alert_id,
                        now,
                        json_comment(
                            "system",
                            f"Auto-escalated: alert was NEW for >{ALERT_AGING_DAYS} days.",
                        ),
                    )

                    escalated.append(alert_id)

                    age_days = (now - row["created_at"].replace(tzinfo=timezone.utc)).days
                    logger.warning(
                        "aged alert escalated",
                        alert_id=alert_id,
                        title=row["title"],
                        severity=row["severity"],
                        age_days=age_days,
                    )

                    if self._notify_callback:
                        alert_dict = dict(row)
                        alert_dict["status"] = "acknowledged"
                        try:
                            await self._notify_callback(
                                alert_dict,
                                f"Alert aging: NEW for >{age_days} days",
                            )
                        except Exception as exc:
                            logger.error(
                                "aging notification failed",
                                alert_id=alert_id,
                                error=str(exc),
                            )

        except Exception as exc:
            logger.error("alert aging check failed", error=str(exc))

        return escalated

    # -----------------------------------------------------------------
    # Periodic lifecycle runner
    # -----------------------------------------------------------------

    async def run_lifecycle_checks(self) -> dict[str, list[str]]:
        """Run all periodic lifecycle checks.

        Returns dict with results from each check.
        """
        results: dict[str, list[str]] = {}

        escalated = await self.check_auto_escalation()
        if escalated:
            results["auto_escalated"] = escalated

        aged = await self.check_alert_aging()
        if aged:
            results["aged_escalated"] = aged

        return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def json_comment(author: str, text: str) -> str:
    """Create a JSON-encoded comment object for PostgreSQL JSONB append."""
    import json
    comment = [{
        "author": author,
        "text": text,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }]
    return json.dumps(comment)
