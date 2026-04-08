"""
CyberNest SOAR Playbook Engine.

Loads YAML playbook definitions, matches them to incoming alerts, renders
Jinja2 templates in step inputs, executes actions with timeout and retry
logic, and records full execution history in PostgreSQL.

Playbook YAML format:
    name: brute_force_response
    description: Respond to brute-force login alerts
    enabled: true
    trigger:
      rule_id: CN-AUTH-001
      severity: [high, critical]
      category: authentication
      schedule: null
    steps:
      - name: lookup_source_ip
        action: virustotal_lookup
        input:
          target: "{{ alert.source_ip }}"
          type: ip
        output: vt_result
        condition: "{{ alert.source_ip is not none }}"
        on_failure: continue
        retry_count: 2
        timeout: 30
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml
from jinja2 import BaseLoader, Environment, StrictUndefined, UndefinedError

from shared.utils.logger import get_logger

# Lazy import to avoid circular deps at module level
_action_registry: dict[str, Any] | None = None

logger = get_logger("soar_engine")

PLAYBOOK_DIR = os.environ.get(
    "SOAR_PLAYBOOK_DIR",
    str(Path(__file__).resolve().parent.parent / "config" / "playbooks"),
)


# ---------------------------------------------------------------------------
# Custom Jinja2 functions available in playbook templates
# ---------------------------------------------------------------------------

def _ip_in_range(ip: str, cidr: str) -> bool:
    """Check whether *ip* falls within the given CIDR range."""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return False


def _is_internal(ip: str) -> bool:
    """Return True if *ip* is in RFC 1918 / RFC 6598 private space."""
    try:
        return ipaddress.ip_address(ip).is_private
    except (ValueError, TypeError):
        return False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ago(seconds: int) -> datetime:
    from datetime import timedelta
    return datetime.now(timezone.utc) - timedelta(seconds=seconds)


def _build_jinja_env() -> Environment:
    """Create a Jinja2 environment with custom globals and filters."""
    env = Environment(
        loader=BaseLoader(),
        undefined=StrictUndefined,
        autoescape=False,
        keep_trailing_newline=True,
    )
    env.globals["ip_in_range"] = _ip_in_range
    env.globals["is_internal"] = _is_internal
    env.globals["now"] = _now
    env.globals["ago"] = _ago
    env.globals["true"] = True
    env.globals["false"] = False
    env.globals["none"] = None
    return env


# ---------------------------------------------------------------------------
# Playbook loader
# ---------------------------------------------------------------------------

class Playbook:
    """In-memory representation of a loaded YAML playbook."""

    __slots__ = (
        "name", "description", "enabled", "trigger", "steps", "file_path",
    )

    def __init__(self, data: dict[str, Any], file_path: str = "") -> None:
        self.name: str = data.get("name", "unnamed")
        self.description: str = data.get("description", "")
        self.enabled: bool = data.get("enabled", True)
        self.trigger: dict[str, Any] = data.get("trigger", {})
        self.steps: list[dict[str, Any]] = data.get("steps", [])
        self.file_path: str = file_path

    def __repr__(self) -> str:
        return f"<Playbook name={self.name!r} steps={len(self.steps)} enabled={self.enabled}>"


def load_playbooks(directory: str | None = None) -> list[Playbook]:
    """Load all YAML playbooks from *directory* (defaults to PLAYBOOK_DIR)."""
    directory = directory or PLAYBOOK_DIR
    playbooks: list[Playbook] = []
    playbook_dir = Path(directory)

    if not playbook_dir.is_dir():
        logger.warning("playbook directory not found", path=str(playbook_dir))
        return playbooks

    for yml_file in sorted(playbook_dir.glob("*.yml")):
        try:
            with open(yml_file, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if not isinstance(data, dict):
                logger.warning("invalid playbook file (not a dict)", path=str(yml_file))
                continue
            pb = Playbook(data, file_path=str(yml_file))
            if pb.enabled:
                playbooks.append(pb)
                logger.info(
                    "playbook loaded",
                    name=pb.name,
                    steps=len(pb.steps),
                    file=str(yml_file),
                )
            else:
                logger.debug("playbook skipped (disabled)", name=pb.name)
        except yaml.YAMLError as exc:
            logger.error("failed to parse playbook", path=str(yml_file), error=str(exc))
        except Exception as exc:
            logger.error("failed to load playbook", path=str(yml_file), error=str(exc))

    logger.info("playbooks loaded", total=len(playbooks))
    return playbooks


def load_playbooks_yaml(directory: str | None = None) -> list[Playbook]:
    """Alias for load_playbooks."""
    return load_playbooks(directory)


# ---------------------------------------------------------------------------
# Playbook trigger matching
# ---------------------------------------------------------------------------

def matches_trigger(playbook: Playbook, alert: dict[str, Any]) -> bool:
    """Return True if an alert matches the playbook trigger criteria."""
    trigger = playbook.trigger
    if not trigger:
        return False

    # Rule ID match
    trigger_rule = trigger.get("rule_id")
    if trigger_rule:
        alert_rule = alert.get("rule_id", "")
        if isinstance(trigger_rule, list):
            if not any(_rule_match(r, alert_rule) for r in trigger_rule):
                return False
        elif not _rule_match(trigger_rule, alert_rule):
            return False

    # Severity match
    trigger_severity = trigger.get("severity")
    if trigger_severity:
        alert_severity = (alert.get("severity") or "").lower()
        if isinstance(trigger_severity, str):
            trigger_severity = [trigger_severity]
        if alert_severity not in [s.lower() for s in trigger_severity]:
            return False

    # Category match
    trigger_category = trigger.get("category")
    if trigger_category:
        alert_category = (alert.get("category") or alert.get("mitre_tactic") or "").lower()
        if isinstance(trigger_category, str):
            trigger_category = [trigger_category]
        if alert_category not in [c.lower() for c in trigger_category]:
            return False

    # Keyword match (optional: match title or description)
    trigger_keyword = trigger.get("keyword")
    if trigger_keyword:
        text = f"{alert.get('title', '')} {alert.get('description', '')}".lower()
        if trigger_keyword.lower() not in text:
            return False

    return True


def _rule_match(pattern: str, rule_id: str) -> bool:
    """Match a rule_id, supporting glob-style trailing wildcard."""
    if pattern.endswith("*"):
        return rule_id.startswith(pattern[:-1])
    return pattern == rule_id


# ---------------------------------------------------------------------------
# Template rendering
# ---------------------------------------------------------------------------

def render_value(value: Any, jinja_env: Environment, template_context: dict[str, Any]) -> Any:
    """Recursively render Jinja2 templates in strings, dicts, and lists."""
    if isinstance(value, str) and "{{" in value:
        try:
            template = jinja_env.from_string(value)
            rendered = template.render(**template_context)
            return rendered
        except UndefinedError:
            return value
        except Exception as exc:
            logger.warning("template render error", template=value[:100], error=str(exc))
            return value
    elif isinstance(value, dict):
        return {k: render_value(v, jinja_env, template_context) for k, v in value.items()}
    elif isinstance(value, list):
        return [render_value(item, jinja_env, template_context) for item in value]
    return value


def evaluate_condition(
    condition: str | None,
    jinja_env: Environment,
    template_context: dict[str, Any],
) -> bool:
    """Evaluate a Jinja2 condition expression. Returns True if no condition."""
    if not condition:
        return True
    try:
        template = jinja_env.from_string(f"{{% if {condition} %}}true{{% else %}}false{{% endif %}}")
        result = template.render(**template_context).strip()
        return result == "true"
    except Exception as exc:
        logger.warning("condition evaluation error", condition=condition, error=str(exc))
        return False


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

def _get_action_registry() -> dict[str, Any]:
    """Lazy-load the action registry and all action modules."""
    global _action_registry
    if _action_registry is not None:
        return _action_registry

    # Import all action modules to trigger @register_action decorators
    import soar.actions.virustotal  # noqa: F401
    import soar.actions.abuseipdb  # noqa: F401
    import soar.actions.shodan_lookup  # noqa: F401
    import soar.actions.whois_lookup  # noqa: F401
    import soar.actions.firewall_block  # noqa: F401
    import soar.actions.ad_disable_user  # noqa: F401
    import soar.actions.isolate_endpoint  # noqa: F401
    import soar.actions.kill_process  # noqa: F401
    import soar.actions.slack_notify  # noqa: F401
    import soar.actions.email_notify  # noqa: F401
    import soar.actions.create_case  # noqa: F401
    import soar.actions.jira_ticket  # noqa: F401

    from soar.actions import ACTION_REGISTRY
    _action_registry = ACTION_REGISTRY
    logger.info("action registry loaded", actions=list(_action_registry.keys()))
    return _action_registry


class SOAREngine:
    """Core SOAR playbook execution engine."""

    def __init__(
        self,
        db_pool: Any = None,
        redis_client: Any = None,
        config: dict[str, Any] | None = None,
        playbook_dir: str | None = None,
    ) -> None:
        self.db_pool = db_pool
        self.redis_client = redis_client
        self.config: dict[str, Any] = config or {}
        self.playbooks: list[Playbook] = []
        self.jinja_env = _build_jinja_env()
        self._playbook_dir = playbook_dir
        self._action_registry = _get_action_registry()

    def load_playbooks(self) -> None:
        """Load all playbooks from disk."""
        self.playbooks = load_playbooks(self._playbook_dir)

    def reload_playbooks(self) -> None:
        """Reload playbooks (hot-reload support)."""
        self.load_playbooks()
        logger.info("playbooks reloaded", count=len(self.playbooks))

    def find_matching_playbooks(self, alert: dict[str, Any]) -> list[Playbook]:
        """Return all enabled playbooks whose trigger matches the alert."""
        return [pb for pb in self.playbooks if matches_trigger(pb, alert)]

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def run_playbook(
        self,
        playbook: Playbook,
        alert: dict[str, Any],
        triggered_by: str = "kafka_consumer",
    ) -> dict[str, Any]:
        """Execute a full playbook against an alert.

        Creates an execution record, iterates through steps, evaluates
        conditions, executes actions with timeout and retry, handles
        failures, and updates the execution record in the database.

        Returns:
            Execution summary dict with status, timing, and per-step results.
        """
        execution_id = uuid.uuid4().hex
        start_time = time.time()
        started_at = datetime.now(timezone.utc)

        logger.info(
            "playbook execution started",
            execution_id=execution_id,
            playbook=playbook.name,
            alert_id=alert.get("alert_id", ""),
            triggered_by=triggered_by,
        )

        # Execution context shared across all steps
        step_outputs: dict[str, Any] = {}
        step_results: list[dict[str, Any]] = []
        execution_status = "running"
        error_message: str | None = None

        # Create execution record in DB
        await self._create_execution_record(
            execution_id, playbook.name, alert, triggered_by, started_at,
        )

        # Build base template context
        base_context = {
            "alert": alert,
            "config": self.config,
            "execution_id": execution_id,
            "playbook_name": playbook.name,
            "db_pool": self.db_pool,
            "step_outputs": step_outputs,
        }

        try:
            for step_index, step in enumerate(playbook.steps):
                step_name = step.get("name", f"step_{step_index}")
                action_name = step.get("action", "")
                step_input = step.get("input", {})
                output_var = step.get("output", step_name)
                condition = step.get("condition")
                on_failure = step.get("on_failure", "continue")
                retry_count = int(step.get("retry_count", 0))
                timeout = int(step.get("timeout", 60))

                step_start = time.time()

                # Build template context with previous step outputs
                template_context = {
                    **base_context,
                    **step_outputs,
                }

                # Evaluate condition
                if condition:
                    should_run = evaluate_condition(condition, self.jinja_env, template_context)
                    if not should_run:
                        step_result = {
                            "step": step_name,
                            "action": action_name,
                            "status": "skipped",
                            "reason": "condition_false",
                            "condition": condition,
                            "duration_ms": 0,
                        }
                        step_results.append(step_result)
                        logger.info(
                            "step skipped (condition false)",
                            execution_id=execution_id,
                            step=step_name,
                            condition=condition,
                        )
                        continue

                # Render input templates
                rendered_input = render_value(step_input, self.jinja_env, template_context)

                # Find action class
                action_cls = self._action_registry.get(action_name)
                if action_cls is None:
                    step_result = {
                        "step": step_name,
                        "action": action_name,
                        "status": "error",
                        "error": f"Unknown action '{action_name}'",
                        "duration_ms": round((time.time() - step_start) * 1000),
                    }
                    step_results.append(step_result)
                    logger.error(
                        "unknown action",
                        execution_id=execution_id,
                        step=step_name,
                        action=action_name,
                    )
                    if on_failure == "abort":
                        execution_status = "failed"
                        error_message = f"Unknown action '{action_name}' in step '{step_name}'"
                        break
                    continue

                # Execute with retry and timeout
                action_instance = action_cls()
                result: dict[str, Any] | None = None
                last_error: str | None = None

                for attempt in range(max(retry_count + 1, 1)):
                    try:
                        result = await asyncio.wait_for(
                            action_instance.execute(rendered_input, base_context),
                            timeout=timeout,
                        )
                        if result.get("success"):
                            break
                        last_error = result.get("error", "Action returned failure")
                        if attempt < retry_count:
                            logger.warning(
                                "step failed, retrying",
                                execution_id=execution_id,
                                step=step_name,
                                attempt=attempt + 1,
                                max_retries=retry_count,
                                error=last_error,
                            )
                            await asyncio.sleep(min(2 ** attempt, 10))
                    except asyncio.TimeoutError:
                        last_error = f"Action timed out after {timeout}s"
                        result = {"success": False, "output": {}, "error": last_error}
                        if attempt < retry_count:
                            logger.warning(
                                "step timed out, retrying",
                                execution_id=execution_id,
                                step=step_name,
                                attempt=attempt + 1,
                            )
                            await asyncio.sleep(min(2 ** attempt, 10))
                    except Exception as exc:
                        last_error = f"Unexpected error: {exc}"
                        result = {"success": False, "output": {}, "error": last_error}
                        logger.error(
                            "step exception",
                            execution_id=execution_id,
                            step=step_name,
                            error=str(exc),
                            traceback=traceback.format_exc(),
                        )
                        if attempt < retry_count:
                            await asyncio.sleep(min(2 ** attempt, 10))

                duration_ms = round((time.time() - step_start) * 1000)

                # Store output for downstream steps
                if result and output_var:
                    step_outputs[output_var] = result

                step_result = {
                    "step": step_name,
                    "action": action_name,
                    "status": "success" if (result and result.get("success")) else "failed",
                    "output": result.get("output", {}) if result else {},
                    "error": result.get("error") if result else last_error,
                    "duration_ms": duration_ms,
                    "retries": max(0, retry_count),
                }
                step_results.append(step_result)

                if result and result.get("success"):
                    logger.info(
                        "step completed",
                        execution_id=execution_id,
                        step=step_name,
                        action=action_name,
                        duration_ms=duration_ms,
                    )
                else:
                    logger.warning(
                        "step failed",
                        execution_id=execution_id,
                        step=step_name,
                        action=action_name,
                        error=last_error,
                        duration_ms=duration_ms,
                    )

                    if on_failure == "abort":
                        execution_status = "failed"
                        error_message = f"Step '{step_name}' failed: {last_error}"
                        break
                    # on_failure == "continue" or "retry" (retries already handled above)

            if execution_status == "running":
                execution_status = "completed"

        except Exception as exc:
            execution_status = "error"
            error_message = f"Engine error: {exc}"
            logger.error(
                "playbook execution error",
                execution_id=execution_id,
                playbook=playbook.name,
                error=str(exc),
                traceback=traceback.format_exc(),
            )

        total_duration_ms = round((time.time() - start_time) * 1000)
        finished_at = datetime.now(timezone.utc)

        execution_summary = {
            "execution_id": execution_id,
            "playbook": playbook.name,
            "alert_id": alert.get("alert_id", ""),
            "status": execution_status,
            "triggered_by": triggered_by,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_ms": total_duration_ms,
            "steps_total": len(playbook.steps),
            "steps_executed": len(step_results),
            "steps_succeeded": sum(1 for s in step_results if s["status"] == "success"),
            "steps_failed": sum(1 for s in step_results if s["status"] == "failed"),
            "steps_skipped": sum(1 for s in step_results if s["status"] == "skipped"),
            "error": error_message,
            "step_results": step_results,
        }

        # Update execution record in DB
        await self._update_execution_record(
            execution_id, execution_status, finished_at,
            total_duration_ms, step_results, error_message,
        )

        logger.info(
            "playbook execution finished",
            execution_id=execution_id,
            playbook=playbook.name,
            status=execution_status,
            duration_ms=total_duration_ms,
            succeeded=execution_summary["steps_succeeded"],
            failed=execution_summary["steps_failed"],
            skipped=execution_summary["steps_skipped"],
        )

        return execution_summary

    # ------------------------------------------------------------------
    # Database helpers
    # ------------------------------------------------------------------

    async def _create_execution_record(
        self,
        execution_id: str,
        playbook_name: str,
        alert: dict[str, Any],
        triggered_by: str,
        started_at: datetime,
    ) -> None:
        """Insert initial playbook execution record."""
        if self.db_pool is None:
            return
        try:
            async with self.db_pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO playbook_executions
                        (execution_id, playbook_name, alert_id, rule_id,
                         triggered_by, status, started_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    """,
                    execution_id,
                    playbook_name,
                    alert.get("alert_id", ""),
                    alert.get("rule_id", ""),
                    triggered_by,
                    "running",
                    started_at,
                )
        except Exception as exc:
            logger.error(
                "failed to create execution record",
                execution_id=execution_id,
                error=str(exc),
            )

    async def _update_execution_record(
        self,
        execution_id: str,
        status: str,
        finished_at: datetime,
        duration_ms: int,
        step_results: list[dict[str, Any]],
        error_message: str | None,
    ) -> None:
        """Update completed playbook execution record."""
        if self.db_pool is None:
            return
        try:
            import json
            async with self.db_pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE playbook_executions
                    SET status = $2,
                        finished_at = $3,
                        duration_ms = $4,
                        step_results = $5::jsonb,
                        error_message = $6,
                        steps_total = $7,
                        steps_succeeded = $8,
                        steps_failed = $9,
                        steps_skipped = $10
                    WHERE execution_id = $1
                    """,
                    execution_id,
                    status,
                    finished_at,
                    duration_ms,
                    json.dumps(step_results),
                    error_message,
                    len(step_results),
                    sum(1 for s in step_results if s["status"] == "success"),
                    sum(1 for s in step_results if s["status"] == "failed"),
                    sum(1 for s in step_results if s["status"] == "skipped"),
                )
        except Exception as exc:
            logger.error(
                "failed to update execution record",
                execution_id=execution_id,
                error=str(exc),
            )

    async def ensure_schema(self) -> None:
        """Create the playbook_executions table if it does not exist."""
        if self.db_pool is None:
            return
        try:
            async with self.db_pool.acquire() as conn:
                await conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS playbook_executions (
                        execution_id    VARCHAR(64) PRIMARY KEY,
                        playbook_name   VARCHAR(255) NOT NULL,
                        alert_id        VARCHAR(64),
                        rule_id         VARCHAR(64),
                        triggered_by    VARCHAR(64),
                        status          VARCHAR(32) NOT NULL DEFAULT 'pending',
                        started_at      TIMESTAMPTZ,
                        finished_at     TIMESTAMPTZ,
                        duration_ms     INTEGER,
                        steps_total     INTEGER DEFAULT 0,
                        steps_succeeded INTEGER DEFAULT 0,
                        steps_failed    INTEGER DEFAULT 0,
                        steps_skipped   INTEGER DEFAULT 0,
                        step_results    JSONB,
                        error_message   TEXT,
                        created_at      TIMESTAMPTZ DEFAULT NOW()
                    );

                    CREATE INDEX IF NOT EXISTS idx_pe_playbook ON playbook_executions(playbook_name);
                    CREATE INDEX IF NOT EXISTS idx_pe_alert    ON playbook_executions(alert_id);
                    CREATE INDEX IF NOT EXISTS idx_pe_status   ON playbook_executions(status);
                    CREATE INDEX IF NOT EXISTS idx_pe_started  ON playbook_executions(started_at);

                    CREATE TABLE IF NOT EXISTS firewall_blocks (
                        id              SERIAL PRIMARY KEY,
                        ip_address      VARCHAR(45) UNIQUE NOT NULL,
                        duration_seconds INTEGER NOT NULL,
                        reason          TEXT,
                        status          VARCHAR(32) DEFAULT 'pending',
                        created_by      VARCHAR(64),
                        created_at      TIMESTAMPTZ DEFAULT NOW(),
                        updated_at      TIMESTAMPTZ DEFAULT NOW()
                    );

                    CREATE TABLE IF NOT EXISTS cases (
                        case_id         VARCHAR(64) PRIMARY KEY,
                        title           TEXT NOT NULL,
                        description     TEXT,
                        severity        VARCHAR(32),
                        status          VARCHAR(32) DEFAULT 'open',
                        assignee        VARCHAR(255),
                        tags            TEXT[],
                        source          VARCHAR(64),
                        playbook        VARCHAR(255),
                        execution_id    VARCHAR(64),
                        alert_ids       TEXT[],
                        evidence        TEXT,
                        source_ip       VARCHAR(45),
                        hostname        VARCHAR(255),
                        username        VARCHAR(255),
                        rule_id         VARCHAR(64),
                        rule_name       VARCHAR(255),
                        created_at      TIMESTAMPTZ DEFAULT NOW(),
                        updated_at      TIMESTAMPTZ DEFAULT NOW()
                    );
                    """
                )
            logger.info("database schema ensured")
        except Exception as exc:
            logger.error("schema creation failed", error=str(exc))
