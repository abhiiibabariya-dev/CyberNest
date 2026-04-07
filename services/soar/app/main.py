"""
CyberNest SOAR Engine — Consumes playbook execution requests from Kafka,
executes action steps sequentially, reports results back to PostgreSQL.
"""

import asyncio
import os
import time
import uuid
from datetime import datetime, timezone

import orjson
import structlog
import redis.asyncio as redis_lib
from aiokafka import AIOKafkaConsumer
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import text

from app.actions.registry import ActionRegistry

logger = structlog.get_logger()

KAFKA_SERVERS = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
CONSUMER_GROUP = os.environ.get("KAFKA_CONSUMER_GROUP", "soar-group")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
POSTGRES_URL = (
    f"postgresql+asyncpg://{os.environ.get('POSTGRES_USER', 'cybernest')}"
    f":{os.environ.get('POSTGRES_PASSWORD', 'cybernest_secret')}"
    f"@{os.environ.get('POSTGRES_HOST', 'localhost')}"
    f":{os.environ.get('POSTGRES_PORT', '5432')}"
    f"/{os.environ.get('POSTGRES_DB', 'cybernest')}"
)

INPUT_TOPIC = "cybernest.soar.actions"


async def execute_playbook(run_data: dict, registry: ActionRegistry, session_factory) -> dict:
    """Execute a playbook: run each step, collect results."""
    run_id = run_data.get("run_id")
    steps = run_data.get("steps", [])
    input_data = run_data.get("input_data", {})
    dry_run = run_data.get("dry_run", False)

    context = dict(input_data or {})
    # Add alert data to context
    context["alert"] = run_data

    step_results = []
    status = "completed"
    error_msg = None
    start_time = time.monotonic()

    for i, step in enumerate(steps):
        step_name = step.get("name", f"Step {i+1}")
        action_name = step.get("action", "")
        step_input = step.get("input", "")
        condition = step.get("condition", "")
        output_var = step.get("output", "")

        # Template variable substitution
        step_input = _render_template(step_input, context)
        condition = _render_template(condition, context) if condition else ""

        # Condition check
        if condition and not _evaluate_condition(condition, context):
            step_results.append({
                "step": step_name,
                "action": action_name,
                "status": "skipped",
                "reason": f"Condition not met: {condition}",
            })
            continue

        # Execute action
        try:
            if dry_run:
                result = {"status": "dry_run", "message": f"Would execute {action_name}({step_input})"}
            else:
                result = await registry.execute(action_name, step_input, context)

            step_results.append({
                "step": step_name,
                "action": action_name,
                "status": "success",
                "result": result,
                "duration_ms": round((time.monotonic() - start_time) * 1000),
            })

            # Store output for next steps
            if output_var and isinstance(result, dict):
                context[output_var] = result

        except Exception as e:
            step_results.append({
                "step": step_name,
                "action": action_name,
                "status": "failed",
                "error": str(e),
            })

            on_failure = step.get("on_failure", "continue")
            if on_failure == "abort":
                status = "failed"
                error_msg = f"Step '{step_name}' failed: {str(e)}"
                break

    duration_ms = round((time.monotonic() - start_time) * 1000)

    # Update DB
    async with session_factory() as session:
        await session.execute(text("""
            UPDATE soar.playbook_runs
            SET status = :status,
                step_results = :step_results,
                error_message = :error_msg,
                completed_at = :completed_at,
                duration_ms = :duration_ms
            WHERE id = :run_id
        """), {
            "run_id": run_id,
            "status": status,
            "step_results": orjson.dumps(step_results).decode(),
            "error_msg": error_msg,
            "completed_at": datetime.now(timezone.utc),
            "duration_ms": duration_ms,
        })
        await session.commit()

    logger.info("Playbook execution completed",
                run_id=run_id, status=status, steps=len(step_results), duration_ms=duration_ms)
    return {"status": status, "step_results": step_results}


def _render_template(template, context: dict) -> str:
    """Replace {{variable}} placeholders with context values."""
    if not isinstance(template, str):
        return str(template)
    import re
    def replacer(match):
        key = match.group(1).strip()
        parts = key.split(".")
        value = context
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part, "")
            else:
                return match.group(0)
        return str(value)
    return re.sub(r"\{\{(.+?)\}\}", replacer, template)


def _evaluate_condition(condition: str, context: dict) -> bool:
    """Evaluate a simple condition string like '{{vt_result.malicious}} > 0'."""
    rendered = _render_template(condition, context)
    try:
        parts = rendered.split()
        if len(parts) == 3:
            left, op, right = parts
            left = float(left) if left.replace(".", "").isdigit() else left
            right = float(right) if right.replace(".", "").isdigit() else right
            if op == ">":
                return left > right
            elif op == "<":
                return left < right
            elif op == ">=":
                return left >= right
            elif op == "==":
                return str(left) == str(right)
            elif op == "!=":
                return str(left) != str(right)
        return bool(rendered and rendered.lower() not in ("false", "0", "none", ""))
    except Exception:
        return True  # Default to executing step if condition evaluation fails


async def run():
    logger.info("Starting CyberNest SOAR Engine")

    engine = create_async_engine(POSTGRES_URL, pool_size=10)
    Session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    registry = ActionRegistry()

    consumer = AIOKafkaConsumer(
        INPUT_TOPIC,
        bootstrap_servers=KAFKA_SERVERS,
        group_id=CONSUMER_GROUP,
        value_deserializer=lambda v: orjson.loads(v),
        auto_offset_reset="latest",
        enable_auto_commit=True,
    )
    await consumer.start()
    logger.info("SOAR consumer started")

    try:
        async for msg in consumer:
            try:
                run_data = msg.value
                if not run_data:
                    continue
                logger.info("Executing playbook",
                            run_id=run_data.get("run_id"),
                            playbook=run_data.get("playbook_name"))
                await execute_playbook(run_data, registry, Session)
            except Exception as e:
                logger.error("SOAR execution error", error=str(e))

    except asyncio.CancelledError:
        logger.info("SOAR Engine shutting down")
    finally:
        await consumer.stop()
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(run())
