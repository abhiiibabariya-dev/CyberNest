"""
CyberNest Alert Deduplicator.

Redis-based alert deduplication using a composite key of rule_id + source_ip +
username with a 5-minute TTL window. Duplicate alerts increment a counter on
the original alert rather than creating new entries.
"""

from __future__ import annotations

import hashlib
from typing import Any, Optional

import redis.asyncio as redis

from shared.utils.logger import get_logger

logger = get_logger("alert_manager")

# Dedup key TTL in seconds
DEDUP_TTL_SECONDS = 300  # 5 minutes
DEDUP_KEY_PREFIX = "cybernest:dedup:"


class AlertDeduplicator:
    """Redis-backed alert deduplication engine."""

    def __init__(self, redis_client: redis.Redis) -> None:
        self._redis = redis_client

    @staticmethod
    def _compute_dedup_key(alert_data: dict[str, Any]) -> str:
        """Compute the deduplication key from alert fields.

        Key = MD5(rule_id + source_ip + username)
        This groups alerts that share the same detection rule, source, and user
        within the TTL window.
        """
        rule_id = str(alert_data.get("rule_id", ""))
        source_ip = str(alert_data.get("source_ip", ""))
        username = str(alert_data.get("username", ""))
        composite = f"{rule_id}|{source_ip}|{username}"
        digest = hashlib.md5(composite.encode("utf-8")).hexdigest()
        return f"{DEDUP_KEY_PREFIX}{digest}"

    async def check_and_set(
        self, alert_data: dict[str, Any]
    ) -> tuple[bool, Optional[str], int]:
        """Check if an alert is a duplicate and handle accordingly.

        Returns:
            Tuple of (is_new, existing_alert_id, occurrence_count).
            - is_new=True: alert is new, proceed with full processing.
            - is_new=False: alert is a duplicate, counter incremented.
        """
        dedup_key = self._compute_dedup_key(alert_data)
        alert_id = alert_data.get("alert_id", "")

        try:
            # Try to set the key only if it doesn't exist (NX)
            existing = await self._redis.get(dedup_key)

            if existing is None:
                # New alert — store its ID and set TTL
                pipe = self._redis.pipeline(transaction=True)
                pipe.hset(dedup_key, mapping={
                    "alert_id": alert_id,
                    "count": "1",
                })
                pipe.expire(dedup_key, DEDUP_TTL_SECONDS)
                await pipe.execute()

                logger.debug(
                    "new alert registered in dedup cache",
                    alert_id=alert_id,
                    dedup_key=dedup_key,
                )
                return True, None, 1

            else:
                # Duplicate — increment counter and return existing alert ID
                pipe = self._redis.pipeline(transaction=True)
                pipe.hincrby(dedup_key, "count", 1)
                pipe.hget(dedup_key, "alert_id")
                pipe.hget(dedup_key, "count")
                # Refresh TTL on activity
                pipe.expire(dedup_key, DEDUP_TTL_SECONDS)
                results = await pipe.execute()

                existing_alert_id = results[1]
                if isinstance(existing_alert_id, bytes):
                    existing_alert_id = existing_alert_id.decode("utf-8")

                count_raw = results[2]
                count = int(count_raw) if count_raw else 1

                logger.info(
                    "duplicate alert suppressed",
                    alert_id=alert_id,
                    existing_alert_id=existing_alert_id,
                    occurrence_count=count,
                    dedup_key=dedup_key,
                )
                return False, existing_alert_id, count

        except redis.RedisError as exc:
            # On Redis failure, allow the alert through to avoid dropping alerts
            logger.error(
                "redis dedup check failed, allowing alert through",
                alert_id=alert_id,
                error=str(exc),
            )
            return True, None, 1

    async def get_occurrence_count(self, alert_data: dict[str, Any]) -> int:
        """Get the current occurrence count for a dedup key."""
        dedup_key = self._compute_dedup_key(alert_data)
        try:
            count_raw = await self._redis.hget(dedup_key, "count")
            if count_raw is None:
                return 0
            return int(count_raw)
        except redis.RedisError:
            return 0

    async def clear_key(self, alert_data: dict[str, Any]) -> None:
        """Manually clear a dedup key (e.g., when an alert is resolved)."""
        dedup_key = self._compute_dedup_key(alert_data)
        try:
            await self._redis.delete(dedup_key)
        except redis.RedisError as exc:
            logger.warning("failed to clear dedup key", error=str(exc))
