"""CyberNest Correlator — Time-window correlation engine using Redis sliding windows."""

import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class WindowRule:
    """Time-window correlation rule definition."""
    id: str
    name: str
    description: str
    severity: str
    level: int

    # Window config
    group_by: str          # Field to group by (e.g., "source.ip", "user.name")
    count_field: str       # Field to count (e.g., "destination.ip" for unique targets)
    count_distinct: bool   # Count distinct values vs total count
    threshold: int         # Trigger when count exceeds this
    window_seconds: int    # Sliding window duration

    # Filters
    event_filter: dict     # Must match these fields to be counted
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)


# ─── Built-in Window Rules ───

BUILTIN_WINDOW_RULES = [
    WindowRule(
        id="CN-WIN-001", name="Brute Force Login",
        description="Multiple failed logins from same source",
        severity="high", level=10,
        group_by="source.ip",
        count_field="user.name",
        count_distinct=False,
        threshold=5, window_seconds=60,
        event_filter={"event.action": "logon_failure"},
        mitre_techniques=["T1110"], mitre_tactics=["credential_access"],
    ),
    WindowRule(
        id="CN-WIN-002", name="Port Scanning Detected",
        description="Same source hitting many unique destination ports",
        severity="medium", level=6,
        group_by="source.ip",
        count_field="destination.port",
        count_distinct=True,
        threshold=20, window_seconds=30,
        event_filter={"event.category": "network"},
        mitre_techniques=["T1046"], mitre_tactics=["discovery"],
    ),
    WindowRule(
        id="CN-WIN-003", name="Horizontal Scanning (Host Sweep)",
        description="Same source contacting many unique internal hosts",
        severity="medium", level=7,
        group_by="source.ip",
        count_field="destination.ip",
        count_distinct=True,
        threshold=20, window_seconds=30,
        event_filter={"event.category": "network"},
        mitre_techniques=["T1046"], mitre_tactics=["discovery"],
    ),
    WindowRule(
        id="CN-WIN-004", name="Data Exfiltration Anomaly",
        description="Large outbound data volume to single external IP",
        severity="high", level=10,
        group_by="destination.ip",
        count_field="network.bytes_out",
        count_distinct=False,
        threshold=104857600,  # 100MB
        window_seconds=300,
        event_filter={"network.direction": "outbound"},
        mitre_techniques=["T1048"], mitre_tactics=["exfiltration"],
    ),
    WindowRule(
        id="CN-WIN-005", name="Lateral Movement",
        description="Same source accessing multiple internal hosts with authentication",
        severity="high", level=10,
        group_by="source.ip",
        count_field="destination.ip",
        count_distinct=True,
        threshold=3, window_seconds=300,
        event_filter={"event.category": "authentication", "event.outcome": "success"},
        mitre_techniques=["T1021"], mitre_tactics=["lateral_movement"],
    ),
    WindowRule(
        id="CN-WIN-006", name="Password Spray Attack",
        description="Multiple users failing login from same source",
        severity="high", level=11,
        group_by="source.ip",
        count_field="user.name",
        count_distinct=True,
        threshold=5, window_seconds=120,
        event_filter={"event.action": "logon_failure"},
        mitre_techniques=["T1110.003"], mitre_tactics=["credential_access"],
    ),
    WindowRule(
        id="CN-WIN-007", name="Rapid Process Creation",
        description="Many processes spawned from same parent in short time",
        severity="medium", level=7,
        group_by="process.parent.name",
        count_field="process.name",
        count_distinct=True,
        threshold=10, window_seconds=10,
        event_filter={"event.category": "process", "event.action": "process_created"},
        mitre_techniques=["T1059"], mitre_tactics=["execution"],
    ),
    WindowRule(
        id="CN-WIN-008", name="DNS Tunneling Suspected",
        description="High volume of DNS queries to same domain",
        severity="high", level=10,
        group_by="dns.question.name",
        count_field="source.ip",
        count_distinct=False,
        threshold=50, window_seconds=60,
        event_filter={"event.action": "dns_query"},
        mitre_techniques=["T1071.004"], mitre_tactics=["command_and_control"],
    ),
    WindowRule(
        id="CN-WIN-009", name="Multiple Account Lockouts",
        description="Several accounts locked out in short period",
        severity="high", level=9,
        group_by="source.ip",
        count_field="user.name",
        count_distinct=True,
        threshold=3, window_seconds=300,
        event_filter={"winlog.event_id": "4740"},
        mitre_techniques=["T1110"], mitre_tactics=["credential_access"],
    ),
    WindowRule(
        id="CN-WIN-010", name="Beaconing C2 Activity",
        description="Periodic connections to same destination at regular intervals",
        severity="critical", level=13,
        group_by="destination.ip",
        count_field="source.ip",
        count_distinct=False,
        threshold=30, window_seconds=600,
        event_filter={"event.category": "network"},
        mitre_techniques=["T1071"], mitre_tactics=["command_and_control"],
    ),
]


class WindowEngine:
    """Sliding window correlation engine backed by Redis."""

    def __init__(self, redis_client):
        self.redis = redis_client
        self.rules = list(BUILTIN_WINDOW_RULES)

    def add_rule(self, rule: WindowRule):
        self.rules.append(rule)

    async def process_event(self, event: dict) -> list[dict]:
        """Process an event against all window rules, return list of triggered alerts."""
        alerts = []

        for rule in self.rules:
            if not self._matches_filter(event, rule.event_filter):
                continue

            group_value = self._get_nested(event, rule.group_by)
            if not group_value:
                continue

            count_value = self._get_nested(event, rule.count_field)

            key = f"window:{rule.id}:{group_value}"
            now = time.time()

            try:
                if rule.count_distinct and count_value:
                    # Use sorted set for distinct values with timestamp as score
                    member = f"{count_value}"
                    await self.redis.zadd(key, {member: now})
                    # Remove expired entries
                    await self.redis.zremrangebyscore(key, 0, now - rule.window_seconds)
                    count = await self.redis.zcard(key)
                elif count_value and rule.count_field in ("network.bytes_out", "network.bytes_in"):
                    # Accumulate bytes
                    await self.redis.incrbyfloat(key, float(count_value))
                    await self.redis.expire(key, rule.window_seconds)
                    count = float(await self.redis.get(key) or 0)
                else:
                    # Simple counter with sorted set for windowing
                    await self.redis.zadd(key, {f"{now}:{count_value}": now})
                    await self.redis.zremrangebyscore(key, 0, now - rule.window_seconds)
                    count = await self.redis.zcard(key)

                await self.redis.expire(key, rule.window_seconds + 60)

                if count >= rule.threshold:
                    # Check if we already fired recently (dedup)
                    dedup_key = f"window:fired:{rule.id}:{group_value}"
                    already_fired = await self.redis.get(dedup_key)
                    if not already_fired:
                        await self.redis.setex(dedup_key, rule.window_seconds, "1")
                        alerts.append(self._create_alert(rule, event, group_value, count))
                        logger.info("Window rule triggered",
                                    rule=rule.id, group=group_value, count=count)

            except Exception as e:
                logger.error("Window engine error", rule=rule.id, error=str(e))

        return alerts

    def _matches_filter(self, event: dict, filters: dict) -> bool:
        for field, expected in filters.items():
            actual = self._get_nested(event, field)
            if actual is None:
                return False
            if str(actual).lower() != str(expected).lower():
                return False
        return True

    def _get_nested(self, data: dict, dotted_key: str) -> Any:
        keys = dotted_key.split(".")
        current = data
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
        return current

    def _create_alert(self, rule: WindowRule, event: dict, group_value: str, count: int) -> dict:
        return {
            "rule_id": rule.id,
            "rule_name": rule.name,
            "description": rule.description,
            "severity": rule.severity,
            "level": rule.level,
            "source_ip": self._get_nested(event, "source.ip"),
            "destination_ip": self._get_nested(event, "destination.ip"),
            "hostname": self._get_nested(event, "host.hostname"),
            "username": self._get_nested(event, "user.name"),
            "process_name": self._get_nested(event, "process.name"),
            "mitre_techniques": rule.mitre_techniques,
            "mitre_tactics": rule.mitre_tactics,
            "group_by_field": rule.group_by,
            "group_by_value": group_value,
            "event_count": count,
            "threshold": rule.threshold,
            "window_seconds": rule.window_seconds,
            "trigger_event": {
                "@timestamp": event.get("@timestamp"),
                "raw": event.get("raw", "")[:500],
            },
        }
