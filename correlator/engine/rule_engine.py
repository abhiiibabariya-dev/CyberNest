"""
CyberNest YAML Detection Rule Engine.

Parses and executes CyberNest-format YAML detection rules against normalized
ECS events.  Supports field-level conditions with short-circuit evaluation,
threshold-based detection via Redis counters, and alert generation.

Rule YAML format:
    id: CN-WIN-AUTH-001
    name: Single Failed Login
    description: ...
    level: low|medium|high|critical|informational
    category: authentication|credential_access|...
    mitre_tactic: TA0006
    mitre_technique: [T1110]
    enabled: true
    conditions:
      logic: and|or
      fields:
        - field: event.outcome
          operator: equals
          value: failure
    threshold:           # optional
      field: user.name
      count: 5
      timeframe: 60      # seconds
"""

from __future__ import annotations

import ipaddress
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

import yaml

from shared.utils.logger import get_logger

logger = get_logger("correlator")

# ---------------------------------------------------------------------------
# Operator implementations
# ---------------------------------------------------------------------------

def _resolve_field(event: dict[str, Any], dotted_key: str) -> Any:
    """Resolve a dot-notated field path against a nested dict."""
    parts = dotted_key.split(".")
    current: Any = event
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
        if current is None:
            return None
    return current


def _to_str(val: Any) -> str:
    if val is None:
        return ""
    return str(val).lower()


def _op_equals(field_val: Any, rule_val: Any) -> bool:
    if field_val is None:
        return False
    return _to_str(field_val) == _to_str(rule_val)


def _op_not_equals(field_val: Any, rule_val: Any) -> bool:
    return not _op_equals(field_val, rule_val)


def _op_contains(field_val: Any, rule_val: Any) -> bool:
    if field_val is None:
        return False
    return _to_str(rule_val) in _to_str(field_val)


def _op_not_contains(field_val: Any, rule_val: Any) -> bool:
    return not _op_contains(field_val, rule_val)


def _op_startswith(field_val: Any, rule_val: Any) -> bool:
    if field_val is None:
        return False
    return _to_str(field_val).startswith(_to_str(rule_val))


def _op_endswith(field_val: Any, rule_val: Any) -> bool:
    if field_val is None:
        return False
    return _to_str(field_val).endswith(_to_str(rule_val))


def _op_regex(field_val: Any, rule_val: Any) -> bool:
    if field_val is None:
        return False
    try:
        return bool(re.search(str(rule_val), str(field_val), re.IGNORECASE))
    except re.error:
        return False


def _op_in(field_val: Any, rule_val: Any) -> bool:
    if field_val is None:
        return False
    if isinstance(rule_val, list):
        return _to_str(field_val) in [_to_str(v) for v in rule_val]
    return _op_equals(field_val, rule_val)


def _op_not_in(field_val: Any, rule_val: Any) -> bool:
    return not _op_in(field_val, rule_val)


def _op_exists(field_val: Any, _rule_val: Any) -> bool:
    return field_val is not None


def _op_not_exists(field_val: Any, _rule_val: Any) -> bool:
    return field_val is None


def _to_float(val: Any) -> Optional[float]:
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def _op_gt(field_val: Any, rule_val: Any) -> bool:
    a, b = _to_float(field_val), _to_float(rule_val)
    if a is None or b is None:
        return False
    return a > b


def _op_gte(field_val: Any, rule_val: Any) -> bool:
    a, b = _to_float(field_val), _to_float(rule_val)
    if a is None or b is None:
        return False
    return a >= b


def _op_lt(field_val: Any, rule_val: Any) -> bool:
    a, b = _to_float(field_val), _to_float(rule_val)
    if a is None or b is None:
        return False
    return a < b


def _op_lte(field_val: Any, rule_val: Any) -> bool:
    a, b = _to_float(field_val), _to_float(rule_val)
    if a is None or b is None:
        return False
    return a <= b


def _op_cidr(field_val: Any, rule_val: Any) -> bool:
    """Check if an IP address falls within a CIDR range."""
    if field_val is None:
        return False
    try:
        ip = ipaddress.ip_address(str(field_val))
        network = ipaddress.ip_network(str(rule_val), strict=False)
        return ip in network
    except (ValueError, TypeError):
        return False


OPERATORS: dict[str, Any] = {
    "equals": _op_equals,
    "not_equals": _op_not_equals,
    "contains": _op_contains,
    "not_contains": _op_not_contains,
    "startswith": _op_startswith,
    "endswith": _op_endswith,
    "regex": _op_regex,
    "in": _op_in,
    "not_in": _op_not_in,
    "exists": _op_exists,
    "not_exists": _op_not_exists,
    "gt": _op_gt,
    "gte": _op_gte,
    "lt": _op_lt,
    "lte": _op_lte,
    "cidr": _op_cidr,
}

# ---------------------------------------------------------------------------
# Severity -> risk score mapping
# ---------------------------------------------------------------------------

SEVERITY_SCORES: dict[str, float] = {
    "informational": 10.0,
    "low": 25.0,
    "medium": 50.0,
    "high": 75.0,
    "critical": 95.0,
}

# ---------------------------------------------------------------------------
# Rule data class
# ---------------------------------------------------------------------------

class DetectionRule:
    """Parsed detection rule ready for matching."""

    __slots__ = (
        "id", "name", "description", "level", "category",
        "mitre_tactic", "mitre_technique", "enabled",
        "logic", "fields", "threshold", "raw",
    )

    def __init__(self, data: dict[str, Any]) -> None:
        self.id: str = data["id"]
        self.name: str = data["name"]
        self.description: str = data.get("description", "")
        self.level: str = data.get("level", "medium")
        self.category: str = data.get("category", "unknown")
        self.mitre_tactic: str = data.get("mitre_tactic", "")
        self.mitre_technique: list[str] = data.get("mitre_technique", [])
        if isinstance(self.mitre_technique, str):
            self.mitre_technique = [self.mitre_technique]
        self.enabled: bool = data.get("enabled", True)

        conditions = data.get("conditions", {})
        self.logic: str = conditions.get("logic", "and")
        self.fields: list[dict[str, Any]] = conditions.get("fields", [])
        self.threshold: Optional[dict[str, Any]] = data.get("threshold")
        self.raw: dict[str, Any] = data

    def __repr__(self) -> str:
        return f"<DetectionRule {self.id}: {self.name}>"


# ---------------------------------------------------------------------------
# Rule Engine
# ---------------------------------------------------------------------------

class RuleEngine:
    """Load CyberNest YAML rules and match events against them."""

    def __init__(self, redis_client: Any = None) -> None:
        self._rules: list[DetectionRule] = []
        self._redis = redis_client

    @property
    def rules(self) -> list[DetectionRule]:
        return self._rules

    # -- Loading -----------------------------------------------------------

    def load_rules_from_directory(self, rules_dir: str) -> int:
        """Recursively load all .yml / .yaml rule files from *rules_dir*.

        Each YAML file may contain a single rule dict or a list of rule dicts
        under a top-level ``rules`` key.

        Returns the number of rules loaded.
        """
        rules_path = Path(rules_dir)
        if not rules_path.exists():
            logger.warning("rules directory does not exist", path=rules_dir)
            return 0

        count = 0
        for yml_path in sorted(rules_path.rglob("*.yml")):
            count += self._load_file(yml_path)
        for yml_path in sorted(rules_path.rglob("*.yaml")):
            count += self._load_file(yml_path)

        logger.info(
            "rules loaded",
            total=len(self._rules),
            new=count,
            directory=rules_dir,
        )
        return count

    def _load_file(self, path: Path) -> int:
        """Load rules from a single YAML file.  Returns count loaded."""
        count = 0
        try:
            with open(path, "r", encoding="utf-8") as fh:
                docs = list(yaml.safe_load_all(fh))

            for doc in docs:
                if doc is None:
                    continue
                if isinstance(doc, dict) and "rules" in doc:
                    for rule_data in doc["rules"]:
                        self._add_rule(rule_data, path)
                        count += 1
                elif isinstance(doc, dict) and "id" in doc:
                    self._add_rule(doc, path)
                    count += 1
                elif isinstance(doc, list):
                    for rule_data in doc:
                        if isinstance(rule_data, dict):
                            self._add_rule(rule_data, path)
                            count += 1
        except Exception:
            logger.exception("failed to load rule file", path=str(path))
        return count

    def _add_rule(self, data: dict[str, Any], path: Path) -> None:
        try:
            rule = DetectionRule(data)
            if rule.enabled:
                self._rules.append(rule)
                logger.debug("rule registered", rule_id=rule.id, name=rule.name)
            else:
                logger.debug("rule skipped (disabled)", rule_id=rule.id)
        except Exception:
            logger.exception("invalid rule definition", path=str(path), data=data)

    def load_rule_from_dict(self, data: dict[str, Any]) -> DetectionRule:
        """Load a single rule from a dict (useful for testing)."""
        rule = DetectionRule(data)
        if rule.enabled:
            self._rules.append(rule)
        return rule

    # -- Matching ----------------------------------------------------------

    def _flatten_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Flatten a nested event dict to dot-notation keys for field lookup."""
        flat: dict[str, Any] = {}

        def _walk(prefix: str, obj: Any) -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    new_key = f"{prefix}.{k}" if prefix else k
                    _walk(new_key, v)
                    # Also store parent dict reference
                    if prefix:
                        flat[prefix] = obj
            elif isinstance(obj, list):
                flat[prefix] = obj
            else:
                flat[prefix] = obj

        _walk("", event)
        return flat

    def _check_field_condition(
        self, flat_event: dict[str, Any], condition: dict[str, Any],
    ) -> bool:
        """Evaluate a single field condition against a flattened event."""
        field_path: str = condition.get("field", "")
        operator_name: str = condition.get("operator", "equals")
        rule_value: Any = condition.get("value")

        field_val = flat_event.get(field_path)
        # Also try resolving against the original nested structure if flat miss
        if field_val is None and "." in field_path:
            # The flat dict stores intermediate dicts too; just use the flat value
            pass

        op_func = OPERATORS.get(operator_name)
        if op_func is None:
            logger.warning("unknown operator", operator=operator_name, rule_field=field_path)
            return False

        return op_func(field_val, rule_value)

    def _conditions_match(
        self, rule: DetectionRule, flat_event: dict[str, Any],
    ) -> bool:
        """Check whether field conditions match with short-circuit logic."""
        if not rule.fields:
            return True  # No conditions = match everything (probably a threshold-only rule)

        if rule.logic == "and":
            for cond in rule.fields:
                if not self._check_field_condition(flat_event, cond):
                    return False  # short-circuit
            return True
        elif rule.logic == "or":
            for cond in rule.fields:
                if self._check_field_condition(flat_event, cond):
                    return True  # short-circuit
            return False
        else:
            logger.warning("unknown logic operator", logic=rule.logic, rule_id=rule.id)
            return False

    async def _check_threshold(
        self, rule: DetectionRule, flat_event: dict[str, Any],
    ) -> bool:
        """Check Redis-backed threshold counter.  Returns True if threshold exceeded."""
        if self._redis is None or rule.threshold is None:
            return True  # No threshold configured -> conditions alone are sufficient

        threshold_field: str = rule.threshold.get("field", "")
        threshold_count: int = int(rule.threshold.get("count", 1))
        timeframe: int = int(rule.threshold.get("timeframe", 60))

        # Build a unique counter key from the rule id and the grouping field value
        group_value = flat_event.get(threshold_field, "unknown")
        redis_key = f"cn:threshold:{rule.id}:{group_value}"

        now = datetime.now(timezone.utc).timestamp()
        pipe = self._redis.pipeline()
        # Sorted set: score = timestamp, member = unique event id
        event_id = flat_event.get("cybernest.event_id") or flat_event.get("event.id") or uuid4().hex
        pipe.zadd(redis_key, {f"{event_id}:{now}": now})
        pipe.zremrangebyscore(redis_key, "-inf", now - timeframe)
        pipe.zcard(redis_key)
        pipe.expire(redis_key, timeframe * 2)
        results = await pipe.execute()

        current_count: int = results[2]
        return current_count >= threshold_count

    async def match(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Match an event against all loaded rules.

        Returns a list of alert dicts for every rule that matched.
        """
        flat_event = self._flatten_event(event)
        alerts: list[dict[str, Any]] = []

        for rule in self._rules:
            if not self._conditions_match(rule, flat_event):
                continue

            # Threshold check (Redis-backed)
            if rule.threshold is not None:
                threshold_met = await self._check_threshold(rule, flat_event)
                if not threshold_met:
                    continue

            alert = self._build_alert(rule, event, flat_event)
            alerts.append(alert)

        return alerts

    def match_sync(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Synchronous match (skips threshold check). Useful for testing."""
        flat_event = self._flatten_event(event)
        alerts: list[dict[str, Any]] = []

        for rule in self._rules:
            if not self._conditions_match(rule, flat_event):
                continue
            # Skip threshold in sync mode
            if rule.threshold is not None and self._redis is None:
                # Allow match when no Redis and threshold present (testing)
                pass
            alert = self._build_alert(rule, event, flat_event)
            alerts.append(alert)

        return alerts

    # -- Alert building ----------------------------------------------------

    def _build_alert(
        self,
        rule: DetectionRule,
        event: dict[str, Any],
        flat_event: dict[str, Any],
    ) -> dict[str, Any]:
        """Construct an alert dict from a matched rule + event."""
        now = datetime.now(timezone.utc).isoformat()
        event_id = (
            flat_event.get("cybernest.event_id")
            or flat_event.get("event.id")
            or uuid4().hex
        )

        return {
            "alert_id": uuid4().hex,
            "rule_id": rule.id,
            "rule_name": rule.name,
            "severity": rule.level,
            "status": "new",
            "title": f"[{rule.id}] {rule.name}",
            "description": rule.description,
            "source_ip": flat_event.get("source.ip"),
            "destination_ip": flat_event.get("destination.ip"),
            "username": flat_event.get("user.name"),
            "hostname": flat_event.get("host.hostname") or flat_event.get("host.name"),
            "raw_log": flat_event.get("raw") or flat_event.get("message"),
            "parsed_event": event,
            "event_ids": [event_id],
            "event_count": 1,
            "mitre_tactic": rule.mitre_tactic,
            "mitre_technique": rule.mitre_technique,
            "risk_score": SEVERITY_SCORES.get(rule.level, 50.0),
            "category": rule.category,
            "created_at": now,
            "updated_at": now,
        }
