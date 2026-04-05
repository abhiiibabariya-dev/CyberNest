"""Detection engine - evaluates rules against incoming events."""

import yaml
import re
from pathlib import Path
from typing import Optional
from loguru import logger

from core.config import settings
from core.models import Severity


def load_rules_from_yaml() -> list[dict]:
    """Load all YAML detection rules from config/rules/."""
    rules = []
    rules_dir = settings.RULES_DIR
    if not rules_dir.exists():
        logger.warning(f"Rules directory not found: {rules_dir}")
        return rules

    for rule_file in rules_dir.glob("*.yml"):
        try:
            with open(rule_file) as f:
                docs = yaml.safe_load_all(f)
                for doc in docs:
                    if doc:
                        rules.append(doc)
        except Exception as e:
            logger.error(f"Failed to load rule {rule_file}: {e}")
    return rules


def evaluate_condition(event: dict, condition: dict) -> bool:
    """Evaluate a single rule condition against an event."""
    field = condition.get("field")
    operator = condition.get("operator", "equals")
    value = condition.get("value")

    if not field or value is None:
        return False

    event_value = event.get(field)
    if event_value is None:
        return False

    event_value = str(event_value).lower()
    value = str(value).lower()

    if operator == "equals":
        return event_value == value
    elif operator == "contains":
        return value in event_value
    elif operator == "regex":
        return bool(re.search(value, event_value))
    elif operator == "gt":
        try:
            return float(event_value) > float(value)
        except ValueError:
            return False
    elif operator == "lt":
        try:
            return float(event_value) < float(value)
        except ValueError:
            return False
    elif operator == "in":
        return event_value in [str(v).lower() for v in value] if isinstance(value, list) else False

    return False


def evaluate_rule(event: dict, rule: dict) -> Optional[dict]:
    """Evaluate a detection rule against an event. Returns alert data if triggered."""
    if not rule.get("enabled", True):
        return None

    conditions = rule.get("conditions", [])
    logic = rule.get("logic", "and")  # "and" or "or"

    if not conditions:
        return None

    results = [evaluate_condition(event, c) for c in conditions]

    triggered = all(results) if logic == "and" else any(results)

    if triggered:
        return {
            "rule_name": rule.get("name", "Unknown Rule"),
            "severity": rule.get("severity", "medium"),
            "title": rule.get("alert_title", f"Detection: {rule.get('name')}"),
            "description": rule.get("description", ""),
            "mitre_tactic": rule.get("mitre_tactic"),
            "mitre_technique": rule.get("mitre_technique"),
        }

    return None


def run_detection(event_data: dict) -> list[dict]:
    """Run all detection rules against a single event. Returns list of triggered alerts."""
    rules = load_rules_from_yaml()
    alerts = []

    for rule in rules:
        result = evaluate_rule(event_data, rule)
        if result:
            result["source_event"] = event_data
            alerts.append(result)
            logger.info(f"Rule triggered: {result['rule_name']} | Severity: {result['severity']}")

    return alerts
