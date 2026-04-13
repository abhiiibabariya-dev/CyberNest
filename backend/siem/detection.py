"""Detection engine — rules cached at startup, not reloaded per event."""
import yaml, re, threading
from pathlib import Path
from typing import Optional
from loguru import logger
from core.config import settings

_rules_cache: list[dict] = []
_rules_lock = threading.Lock()
_rules_loaded = False

def load_rules() -> list[dict]:
    global _rules_cache, _rules_loaded
    rules = []
    rules_dir = settings.RULES_DIR
    if not rules_dir.exists():
        logger.error(f"Rules directory not found: {rules_dir}")
        return rules
    for rule_file in sorted(rules_dir.glob("*.yml")):
        try:
            with open(rule_file) as f:
                for doc in yaml.safe_load_all(f):
                    if doc and isinstance(doc, dict):
                        doc["_source_file"] = rule_file.name
                        rules.append(doc)
        except Exception as e:
            logger.error(f"Failed to load rule {rule_file}: {e}")
    logger.info(f"Detection engine: loaded {len(rules)} rules from {rules_dir}")
    with _rules_lock:
        _rules_cache = rules
        _rules_loaded = True
    return rules

def get_rules() -> list[dict]:
    global _rules_loaded
    if not _rules_loaded:
        load_rules()
    return _rules_cache

def reload_rules() -> int:
    global _rules_loaded
    _rules_loaded = False
    return len(load_rules())

def evaluate_condition(event: dict, condition: dict) -> bool:
    field = condition.get("field")
    operator = condition.get("operator", "equals")
    value = condition.get("value")
    if not field or value is None:
        return False
    event_value = event.get(field)
    if event_value is None:
        return False
    ev = str(event_value).lower()
    vv = str(value).lower()
    if operator == "equals":       return ev == vv
    if operator == "contains":     return vv in ev
    if operator == "not_contains": return vv not in ev
    if operator == "startswith":   return ev.startswith(vv)
    if operator == "endswith":     return ev.endswith(vv)
    if operator == "regex":
        try: return bool(re.search(vv, ev, re.IGNORECASE))
        except: return False
    if operator == "gt":
        try: return float(ev) > float(vv)
        except: return False
    if operator == "lt":
        try: return float(ev) < float(vv)
        except: return False
    if operator == "in":
        vals = value if isinstance(value, list) else [value]
        return ev in [str(v).lower() for v in vals]
    return False

def evaluate_rule(event: dict, rule: dict) -> Optional[dict]:
    if not rule.get("enabled", True):
        return None
    conditions = rule.get("conditions", [])
    logic = rule.get("logic", "and").lower()
    if not conditions:
        return None
    results = [evaluate_condition(event, c) for c in conditions]
    if not (all(results) if logic == "and" else any(results)):
        return None
    return {
        "rule_name": rule.get("name", "Unknown"),
        "severity":  rule.get("severity", "medium"),
        "title":     rule.get("alert_title", f"Detection: {rule.get('name')}"),
        "description": rule.get("description", ""),
        "mitre_tactic":    rule.get("mitre_tactic"),
        "mitre_technique": rule.get("mitre_technique"),
        "source_file":     rule.get("_source_file", ""),
    }

def run_detection(event_data: dict) -> list[dict]:
    alerts = []
    for rule in get_rules():
        result = evaluate_rule(event_data, rule)
        if result:
            result["source_event"] = event_data
            alerts.append(result)
            logger.info(f"[DETECTION] {result[\'rule_name\']} | {result[\'severity\']} | src={event_data.get(\'src_ip\',\'N/A\')}")
    return alerts
