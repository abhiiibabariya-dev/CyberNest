"""CyberNest Correlator — Rule evaluation engine with Sigma + CyberNest YAML rules."""

import re
import yaml
import os
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class CompiledRule:
    """Pre-compiled detection rule for fast evaluation."""

    def __init__(self, rule_data: dict, source_file: str = ""):
        self.id: str = rule_data.get("id", "")
        self.name: str = rule_data.get("name", "")
        self.description: str = rule_data.get("description", "")
        self.severity: str = rule_data.get("severity", "medium")
        self.level: int = rule_data.get("level", 5)
        self.enabled: bool = rule_data.get("enabled", True)
        self.rule_type: str = rule_data.get("type", "threshold")
        self.conditions: list = rule_data.get("conditions", [])
        self.logic: str = rule_data.get("logic", "and").lower()
        self.mitre_tactics: list = rule_data.get("mitre_tactics", [])
        self.mitre_techniques: list = rule_data.get("mitre_techniques", [])
        self.group: str = rule_data.get("group", "")
        self.tags: list = rule_data.get("tags", [])
        self.false_positives: list = rule_data.get("false_positives", [])
        self.source_file: str = source_file

        # Pre-compile regex conditions
        self._compiled_conditions = []
        for cond in self.conditions:
            compiled = dict(cond)
            if cond.get("operator") == "regex":
                try:
                    compiled["_regex"] = re.compile(cond["value"], re.IGNORECASE)
                except re.error:
                    logger.warning("Invalid regex in rule", rule=self.id, pattern=cond["value"])
            self._compiled_conditions.append(compiled)

    def evaluate(self, event: dict) -> bool:
        """Evaluate this rule against an ECS-normalized event."""
        if not self.enabled:
            return False

        results = [self._eval_condition(cond, event) for cond in self._compiled_conditions]

        if not results:
            return False

        if self.logic == "and":
            return all(results)
        elif self.logic == "or":
            return any(results)
        return False

    def _eval_condition(self, cond: dict, event: dict) -> bool:
        field = cond.get("field", "")
        operator = cond.get("operator", "equals")
        expected = cond.get("value", "")

        actual = self._get_nested(event, field)
        if actual is None:
            return operator in ("not_exists", "is_null")

        actual_str = str(actual).lower()
        expected_str = str(expected).lower()

        if operator == "equals":
            return actual_str == expected_str
        elif operator == "not_equals":
            return actual_str != expected_str
        elif operator == "contains":
            return expected_str in actual_str
        elif operator == "not_contains":
            return expected_str not in actual_str
        elif operator == "startswith":
            return actual_str.startswith(expected_str)
        elif operator == "endswith":
            return actual_str.endswith(expected_str)
        elif operator == "regex":
            compiled_re = cond.get("_regex")
            return bool(compiled_re.search(str(actual))) if compiled_re else False
        elif operator == "gt":
            try:
                return float(actual) > float(expected)
            except (ValueError, TypeError):
                return False
        elif operator == "lt":
            try:
                return float(actual) < float(expected)
            except (ValueError, TypeError):
                return False
        elif operator == "gte":
            try:
                return float(actual) >= float(expected)
            except (ValueError, TypeError):
                return False
        elif operator == "lte":
            try:
                return float(actual) <= float(expected)
            except (ValueError, TypeError):
                return False
        elif operator == "in":
            if isinstance(expected, list):
                return actual_str in [str(v).lower() for v in expected]
            return actual_str in expected_str.split(",")
        elif operator == "not_in":
            if isinstance(expected, list):
                return actual_str not in [str(v).lower() for v in expected]
            return actual_str not in expected_str.split(",")
        elif operator == "exists":
            return actual is not None
        elif operator == "not_exists":
            return actual is None

        return False

    def _get_nested(self, data: dict, dotted_key: str) -> Any:
        """Get a nested dict value using dot notation (e.g., 'event.action')."""
        keys = dotted_key.split(".")
        current = data
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
        return current


class SigmaAdapter:
    """Convert Sigma YAML rules to CyberNest CompiledRule format."""

    SIGMA_MODIFIER_MAP = {
        "contains": "contains",
        "startswith": "startswith",
        "endswith": "endswith",
        "re": "regex",
        "base64": "contains",  # simplified
    }

    @staticmethod
    def parse_sigma(sigma_yaml: str, source_file: str = "") -> CompiledRule | None:
        try:
            data = yaml.safe_load(sigma_yaml)
        except yaml.YAMLError:
            return None

        if not data or not isinstance(data, dict):
            return None

        rule_data = {
            "id": data.get("id", "sigma-" + data.get("title", "unknown").lower().replace(" ", "-")),
            "name": data.get("title", ""),
            "description": data.get("description", ""),
            "severity": data.get("level", "medium"),
            "level": {"informational": 2, "low": 4, "medium": 6, "high": 10, "critical": 14}.get(
                data.get("level", "medium"), 6
            ),
            "type": "sigma",
            "group": ",".join(data.get("tags", [])),
            "tags": data.get("tags", []),
            "false_positives": data.get("falsepositives", []),
            "conditions": [],
            "logic": "and",
        }

        # Extract MITRE from tags
        mitre_tactics = []
        mitre_techniques = []
        for tag in data.get("tags", []):
            if tag.startswith("attack.t"):
                mitre_techniques.append(tag.replace("attack.", "").upper())
            elif tag.startswith("attack."):
                mitre_tactics.append(tag.replace("attack.", ""))

        rule_data["mitre_tactics"] = mitre_tactics
        rule_data["mitre_techniques"] = mitre_techniques

        # Parse detection
        detection = data.get("detection", {})
        condition = detection.get("condition", "")

        for sel_name, sel_value in detection.items():
            if sel_name == "condition":
                continue
            if isinstance(sel_value, dict):
                for field, value in sel_value.items():
                    operator = "equals"
                    # Handle Sigma modifiers
                    parts = field.split("|")
                    actual_field = parts[0]
                    for modifier in parts[1:]:
                        if modifier in SigmaAdapter.SIGMA_MODIFIER_MAP:
                            operator = SigmaAdapter.SIGMA_MODIFIER_MAP[modifier]
                        elif modifier == "all":
                            rule_data["logic"] = "and"

                    # Map Sigma field names to ECS
                    ecs_field = SigmaAdapter._map_field(actual_field)

                    if isinstance(value, list):
                        for v in value:
                            rule_data["conditions"].append({
                                "field": ecs_field,
                                "operator": operator,
                                "value": str(v),
                            })
                        if "or" in condition or len(value) > 1:
                            rule_data["logic"] = "or"
                    else:
                        rule_data["conditions"].append({
                            "field": ecs_field,
                            "operator": operator,
                            "value": str(value),
                        })

        if not rule_data["conditions"]:
            return None

        return CompiledRule(rule_data, source_file)

    @staticmethod
    def _map_field(sigma_field: str) -> str:
        """Map Sigma field names to ECS equivalents."""
        mapping = {
            "EventID": "winlog.event_id",
            "Image": "process.name",
            "ParentImage": "process.parent.name",
            "CommandLine": "process.command_line",
            "ParentCommandLine": "process.parent.command_line",
            "User": "user.name",
            "SourceIp": "source.ip",
            "DestinationIp": "destination.ip",
            "DestinationPort": "destination.port",
            "SourcePort": "source.port",
            "TargetFilename": "file.path",
            "TargetObject": "registry.path",
            "QueryName": "dns.question.name",
            "sha256": "file.hash.sha256",
            "md5": "file.hash.md5",
            "Hashes": "file.hash.sha256",
            "Protocol": "network.protocol",
            "LogonType": "winlog.logon.type",
            "ServiceName": "service.name",
            "Channel": "winlog.channel",
            "Provider_Name": "winlog.provider_name",
        }
        return mapping.get(sigma_field, sigma_field.lower().replace(" ", "."))


def load_rules(rules_dir: str) -> list[CompiledRule]:
    """Load all rules from a directory (YAML CyberNest format + Sigma YAML)."""
    rules = []
    rules_path = Path(rules_dir)

    if not rules_path.exists():
        logger.warning("Rules directory not found", path=rules_dir)
        return rules

    for yml_file in rules_path.rglob("*.yml"):
        try:
            content = yml_file.read_text(encoding="utf-8")

            # Check if it's a Sigma rule
            if "logsource:" in content and "detection:" in content:
                # Multi-document YAML
                for doc in yaml.safe_load_all(content):
                    if doc and isinstance(doc, dict) and "detection" in doc:
                        rule = SigmaAdapter.parse_sigma(yaml.dump(doc), str(yml_file))
                        if rule:
                            rules.append(rule)
                            logger.debug("Loaded Sigma rule", name=rule.name, file=str(yml_file))
            else:
                # CyberNest YAML format
                for doc in yaml.safe_load_all(content):
                    if doc and isinstance(doc, dict) and "conditions" in doc:
                        rule = CompiledRule(doc, str(yml_file))
                        rules.append(rule)
                        logger.debug("Loaded rule", name=rule.name, file=str(yml_file))

        except Exception as e:
            logger.error("Failed to load rule file", file=str(yml_file), error=str(e))

    logger.info("Rules loaded", total=len(rules), directory=rules_dir)
    return rules
