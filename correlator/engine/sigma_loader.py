"""
CyberNest Sigma Rule Loader.

Full parser for Sigma detection rules (.yml).  Converts Sigma rules into the
internal CyberNest DetectionRule format so they can be evaluated by the
RuleEngine alongside native CyberNest rules.

Supported Sigma features:
  - detection.selection maps  (field: value | [value1, value2])
  - detection.keywords        (plain string lists searched in message/raw)
  - modifiers: contains, startswith, endswith, re, base64, all, any
  - condition expressions:
      selection AND NOT filter
      1 of selection*
      all of them
      selection1 OR selection2
  - Tags -> MITRE ATT&CK mapping

Reference: https://sigmahq.io/docs/specification.html
"""

from __future__ import annotations

import base64
import os
import re
from pathlib import Path
from typing import Any, Optional

import yaml

from shared.utils.logger import get_logger

logger = get_logger("correlator")

# ---------------------------------------------------------------------------
# Sigma tag -> MITRE mapping (common prefixes)
# ---------------------------------------------------------------------------

SIGMA_TAG_TO_MITRE: dict[str, dict[str, str]] = {
    "attack.initial_access":      {"tactic": "TA0001", "tactic_name": "Initial Access"},
    "attack.execution":           {"tactic": "TA0002", "tactic_name": "Execution"},
    "attack.persistence":         {"tactic": "TA0003", "tactic_name": "Persistence"},
    "attack.privilege_escalation": {"tactic": "TA0004", "tactic_name": "Privilege Escalation"},
    "attack.defense_evasion":     {"tactic": "TA0005", "tactic_name": "Defense Evasion"},
    "attack.credential_access":   {"tactic": "TA0006", "tactic_name": "Credential Access"},
    "attack.discovery":           {"tactic": "TA0007", "tactic_name": "Discovery"},
    "attack.lateral_movement":    {"tactic": "TA0008", "tactic_name": "Lateral Movement"},
    "attack.collection":          {"tactic": "TA0009", "tactic_name": "Collection"},
    "attack.exfiltration":        {"tactic": "TA0010", "tactic_name": "Exfiltration"},
    "attack.command_and_control": {"tactic": "TA0011", "tactic_name": "Command and Control"},
    "attack.impact":              {"tactic": "TA0040", "tactic_name": "Impact"},
    "attack.resource_development": {"tactic": "TA0042", "tactic_name": "Resource Development"},
    "attack.reconnaissance":      {"tactic": "TA0043", "tactic_name": "Reconnaissance"},
}

# Technique tag pattern: attack.t1059, attack.t1059.001
TECHNIQUE_PATTERN = re.compile(r"^attack\.t(\d{4})(?:\.(\d{3}))?$", re.IGNORECASE)

# Sigma severity mapping
SIGMA_LEVEL_MAP: dict[str, str] = {
    "informational": "informational",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

# ---------------------------------------------------------------------------
# Modifier handlers
# ---------------------------------------------------------------------------

def _apply_modifier(field_name: str, modifier: str, values: list[Any]) -> list[dict[str, Any]]:
    """Convert a Sigma field+modifier+values into CyberNest condition dicts."""
    conditions: list[dict[str, Any]] = []

    if modifier == "contains":
        for v in values:
            conditions.append({"field": field_name, "operator": "contains", "value": str(v)})
    elif modifier == "startswith":
        for v in values:
            conditions.append({"field": field_name, "operator": "startswith", "value": str(v)})
    elif modifier == "endswith":
        for v in values:
            conditions.append({"field": field_name, "operator": "endswith", "value": str(v)})
    elif modifier == "re":
        for v in values:
            conditions.append({"field": field_name, "operator": "regex", "value": str(v)})
    elif modifier == "base64":
        for v in values:
            b64_val = base64.b64encode(str(v).encode()).decode()
            conditions.append({"field": field_name, "operator": "contains", "value": b64_val})
    elif modifier == "base64offset":
        for v in values:
            raw = str(v).encode()
            for offset in range(3):
                padded = b"\x00" * offset + raw
                b64_val = base64.b64encode(padded).decode()
                # Trim padding artifacts
                trimmed = b64_val[offset:] if offset else b64_val
                conditions.append({"field": field_name, "operator": "contains", "value": trimmed})
    else:
        # No recognized modifier — treat as equals
        for v in values:
            conditions.append({"field": field_name, "operator": "equals", "value": str(v)})

    return conditions


def _parse_field_with_modifiers(raw_field: str) -> tuple[str, list[str]]:
    """Split 'FieldName|contains|all' -> ('FieldName', ['contains', 'all'])."""
    parts = raw_field.split("|")
    return parts[0], parts[1:]


# ---------------------------------------------------------------------------
# Selection parser
# ---------------------------------------------------------------------------

def _parse_selection(name: str, selection: Any) -> dict[str, Any]:
    """Parse a single Sigma detection selection into internal condition groups.

    Returns a dict with:
        logic: 'and' | 'or'
        fields: [condition_dicts]
    """
    if isinstance(selection, list):
        # keyword list — search in message field with OR logic
        conditions: list[dict[str, Any]] = []
        for kw in selection:
            conditions.append({
                "field": "message",
                "operator": "contains",
                "value": str(kw),
            })
        return {"logic": "or", "fields": conditions}

    if isinstance(selection, dict):
        conditions = []
        for raw_field, raw_value in selection.items():
            field_name, modifiers = _parse_field_with_modifiers(raw_field)
            values = raw_value if isinstance(raw_value, list) else [raw_value]

            has_all = "all" in modifiers
            effective_modifiers = [m for m in modifiers if m not in ("all", "any")]
            modifier = effective_modifiers[0] if effective_modifiers else ""

            if modifier:
                field_conditions = _apply_modifier(field_name, modifier, values)
            else:
                field_conditions = []
                for v in values:
                    if v is None:
                        field_conditions.append({"field": field_name, "operator": "not_exists", "value": None})
                    else:
                        field_conditions.append({"field": field_name, "operator": "equals", "value": str(v)})

            if has_all:
                # All values must match -> each becomes an AND condition
                conditions.extend(field_conditions)
            else:
                # Any value can match -> wrap in an OR sub-group
                if len(field_conditions) == 1:
                    conditions.extend(field_conditions)
                else:
                    # Create a virtual OR group represented as a single condition
                    # with the 'in' operator
                    if modifier == "" and all(c["operator"] == "equals" for c in field_conditions):
                        conditions.append({
                            "field": field_name,
                            "operator": "in",
                            "value": [c["value"] for c in field_conditions],
                        })
                    else:
                        # For modifier-based multi-value, we need OR semantics
                        # Store as _or_group for the evaluator
                        conditions.append({
                            "_or_group": field_conditions,
                        })

        return {"logic": "and", "fields": conditions}

    return {"logic": "and", "fields": []}


# ---------------------------------------------------------------------------
# Condition expression parser
# ---------------------------------------------------------------------------

class _ConditionNode:
    """Simple AST node for Sigma condition expressions."""

    def __init__(self, node_type: str, **kwargs: Any) -> None:
        self.type = node_type  # 'ref', 'and', 'or', 'not', '1_of', 'all_of'
        self.name: str = kwargs.get("name", "")
        self.children: list[_ConditionNode] = kwargs.get("children", [])
        self.pattern: str = kwargs.get("pattern", "")


def _tokenize_condition(condition_str: str) -> list[str]:
    """Tokenize a Sigma condition expression."""
    # Handle parentheses, AND, OR, NOT, 1 of, all of
    tokens: list[str] = []
    i = 0
    s = condition_str.strip()
    while i < len(s):
        if s[i].isspace():
            i += 1
            continue
        if s[i] == "(":
            tokens.append("(")
            i += 1
        elif s[i] == ")":
            tokens.append(")")
            i += 1
        else:
            # Read a word
            j = i
            while j < len(s) and not s[j].isspace() and s[j] not in ("(", ")"):
                j += 1
            word = s[i:j]
            tokens.append(word)
            i = j
    return tokens


def _parse_condition_expr(condition_str: str) -> _ConditionNode:
    """Parse a Sigma condition string into an AST.

    Supports: selection AND NOT filter, 1 of selection*, all of them,
              selection1 OR selection2, parenthesized groups.
    """
    tokens = _tokenize_condition(condition_str)
    pos = [0]

    def peek() -> Optional[str]:
        if pos[0] < len(tokens):
            return tokens[pos[0]]
        return None

    def consume() -> str:
        tok = tokens[pos[0]]
        pos[0] += 1
        return tok

    def parse_or() -> _ConditionNode:
        left = parse_and()
        while peek() and peek().lower() == "or":
            consume()  # 'or'
            right = parse_and()
            left = _ConditionNode("or", children=[left, right])
        return left

    def parse_and() -> _ConditionNode:
        left = parse_not()
        while peek() and peek().lower() == "and":
            consume()  # 'and'
            right = parse_not()
            left = _ConditionNode("and", children=[left, right])
        return left

    def parse_not() -> _ConditionNode:
        if peek() and peek().lower() == "not":
            consume()  # 'not'
            child = parse_primary()
            return _ConditionNode("not", children=[child])
        return parse_primary()

    def parse_primary() -> _ConditionNode:
        tok = peek()
        if tok == "(":
            consume()  # '('
            node = parse_or()
            if peek() == ")":
                consume()
            return node
        if tok and tok.lower() in ("1", "all"):
            quant = consume().lower()
            if peek() and peek().lower() == "of":
                consume()  # 'of'
                target = consume() if peek() else "*"
                if quant == "1":
                    return _ConditionNode("1_of", pattern=target)
                else:
                    return _ConditionNode("all_of", pattern=target)
            # Fallback: treat as reference
            return _ConditionNode("ref", name=quant)
        if tok:
            return _ConditionNode("ref", name=consume())
        return _ConditionNode("ref", name="")

    return parse_or()


# ---------------------------------------------------------------------------
# Sigma Rule converter
# ---------------------------------------------------------------------------

class SigmaRule:
    """Parsed Sigma rule with all detection logic."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.raw = data
        self.title: str = data.get("title", "")
        self.id: str = data.get("id", "")
        self.status: str = data.get("status", "experimental")
        self.description: str = data.get("description", "")
        self.level: str = SIGMA_LEVEL_MAP.get(data.get("level", "medium"), "medium")
        self.tags: list[str] = data.get("tags", [])
        self.logsource: dict[str, Any] = data.get("logsource", {})
        self.detection: dict[str, Any] = data.get("detection", {})
        self.falsepositives: list[str] = data.get("falsepositives", [])

        # Parse MITRE from tags
        self.mitre_tactic: str = ""
        self.mitre_techniques: list[str] = []
        self._parse_mitre_tags()

        # Parse detection selections
        self.selections: dict[str, dict[str, Any]] = {}
        self.condition_str: str = ""
        self._parse_detection()

    def _parse_mitre_tags(self) -> None:
        for tag in self.tags:
            tag_lower = tag.lower()
            if tag_lower in SIGMA_TAG_TO_MITRE:
                self.mitre_tactic = SIGMA_TAG_TO_MITRE[tag_lower]["tactic"]
            match = TECHNIQUE_PATTERN.match(tag_lower)
            if match:
                tid = f"T{match.group(1)}"
                if match.group(2):
                    tid += f".{match.group(2)}"
                self.mitre_techniques.append(tid)

    def _parse_detection(self) -> None:
        detection = self.detection
        self.condition_str = detection.get("condition", "")

        for key, value in detection.items():
            if key == "condition" or key == "timeframe":
                continue
            self.selections[key] = _parse_selection(key, value)

    def to_internal_format(self) -> dict[str, Any]:
        """Convert to CyberNest internal rule format."""
        # Build the conditions by evaluating the condition expression
        conditions = self._build_conditions()

        rule_id = f"SIGMA-{self.id[:8].upper()}" if self.id else f"SIGMA-{hash(self.title) & 0xFFFF:04X}"

        return {
            "id": rule_id,
            "name": self.title,
            "description": self.description,
            "level": self.level,
            "category": self.logsource.get("category", "unknown"),
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_techniques,
            "enabled": self.status != "unsupported",
            "conditions": conditions,
            "source": "sigma",
            "sigma_id": self.id,
            "sigma_logsource": self.logsource,
        }

    def _build_conditions(self) -> dict[str, Any]:
        """Evaluate the condition expression and flatten into internal format."""
        if not self.condition_str:
            # No condition -> combine all selections with AND
            all_fields: list[dict[str, Any]] = []
            for sel in self.selections.values():
                all_fields.extend(sel.get("fields", []))
            return {"logic": "and", "fields": all_fields}

        ast = _parse_condition_expr(self.condition_str)
        return self._eval_ast(ast)

    def _eval_ast(self, node: _ConditionNode) -> dict[str, Any]:
        """Recursively evaluate an AST node into conditions."""
        if node.type == "ref":
            sel = self.selections.get(node.name, {"logic": "and", "fields": []})
            return sel

        if node.type == "and":
            left = self._eval_ast(node.children[0])
            right = self._eval_ast(node.children[1])
            combined_fields = left.get("fields", []) + right.get("fields", [])
            return {"logic": "and", "fields": combined_fields}

        if node.type == "or":
            left = self._eval_ast(node.children[0])
            right = self._eval_ast(node.children[1])
            # Merge OR: if both have fields, create an _or_group structure
            combined_fields = []
            left_fields = left.get("fields", [])
            right_fields = right.get("fields", [])
            if left_fields and right_fields:
                combined_fields.append({"_or_group": left_fields + right_fields})
            else:
                combined_fields = left_fields + right_fields
            return {"logic": "or", "fields": combined_fields}

        if node.type == "not":
            child = self._eval_ast(node.children[0])
            # Negate: flip operators
            negated_fields: list[dict[str, Any]] = []
            for f in child.get("fields", []):
                neg = dict(f)
                op = neg.get("operator", "equals")
                negation_map = {
                    "equals": "not_equals",
                    "not_equals": "equals",
                    "contains": "not_contains",
                    "not_contains": "contains",
                    "in": "not_in",
                    "not_in": "in",
                    "exists": "not_exists",
                    "not_exists": "exists",
                    "startswith": "not_contains",  # approximation
                    "endswith": "not_contains",     # approximation
                }
                neg["operator"] = negation_map.get(op, op)
                negated_fields.append(neg)
            return {"logic": "and", "fields": negated_fields}

        if node.type == "1_of":
            pattern = node.pattern
            matching_sels = self._match_selections(pattern)
            all_fields: list[dict[str, Any]] = []
            for sel in matching_sels:
                fields = sel.get("fields", [])
                if fields:
                    all_fields.extend(fields)
            return {"logic": "or", "fields": all_fields}

        if node.type == "all_of":
            pattern = node.pattern
            matching_sels = self._match_selections(pattern)
            all_fields = []
            for sel in matching_sels:
                all_fields.extend(sel.get("fields", []))
            return {"logic": "and", "fields": all_fields}

        return {"logic": "and", "fields": []}

    def _match_selections(self, pattern: str) -> list[dict[str, Any]]:
        """Match selection names against a glob pattern like 'selection*' or 'them'."""
        if pattern.lower() == "them":
            return list(self.selections.values())

        if pattern.endswith("*"):
            prefix = pattern[:-1]
            return [
                sel for name, sel in self.selections.items()
                if name.startswith(prefix)
            ]

        sel = self.selections.get(pattern)
        return [sel] if sel else []


# ---------------------------------------------------------------------------
# Sigma Rule Loader
# ---------------------------------------------------------------------------

class SigmaLoader:
    """Recursively load Sigma rules from a directory and convert to internal format."""

    def __init__(self) -> None:
        self._sigma_rules: list[SigmaRule] = []
        self._internal_rules: list[dict[str, Any]] = []

    @property
    def sigma_rules(self) -> list[SigmaRule]:
        return self._sigma_rules

    @property
    def internal_rules(self) -> list[dict[str, Any]]:
        return self._internal_rules

    def load_directory(self, sigma_dir: str) -> int:
        """Load all .yml Sigma rules recursively from *sigma_dir*.

        Returns the number of rules loaded.
        """
        sigma_path = Path(sigma_dir)
        if not sigma_path.exists():
            logger.warning("sigma rules directory not found", path=sigma_dir)
            return 0

        count = 0
        for yml_file in sorted(sigma_path.rglob("*.yml")):
            count += self._load_file(yml_file)
        for yml_file in sorted(sigma_path.rglob("*.yaml")):
            count += self._load_file(yml_file)

        logger.info(
            "sigma rules loaded",
            total=len(self._sigma_rules),
            new=count,
            directory=sigma_dir,
        )
        return count

    def _load_file(self, path: Path) -> int:
        """Load Sigma rules from a single file.  Sigma files contain one rule per doc."""
        count = 0
        try:
            with open(path, "r", encoding="utf-8") as fh:
                docs = list(yaml.safe_load_all(fh))

            for doc in docs:
                if doc is None:
                    continue
                if not isinstance(doc, dict):
                    continue
                # Sigma rules have a 'title' and 'detection' key
                if "title" not in doc or "detection" not in doc:
                    continue
                try:
                    sigma_rule = SigmaRule(doc)
                    self._sigma_rules.append(sigma_rule)
                    internal = sigma_rule.to_internal_format()
                    self._internal_rules.append(internal)
                    count += 1
                    logger.debug(
                        "sigma rule loaded",
                        title=sigma_rule.title,
                        sigma_id=sigma_rule.id,
                    )
                except Exception:
                    logger.exception("failed to parse sigma rule", path=str(path))
        except Exception:
            logger.exception("failed to read sigma file", path=str(path))

        return count

    def load_single(self, data: dict[str, Any]) -> dict[str, Any]:
        """Parse a single Sigma rule dict and return internal format."""
        sigma_rule = SigmaRule(data)
        self._sigma_rules.append(sigma_rule)
        internal = sigma_rule.to_internal_format()
        self._internal_rules.append(internal)
        return internal
