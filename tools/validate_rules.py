"""Lint every detection rule in the repository.

Checks metadata quality, not detection logic: required fields, valid UUIDs,
MITRE ATT&CK mapping, unique IDs and names, schedule sanity for Sentinel rules,
and that every mapped entity column is actually produced by the query.

    python tools/validate_rules.py
"""

from __future__ import annotations

import re
import sys
import uuid

from rulelib import TACTICS, TECHNIQUE_RE, Rule, load_rules

SIGMA_REQUIRED = ["title", "id", "status", "description", "author", "date",
                  "tags", "logsource", "detection", "falsepositives", "level"]
SIGMA_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
SIGMA_LEVEL = {"informational", "low", "medium", "high", "critical"}

SENTINEL_REQUIRED = ["id", "name", "description", "severity", "kind",
                     "requiredDataConnectors", "queryFrequency", "queryPeriod",
                     "triggerOperator", "triggerThreshold", "tactics",
                     "relevantTechniques", "query", "entityMappings", "version"]
SENTINEL_SEVERITY = {"Informational", "Low", "Medium", "High"}
DURATION_RE = re.compile(r"^(\d+)([mhd])$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
UNIT_MINUTES = {"m": 1, "h": 60, "d": 1440}


def _minutes(value: str) -> int | None:
    match = DURATION_RE.match(str(value))
    return int(match.group(1)) * UNIT_MINUTES[match.group(2)] if match else None


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except ValueError:
        return False


def _balanced(query: str) -> bool:
    """Cheap structural check: brackets balance outside string literals."""
    pairs = {")": "(", "]": "[", "}": "{"}
    stack, quote = [], None
    for line in query.splitlines():
        line = line.split("//", 1)[0] if quote is None else line
        for ch in line:
            if quote:
                if ch == quote:
                    quote = None
                continue
            if ch in "\"'":
                quote = ch
            elif ch in "([{":
                stack.append(ch)
            elif ch in pairs:
                if not stack or stack.pop() != pairs[ch]:
                    return False
    return not stack and quote is None


def check_common(rule: Rule) -> list[str]:
    problems = []
    if not _is_uuid(rule.rule_id):
        problems.append("id is not a valid UUID")
    if not rule.techniques:
        problems.append("no MITRE ATT&CK technique mapped")
    for technique in rule.techniques:
        if not TECHNIQUE_RE.match(technique):
            problems.append(f"invalid technique id {technique!r}")
    if not rule.tactics:
        problems.append("no MITRE ATT&CK tactic mapped")
    return problems


def check_sigma(rule: Rule) -> list[str]:
    data = rule.data
    problems = [f"missing field {key!r}" for key in SIGMA_REQUIRED if key not in data]
    if data.get("status") not in SIGMA_STATUS:
        problems.append(f"status must be one of {sorted(SIGMA_STATUS)}")
    if data.get("level") not in SIGMA_LEVEL:
        problems.append(f"level must be one of {sorted(SIGMA_LEVEL)}")
    if "condition" not in (data.get("detection") or {}):
        problems.append("detection has no condition")
    if not data.get("falsepositives"):
        problems.append("document at least one false-positive scenario")
    return problems


def check_sentinel(rule: Rule) -> list[str]:
    data = rule.data
    problems = [f"missing field {key!r}" for key in SENTINEL_REQUIRED if key not in data]
    if data.get("severity") not in SENTINEL_SEVERITY:
        problems.append(f"severity must be one of {sorted(SENTINEL_SEVERITY)}")
    if data.get("kind") != "Scheduled":
        problems.append("only kind: Scheduled is supported")
    frequency = _minutes(data.get("queryFrequency", ""))
    period = _minutes(data.get("queryPeriod", ""))
    if frequency is None or period is None:
        problems.append("queryFrequency/queryPeriod must look like 30m, 1h or 1d")
    elif period < frequency:
        problems.append("queryPeriod is shorter than queryFrequency: events would be missed")
    for tactic in rule.tactics:
        if tactic not in TACTICS:
            problems.append(f"unknown tactic {tactic!r}")
    if not SEMVER_RE.match(str(data.get("version", ""))):
        problems.append("version must be semantic (1.0.0)")
    query = str(data.get("query", ""))
    if not query.strip():
        problems.append("query is empty")
    elif not _balanced(query):
        problems.append("query has unbalanced brackets or quotes")
    for mapping in data.get("entityMappings", []) or []:
        for field in mapping.get("fieldMappings", []) or []:
            column = str(field.get("columnName", ""))
            if not re.search(rf"\b{re.escape(column)}\b", query):
                problems.append(f"entity column {column!r} does not appear in the query")
    return problems


def main() -> int:
    rules = load_rules()
    failures = 0
    seen_ids: dict[str, str] = {}
    seen_names: dict[str, str] = {}
    for rule in rules:
        problems = check_common(rule)
        problems += check_sigma(rule) if rule.kind == "sigma" else check_sentinel(rule)
        for registry, key, label in ((seen_ids, rule.rule_id, "id"),
                                     (seen_names, rule.name.lower(), "name")):
            if key in registry:
                problems.append(f"duplicate {label}, also used by {registry[key]}")
            registry[key] = rule.path.name
        status = "OK  " if not problems else "FAIL"
        print(f"{status} [{rule.kind:8}] {rule.path.name}")
        for problem in problems:
            print(f"       - {problem}")
        failures += bool(problems)
    print(f"\n{len(rules)} rule(s), {failures} with problems")
    return 1 if failures or not rules else 0


if __name__ == "__main__":
    sys.exit(main())
