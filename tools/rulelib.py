"""Shared helpers to load detection rules and read their MITRE ATT&CK mapping.

Two rule formats live in this repository:

* ``rules/sigma/*.yml``      - vendor-neutral Sigma rules, converted to KQL by
                               ``tools/convert_sigma.py``.
* ``rules/sentinel/*.yaml``  - native Microsoft Sentinel scheduled analytics
                               rules, in the same YAML layout Microsoft uses for
                               its public analytics rule templates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SIGMA_DIR = REPO_ROOT / "rules" / "sigma"
SENTINEL_DIR = REPO_ROOT / "rules" / "sentinel"
KQL_DIR = REPO_ROOT / "rules" / "kql"

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# Sentinel tactic name -> Sigma tag suffix (attack.<suffix>)
TACTICS = {
    "Reconnaissance": "reconnaissance",
    "ResourceDevelopment": "resource-development",
    "InitialAccess": "initial-access",
    "Execution": "execution",
    "Persistence": "persistence",
    "PrivilegeEscalation": "privilege-escalation",
    "DefenseEvasion": "defense-evasion",
    "CredentialAccess": "credential-access",
    "Discovery": "discovery",
    "LateralMovement": "lateral-movement",
    "Collection": "collection",
    "CommandAndControl": "command-and-control",
    "Exfiltration": "exfiltration",
    "Impact": "impact",
}
SIGMA_TACTIC_TAGS = {v: k for k, v in TACTICS.items()}


@dataclass
class Rule:
    path: Path
    kind: str  # "sigma" or "sentinel"
    data: dict
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)

    @property
    def rule_id(self) -> str:
        return str(self.data.get("id", ""))

    @property
    def name(self) -> str:
        return str(self.data.get("title") or self.data.get("name") or self.path.stem)


def _sigma_attack(tags: list[str]) -> tuple[list[str], list[str]]:
    tactics, techniques = [], []
    for tag in tags or []:
        tag = str(tag).lower()
        if not tag.startswith("attack."):
            continue
        value = tag.removeprefix("attack.")
        if re.fullmatch(r"t\d{4}(\.\d{3})?", value):
            techniques.append(value.upper())
        elif value in SIGMA_TACTIC_TAGS:
            tactics.append(SIGMA_TACTIC_TAGS[value])
    return tactics, techniques


def load_rules() -> list[Rule]:
    rules: list[Rule] = []
    for path in sorted(SIGMA_DIR.glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        tactics, techniques = _sigma_attack(data.get("tags", []))
        rules.append(Rule(path, "sigma", data, tactics, techniques))
    for path in sorted(SENTINEL_DIR.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        rules.append(
            Rule(
                path,
                "sentinel",
                data,
                [str(t) for t in data.get("tactics", []) or []],
                [str(t) for t in data.get("relevantTechniques", []) or []],
            )
        )
    return rules


def kql_path_for(sigma_rule_path: Path) -> Path:
    return KQL_DIR / f"{sigma_rule_path.stem}.kql"
