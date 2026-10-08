"""Declarative policy configuration: rules and gate decisions in one file.

Why this exists: the default rules used to be hardcoded in Python. A
security tool whose rules cannot be inspected, versioned, or reviewed
outside the code is a maintenance trap — the rules ARE the policy, and
policy belongs in a file humans can read.

File format (JSON):
    {
      "rules": [
        {
          "name": "tool_on_vulnerable_component",
          "body": [["?agent", "calls", "?tool"], ...],
          "head": ["?agent", "exposes", "?component"],
          "description": "..."
        }
      ],
      "gate": [
        {"name": "...", "match_relation": "exposes", "decision": "BLOCK"}
      ]
    }

Loading is fail-closed: any structural problem raises PolicyConfigError
with the precise location. Nothing is coerced or defaulted.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .ledger import EvidenceLedger
from .rules import Pattern, Rule, RuleDefinitionError
from .gate import Decision, PolicyGate, PolicyRule


class PolicyConfigError(ValueError):
    """Raised when a policy file is malformed (never silently ignored)."""


VALID_DECISIONS = {d.value for d in Decision}


def _validate_pattern(triple: Any, where: str) -> Pattern:
    if not isinstance(triple, list) or len(triple) != 3:
        raise PolicyConfigError(f"{where}: pattern must be a [subject, relation, object] triple")
    for token in triple:
        if not isinstance(token, str) or not token.strip():
            raise PolicyConfigError(f"{where}: pattern positions must be non-empty strings")
    return Pattern(subject=triple[0], relation=triple[1], object=triple[2])


def _validate_rule(raw: dict, idx: int) -> Rule:
    where = f"rules[{idx}]"
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise PolicyConfigError(f"{where}: missing or invalid 'name'")

    body_raw = raw.get("body")
    if not isinstance(body_raw, list) or not body_raw:
        raise PolicyConfigError(f"{where}: 'body' must be a non-empty list of patterns")
    body = tuple(_validate_pattern(t, f"{where}.body[{i}]") for i, t in enumerate(body_raw))

    head_raw = raw.get("head")
    if not isinstance(head_raw, list) or len(head_raw) != 3:
        raise PolicyConfigError(f"{where}: 'head' must be a [subject, relation, object] triple")
    head = _validate_pattern(head_raw, f"{where}.head")

    # every head variable must appear in the body, else the rule never fires
    body_vars = set()
    for p in body:
        body_vars.update(p.variables())
    for var in head.variables():
        if var not in body_vars:
            raise PolicyConfigError(
                f"{where}: head variable {var} does not appear in the body "
                "(the rule could never fire)"
            )

    description = raw.get("description", "")
    if not isinstance(description, str):
        raise PolicyConfigError(f"{where}: 'description' must be a string")
    return Rule(name=name, body=body, head=head, description=description)


def _validate_gate_entry(raw: dict, idx: int) -> PolicyRule:
    where = f"gate[{idx}]"
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise PolicyConfigError(f"{where}: missing or invalid 'name'")
    relation = raw.get("match_relation")
    if not isinstance(relation, str) or not relation.strip():
        raise PolicyConfigError(f"{where}: missing or invalid 'match_relation'")
    decision = raw.get("decision")
    if decision not in VALID_DECISIONS:
        raise PolicyConfigError(
            f"{where}: decision must be one of {sorted(VALID_DECISIONS)}, got {decision!r}"
        )
    match_object = raw.get("match_object")
    if match_object is not None and not isinstance(match_object, str):
        raise PolicyConfigError(f"{where}: 'match_object' must be a string when present")
    description = raw.get("description", "")
    return PolicyRule(
        name=name,
        match_relation=relation,
        decision=Decision(decision),
        match_object=match_object,
        description=description if isinstance(description, str) else "",
    )


def load_policy(path: str | Path) -> tuple[list[Rule], list[PolicyRule]]:
    """Load and validate a policy file. Returns (rules, gate_rules).

    Raises PolicyConfigError with a precise location on any problem.
    """
    path = Path(path)
    if not path.is_file():
        raise PolicyConfigError(f"policy file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PolicyConfigError(f"policy file is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise PolicyConfigError("policy file must be a JSON object")

    rules_raw = data.get("rules", [])
    gate_raw = data.get("gate", [])
    if not isinstance(rules_raw, list):
        raise PolicyConfigError("'rules' must be a list")
    if not isinstance(gate_raw, list):
        raise PolicyConfigError("'gate' must be a list")

    rules = [_validate_rule(r, i) for i, r in enumerate(rules_raw)]
    gate = [_validate_gate_entry(g, i) for i, g in enumerate(gate_raw)]
    return rules, gate


def default_policy() -> tuple[list[Rule], list[PolicyRule]]:
    """The built-in tool-call security policy (same as the CLI defaults)."""
    rules = [
        Rule(
            name="tool_on_vulnerable_component",
            body=(
                Pattern("?agent", "calls", "?tool"),
                Pattern("?agent", "operates_on", "?component"),
                Pattern("?component", "has_vulnerability", "?cve"),
            ),
            head=Pattern("?agent", "exposes", "?component"),
            description="An agent operating a tool on a vulnerable component exposes it.",
        ),
        Rule(
            name="policy_denied_action",
            body=(
                Pattern("?agent", "calls", "?tool"),
                Pattern("?agent", "policy_denies", "?action"),
            ),
            head=Pattern("?agent", "violates", "policy"),
            description="An agent calling a tool whose action is policy-denied violates policy.",
        ),
    ]
    gate = [
        PolicyRule(
            name="block_vulnerable_exposure",
            match_relation="exposes",
            decision=Decision.BLOCK,
            description="Exposure of a vulnerable component is blocked.",
        ),
        PolicyRule(
            name="alert_policy_violation",
            match_relation="violates",
            decision=Decision.ALERT,
            description="Policy violations raise an alert.",
        ),
    ]
    return rules, gate
