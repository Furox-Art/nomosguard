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

import hashlib
import hmac
from pathlib import Path
from typing import Any

from .constants import (
    POLICY_FORMAT,
    POLICY_FORMAT_VERSION,
    tool_call_gate_rules,
    tool_call_rules,
)
from .gate import Decision, PolicyRule
from .rules import Pattern, Rule
from .schema import RecordValidator, parse_json_record


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
    if not isinstance(raw, dict):
        raise PolicyConfigError(f"{where}: rule must be a JSON object, got {type(raw).__name__}")
    v = RecordValidator(raw, where, error=PolicyConfigError)

    name = v.string("name")
    body_raw = v.list_of("body", non_empty=True)
    assert body_raw is not None  # required, so present by construction
    head_raw = v.list_of("head", non_empty=True)
    assert head_raw is not None
    body = tuple(_validate_pattern(t, f"{where}.body[{i}]") for i, t in enumerate(body_raw))

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

    description = v.string("description", required=False, allow_blank=True)
    return Rule(name=name, body=body, head=head, description=description or "")


def _validate_gate_entry(raw: dict, idx: int) -> PolicyRule:
    where = f"gate[{idx}]"
    if not isinstance(raw, dict):
        raise PolicyConfigError(f"{where}: gate entry must be a JSON object, got {type(raw).__name__}")
    v = RecordValidator(raw, where, error=PolicyConfigError)

    name = v.string("name")
    relation = v.string("match_relation")
    # Decision values are case-sensitive on purpose: the enum's spelling IS
    # the contract (PolicyConfigError, not a silent normalisation).
    decision = v.enum("decision", VALID_DECISIONS, fold=None)
    assert decision is not None
    match_object = v.string("match_object", required=False)
    description = v.string("description", required=False, allow_blank=True)
    return PolicyRule(
        name=name,
        match_relation=relation,
        decision=Decision(decision),
        match_object=match_object,
        description=description or "",
    )


def load_policy(
    path: str | Path,
    *,
    expected_digest: str | None = None,
) -> tuple[list[Rule], list[PolicyRule]]:
    """Load and validate a policy file. Returns (rules, gate_rules).

    A policy file is a BUNDLE, not arbitrary data: it is the rule set the
    gate will apply, so it is pinned like one.

      - `expected_digest="sha256:<hex>"` verifies the file's bytes before
        anything is parsed; a mismatch raises PolicyConfigError (fail
        closed — a policy that is not the one you pinned is not loaded).
      - a `format_version` header is checked when present, and an unknown
        one is refused.

    Raises PolicyConfigError with a precise location on any problem.
    Messages follow the contract in `nomosguard.schema`, so a policy file
    rejection reads exactly like a JSONL record rejection.
    """
    path = Path(path)
    if not path.is_file():
        raise PolicyConfigError(f"policy file not found: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyConfigError(f"cannot read policy file: {exc}") from exc

    if expected_digest is not None:
        actual = policy_digest(path)
        if not _digest_matches(actual, expected_digest):
            raise PolicyConfigError(
                f"policy digest mismatch: {path} is {actual}, "
                f"expected {expected_digest} — refusing to run a policy "
                "that is not the one you pinned"
            )

    data = parse_json_record(text, "policy file", error=PolicyConfigError)

    declared_format = data.get("format")
    if declared_format is not None and declared_format != POLICY_FORMAT:
        raise PolicyConfigError(
            f"policy file declares format {declared_format!r}, "
            f"expected {POLICY_FORMAT!r}"
        )
    declared_version = data.get("format_version")
    if declared_version is not None and declared_version != POLICY_FORMAT_VERSION:
        raise PolicyConfigError(
            f"unsupported policy format version {declared_version!r} "
            f"(expected {POLICY_FORMAT_VERSION}); this tool cannot judge a "
            "policy written for another dialect"
        )

    rules_raw = data.get("rules", [])
    gate_raw = data.get("gate", [])
    if not isinstance(rules_raw, list):
        raise PolicyConfigError("'rules' must be a list")
    if not isinstance(gate_raw, list):
        raise PolicyConfigError("'gate' must be a list")

    rules = [_validate_rule(r, i) for i, r in enumerate(rules_raw)]
    gate = [_validate_gate_entry(g, i) for i, g in enumerate(gate_raw)]
    return rules, gate


def policy_digest(path: str | Path) -> str:
    """The digest pin for a policy file: `sha256:<hex>` of its bytes.

    Commit this next to the policy file (or in a digest manifest) and pass
    it back as `load_policy(..., expected_digest=...)` so a policy that
    changed without review is refused instead of silently applied.

    CRLF bytes are normalised to LF before hashing. A digest pinned on one
    platform must hold on every other: without this, a Windows checkout
    (``core.autocrlf``) recomputes a different digest for byte-identical
    JSON and the fail-closed pin rejects a policy nobody changed.
    """
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PolicyConfigError(f"cannot read policy file: {exc}") from exc
    return "sha256:" + hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest()


def _digest_matches(actual: str, expected: str) -> bool:
    """Compare digests without short-circuiting (constant-time-ish)."""
    if not isinstance(expected, str) or not expected.startswith("sha256:"):
        raise PolicyConfigError(
            f"expected digest must look like sha256:<hex>, got {expected!r}"
        )
    return hmac.compare_digest(actual, expected)


def default_policy() -> tuple[list[Rule], list[PolicyRule]]:
    """The built-in tool-call security policy (same as the CLI defaults).

    The rule set and the gate rules are the canonical objects defined in
    `nomosguard.constants` — not a local copy. A policy rule that exists
    in two files is a policy rule that will disagree with itself.
    """
    return tool_call_rules(), tool_call_gate_rules()
