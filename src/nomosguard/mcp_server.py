"""NomosGuard MCP server: exposes the deterministic core as MCP tools.

Every tool is a thin, deterministic wrapper around the core. The MCP
layer adds NO decision logic — it only serializes and deserializes. The
invariant holds at the tool boundary:

  - `evidence_ingest` accepts claims + evidence, stores them in the ledger
  - `assert_claim` validates a claim (evidence required) and appends it
  - `derive_paths` runs the rule engine (pure logic, no model)
  - `decide` runs the policy gate (fail-closed, no model)
  - `explain` renders a decision chain in human-readable form (narration
    only — the LLM at the explanation edge may reword it, but the chain
    itself comes from the ledger and cannot be altered)

Run with:  python -m nomosguard.mcp_server
Configure an MCP client to run it over stdio.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from .ledger import Claim, EvidenceLedger, UnevidencedClaimError
from .rules import Pattern, Rule, RuleEngine
from .gate import Decision, PolicyGate, PolicyRule

# MCP protocol constants
JSONRPC_VERSION = "2.0"
PROTOCOL_VERSION = "2025-06-18"

SERVER_INFO = {
    "name": "nomosguard",
    "version": "0.1.0",
    "description": (
        "Deterministic security reasoning core exposed as MCP tools. "
        "LLMs may produce evidence and explain decisions; the ledger, "
        "rule engine, and policy gate never consult a model."
    ),
}


class NomosGuardSession:
    """A single session holding one ledger + engine + gate instance.

    The MCP server holds one session (or a registry keyed by session id
    for multi-tenant use). All state lives here; the protocol layer is
    stateless.
    """

    def __init__(
        self,
        rules: list[Rule] | None = None,
        policy_rules: list[PolicyRule] | None = None,
    ) -> None:
        self.ledger = EvidenceLedger()
        self.rules = list(rules) if rules else []
        self.policy_rules = list(policy_rules) if policy_rules else []

    # -- tool implementations -------------------------------------------------

    def evidence_ingest(self, claims: list[dict[str, Any]]) -> dict[str, Any]:
        """Ingest multiple claims at once. Returns accepted/rejected counts."""
        accepted = 0
        rejected: list[dict[str, Any]] = []
        for i, raw in enumerate(claims):
            try:
                claim = Claim(
                    kind=str(raw.get("kind", "")),
                    payload=dict(raw.get("payload", {})),
                    evidence=str(raw.get("evidence", "")),
                )
                self.ledger.append(claim)
                accepted += 1
            except UnevidencedClaimError as exc:
                rejected.append({"index": i, "reason": str(exc)})
        return {
            "accepted": accepted,
            "rejected": rejected,
            "ledger_size": len(self.ledger.entries),
        }

    def assert_claim(self, kind: str, payload: dict[str, Any], evidence: str) -> dict[str, Any]:
        """Assert a single claim. Rejected (fail-closed) without evidence."""
        claim = Claim(kind=kind, payload=payload, evidence=evidence)
        try:
            entry = self.ledger.append(claim)
        except UnevidencedClaimError as exc:
            return {"accepted": False, "reason": str(exc)}
        return {
            "accepted": True,
            "seq": entry.seq,
            "entry_hash": entry.entry_hash,
            "ledger_size": len(self.ledger.entries),
        }

    def derive_paths(self) -> dict[str, Any]:
        """Run the rule engine over the current ledger. Pure logic."""
        engine = RuleEngine(rules=self.rules)
        engine.add_facts_from_ledger(self.ledger)
        summary = engine.derive()
        return {
            "derived_facts": [str(f) for f in engine.facts],
            "rules_fired": summary["rules_fired"],
            "trace": summary["trace"],
            "ledger_verified": self.ledger.verify()[0],
        }

    def decide(self, fallback: str = "BLOCK") -> dict[str, Any]:
        """Run the policy gate. Fail-closed; never consults a model."""
        engine = RuleEngine(rules=self.rules)
        engine.add_facts_from_ledger(self.ledger)
        engine.derive()
        gate = PolicyGate(
            policy_rules=self.policy_rules,
            fallback=Decision(fallback),
        )
        result = gate.evaluate_with_fallback(engine)
        result["ledger_verified"] = self.ledger.verify()[0]
        return result

    def explain(self) -> dict[str, Any]:
        """Render the current state as a human-readable audit summary.

        This is narration, not decision. The text is generated from the
        ledger and derivation trace; an LLM at the explanation edge may
        reword it, but the facts cited cannot be changed.
        """
        ok, detail = self.ledger.verify()
        engine = RuleEngine(rules=self.rules)
        engine.add_facts_from_ledger(self.ledger)
        summary = engine.derive()
        gate = PolicyGate(policy_rules=self.policy_rules, fallback=Decision.BLOCK)
        decision = gate.evaluate_with_fallback(engine)
        lines = [
            f"Ledger: {detail}",
            f"Base facts: {len([f for f in engine.facts if not f.sources])}",
            f"Derived facts: {len([f for f in engine.facts if f.sources])}",
            f"Rules fired: {summary['rules_fired']}",
            f"Gate decision: {decision['decision']} ({decision['reason']})",
        ]
        for d in decision.get("all_decisions", []):
            lines.append(f"  - {d['subject']}: {d['decision']} via {d['policy_rule']}")
            for step in d.get("chain", []):
                lines.append(f"      {step}")
        return {
            "summary": "\n".join(lines),
            "ledger_verified": ok,
            "decision": decision["decision"],
        }

    def export_ledger(self) -> dict[str, Any]:
        """Export the full ledger for audit/archive."""
        ok, detail = self.ledger.verify()
        return {
            "verified": ok,
            "detail": detail,
            "entries": self.ledger.export(),
        }


# -- default rule and policy sets (tool-call security, the v1 path) ----------

def default_rules() -> list[Rule]:
    return [
        Rule(
            name="tool_on_vulnerable_component",
            body=(
                Pattern("?agent", "calls", "?tool"),
                Pattern("?tool", "operates_on", "?component"),
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


def default_policy_rules() -> list[PolicyRule]:
    return [
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
