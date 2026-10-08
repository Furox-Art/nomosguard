"""End-to-end demo: tool-call evidence -> derivation -> fail-closed gate.

Runs a committed scenario through the full deterministic chain and prints
the real output. Run with:

    python -m nomosguard.demo
"""

from __future__ import annotations

import json

from .ledger import Claim, EvidenceLedger
from .rules import Pattern, Rule, RuleEngine
from .gate import Decision, PolicyGate, PolicyRule


def build_scenario() -> EvidenceLedger:
    """A committed, deterministic tool-call scenario.

    Scenario: agent 'researcher' calls a data-analysis tool that operates
    on a database component which has a known CVE. Policy denies access
    to components with vulnerabilities.
    """
    ledger = EvidenceLedger()
    ledger.append(
        Claim(
            kind="tool_call",
            payload={"agent": "researcher", "tool": "sql_query", "target": "orders_db"},
            evidence="agent log line 42: researcher invoked sql_query on orders_db",
        )
    )
    ledger.append(
        Claim(
            kind="vulnerability",
            payload={"component": "orders_db", "cve": "CVE-2026-1234", "severity": "high"},
            evidence="NVD record CVE-2026-1234 affects orders_db (SQL injection)",
        )
    )
    return ledger


def run() -> dict:
    ledger = build_scenario()
    ok, detail = ledger.verify()

    engine = RuleEngine(
        rules=[
            Rule(
                name="tool_on_vulnerable_component",
                body=(
                    Pattern("?agent", "calls", "?tool"),
                    Pattern("?tool", "operates_on", "?component"),
                    Pattern("?component", "has_vulnerability", "?cve"),
                ),
                head=Pattern("?agent", "exposes", "?component"),
                description="An agent operating a tool on a vulnerable component exposes it.",
            )
        ]
    )
    engine.add_facts_from_ledger(ledger)
    derivation = engine.derive()

    gate = PolicyGate(
        policy_rules=[
            PolicyRule(
                name="block_vulnerable_exposure",
                match_relation="exposes",
                decision=Decision.BLOCK,
                description="Exposure of a vulnerable component is blocked.",
            )
        ],
        fallback=Decision.BLOCK,
    )
    result = gate.evaluate_with_fallback(engine)

    return {
        "ledger_verified": ok,
        "ledger_detail": detail,
        "entries": len(ledger.entries),
        "derived_facts": [str(f) for f in engine.facts],
        "derivation": derivation,
        "gate_decision": result,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
