"""End-to-end demo: tool-call evidence -> derivation -> fail-closed gate.

Runs a committed scenario through the full deterministic chain and prints
the real output. Run with:

    python -m nomosguard.demo
"""

from __future__ import annotations

import json

from .constants import tool_call_gate_rules, tool_call_rules
from .gate import Decision, PolicyGate
from .ledger import Claim, EvidenceLedger
from .rules import RuleEngine


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

    # The demo runs the SAME canonical rule set and gate rules as the CLI
    # and the MCP server (nomosguard.constants) — it is a scenario, not a
    # second policy. An earlier local copy of these rules had quietly lost
    # `policy_denied_action`, which is exactly what one definition prevents.
    engine = RuleEngine(rules=tool_call_rules())
    engine.add_facts_from_ledger(ledger)
    derivation = engine.derive()

    gate = PolicyGate(
        policy_rules=tool_call_gate_rules(),
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
