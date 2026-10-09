"""Determinism tests: the core must produce identical output for identical input.

This is the property the whole project rests on: the decision boundary is
deterministic, so the same evidence in = the same decision out, on every
run, in any process order. If this test ever fails, the "deterministic
core" claim is dead.
"""

from __future__ import annotations

import json
from pathlib import Path

from nomosguard.ledger import EvidenceLedger, Claim
from nomosguard.rules import RuleEngine
from nomosguard.rules_security import security_rules
from nomosguard.gate import PolicyGate, Decision
from nomosguard.policy_security import containment_policy_rules


# A fixed scenario: the same claims a security incident would produce
SCENARIO = [
    ("network", {"host": "web01", "protocol": "ssh", "port": 22, "allowed_from": "203.0.113.77"}, "fw log line A"),
    ("vuln_host", {"host": "web01", "cve": "CVE-2026-31142"}, "nvd line B"),
    ("network", {"host": "db02", "protocol": "postgres", "port": 5432, "allowed_from": "web01 (10.0.4.21)"}, "netflow line C"),
    ("exec_code", {"host": "web01", "user": "deploy"}, "iam line D"),
    ("network", {"host": "web02", "protocol": "https", "port": 443, "allowed_from": "203.0.113.77"}, "fw log line E"),
]


def _run_once() -> dict:
    """Run the full pipeline once and return a canonical JSON snapshot."""
    ledger = EvidenceLedger()
    for kind, payload, evidence in SCENARIO:
        ledger.append(Claim(kind=kind, payload=payload, evidence=evidence))

    ok, detail = ledger.verify()

    engine = RuleEngine(rules=security_rules())
    engine.add_facts_from_ledger(ledger)
    engine.derive()

    gate = PolicyGate(policy_rules=containment_policy_rules(), fallback=Decision.ALERT)
    result = gate.evaluate_with_fallback(engine)

    return {
        "ledger_ok": ok,
        "ledger_size": len(ledger.entries),
        "ledger_hashes": [e.entry_hash for e in ledger.entries],
        "derived_facts": sorted(str(f) for f in engine.facts if f.sources),
        "gate_decision": str(result["decision"]),
        "gate_decisions": sorted(
            (d["subject"], str(d["decision"]), d["policy_rule"]) for d in result.get("all_decisions", [])
        ),
    }


class TestDeterminism:
    """The same claims must always produce the same bytes out."""

    def test_identical_output_across_runs(self):
        """Run the pipeline twice; snapshots must be byte-for-byte identical."""
        run1 = _run_once()
        run2 = _run_once()
        j1 = json.dumps(run1, sort_keys=True)
        j2 = json.dumps(run2, sort_keys=True)
        assert j1 == j2, "pipeline is not deterministic across runs"

    def test_ledger_hash_chain_is_stable(self):
        """Ledger hashes must be content-addressed, not random."""
        run1 = _run_once()
        run2 = _run_once()
        assert run1["ledger_hashes"] == run2["ledger_hashes"]
        # reordering the same claims must change the chain (order-sensitive)
        reordered = list(reversed(SCENARIO))
        ledger = EvidenceLedger()
        for kind, payload, evidence in reordered:
            ledger.append(Claim(kind=kind, payload=payload, evidence=evidence))
        assert [e.entry_hash for e in ledger.entries] != run1["ledger_hashes"]

    def test_gate_decision_is_content_addressed(self):
        """Same evidence always yields the same gate verdict."""
        r1 = _run_once()
        r2 = _run_once()
        assert r1["gate_decision"] == r2["gate_decision"]
        assert r1["gate_decisions"] == r2["gate_decisions"]

    def test_derived_facts_are_stable(self):
        """Rule derivation must not depend on dict/set iteration order."""
        r1 = _run_once()
        r2 = _run_once()
        assert r1["derived_facts"] == r2["derived_facts"]

    def test_evidence_order_independent_for_gate(self):
        """The gate verdict must not depend on claim insertion order."""
        def _run_with_order(order: list) -> str:
            ledger = EvidenceLedger()
            for i in order:
                kind, payload, evidence = SCENARIO[i]
                ledger.append(Claim(kind=kind, payload=payload, evidence=evidence))
            engine = RuleEngine(rules=security_rules())
            engine.add_facts_from_ledger(ledger)
            engine.derive()
            gate = PolicyGate(policy_rules=containment_policy_rules(), fallback=Decision.ALERT)
            return str(gate.evaluate_with_fallback(engine)["decision"])

        normal = _run_with_order([0, 1, 2, 3, 4])
        shuffled = _run_with_order([4, 2, 0, 3, 1])
        reversed_order = _run_with_order([4, 3, 2, 1, 0])
        assert normal == shuffled == reversed_order, (
            "gate verdict changed with claim order — decision is not order-independent"
        )
