"""Tests for the NomosGuard core: ledger chaining, rule derivation, gate."""

from __future__ import annotations

import copy

import pytest

from nomosguard.ledger import Claim, EvidenceLedger, UnevidencedClaimError
from nomosguard.rules import Fact, Rule, RuleEngine
from nomosguard.gate import Decision, PolicyGate, PolicyRule


class TestEvidenceLedger:
    def test_append_and_verify(self):
        ledger = EvidenceLedger()
        ledger.append(Claim("tool_call", {"agent": "a", "tool": "t"}, "evidence line"))
        ok, detail = ledger.verify()
        assert ok, detail
        assert "1 entries" in detail

    def test_chain_links(self):
        ledger = EvidenceLedger()
        e1 = ledger.append(Claim("k", {"x": 1}, "e1"))
        e2 = ledger.append(Claim("k", {"x": 2}, "e2"))
        assert e1.entry_hash != e2.entry_hash
        assert e2.prev_hash == e1.entry_hash

    def test_unevidenced_claim_rejected(self):
        ledger = EvidenceLedger()
        with pytest.raises(UnevidencedClaimError):
            ledger.append(Claim("k", {"x": 1}, ""))

    def test_tamper_detected(self):
        ledger = EvidenceLedger()
        ledger.append(Claim("k", {"x": 1}, "e1"))
        # retroactively mutate an entry (simulate tampering)
        ledger._entries[0] = copy.deepcopy(ledger._entries[0])
        object.__setattr__(ledger._entries[0].claim, "payload", {"x": 999})
        ok, detail = ledger.verify()
        assert not ok
        assert "tamper" in detail.lower()


class TestRuleEngine:
    def _engine(self) -> RuleEngine:
        engine = RuleEngine(
            rules=[
                Rule(
                    name="r1",
                    body=(("calls", "?tool"), ("operates_on", "?component")),
                    head=("reaches", "component"),
                )
            ]
        )
        engine.add_fact(Fact("agent1", "calls", "sql"))
        engine.add_fact(Fact("sql", "operates_on", "db"))
        return engine

    def test_derivation_fixpoint(self):
        engine = self._engine()
        summary = engine.derive()
        derived = [f for f in engine.facts if f.relation == "reaches"]
        assert len(derived) == 1
        assert derived[0].subject == "agent1"
        assert summary["rules_fired"]["r1"] == 1

    def test_deterministic(self):
        a = self._engine()
        b = self._engine()
        sa, sb = a.derive(), b.derive()
        assert [str(f) for f in a.facts] == [str(f) for f in b.facts]

    def test_no_rule_no_derivation(self):
        engine = RuleEngine(rules=[])
        engine.add_fact(Fact("a", "calls", "b"))
        engine.derive()
        assert len(engine.facts) == 1  # only the base fact, nothing derived


class TestPolicyGate:
    def test_fail_closed_default(self):
        engine = RuleEngine(rules=[])
        gate = PolicyGate(policy_rules=[], fallback=Decision.BLOCK)
        result = gate.evaluate_with_fallback(engine)
        assert result["decision"] == "BLOCK"
        assert "fail-closed" in result["reason"]

    def test_block_on_derived_path(self):
        engine = RuleEngine(
            rules=[Rule("r", (("calls", "?t"), ("operates_on", "?c")), ("exposes", "vuln"))]
        )
        engine.add_fact(Fact("agent", "calls", "sql"))
        engine.add_fact(Fact("sql", "operates_on", "db"))
        engine.derive()
        gate = PolicyGate(
            policy_rules=[PolicyRule("block_exposure", "exposes", Decision.BLOCK)],
            fallback=Decision.BLOCK,
        )
        result = gate.evaluate_with_fallback(engine)
        assert result["decision"] == "BLOCK"
        assert result["policy_rule"] == "block_exposure"
        assert len(result["chain"]) >= 1


class TestEndToEnd:
    def test_demo_scenario(self):
        from nomosguard.demo import run

        result = run()
        assert result["ledger_verified"] is True
        assert result["gate_decision"]["decision"] == "BLOCK"
