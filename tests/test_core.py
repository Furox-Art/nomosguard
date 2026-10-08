"""Tests for the NomosGuard core: ledger chaining, rule derivation, gate."""

from __future__ import annotations

import copy

import pytest

from nomosguard.ledger import Claim, EvidenceLedger, UnevidencedClaimError
from nomosguard.rules import Fact, Pattern, Rule, RuleEngine, RuleDefinitionError
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
                    body=(
                        Pattern("?agent", "calls", "?tool"),
                        Pattern("?tool", "operates_on", "?target"),
                    ),
                    head=Pattern("?agent", "reaches", "?target"),
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
        assert derived[0].object == "db"  # head variable is substituted
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

    def test_variable_consistency_across_body(self):
        """A variable cannot bind two different values in one match.

        agent1 calls toolA; toolB operates on db. toolA does NOT touch db,
        so the rule must NOT fire — the ?tool variable would have to bind
        to both toolA and toolB simultaneously.
        """
        engine = RuleEngine(
            rules=[
                Rule(
                    name="tool_reaches",
                    body=(
                        Pattern("?agent", "calls", "?tool"),
                        Pattern("?tool", "operates_on", "?target"),
                    ),
                    head=Pattern("?agent", "reaches", "?target"),
                )
            ]
        )
        engine.add_fact(Fact("agent1", "calls", "toolA"))
        engine.add_fact(Fact("toolB", "operates_on", "db"))  # different tool
        engine.derive()
        derived = [f for f in engine.facts if f.relation == "reaches"]
        assert derived == [], "variable binding must be consistent across the body"

    def test_head_variable_substitution(self):
        """The head must carry the bound values, not a constant string."""
        engine = RuleEngine(
            rules=[
                Rule(
                    name="expose",
                    body=(
                        Pattern("?agent", "calls", "?tool"),
                        Pattern("?tool", "operates_on", "?component"),
                        Pattern("?component", "has_vulnerability", "?cve"),
                    ),
                    head=Pattern("?agent", "exposes", "?component"),
                )
            ]
        )
        engine.add_fact(Fact("researcher", "calls", "sql", ("tool_call",)))
        engine.add_fact(Fact("sql", "operates_on", "orders_db", ("tool_call",)))
        engine.add_fact(Fact("orders_db", "has_vulnerability", "CVE-2026-1234", ("vulnerability",)))
        engine.derive()
        derived = [f for f in engine.facts if f.relation == "exposes"]
        assert len(derived) == 1
        assert derived[0].object == "orders_db"
        # provenance: both source claim kinds flow into the derived fact
        assert set(derived[0].sources) == {"tool_call", "vulnerability"}

    def test_multiple_matches_all_fire(self):
        """Every valid substitution fires — no silent first-match picking."""
        engine = RuleEngine(
            rules=[
                Rule(
                    name="expose",
                    body=(
                        Pattern("?agent", "calls", "?tool"),
                        Pattern("?tool", "operates_on", "?component"),
                        Pattern("?component", "has_vulnerability", "?cve"),
                    ),
                    head=Pattern("?agent", "exposes", "?component"),
                )
            ]
        )
        engine.add_fact(Fact("agent1", "calls", "tool1"))
        engine.add_fact(Fact("agent2", "calls", "tool2"))
        engine.add_fact(Fact("tool1", "operates_on", "db_a"))
        engine.add_fact(Fact("tool2", "operates_on", "db_b"))
        engine.add_fact(Fact("db_a", "has_vulnerability", "CVE-1"))
        engine.add_fact(Fact("db_b", "has_vulnerability", "CVE-2"))
        engine.derive()
        derived = {f.key for f in engine.facts if f.relation == "exposes"}
        assert ("agent1", "exposes", "db_a") in derived
        assert ("agent2", "exposes", "db_b") in derived

    def test_unbound_head_variable_rejected(self):
        """A head variable absent from the body can never fire."""
        engine = RuleEngine(
            rules=[
                Rule(
                    name="bad",
                    body=(Pattern("?a", "calls", "?t"),),
                    head=Pattern("?a", "reaches", "?nowhere"),  # ?nowhere unbound
                )
            ]
        )
        engine.add_fact(Fact("agent1", "calls", "tool1"))
        with pytest.raises(RuleDefinitionError):
            engine.derive()

    def test_concrete_pattern_matches_exact_value(self):
        """A concrete (non-variable) pattern position matches only that value."""
        engine = RuleEngine(
            rules=[
                Rule(
                    name="specific",
                    body=(Pattern("?c", "has_vulnerability", "CVE-2026-1234"),),
                    head=Pattern("?c", "is", "critical"),
                )
            ]
        )
        engine.add_fact(Fact("orders_db", "has_vulnerability", "CVE-2026-1234"))
        engine.add_fact(Fact("users_db", "has_vulnerability", "CVE-2026-9999"))
        engine.derive()
        derived = {f.subject for f in engine.facts if f.relation == "is"}
        assert derived == {"orders_db"}


class TestPolicyGate:
    def test_fail_closed_default(self):
        engine = RuleEngine(rules=[])
        gate = PolicyGate(policy_rules=[], fallback=Decision.BLOCK)
        result = gate.evaluate_with_fallback(engine)
        assert result["decision"] == "BLOCK"
        assert "fail-closed" in result["reason"]

    def test_block_on_derived_path(self):
        engine = RuleEngine(
            rules=[
                Rule(
                    name="r",
                    body=(
                        Pattern("?a", "calls", "?t"),
                        Pattern("?t", "operates_on", "?c"),
                    ),
                    head=Pattern("?a", "exposes", "?c"),
                )
            ]
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
        # the head fact must carry the real component name, not a constant
        assert any("researcher -exposes-> orders_db" in f for f in result["derived_facts"])
