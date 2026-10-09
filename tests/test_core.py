"""Tests for the NomosGuard core: ledger chaining, rule derivation, gate."""

from __future__ import annotations

import copy

import pytest

from nomosguard.ledger import (
    Claim,
    EvidenceLedger,
    LedgerFileError,
    UnevidencedClaimError,
)
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


class TestLedgerPersistence:
    """The chain must survive process restarts — that is its whole point."""

    def _seeded(self) -> EvidenceLedger:
        ledger = EvidenceLedger()
        ledger.append(Claim("tool_call", {"agent": "a1", "tool": "t1"}, "log line 1"))
        ledger.append(Claim("vulnerability", {"component": "db1", "cve": "CVE-1"}, "NVD record"))
        return ledger

    def test_save_load_roundtrip(self, tmp_path=None):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = self._seeded()
            ledger.save(path)

            loaded = EvidenceLedger.load(path)
            assert len(loaded.entries) == 2
            assert loaded.head_hash == ledger.head_hash
            ok, detail = loaded.verify()
            assert ok, detail

    def test_append_after_load_continues_chain(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = self._seeded()
            ledger.save(path)

            loaded = EvidenceLedger.load(path)
            new_entry = loaded.append(Claim("policy_rule", {"effect": "deny"}, "policy doc"))
            assert new_entry.seq == 3
            assert new_entry.prev_hash == ledger.head_hash  # chain continues
            ok, detail = loaded.verify()
            assert ok, detail

    def test_save_after_load_is_stable(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            path2 = Path(td) / "ledger2.jsonl"
            ledger = self._seeded()
            ledger.save(path)

            loaded = EvidenceLedger.load(path)
            loaded.save(path2)
            assert path.read_text() == path2.read_text(), "save/load must be idempotent"

    def test_tampered_entry_rejected(self):
        import json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = self._seeded()
            ledger.save(path)

            # tamper: change a claim payload on disk
            lines = path.read_text().splitlines()
            record = json.loads(lines[1])
            record["claim"]["payload"]["agent"] = "attacker"
            lines[1] = json.dumps(record, sort_keys=True)
            path.write_text("\n".join(lines) + "\n")

            try:
                EvidenceLedger.load(path)
                assert False, "tampered ledger must be refused"
            except LedgerFileError:
                pass  # correct: the chain does not verify

    def test_truncated_entry_count_rejected(self):
        import json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = self._seeded()
            ledger.save(path)

            lines = path.read_text().splitlines()
            header = json.loads(lines[0])
            header["entries"] = 99  # lie about the count
            lines[0] = json.dumps(header, sort_keys=True)
            path.write_text("\n".join(lines) + "\n")

            try:
                EvidenceLedger.load(path)
                assert False, "count mismatch must be refused"
            except LedgerFileError:
                pass

    def test_missing_file_rejected(self):
        from pathlib import Path

        try:
            EvidenceLedger.load(Path("/nonexistent/ledger.jsonl"))
            assert False, "missing file must raise LedgerFileError"
        except LedgerFileError:
            pass

    def test_empty_file_rejected(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            path.write_text("")
            try:
                EvidenceLedger.load(path)
                assert False, "empty file must raise LedgerFileError"
            except LedgerFileError:
                pass


class TestIndexedMatching:
    """The index must not change results, and must keep derivation tractable."""

    def test_index_preserves_derivation_results(self):
        """Same rules, same facts: indexed matcher derives exactly what the
        full-scan matcher would (correctness is not traded for speed)."""
        engine = RuleEngine(
            rules=[
                Rule(
                    name="expose",
                    body=(
                        Pattern("?agent", "calls", "?tool"),
                        Pattern("?agent", "operates_on", "?component"),
                        Pattern("?component", "has_vulnerability", "?cve"),
                    ),
                    head=Pattern("?agent", "exposes", "?component"),
                )
            ]
        )
        for a in range(5):
            for c in range(5):
                if a <= c:
                    engine.add_fact(Fact(f"agent{a}", "calls", f"tool{a}", ("tool_call",)))
                    engine.add_fact(Fact(f"agent{a}", "operates_on", f"comp{c}", ("tool_call",)))
        engine.add_fact(Fact("comp1", "has_vulnerability", "CVE-1", ("vulnerability",)))
        engine.add_fact(Fact("comp3", "has_vulnerability", "CVE-3", ("vulnerability",)))
        engine.derive()
        derived = {f.key for f in engine.facts if f.relation == "exposes"}
        # agent1 operates on comps 1..4 (c>=1), only comp1 vulnerable
        assert ("agent1", "exposes", "comp1") in derived
        # agent3 operates on comps 3..4, only comp3 vulnerable
        assert ("agent3", "exposes", "comp3") in derived
        # agent0 operates on all comps incl. 1 and 3
        assert ("agent0", "exposes", "comp1") in derived
        assert ("agent0", "exposes", "comp3") in derived
        # agent4 operates only on comp4 (not vulnerable) -> nothing
        assert not any(k[0] == "agent4" for k in derived)

    def test_large_graph_derivation_completes(self):
        """A 30k-claim graph derives in bounded time (regression guard).

        Before the index, 4k claims took ~10s and 33k timed out. The
        indexed matcher must finish well under a minute on this size.
        """
        import time

        engine = RuleEngine(
            rules=[
                Rule(
                    name="expose",
                    body=(
                        Pattern("?agent", "calls", "?tool"),
                        Pattern("?agent", "operates_on", "?component"),
                        Pattern("?component", "has_vulnerability", "?cve"),
                    ),
                    head=Pattern("?agent", "exposes", "?component"),
                )
            ]
        )
        for a in range(100):
            for t in range(20):
                for c in range(50):
                    if (a + t + c) % 3 == 0:
                        engine.add_fact(Fact(f"a{a}", "calls", f"t{t}", ("tool_call",)))
                        engine.add_fact(Fact(f"a{a}", "operates_on", f"c{c}", ("tool_call",)))
        engine.add_fact(Fact("c1", "has_vulnerability", "CVE-1", ("vulnerability",)))
        t0 = time.time()
        engine.derive()
        elapsed = time.time() - t0
        assert elapsed < 30.0, f"derivation took {elapsed:.1f}s on 33k claims (index regression?)"
        derived = [f for f in engine.facts if f.relation == "exposes"]
        assert derived, "expected at least one exposure on the large graph"
