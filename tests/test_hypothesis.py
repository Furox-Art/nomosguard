"""Tests for hypothesis tracking: multiple evidence chains per derived fact."""

from __future__ import annotations

import pytest

from nomosguard.ledger import Claim, EvidenceLedger
from nomosguard.rules import Pattern, Rule, RuleEngine
from nomosguard.hypothesis import Hypothesis, HypothesisTracker


def _engine_with_rules() -> RuleEngine:
    return RuleEngine(
        rules=[
            Rule("direct",
                body=(Pattern("?agent", "calls", "?tool"),
                      Pattern("?agent", "operates_on", "?component"),
                      Pattern("?component", "has_vulnerability", "?cve")),
                head=Pattern("?agent", "exposes", "?component")),
            Rule("reaches_base",
                body=(Pattern("?from", "operates_on", "?to"),),
                head=Pattern("?from", "reaches", "?to")),
            Rule("reaches_transitive",
                body=(Pattern("?from", "reaches", "?mid"),
                      Pattern("?mid", "reaches", "?to")),
                head=Pattern("?from", "reaches", "?to")),
            Rule("transitive_exposure",
                body=(Pattern("?agent", "calls", "?tool"),
                      Pattern("?agent", "reaches", "?component"),
                      Pattern("?component", "has_vulnerability", "?cve")),
                head=Pattern("?agent", "exposes", "?component")),
        ]
    )


class TestHypothesisTracker:
    def test_tracks_exposure_hypothesis(self):
        ledger = EvidenceLedger()
        ledger.append(Claim("tool_call", {"agent": "researcher", "tool": "sql", "target": "orders_db"}, "log1"))
        ledger.append(Claim("vulnerability", {"component": "orders_db", "cve": "CVE-1"}, "nvd"))
        engine = _engine_with_rules()
        engine.add_facts_from_ledger(ledger)
        engine.derive()

        tracker = HypothesisTracker.from_engine(engine)
        hyps = tracker.hypotheses
        assert len(hyps) >= 1
        exposes = [h for h in hyps if h.fact.relation == "exposes"]
        assert len(exposes) == 1
        assert exposes[0].fact.object == "orders_db"
        assert exposes[0].chain_count >= 1
        assert "tool_call" in exposes[0].all_sources
        assert "vulnerability" in exposes[0].all_sources

    def test_multiple_hypotheses_tracked(self):
        """Multiple derived facts are tracked separately, each with its chains."""
        ledger = EvidenceLedger()
        ledger.append(Claim("tool_call", {"agent": "researcher", "tool": "sql", "target": "orders_db"}, "log1"))
        ledger.append(Claim("tool_call", {"agent": "researcher", "tool": "backup", "target": "orders_db"}, "log2"))
        ledger.append(Claim("vulnerability", {"component": "orders_db", "cve": "CVE-1"}, "nvd"))
        engine = _engine_with_rules()
        engine.add_facts_from_ledger(ledger)
        engine.derive()

        tracker = HypothesisTracker.from_engine(engine)
        hyps = tracker.hypotheses
        # both exposes and reaches hypotheses are tracked
        relations = {h.fact.relation for h in hyps}
        assert "exposes" in relations
        assert "reaches" in relations
        # every hypothesis has at least one chain
        for h in hyps:
            assert h.chain_count >= 1

    def test_deterministic(self):
        ledger = EvidenceLedger()
        ledger.append(Claim("tool_call", {"agent": "a", "tool": "t", "target": "db"}, "log"))
        ledger.append(Claim("vulnerability", {"component": "db", "cve": "CVE-1"}, "nvd"))
        engine1 = _engine_with_rules()
        engine1.add_facts_from_ledger(ledger)
        engine1.derive()
        engine2 = _engine_with_rules()
        engine2.add_facts_from_ledger(ledger)
        engine2.derive()
        s1 = HypothesisTracker.from_engine(engine1).summary()
        s2 = HypothesisTracker.from_engine(engine2).summary()
        assert s1 == s2

    def test_summary_structure(self):
        ledger = EvidenceLedger()
        ledger.append(Claim("tool_call", {"agent": "a", "tool": "t", "target": "db"}, "log"))
        ledger.append(Claim("vulnerability", {"component": "db", "cve": "CVE-1"}, "nvd"))
        engine = _engine_with_rules()
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        tracker = HypothesisTracker.from_engine(engine)
        summary = tracker.summary()
        assert "total_hypotheses" in summary
        assert "hypotheses" in summary
        for h in summary["hypotheses"]:
            assert "fact" in h
            assert "chain_count" in h
            assert "sources" in h

    def test_strongest(self):
        ledger = EvidenceLedger()
        ledger.append(Claim("tool_call", {"agent": "researcher", "tool": "sql", "target": "orders_db"}, "log1"))
        ledger.append(Claim("tool_call", {"agent": "researcher", "tool": "backup", "target": "orders_db"}, "log2"))
        ledger.append(Claim("vulnerability", {"component": "orders_db", "cve": "CVE-1"}, "nvd"))
        engine = _engine_with_rules()
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        tracker = HypothesisTracker.from_engine(engine)
        strongest = tracker.strongest()
        assert strongest is not None
        assert strongest.chain_count >= 1

    def test_empty_engine_no_hypotheses(self):
        engine = _engine_with_rules()
        tracker = HypothesisTracker.from_engine(engine)
        assert tracker.hypotheses == ()
        assert tracker.strongest() is None
        assert tracker.summary()["total_hypotheses"] == 0
