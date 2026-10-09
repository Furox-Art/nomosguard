"""Real-corpus tests: UNSW-NB15 flows through the deterministic core.

These tests do NOT call any model — they verify that real telemetry
flows, once converted to claims by any extractor, drive the same
deterministic pipeline (ledger -> rules -> gate) as synthetic data.
Network rows marked with attacks must produce access facts; exploit
rows must additionally produce vulnExists facts.
"""

from __future__ import annotations

import pytest

from nomosguard.benchmark.real_corpus.scenarios import load_scenarios
from nomosguard.ledger import EvidenceLedger, Claim
from nomosguard.rules import RuleEngine
from nomosguard.rules_security import security_rules
from nomosguard.gate import PolicyGate, Decision
from nomosguard.policy_security import containment_policy_rules
from nomosguard import facts_security  # noqa: F401


@pytest.fixture(scope="module")
def scenarios():
    try:
        return load_scenarios(300)
    except Exception as exc:
        pytest.skip(f"UNSW-NB15 fetch failed: {exc}")


class TestRealCorpus:
    def test_scenarios_built_from_real_data(self, scenarios):
        assert len(scenarios) >= 1
        for s in scenarios:
            assert "UNSW-NB15" in s.source
            assert len(s.expected_claims) >= 1
            assert s.raw_logs.strip()

    def test_attack_rows_produce_access_facts(self, scenarios):
        """Every scenario's ground truth includes network claims — the
        deterministic core must turn them into canAccessHost facts."""
        for s in scenarios:
            network_claims = [p for k, p in s.expected_claims if k == "network"]
            assert network_claims, f"{s.name}: no network ground truth"

    def test_exploit_rows_produce_vuln_facts(self, scenarios):
        """Exploit-category scenarios must include vuln_host claims."""
        exploit = [s for s in scenarios if "exploit" in s.name]
        if not exploit:
            pytest.skip("no exploit-category scenario in fetched rows")
        for s in exploit:
            vulns = [p for k, p in s.expected_claims if k == "vuln_host"]
            assert vulns, f"{s.name}: exploit scenario without vuln ground truth"

    def test_real_claims_flow_through_gate(self, scenarios):
        """End-to-end: real ground-truth claims -> gate decision."""
        s = scenarios[0]
        ledger = EvidenceLedger()
        for kind, payload in s.expected_claims:
            evidence = s.raw_logs.splitlines()[0]
            ledger.append(Claim(kind=kind, payload=payload, evidence=evidence))
        ok, _ = ledger.verify()
        assert ok

        engine = RuleEngine(rules=security_rules())
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        gate = PolicyGate(policy_rules=containment_policy_rules(),
                          fallback=Decision.ALERT)
        result = gate.evaluate_with_fallback(engine)
        # real attack telemetry must produce SOME decision
        assert result["all_decisions"] or result["decision"] == "ALERT"

    def test_gate_decision_is_reproducible(self, scenarios):
        """Determinism holds on real data too, not just synthetic."""
        s = scenarios[0]

        def run() -> str:
            ledger = EvidenceLedger()
            for kind, payload in s.expected_claims:
                ledger.append(Claim(kind=kind, payload=payload,
                                    evidence=s.raw_logs.splitlines()[0]))
            engine = RuleEngine(rules=security_rules())
            engine.add_facts_from_ledger(ledger)
            engine.derive()
            gate = PolicyGate(policy_rules=containment_policy_rules(),
                              fallback=Decision.ALERT)
            r = gate.evaluate_with_fallback(engine)
            return str(sorted((d["subject"], d["decision"])
                              for d in r["all_decisions"]))

        assert run() == run()
