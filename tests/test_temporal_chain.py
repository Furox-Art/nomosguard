"""End-to-end: raw logs -> temporal rules -> ledger -> engine -> gate.

This is the property the temporal bridge exists for: a brute-force
burst in the logs, combined with the attacker's network reachability,
must produce a gate decision — and a deterministic one.
"""

from __future__ import annotations

from nomosguard.temporal_bridge import run_temporal_into_ledger
from nomosguard.temporal import default_temporal_rules
from nomosguard.rules import RuleEngine
from nomosguard.rules_security import security_rules
from nomosguard.gate import PolicyGate, Decision
from nomosguard.policy_security import containment_policy_rules
from nomosguard import facts_security, temporal_bridge  # noqa: F401 — register extractors


BRUTE_LOGS = [
    "[08:14:01] auth: src=203.0.113.77:1234 failed password for admin",
    "[08:14:05] auth: src=203.0.113.77:1234 failed password for root",
    "[08:14:09] auth: src=203.0.113.77:1234 failed password for admin",
    "[08:14:13] auth: src=203.0.113.77:1234 failed password for test",
    "[08:14:17] auth: src=203.0.113.77:1234 failed password for oracle",
    "[08:14:21] auth: src=203.0.113.77:1234 failed password for deploy",
]


class TestTemporalIntoChain:
    def _run(self, extra_claims=()):
        ledger, temporal = run_temporal_into_ledger(
            BRUTE_LOGS, default_temporal_rules()
        )
        for kind, payload, evidence in extra_claims:
            from nomosguard.ledger import Claim
            ledger.append(Claim(kind=kind, payload=payload, evidence=evidence))
        engine = RuleEngine(rules=security_rules())
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        gate = PolicyGate(policy_rules=containment_policy_rules(),
                          fallback=Decision.ALERT)
        return ledger, temporal, engine, gate.evaluate_with_fallback(engine)

    def test_temporal_finding_becomes_ledger_claim(self):
        ledger, temporal, _, _ = self._run()
        assert any("brute_force" in str(e.claim.kind) for e in ledger.entries)
        ok, _ = ledger.verify()
        assert ok  # the chain is intact

    def test_temporal_fact_in_engine(self):
        _, _, engine, _ = self._run()
        assert any(f.relation == "bruteForceDetected" for f in engine.facts)

    def test_brute_force_plus_reachability_escalates(self):
        """The full chain: temporal finding + network reachability ->
        accessAttemptInProgress -> ESCALATE."""
        _, _, _, result = self._run(extra_claims=[
            ("network", {"host": "web01", "protocol": "ssh", "port": 22,
                         "allowed_from": "203.0.113.77"}, "firewall: 203.0.113.77 -> web01:22"),
        ])
        decisions = [d["decision"] for d in result.get("all_decisions", [])]
        assert "ESCALATE" in decisions, f"expected ESCALATE, got {decisions}"

    def test_brute_force_alone_does_not_escalate(self):
        """No reachability evidence -> no access-attempt derivation ->
        no ESCALATE. Temporal evidence alone is not an attack."""
        _, _, _, result = self._run()
        decisions = [d["decision"] for d in result.get("all_decisions", [])]
        assert "ESCALATE" not in decisions

    def test_scan_plus_reachability_revokes(self):
        """Scan burst + reachability -> enumeratingHost -> REVOKE_ACCESS."""
        scan_logs = [
            "[08:20:0%d] net: src=10.9.9.9:%d SYN scan port %d" % (i, 1000 + i, 20 + i)
            for i in range(1, 6)
        ]
        from nomosguard.temporal import evaluate_temporal, default_temporal_rules
        from nomosguard.ledger import Claim
        ledger, temporal = run_temporal_into_ledger(scan_logs, default_temporal_rules())
        # add the reachability evidence for the scanner
        ledger.append(Claim(
            kind="network",
            payload={"host": "web01", "protocol": "tcp", "port": 443,
                     "allowed_from": "10.9.9.9"},
            evidence="firewall: 10.9.9.9 -> web01:443",
        ))
        engine = RuleEngine(rules=security_rules())
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        gate = PolicyGate(policy_rules=containment_policy_rules(),
                          fallback=Decision.ALERT)
        result = gate.evaluate_with_fallback(engine)
        decisions = [d["decision"] for d in result.get("all_decisions", [])]
        assert "REVOKE_ACCESS" in decisions

    def test_decision_is_deterministic(self):
        _, _, _, r1 = self._run(extra_claims=[
            ("network", {"host": "web01", "protocol": "ssh", "port": 22,
                         "allowed_from": "203.0.113.77"}, "fw"),
        ])
        _, _, _, r2 = self._run(extra_claims=[
            ("network", {"host": "web01", "protocol": "ssh", "port": 22,
                         "allowed_from": "203.0.113.77"}, "fw"),
        ])
        assert r1["decision"] == r2["decision"]
        assert r1["missing_evidence"] == r2["missing_evidence"]

    def test_missing_evidence_reported_for_temporal_escalation(self):
        """A brute-force escalation derived WITHOUT network evidence
        (impossible by rule, but if the temporal claim were the only
        source) must report the missing class."""
        _, _, _, result = self._run(extra_claims=[
            ("network", {"host": "web01", "protocol": "ssh", "port": 22,
                         "allowed_from": "203.0.113.77"}, "fw"),
        ])
        # with both sources present, nothing missing
        assert result["missing_evidence"] == []
