"""Tests for MulVAL-style security rules, facts, and containment decisions."""

from __future__ import annotations

import pytest

from nomosguard.ledger import Claim, EvidenceLedger
from nomosguard.rules import RuleEngine
from nomosguard.rules_security import security_rules
from nomosguard.gate import Decision, PolicyGate
from nomosguard.policy_security import containment_policy_rules
from nomosguard.hypothesis import HypothesisTracker
from nomosguard import facts_security  # noqa: F401  — register extractors
from nomosguard.benchmark.security_scenarios import build_security_scenarios
from nomosguard.benchmark.security_run_suite import run_security_scenario


class TestSecurityFacts:
    def test_network_fact_extraction(self):
        ledger = EvidenceLedger()
        ledger.append(Claim("network", {"host": "web01", "protocol": "tcp", "port": 443, "allowed_from": "attacker"}, "fw"))
        engine = RuleEngine(rules=security_rules())
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        assert any(f.relation == "netAccess" for f in engine.facts)
        assert any(f.relation == "canAccessHost" for f in engine.facts)

    def test_vuln_host_fact_extraction(self):
        ledger = EvidenceLedger()
        ledger.append(Claim("vuln_host", {"host": "web01", "cve": "CVE-2026-1"}, "nvd"))
        engine = RuleEngine(rules=security_rules())
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        assert any(f.relation == "vulExists" for f in engine.facts)

    def test_privilege_fact_extraction(self):
        ledger = EvidenceLedger()
        ledger.append(Claim("privilege", {"user": "attacker", "privilege": "admin", "host": "db"}, "iam"))
        engine = RuleEngine(rules=security_rules())
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        assert any(f.relation == "hasPrivilege" for f in engine.facts)


class TestExploitRule:
    def test_exploit_derives_exec_code(self):
        ledger = EvidenceLedger()
        ledger.append(Claim("network", {"host": "web01", "protocol": "tcp", "port": 443, "allowed_from": "attacker"}, "fw"))
        ledger.append(Claim("vuln_host", {"host": "web01", "cve": "CVE-2026-1"}, "nvd"))
        engine = RuleEngine(rules=security_rules())
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        exec_code = [f for f in engine.facts if f.relation == "execCode"]
        assert len(exec_code) == 1
        assert exec_code[0].subject == "web01"
        assert exec_code[0].object == "attacker"

    def test_no_vuln_no_exec_code(self):
        ledger = EvidenceLedger()
        ledger.append(Claim("network", {"host": "web01", "protocol": "tcp", "port": 443, "allowed_from": "attacker"}, "fw"))
        engine = RuleEngine(rules=security_rules())
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        assert not any(f.relation == "execCode" for f in engine.facts)

    def test_no_reach_no_exec_code(self):
        ledger = EvidenceLedger()
        ledger.append(Claim("vuln_host", {"host": "web01", "cve": "CVE-2026-1"}, "nvd"))
        engine = RuleEngine(rules=security_rules())
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        assert not any(f.relation == "execCode" for f in engine.facts)


class TestLateralMovement:
    def test_pivot_through_compromised_host(self):
        ledger = EvidenceLedger()
        ledger.append(Claim("network", {"host": "host1", "protocol": "tcp", "port": 443, "allowed_from": "attacker"}, "fw1"))
        ledger.append(Claim("vuln_host", {"host": "host1", "cve": "CVE-2026-1"}, "nvd"))
        ledger.append(Claim("network", {"host": "host2", "protocol": "tcp", "port": 443, "allowed_from": "internal"}, "fw2"))
        engine = RuleEngine(rules=security_rules())
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        can_access = {(f.subject, f.object) for f in engine.facts if f.relation == "canAccessHost"}
        assert ("attacker", "host2") in can_access

    def test_different_port_no_pivot(self):
        """A host on a different port must NOT be reachable by pivot."""
        ledger = EvidenceLedger()
        ledger.append(Claim("network", {"host": "host1", "protocol": "tcp", "port": 443, "allowed_from": "attacker"}, "fw1"))
        ledger.append(Claim("vuln_host", {"host": "host1", "cve": "CVE-2026-1"}, "nvd"))
        ledger.append(Claim("network", {"host": "host2", "protocol": "tcp", "port": 8080, "allowed_from": "internal"}, "fw2"))
        engine = RuleEngine(rules=security_rules())
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        can_access = {(f.subject, f.object) for f in engine.facts if f.relation == "canAccessHost"}
        assert ("attacker", "host2") not in can_access


class TestContainmentDecisions:
    def test_isolate_compromised_host(self):
        ledger = EvidenceLedger()
        ledger.append(Claim("network", {"host": "web01", "protocol": "tcp", "port": 443, "allowed_from": "attacker"}, "fw"))
        ledger.append(Claim("vuln_host", {"host": "web01", "cve": "CVE-2026-1"}, "nvd"))
        engine = RuleEngine(rules=security_rules())
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        gate = PolicyGate(policy_rules=containment_policy_rules(), fallback=Decision.ALERT)
        decisions = gate.evaluate(engine)
        assert any(d.decision == Decision.ISOLATE_HOST for d in decisions)

    def test_revoke_attacker_access(self):
        ledger = EvidenceLedger()
        ledger.append(Claim("network", {"host": "web01", "protocol": "tcp", "port": 443, "allowed_from": "attacker"}, "fw"))
        ledger.append(Claim("vuln_host", {"host": "web01", "cve": "CVE-2026-1"}, "nvd"))
        engine = RuleEngine(rules=security_rules())
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        gate = PolicyGate(policy_rules=containment_policy_rules(), fallback=Decision.ALERT)
        decisions = gate.evaluate(engine)
        assert any(d.decision == Decision.REVOKE_ACCESS for d in decisions)

    def test_escalate_privileged_compromise(self):
        ledger = EvidenceLedger()
        ledger.append(Claim("network", {"host": "db01", "protocol": "tcp", "port": 5432, "allowed_from": "attacker"}, "fw"))
        ledger.append(Claim("vuln_host", {"host": "db01", "cve": "CVE-2026-2"}, "nvd"))
        ledger.append(Claim("privilege", {"user": "attacker", "privilege": "admin", "host": "db01"}, "iam"))
        engine = RuleEngine(rules=security_rules())
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        gate = PolicyGate(policy_rules=containment_policy_rules(), fallback=Decision.ALERT)
        decisions = gate.evaluate(engine)
        assert any(d.decision == Decision.ESCALATE for d in decisions)


class TestSecurityBenchmark:
    def test_all_scenarios_pass(self):
        scenarios = build_security_scenarios()
        assert len(scenarios) == 5
        for s in scenarios:
            result = run_security_scenario(s)
            assert result["exec_code_derived"] == result["exec_code_expected"], s.name
            assert result["can_access_derived"] == result["can_access_expected"], s.name
            assert result["grants_derived"] == result["grants_expected"], s.name

    def test_hypothesis_tracking_on_security_facts(self):
        ledger = EvidenceLedger()
        ledger.append(Claim("network", {"host": "web01", "protocol": "tcp", "port": 443, "allowed_from": "attacker"}, "fw"))
        ledger.append(Claim("vuln_host", {"host": "web01", "cve": "CVE-2026-1"}, "nvd"))
        engine = RuleEngine(rules=security_rules())
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        tracker = HypothesisTracker.from_engine(engine)
        assert tracker.strongest() is not None
        exec_code_hyps = [h for h in tracker.hypotheses if h.fact.relation == "execCode"]
        assert len(exec_code_hyps) == 1
