"""Adversarial security probes: try to break the core's invariants.

Each test attempts a concrete attack and asserts the invariant holds.
These are regression guards for the security properties the project
claims — determinism, tamper-evidence, no path escape, no ReDoS.
"""

from __future__ import annotations

import time

import pytest

from nomosguard import facts_security  # noqa: F401  # codeql[py/unused-import] — register extractors
from nomosguard.gate import Decision, PolicyGate
from nomosguard.ledger import Claim, EvidenceLedger, UnevidencedClaimError
from nomosguard.policy_security import containment_policy_rules
from nomosguard.rules import RuleEngine
from nomosguard.rules_security import security_rules


class TestTamperEvasion:
    def test_tampered_middle_entry_is_detected(self):
        led = EvidenceLedger()
        led.append(Claim(kind="network", payload={"host": "a", "port": 22,
                         "allowed_from": "x", "protocol": "tcp"}, evidence="e1"))
        led.append(Claim(kind="network", payload={"host": "b", "port": 22,
                         "allowed_from": "y", "protocol": "tcp"}, evidence="e2"))
        # rewrite a stored claim but keep its hash
        led._entries[0].claim.payload["host"] = "HOSTILE"
        ok, detail = led.verify()
        assert not ok
        assert "tamper" in detail.lower()


class TestDeterminismUnderAdversary:
    def test_hashes_stable_across_runs(self):
        def run():
            led = EvidenceLedger()
            for i in range(5):
                led.append(Claim(kind="vuln_host",
                                 payload={"host": f"h{i}", "cve": f"CVE-2026-{i}"},
                                 evidence=f"e{i}"))
            return [e.entry_hash for e in led.entries]
        assert run() == run()

    def test_gate_decision_order_independent(self):
        claims = [
            ("network", {"host": "web01", "port": 22, "allowed_from": "1.2.3.4",
                         "protocol": "ssh"}, "fw"),
            ("vuln_host", {"host": "web01", "cve": "CVE-2026-1"}, "nvd"),
            ("exec_code", {"host": "web01", "user": "deploy"}, "iam"),
        ]
        def run(order):
            led = EvidenceLedger()
            for i in order:
                k, p, e = claims[i]
                led.append(Claim(kind=k, payload=p, evidence=e))
            eng = RuleEngine(rules=security_rules())
            eng.add_facts_from_ledger(led)
            eng.derive()
            g = PolicyGate(policy_rules=containment_policy_rules(),
                           fallback=Decision.ALERT)
            r = g.evaluate_with_fallback(eng)
            return str(sorted((d["subject"], d["decision"])
                              for d in r.get("all_decisions", [])))
        assert run([0, 1, 2]) == run([2, 0, 1]) == run([1, 2, 0])


class TestRedos:
    def test_temporal_no_catastrophic_backtracking(self):
        from nomosguard.temporal import default_temporal_rules, evaluate_temporal
        evil = "src=" + "a" * 5000 + " " + "failed password " * 200
        t0 = time.perf_counter()
        evaluate_temporal([evil], default_temporal_rules())
        assert time.perf_counter() - t0 < 2.0

    def test_signatures_no_catastrophic_backtracking(self):
        from nomosguard.signatures import match_all
        from nomosguard.signatures_builtin import builtin_signatures
        evil = "[flow 1] tcp src=" + "a" * 3000 + " service=" + "h" * 2000 + \
               " state=FIN dbytes=999999999999999"
        t0 = time.perf_counter()
        match_all([evil], builtin_signatures())
        assert time.perf_counter() - t0 < 3.0


class TestPayloadInjection:
    def test_quote_injection_payload_still_verifies(self):
        led = EvidenceLedger()
        evil = {"host": "a", "port": 22,
                "allowed_from": '"} , "injected": "x', "protocol": "tcp"}
        led.append(Claim(kind="network", payload=evil, evidence="e"))
        ok, _ = led.verify()
        assert ok

    def test_empty_evidence_rejected(self):
        led = EvidenceLedger()
        with pytest.raises(UnevidencedClaimError):
            led.append(Claim(kind="network",
                             payload={"host": "a", "port": 22,
                                      "allowed_from": "x", "protocol": "tcp"},
                             evidence=""))

    def test_unicode_host_no_crash(self):
        led = EvidenceLedger()
        led.append(Claim(kind="network", payload={"host": "web\u200b01",
                         "port": 22, "allowed_from": "1.2.3.4",
                         "protocol": "ssh"}, evidence="e"))
        ok, _ = led.verify()
        assert ok
