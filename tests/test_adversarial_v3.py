"""Adversarial probes v3: fuzzing, scale, severity, transitive closure.

Third adversarial layer: random-input robustness, large-input
performance, decision-severity ordering, and rule-engine closure.
The fuzz seeds are fixed, so these tests are reproducible.
"""

from __future__ import annotations

import random
import string
import time

from nomosguard.gate import Decision, PolicyGate
from nomosguard.ledger import Claim, EvidenceLedger
from nomosguard.rules import Fact, Pattern, Rule, RuleEngine


class TestSignatureFuzz:
    def test_2000_random_lines_no_crash_no_malformed(self):
        from nomosguard.signatures import match_all
        from nomosguard.signatures_builtin import builtin_signatures
        rng = random.Random(1337)
        sigs = builtin_signatures()
        lines = [
            "".join(rng.choice(string.printable) for _ in range(rng.randint(0, 300)))
            for _ in range(2000)
        ]
        t0 = time.perf_counter()
        matches = match_all(lines, sigs)
        assert time.perf_counter() - t0 < 10
        assert all(m.line and m.signature_id for m in matches)


class TestTemporalFuzz:
    def test_500_random_events_no_hang(self):
        from nomosguard.temporal import default_temporal_rules, evaluate_temporal
        rng = random.Random(1337)
        keywords = ["failed password", "SYN scan", "dbytes=9999999", "normal"]
        lines = [
            f"[{rng.randint(0,30):02d}:{rng.randint(0,99):02d}:{rng.randint(0,99):02d}] "
            f"auth: src={rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(0,255)}:1 "
            f"{rng.choice(keywords)}"
            for _ in range(500)
        ]
        t0 = time.perf_counter()
        evaluate_temporal(lines, default_temporal_rules())
        assert time.perf_counter() - t0 < 2


class TestNormalizeFuzz:
    def test_malformed_inputs_survive(self):
        from nomosguard.log_normalize import normalize_logs
        fuzz = [
            '{"unclosed": ', '<not xml', 'a=b c=d e=', '', '   ', '::::', '=no key',
            '{"a": {"b": {"c": 1}}}', '<a><b><c>deep</c></b></a>',
            'x' * 10000, '{"json": true}' * 100,
            '\x00\x01\x02 control chars', 'unicode: café ñ 日本',
        ]
        out = normalize_logs(fuzz)
        assert len(out) <= len(fuzz)


class TestGateSeverity:
    def test_worst_decision_wins(self):
        eng = RuleEngine(rules=[])
        eng.add_fact(Fact("h", "execCode", "attacker", ("x",)))
        eng.add_fact(Fact("attacker", "canAccessHost", "h", ("y",)))
        from nomosguard.policy_security import containment_policy_rules
        gate = PolicyGate(policy_rules=containment_policy_rules(), fallback=Decision.ALERT)
        r = gate.evaluate_with_fallback(eng)
        assert r["decision"] == "ISOLATE_HOST"  # ISOLATE outranks REVOKE


class TestScale:
    def test_1mb_line_no_hang(self):
        from nomosguard.signatures import match_all
        from nomosguard.signatures_builtin import builtin_signatures
        huge = "[flow 1] tcp " + "a=b " * 200000
        t0 = time.perf_counter()
        match_all([huge], builtin_signatures())
        assert time.perf_counter() - t0 < 5

    def test_5000_entry_chain_verifies_fast(self):
        led = EvidenceLedger()
        for i in range(5000):
            led.append(Claim(kind="network",
                             payload={"host": f"h{i%100}", "port": 22,
                                      "allowed_from": "x", "protocol": "tcp"},
                             evidence=f"e{i}"))
        t0 = time.perf_counter()
        ok, detail = led.verify()
        assert ok, detail
        assert time.perf_counter() - t0 < 5


class TestRuleClosure:
    def test_transitive_closure(self):
        eng = RuleEngine(rules=[Rule(
            name="trans",
            body=(Pattern("?a", "reach", "?b"), Pattern("?b", "reach", "?c")),
            head=Pattern("?a", "reach", "?c"),
        )])
        for i in range(5):
            eng.add_fact(Fact(f"n{i}", "reach", f"n{i+1}", ("network",)))
        eng.derive()
        reaches = [f for f in eng.facts if f.subject == "n0" and f.relation == "reach"]
        assert len(reaches) >= 5  # n0 reaches n1..n5 via closure

    def test_duplicate_facts_idempotent(self):
        eng = RuleEngine(rules=[])
        f = Fact("a", "rel", "b", ("x",))
        eng.add_fact(f)
        eng.add_fact(f)
        eng.add_fact(f)
        assert len(eng.facts) == 1


class TestEmptyInputs:
    def test_all_layers_handle_empty(self):
        from nomosguard.log_normalize import normalize_logs
        from nomosguard.signatures import match_all
        from nomosguard.signatures_builtin import builtin_signatures
        from nomosguard.temporal import default_temporal_rules, evaluate_temporal
        assert match_all([], builtin_signatures()) == []
        assert normalize_logs([]) == []
        evaluate_temporal([], default_temporal_rules())  # no crash
