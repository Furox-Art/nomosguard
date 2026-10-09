"""Temporal rules: time-window correlation, deterministic."""

from __future__ import annotations

from nomosguard.temporal import (
    evaluate_temporal, default_temporal_rules, TemporalRule, _to_seconds,
)


BRUTE_LINES = [
    "[08:14:01] auth: src=203.0.113.77:1234 failed password for admin",
    "[08:14:05] auth: src=203.0.113.77:1234 failed password for root",
    "[08:14:09] auth: src=203.0.113.77:1234 failed password for admin",
    "[08:14:13] auth: src=203.0.113.77:1234 failed password for test",
    "[08:14:17] auth: src=203.0.113.77:1234 failed password for oracle",
    "[08:14:21] auth: src=203.0.113.77:1234 failed password for deploy",
]


class TestTimestampParsing:
    def test_hhmmss_bracket(self):
        assert _to_seconds("[08:14:02] x") == 8 * 3600 + 14 * 60 + 2

    def test_iso8601(self):
        ts = _to_seconds("2026-10-09T08:14:02 something")
        assert ts is not None and ts > 1_700_000_000

    def test_epoch(self):
        assert _to_seconds("1728466442 event") == 1728466442

    def test_no_timestamp(self):
        assert _to_seconds("no time here at all") is None


class TestBruteForce:
    def test_threshold_crossed_fires(self):
        r = evaluate_temporal(BRUTE_LINES, default_temporal_rules())
        relations = [f for f in r.facts if f[1] == "bruteForceDetected"]
        assert len(relations) == 1
        assert relations[0][0] == "203.0.113.77"

    def test_below_threshold_silent(self):
        lines = BRUTE_LINES[:3]  # only 3 events
        r = evaluate_temporal(lines, default_temporal_rules())
        assert not [f for f in r.facts if f[1] == "bruteForceDetected"]

    def test_window_exceeded_no_fire(self):
        """Events spread beyond the 120s window must NOT fire."""
        lines = [
            "[08:00:01] auth: src=1.2.3.4:1 failed password",
            "[08:10:01] auth: src=1.2.3.4:1 failed password",
            "[08:20:01] auth: src=1.2.3.4:1 failed password",
            "[08:30:01] auth: src=1.2.3.4:1 failed password",
            "[08:40:01] auth: src=1.2.3.4:1 failed password",
            "[08:50:01] auth: src=1.2.3.4:1 failed password",
        ]
        r = evaluate_temporal(lines, default_temporal_rules())
        assert not [f for f in r.facts if f[1] == "bruteForceDetected"]

    def test_different_sources_counted_separately(self):
        """Two sources, each below threshold, must not fire."""
        lines = [
            "[08:00:01] auth: src=1.1.1.1:1 failed password",
            "[08:00:02] auth: src=1.1.1.1:1 failed password",
            "[08:00:03] auth: src=2.2.2.2:1 failed password",
            "[08:00:04] auth: src=2.2.2.2:1 failed password",
        ]
        r = evaluate_temporal(lines, default_temporal_rules())
        assert not [f for f in r.facts if f[1] == "bruteForceDetected"]


class TestDeterminism:
    def test_same_input_same_output(self):
        r1 = evaluate_temporal(BRUTE_LINES, default_temporal_rules())
        r2 = evaluate_temporal(BRUTE_LINES, default_temporal_rules())
        assert sorted(r1.facts) == sorted(r2.facts)

    def test_order_independent(self):
        import random
        shuffled = BRUTE_LINES[:]
        random.Random(42).shuffle(shuffled)
        r1 = evaluate_temporal(BRUTE_LINES, default_temporal_rules())
        r2 = evaluate_temporal(shuffled, default_temporal_rules())
        assert sorted(r1.facts) == sorted(r2.facts)


class TestCustomRules:
    def test_custom_rule(self):
        rule = TemporalRule(
            name="many_conns",
            group_by=r"dst=(\S+?):",
            match=r"dbytes=\d{6,}",
            threshold=2,
            window_s=300,
            fact_relation="exfilSuspected",
        )
        lines = [
            "[08:00:01] net: dst=10.0.0.9:443 dbytes=2000000",
            "[08:00:02] net: dst=10.0.0.9:443 dbytes=3000000",
        ]
        r = evaluate_temporal(lines, [rule])
        assert len(r.facts) == 1
        assert r.facts[0][0] == "10.0.0.9"
