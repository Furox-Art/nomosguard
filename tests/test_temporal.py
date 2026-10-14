"""Temporal rules: time-window correlation, deterministic."""

from __future__ import annotations

from nomosguard.temporal import (
    TemporalRule,
    _to_seconds,
    default_temporal_rules,
    evaluate_temporal,
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


class TestFiringWindowEvidence:
    """The finding must cite the events that produced it, per subject."""

    def test_fired_events_are_recorded_per_subject(self):
        lines = [
            # 203.0.113.77 crosses the threshold (6 events in 120 s)
            "[08:14:01] auth: src=203.0.113.77:1 failed password",
            "[08:14:05] auth: src=203.0.113.77:1 failed password",
            "[08:14:09] auth: src=203.0.113.77:1 failed password",
            "[08:14:13] auth: src=203.0.113.77:1 failed password",
            "[08:14:17] auth: src=203.0.113.77:1 failed password",
            "[08:14:21] auth: src=203.0.113.77:1 failed password",
            # 198.51.100.9 has only 2 — below threshold
            "[08:14:02] auth: src=198.51.100.9:1 failed password",
            "[08:14:06] auth: src=198.51.100.9:1 failed password",
        ]
        r = evaluate_temporal(lines, default_temporal_rules())
        detail = r.report["brute_force"]
        assert detail["fired_for"] == ["203.0.113.77"]
        events = detail["fired_events"]["203.0.113.77"]
        assert events["event_count"] == 6
        assert len(events["lines"]) == 6
        assert all("203.0.113.77" in ln for ln in events["lines"])

    def test_per_subject_count_is_not_a_global_max(self):
        """Two firing subjects: each count is its own, not the global max."""
        lines = []
        # subject A: 5 events within 4 seconds (exactly at threshold)
        for second in range(1, 6):
            lines.append(f"[08:00:0{second}] auth: src=10.0.0.1:1 failed password")
        # subject B: 9 events within 8 seconds
        for second in range(1, 10):
            lines.append(f"[08:10:0{second}] auth: src=10.0.0.2:1 failed password")
        r = evaluate_temporal(lines, default_temporal_rules())
        fired = r.report["brute_force"]["fired_events"]
        assert fired["10.0.0.1"]["event_count"] == 5
        assert fired["10.0.0.2"]["event_count"] == 9


class TestTemporalIntoTheLedger:
    """The bridge: findings become evidenced claims a reviewer can audit."""

    def test_default_rules_are_used_when_none_are_given(self):
        from nomosguard.temporal_bridge import run_temporal_into_ledger

        ledger, result = run_temporal_into_ledger(BRUTE_LINES)  # rules omitted
        assert result.report["brute_force"]["fired_for"] == ["203.0.113.77"]
        assert len(ledger.entries) == 1

    def test_evidence_cites_the_firing_events(self):
        from nomosguard.temporal_bridge import run_temporal_into_ledger

        ledger, _ = run_temporal_into_ledger(BRUTE_LINES)
        evidence = ledger.entries[0].claim.evidence
        assert "temporal rule brute_force" in evidence
        assert "6 in the firing window" in evidence
        # the cited lines are THE events, not a pointer to them
        assert "08:14:01" in evidence and "08:14:21" in evidence

    def test_payload_carries_the_per_subject_count(self):
        from nomosguard.temporal_bridge import run_temporal_into_ledger

        ledger, _ = run_temporal_into_ledger(BRUTE_LINES)
        assert ledger.entries[0].claim.payload["event_count"] == 6
