"""Every temporal-bridge branch tested without speculative attack conclusions."""

from __future__ import annotations

from nomosguard import temporal_bridge as bridge
from nomosguard.ledger import EvidenceLedger
from nomosguard.temporal import TemporalResult


def test_temporal_claims_preserve_own_event_counts_and_source_lines() -> None:
    result = TemporalResult(
        report={
            "brute_force": {
                "threshold": 3,
                "window_s": 60,
                "groups": 2,
                "fired_for": ["203.0.113.1", "203.0.113.2"],
                "fired_events": {
                    "203.0.113.1": {"event_count": 5, "lines": ["line 1", "line 2"]},
                    "203.0.113.2": {"event_count": 3, "lines": ["line 3"]},
                },
            },
            "port_scan": {
                "fired_for": ["source-without-event-context"],
            },
            "exfil_burst": {"threshold": 5, "fired_for": []},
        }
    )
    claims = bridge.temporal_claims(result)
    assert len(claims) == 3
    assert claims[0].payload["event_count"] == 5
    assert "line 1 | line 2" in claims[0].evidence
    assert claims[1].payload["event_count"] == 3
    assert "line 3" in claims[1].evidence
    assert claims[2].payload["event_count"] is None
    assert "?" in claims[2].evidence


def test_temporal_extractors_refuse_empty_actor_without_guessing() -> None:
    for extractor in (
        bridge._extract_brute_force,
        bridge._extract_port_scan,
        bridge._extract_exfil_burst,
    ):
        assert extractor({"subject": ""}, "provided evidence") == []
        assert extractor({"subject": " "}, "provided evidence") == []


def test_all_three_temporal_extractors_return_distinct_evidenced_facts() -> None:
    facts = [
        bridge._extract_brute_force({"subject": "attacker"}, "evidence")[0],
        bridge._extract_port_scan({"subject": "scanner"}, "evidence")[0],
        bridge._extract_exfil_burst({"subject": "external"}, "evidence")[0],
    ]
    assert [(f.subject, f.relation) for f in facts] == [
        ("attacker", "bruteForceDetected"),
        ("scanner", "scanDetected"),
        ("external", "exfilSuspected"),
    ]
    assert all(f.sources for f in facts)


def test_provided_ledger_is_reused_and_builtin_rules_are_available() -> None:
    original = EvidenceLedger()
    ledger, result = bridge.run_temporal_into_ledger([], ledger=original)
    assert ledger is original
    assert result.facts == []
    assert not ledger.entries


def test_explicit_empty_rules_do_not_fall_back_to_defaults() -> None:
    lines = ["[08:14:01] auth: src=1.2.3.4 failed password"] * 7
    ledger, report = bridge.run_temporal_into_ledger(lines, rules=[])
    assert not ledger.entries
    assert report.facts == []
