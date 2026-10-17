"""Observed telemetry normalization stays lossless at uncommon input boundaries."""

from __future__ import annotations

import pytest

from nomosguard.log_normalize import (
    normalize_gelf,
    normalize_json,
    normalize_kv,
    normalize_pipe,
)
from nomosguard.rules import Fact, Pattern, RuleEngine
from nomosguard.signature_bridge import _extract_signature_claim
from nomosguard.temporal import _to_seconds


def test_kv_source_with_inline_port_preserves_both_address_and_port():
    line = "time=11:22:33 src=203.0.113.12:8888 dest=198.51.100.5:443 action=deny"
    out = normalize_kv(line)
    assert out is not None
    assert out.src_ip == "203.0.113.12"
    assert out.src_port == "8888"
    assert out.dst_ip == "198.51.100.5"
    assert out.dst_port == "443"


def test_strict_json_rejects_valid_but_unexpected_nonmapping(monkeypatch):
    from nomosguard import log_normalize as mod

    monkeypatch.setattr(mod, "_load_strict_json", lambda text: [1, 2])
    assert normalize_json('{"timestamp":"10:00:00"}') is None


@pytest.mark.parametrize(
    "line",
    [
        '{"version":"1.1","host":"node","timestamp":"99999999999999999999999999999"}',
        '{"version":"1.1","host":"node","timestamp":"0.0"}',
    ],
)
def test_gelf_out_of_range_time_never_breaks_log_normalization(line):
    out = normalize_gelf(line)
    assert out is not None
    assert out.category == "gelf"


@pytest.mark.parametrize("line", ['{"host":"a"}', '{"version":"1.1"}', "not json"])
def test_gelf_requires_both_transport_envelope_identifiers(line):
    assert normalize_gelf(line) is None


def test_pipe_action_probe_is_carried_with_canonical_scan_observation():
    out = normalize_pipe("Time:10:20:30|Action:PROBE|SourceAddress:192.0.2.1")
    assert out is not None
    assert out.time == "10:20:30"
    assert "action=SCAN" in out.keywords


def test_pipe_action_scan_does_not_duplicate_a_canonical_scan_keyword():
    out = normalize_pipe("Time:10:20:30|Action:SCAN|SourceAddress:192.0.2.1")
    assert out is not None
    assert out.keywords.count("action=SCAN") == 1


@pytest.mark.parametrize(
    ("payload", "relations"),
    [
        ({"subject": "", "signature_id": "NG-1", "level": "critical"}, []),
        ({"subject": "operator", "signature_id": "", "level": "critical"}, []),
        (
            {"subject": "operator", "signature_id": "NG-1", "level": "medium"},
            ["signatureMatched"],
        ),
        (
            {"subject": "operator", "signature_id": "NG-1", "level": "critical"},
            ["signatureMatched", "maliciousActivity"],
        ),
    ],
)
def test_signature_evidence_keeps_detection_separate_from_compromise(
    payload, relations
):
    facts = _extract_signature_claim(payload, "source-line")
    assert [fact.relation for fact in facts] == relations


def test_concrete_and_variable_patterns_use_different_indexes_without_guessing():
    engine = RuleEngine()
    engine.add_fact(Fact("alice", "calls", "tool1"))
    engine.add_fact(Fact("bob", "calls", "tool2"))
    engine._rebuild_index()
    assert [
        f.object for f in engine._candidates(Pattern("alice", "calls", "?obj"), {})
    ] == ["tool1"]
    assert [
        f.object
        for f in engine._candidates(
            Pattern("?actor", "calls", "?obj"), {"?actor": "bob"}
        )
    ] == ["tool2"]
    assert [
        f.subject for f in engine._candidates(Pattern("?actor", "calls", "tool1"), {})
    ] == ["alice"]
    assert len(engine._candidates(Pattern("?actor", "calls", "?obj"), {})) == 2


@pytest.mark.parametrize(
    ("line", "seconds"),
    [
        ("[08:14:02] event", 8 * 3600 + 14 * 60 + 2),
        ("1600000000 event", 1600000000),
        ("1600000000000 event", 1600000000),
        ("not timed", None),
    ],
)
def test_temporal_epoch_and_local_clock_paths_are_never_fabricated(line, seconds):
    assert _to_seconds(line) == seconds
