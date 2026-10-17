"""Remaining deterministic evidence-validation branches."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from nomosguard import log_normalize, temporal
from nomosguard.hypothesis import HypothesisTracker
from nomosguard.ingest import ingest_policy_jsonl, ingest_vuln_jsonl
from nomosguard.ingest.vuln_jsonl import parse_vuln_line
from nomosguard.ledger import EvidenceLedger
from nomosguard.rules import Fact, RuleEngine


def test_json_type_guard_rejects_wrong_decoded_type(monkeypatch: pytest.MonkeyPatch):
    # Inject a faulty decoder: a non-mapping must never become a log event.
    monkeypatch.setattr(
        log_normalize, "_load_strict_json", lambda _line: ["not a mapping"]
    )
    assert log_normalize.normalize_json('{"time":"08:14:01"}') is None


def test_defensive_timestamp_parser_rejects_unexpected_group_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Fault injection: a future regex schema change must not invent time units.
    monkeypatch.setattr(
        temporal, "_TS_PATTERNS", [re.compile(r"(?P<a>\d+):(?P<b>\d+)")]
    )
    assert temporal._to_seconds("11:22") is None


def test_derivation_trace_without_matching_evidence_produces_no_hypothesis() -> None:
    engine = RuleEngine()
    engine.add_fact(Fact("operator", "reaches", "public", ("tool_call",)))
    engine._derivation_trace.append(
        {
            "derived": "Fact(operator -reaches-> private)",
            "rule": "ghost",
            "matched_on": [],
        }
    )
    tracker = HypothesisTracker.from_engine(engine)
    assert tracker.hypotheses == ()
    assert tracker.strongest() is None
    assert tracker.summary()["total_hypotheses"] == 0


@pytest.mark.parametrize("kind", ["vulnerability", "policy_rule"])
def test_blank_lines_do_not_enter_evidence_or_change_record_counters(
    tmp_path: Path,
    kind: str,
) -> None:
    if kind == "vulnerability":
        document = '{"component":"db","cve":"CVE-2026-1234","description":"verified"}'
        ingest = ingest_vuln_jsonl
    else:
        document = (
            '{"subject":"operator","action":"read","resource":"data","effect":"deny"}'
        )
        ingest = ingest_policy_jsonl
    path = tmp_path / "events.jsonl"
    path.write_text("\n \n\r\n" + document + "\n\t\n", encoding="utf-8")
    ledger = EvidenceLedger()
    report = ingest(ledger, path)
    assert (report.total_lines, report.accepted, report.duplicates) == (1, 1, 0)
    assert report.rejected == []
    assert len(ledger.entries) == 1
    assert ledger.entries[0].claim.kind == kind


def test_optional_cve_description_roundtrips_into_claim_payload() -> None:
    result = parse_vuln_line(
        '{"component":"db","cve":"CVE-2026-1234","description":"verified"}', 1
    )
    assert result["description"] == "verified"
