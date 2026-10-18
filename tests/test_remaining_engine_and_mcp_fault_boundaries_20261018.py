"""Security reasoning failure branches and persistent claim refusal contracts."""

from __future__ import annotations

import re
from types import SimpleNamespace

from nomosguard import (
    hypothesis,
    log_normalize,
    mcp_server,
    rules,
    signature_bridge,
    temporal,
)
from nomosguard.ledger import EvidenceLedger


def test_hypothesis_tracker_cannot_invent_a_fact_missing_from_engine():
    real = rules.Fact("actual", "calls", "tool", ("source",))
    fake_engine = SimpleNamespace(
        facts=[real], derivation_trace=[{"derived": "Fact(missing -calls-> tool)", "rule": "sample", "matched_on": []}]
    )
    tracker = hypothesis.HypothesisTracker.from_engine(fake_engine)
    assert tracker.strongest() is None


def test_timestamp_parser_can_safely_ignore_new_unknown_pattern_shape(monkeypatch):
    monkeypatch.setattr(temporal, "_TS_PATTERNS", [re.compile(r"(ABC)-(DEF)"), re.compile(r"(\d{2}):(\d{2}):(\d{2})")])
    assert temporal._to_seconds("ABC-DEF") is None


def test_rule_engine_concrete_subject_candidate_lookup_is_not_full_scan():
    engine = rules.RuleEngine()
    only = rules.Fact("alice", "calls", "tool", ())
    other = rules.Fact("bob", "calls", "tool", ())
    engine.add_fact(only)
    engine.add_fact(other)
    engine._rebuild_index()
    assert engine._candidates(rules.Pattern("alice", "calls", "?tool"), {}) == [only]


def test_vulnerability_claim_with_missing_component_never_generates_fact():
    assert rules._extract_vulnerability({"component": "", "cve": "CVE-2026-0001"}, "source") == []


def test_policy_claim_without_subject_cannot_prove_a_permission():
    assert rules._extract_policy_rule({"subject": "", "action": "read", "resource": "database", "effect": "allow"}, "source") == []


def test_policy_claim_without_resource_cannot_prove_resource_permission():
    facts = rules._extract_policy_rule({"subject": "alice", "action": "read", "resource": "", "effect": "allow"}, "source")
    assert all(f.relation != "policy_allows" for f in facts)
    assert len(facts) == 1


def test_signature_bridge_retains_callers_existing_ledger():
    state = EvidenceLedger()
    returned, matches = signature_bridge.run_signatures_into_ledger([], [], state)
    assert returned is state
    assert matches == []


def test_syslog_with_no_source_address_does_not_invent_one():
    line = "Oct  9 08:14:01 host firewall: connection timeout"
    result = log_normalize.normalize_syslog(line)
    assert result is not None
    assert result.src_ip == ""


def test_pipe_generic_event_without_scan_does_not_add_scan_evidence():
    line = "Time:12:13:14|Event:ordinary|SourceAddress:192.0.2.1"
    result = log_normalize.normalize_pipe(line)
    assert result is not None
    assert "action=SCAN" not in result.keywords


def test_existing_ledger_file_is_a_valid_write_target(tmp_path):
    target = tmp_path / "exists.jsonl"
    target.write_text("evidence\n")
    assert mcp_server._writable_ledger_target(target) is None


def test_claim_is_refused_on_unexpected_ledger_persistence_error(monkeypatch):
    session = mcp_server.NomosGuardSession()
    def unavailable(claim):
        raise OSError("disk not writable")
    monkeypatch.setattr(session, "_append_persisted", unavailable)
    result = session.assert_claim("tool_call", {"agent": "alice", "tool": "db"}, "real source log")
    assert result["accepted"] is False
    assert "ledger persistence failed" in result["reason"]
    assert len(session.ledger.entries) == 0


def test_explanation_records_all_explicit_policy_derivation_steps(monkeypatch):
    session = mcp_server.NomosGuardSession()
    decision = {
        "decision": "BLOCK", "reason": "policy", "denied": True,
        "all_decisions": [{"subject": "alice", "decision": "BLOCK", "policy_rule": "restrict", "chain": ["actual evidence step"]}],
    }
    monkeypatch.setattr(session, "_gate_result", lambda *args, **kwargs: decision)
    report = session.explain()
    assert "alice: BLOCK via restrict" in report["summary"]
    assert "actual evidence step" in report["summary"]
