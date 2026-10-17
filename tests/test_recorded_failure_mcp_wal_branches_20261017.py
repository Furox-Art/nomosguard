"""Measured fail-closed persistence, WAL, and runnable failure-scenario boundaries."""

from __future__ import annotations

import runpy
import warnings
from dataclasses import replace
from types import SimpleNamespace

import pytest

from nomosguard import demo_e2e, ledger, ledger_wal
from nomosguard.ledger import Claim, EvidenceLedger, LedgerFileError
from nomosguard.ledger_wal import WalError
from nomosguard.mcp_server import NomosGuardSession, _writable_ledger_target


def claim():
    return Claim(
        "tool_call", {"agent": "operator", "tool": "read"}, "direct audit record"
    )


def test_existing_file_is_accepted_as_possible_ledger_target_not_overwritten(tmp_path):
    path = tmp_path / "ledger.jsonl"
    path.write_text("untouched file")
    _writable_ledger_target(path)
    assert path.read_text() == "untouched file"


def test_mcp_assert_claim_refuses_disk_write_failure_without_memory_only_evidence(
    monkeypatch,
):
    session = NomosGuardSession()

    def broken(*a, **kw):
        raise OSError("simulated disk error")

    monkeypatch.setattr(session, "_append_persisted", broken)
    out = session.assert_claim(
        "tool_call", {"agent": "a", "tool": "t"}, "actual evidence"
    )
    assert out["accepted"] is False
    assert "ledger persistence failed" in out["reason"]
    assert session.ledger.entries == ()


def test_mcp_explanation_uses_recorded_decision_trace_instead_of_inventing_one(
    monkeypatch,
):
    session = NomosGuardSession()
    monkeypatch.setattr(
        session,
        "_gate_result",
        lambda fallback: {
            "decision": "ALERT",
            "reason": "explicit source",
            "all_decisions": [
                {
                    "subject": "agent",
                    "decision": "ALERT",
                    "policy_rule": "observed",
                    "chain": ["actual ledger evidence"],
                }
            ],
        },
    )
    out = session.explain()
    assert "agent: ALERT via observed" in out["summary"]
    assert "actual ledger evidence" in out["summary"]
    assert out["ledger_verified"] is True


def test_valid_unpersisted_wal_record_type_error_is_refused_not_discarded(
    monkeypatch, tmp_path
):
    path = tmp_path / "ledger.jsonl"
    recorded = EvidenceLedger()
    entry = recorded.append(claim())
    assert ledger_wal.write_wal(path, [entry]) == 1
    monkeypatch.setattr(
        ledger_wal,
        "Claim",
        lambda **kwargs: (_ for _ in ()).throw(TypeError("unreadable type")),
    )
    with pytest.raises(WalError, match="malformed claim"):
        ledger_wal.recover(path)


def test_ledger_load_with_simulated_malformed_claim_never_accepts_record(
    monkeypatch, tmp_path
):
    path = tmp_path / "ledger.jsonl"
    recorded = EvidenceLedger()
    recorded.append(claim())
    recorded.save(path)
    monkeypatch.setattr(
        ledger,
        "Claim",
        lambda **kwargs: (_ for _ in ()).throw(TypeError("bad claim shape")),
    )
    with pytest.raises(LedgerFileError, match="malformed claim"):
        EvidenceLedger.load(path)


def test_hashchain_verification_detects_broken_sequence_and_predecessor():
    for attribute, value, fragment in [
        ("seq", 4, "sequence broken"),
        ("prev_hash", "tampered", "chain broken"),
    ]:
        chain = EvidenceLedger()
        entry = chain.append(claim())
        chain._entries[0] = replace(entry, **{attribute: value})
        passed, reason = chain.verify()
        assert passed is False
        assert fragment in reason


def test_torn_nonobject_final_ledger_line_is_reported_not_laundered():
    parsed = ledger._parse_line("[42]", 3, "audit.jsonl", torn_allowed=True)
    assert parsed["torn"] is True
    assert parsed["record"] is None
    assert "not a JSON object" in parsed["error"]


def test_digest_unreadable_directory_refuses_to_invent_a_pin(tmp_path):
    with pytest.raises(LedgerFileError, match="cannot read ledger file"):
        ledger.ledger_digest(tmp_path)


def test_main_failure_mode_receives_false_response_as_reported_failure(
    monkeypatch, capsys
):
    monkeypatch.setattr(
        demo_e2e,
        "failure_mode_scenarios",
        lambda: (
            SimpleNamespace(
                name="deliberately-unsafe-demo",
                run=lambda: demo_e2e.FailureModeOutcome(
                    refused=False, detail="incorrectly allowed"
                ),
            ),
        ),
    )
    assert demo_e2e.failure_modes() == 1
    assert "deliberately-unsafe-demo" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("refused", "decision", "entries", "verified", "expected"),
    [
        (False, None, None, False, False),
        (True, "INVENTED_ALLOW", None, False, False),
        (True, "BLOCK", 2, False, False),
        (True, "BLOCK", 2, True, True),
        (True, None, None, False, True),
    ],
)
def test_failure_mode_outcome_requires_actual_refusal_and_intact_ledger(
    refused, decision, entries, verified, expected
):
    out = demo_e2e.FailureModeOutcome(
        refused=refused,
        detail="measured",
        decision=decision,
        ledger_entries=entries,
        ledger_verified=verified,
    )
    assert out.fails_closed() is expected


def test_end_to_end_demo_reports_missing_hypotheses_and_reversible_plan(
    monkeypatch, capsys
):
    monkeypatch.setattr(
        demo_e2e.HypothesisTracker,
        "from_engine",
        staticmethod(lambda engine: SimpleNamespace(strongest=lambda: None)),
    )
    monkeypatch.setattr(
        demo_e2e,
        "render_plan",
        lambda result: {
            "count": 1,
            "commands": [
                {
                    "argv": ["echo", "audit"],
                    "description": "operator-reviewable",
                    "undo": ["echo", "reverse"],
                }
            ],
        },
    )
    monkeypatch.setattr(demo_e2e, "failure_modes", lambda: 0)
    assert demo_e2e.main() == 0
    output = capsys.readouterr().out
    assert "no hypothesis tracked" in output
    assert "undo:" in output


def test_module_entrypoint_executes_real_failure_mode_demo():
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message="'nomosguard.demo_e2e' found in sys.modules",
            category=RuntimeWarning,
        )
        with pytest.raises(SystemExit) as exc:
            runpy.run_module("nomosguard.demo_e2e", run_name="__main__")
    assert exc.value.code == 0
