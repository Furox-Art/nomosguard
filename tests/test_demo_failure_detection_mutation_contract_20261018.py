"""Regression sentinels: the demo loudly exposes any injected security bypass.

Fault injection is confined to the demo harness: real security layers stay
strict. These tests prove the failing-diagnostic path is observable, not
that bypasses are valid in production.
"""

from __future__ import annotations

import runpy
from types import SimpleNamespace

import pytest

from nomosguard import demo_e2e as demo


def test_failure_outcome_requires_an_actual_refusal():
    assert demo.FailureModeOutcome(refused=False, detail="accepted unexpectedly").fails_closed() is False


def test_failure_outcome_does_not_consider_allow_or_alert_fail_closed():
    for value in ("ALLOW", "ALERT", "PASS"):
        assert demo.FailureModeOutcome(refused=True, detail="unsafe", decision=value).fails_closed() is False


def test_unevidenced_claim_regression_is_reported_if_injected(monkeypatch):
    class UnsafeLedger:
        def append(self, claim):
            return None
    monkeypatch.setattr(demo, "EvidenceLedger", UnsafeLedger)
    outcome = demo._run_unevidenced_claim()
    assert outcome.refused is False and outcome.fails_closed() is False


def test_tampered_record_regression_is_reported_if_injected(monkeypatch):
    class UnsafeLoader:
        @staticmethod
        def load(path):
            return None
    monkeypatch.setattr(demo.EvidenceLedger, "load", UnsafeLoader.load)
    outcome = demo._run_tampered_ledger_file()
    assert outcome.refused is False


@pytest.mark.parametrize("runner", [
    "_run_missing_ledger_path", "_run_ledger_path_is_a_directory",
    "_run_ledger_parent_is_not_a_directory",
])
def test_invalid_disk_path_regression_is_reported_if_injected(monkeypatch, runner):
    monkeypatch.setattr(demo, "_default_session", lambda **kwargs: SimpleNamespace())
    outcome = getattr(demo, runner)()
    assert outcome.refused is False and outcome.fails_closed() is False


def test_policy_digest_bypass_is_reported_if_injected(monkeypatch):
    from nomosguard import policy
    monkeypatch.setattr(policy, "load_policy", lambda *args, **kwargs: ([], []))
    outcome = demo._run_policy_digest_pin()
    assert outcome.refused is False and outcome.fails_closed() is False


def test_forged_wal_recovery_bypass_is_reported_if_injected(monkeypatch):
    monkeypatch.setattr(demo, "recover", lambda path: None)
    outcome = demo._run_tampered_wal()
    assert outcome.refused is False and outcome.fails_closed() is False


def test_ledger_digest_rewrite_bypass_is_reported_if_injected(monkeypatch):
    monkeypatch.setattr(demo, "NomosGuardSession", lambda **kwargs: object())
    outcome = demo._run_ledger_digest_pin()
    assert outcome.refused is False and outcome.fails_closed() is False


def test_failure_mode_diagnostic_returns_nonzero_for_bypassed_mode(monkeypatch, capsys):
    broken = SimpleNamespace(
        name="deliberately unsafe regression",
        run=lambda: demo.FailureModeOutcome(refused=False, detail="accepted injected invalid claim"),
    )
    monkeypatch.setattr(demo, "failure_mode_scenarios", lambda: (broken,))
    assert demo.failure_modes() == 1
    out = capsys.readouterr().out
    assert "[FAIL" in out and "FAILED: 1" in out


def test_demo_main_tells_operator_when_hypothesis_is_unavailable(monkeypatch, capsys):
    monkeypatch.setattr(demo.HypothesisTracker, "from_engine", lambda engine: SimpleNamespace(strongest=lambda: None))
    monkeypatch.setattr(demo, "render_plan", lambda result: {"count": 1, "commands": [
        {"argv": ["echo", "dry-run"], "description": "operator-reviewed", "undo": ["echo", "undo"]},
    ]})
    monkeypatch.setattr(demo, "failure_modes", lambda: 0)
    assert demo.main() == 0
    out = capsys.readouterr().out
    assert "no hypothesis tracked" in out
    assert "undo:" in out


def test_demo_module_entrypoint_runs_real_demo_and_exits_successfully(capsys):
    with pytest.raises(SystemExit) as stopped:
        runpy.run_module("nomosguard.demo_e2e", run_name="__main__")
    assert stopped.value.code == 0
    assert "all fail closed" in capsys.readouterr().out
