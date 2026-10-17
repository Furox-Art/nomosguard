"""Adversarial fault injection exposes a security demo accidentally failing OPEN.

These tests do not change production policy. By replacing each individual
refusal with an intentionally broken stub, they prove the scenario auditor
detects an incorrectly accepted or unverifiable security state.
"""

from __future__ import annotations

import pytest

from nomosguard import demo_e2e, policy
from nomosguard.ledger import EvidenceLedger


@pytest.mark.parametrize(
    ("scenario", "broken_component"),
    [
        ("_run_unevidenced_claim", "append"),
        ("_run_tampered_ledger_file", "ledger_load"),
        ("_run_missing_ledger_path", "default_session"),
        ("_run_policy_digest_pin", "policy_load"),
        ("_run_tampered_wal", "wal_recover"),
        ("_run_ledger_path_is_a_directory", "default_session"),
        ("_run_ledger_parent_is_not_a_directory", "default_session"),
        ("_run_ledger_digest_pin", "session_new"),
    ],
)
def test_each_fail_open_regression_is_reported_as_failure_not_as_accepted_security(
    monkeypatch, scenario, broken_component
):
    if broken_component == "append":
        monkeypatch.setattr(EvidenceLedger, "append", lambda *a, **kw: None)
    elif broken_component == "ledger_load":
        monkeypatch.setattr(EvidenceLedger, "load", lambda *a, **kw: EvidenceLedger())
    elif broken_component == "default_session":
        monkeypatch.setattr(demo_e2e, "_default_session", lambda **kw: object())
    elif broken_component == "policy_load":
        monkeypatch.setattr(policy, "load_policy", lambda *a, **kw: ([], []))
    elif broken_component == "wal_recover":
        monkeypatch.setattr(demo_e2e, "recover", lambda *a, **kw: None)
    elif broken_component == "session_new":
        monkeypatch.setattr(demo_e2e, "NomosGuardSession", lambda *a, **kw: object())

    outcome = getattr(demo_e2e, scenario)()
    assert outcome.refused is False, (scenario, outcome)
    assert outcome.fails_closed() is False
    assert outcome.detail
