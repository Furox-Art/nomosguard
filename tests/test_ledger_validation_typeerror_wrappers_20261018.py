"""Persisted ledger/WAL claim validation errors cannot be laundered into evidence."""

from __future__ import annotations

import pytest

from nomosguard import ledger, ledger_wal


def _state():
    state = ledger.EvidenceLedger()
    state.append(ledger.Claim(kind="tool_call", payload={"agent": "alice", "tool": "db"}, evidence="source:log-1"))
    return state


def test_persisted_ledger_refuses_unexpected_type_error_in_claim_validation(tmp_path, monkeypatch):
    path = tmp_path / "ledger.jsonl"
    _state().save(path)

    def malformed_validation(self):
        raise TypeError("invalid stored claim value")

    monkeypatch.setattr(ledger.Claim, "validate", malformed_validation)
    with pytest.raises(ledger.LedgerFileError, match="malformed claim"):
        ledger.EvidenceLedger.load(path)


def test_wal_recovery_refuses_unexpected_type_error_in_claim_validation(tmp_path, monkeypatch):
    path = tmp_path / "ledger.jsonl"
    state = _state()
    assert ledger_wal.write_wal(path, state.entries) == 1

    def malformed_validation(self):
        raise TypeError("unexpected persisted claim shape")

    monkeypatch.setattr(ledger.Claim, "validate", malformed_validation)
    with pytest.raises(ledger_wal.WalError, match="malformed claim"):
        ledger_wal.recover(path)
