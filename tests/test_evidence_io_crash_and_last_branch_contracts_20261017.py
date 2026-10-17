"""Crash-injection checks verify ledger bytes and preserve original exception causes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nomosguard import ledger as ledger_module
from nomosguard.ledger import (
    Claim,
    EvidenceLedger,
    LedgerFileError,
    _atomic_write_lines,
    _finite_json_float,
)
from nomosguard.signature_bridge import run_signatures_into_ledger


def recorded_ledger(tmp_path):
    path = tmp_path / "recorded.jsonl"
    chain = EvidenceLedger()
    chain.append(Claim("tool_call", {"agent": "a", "tool": "b"}, "real evidence"))
    chain.save(path)
    return path


@pytest.mark.parametrize("literal", ["1e99999", "-1e99999"])
def test_ledger_scientific_number_overflow_does_not_become_accepted_infinity(literal):
    with pytest.raises(ValueError, match="non-finite JSON"):
        _finite_json_float(literal)


def test_ledger_empty_head_is_none_until_an_entry_is_recorded():
    chain = EvidenceLedger()
    assert chain.head is None
    assert chain.head_hash == ""
    assert chain.verify()[0] is True


def test_signature_bridge_can_create_a_new_empty_ledger_without_fake_matches():
    ledger, matches = run_signatures_into_ledger([], [])
    assert matches == []
    assert ledger.entries == ()


def test_atomic_writer_handles_dir_open_failure_without_changing_saved_bytes(
    monkeypatch, tmp_path
):
    path = tmp_path / "events.jsonl"
    old_open = ledger_module.os.open

    def fail_directory(fd_name, flags, *args, **kwargs):
        if str(fd_name) == str(tmp_path):
            raise OSError("directory fsync not supported")
        return old_open(fd_name, flags, *args, **kwargs)

    monkeypatch.setattr(ledger_module.os, "open", fail_directory)
    _atomic_write_lines(path, ['{"status":"audited"}'])
    assert json.loads(path.read_text()) == {"status": "audited"}


def test_atomic_writer_handles_dir_fsync_failure_as_nondurable_warning_path(
    monkeypatch, tmp_path
):
    path = tmp_path / "events.jsonl"
    fsync = ledger_module.os.fsync
    calls = []

    def inject_failure(fd):
        calls.append(fd)
        if len(calls) == 2:
            raise OSError("filesystem lacks directory fsync")
        return fsync(fd)

    monkeypatch.setattr(ledger_module.os, "fsync", inject_failure)
    _atomic_write_lines(path, ['{"status":"audited"}'])
    assert json.loads(path.read_text()) == {"status": "audited"}
    assert len(calls) == 2


def test_atomic_writer_cleans_tmp_after_replace_failure(monkeypatch, tmp_path):
    path = tmp_path / "events.jsonl"

    def simulated_crash(*a, **kw):
        raise OSError("simulated rename refusal")

    monkeypatch.setattr(ledger_module.os, "replace", simulated_crash)
    with pytest.raises(OSError, match="rename refusal"):
        _atomic_write_lines(path, ['{"status":"new"}'])
    assert not path.exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_atomic_writer_preserves_original_error_when_tmp_unlink_also_fails(
    monkeypatch, tmp_path
):
    path = tmp_path / "events.jsonl"

    def reject(*a, **kw):
        raise OSError("simulated rename refusal")

    monkeypatch.setattr(ledger_module.os, "replace", reject)
    monkeypatch.setattr(ledger_module.os, "unlink", reject)
    with pytest.raises(OSError, match="rename refusal"):
        _atomic_write_lines(path, ['{"status":"new"}'])
    assert not path.exists()
    assert len(list(tmp_path.glob("*.tmp"))) == 1


def test_ledger_load_fails_closed_on_read_error_after_existing_file_check(
    monkeypatch, tmp_path
):
    path = recorded_ledger(tmp_path)
    original = Path.open

    def deny_read(self, *a, **kw):
        if self == path:
            raise OSError("simulated unreadable")
        return original(self, *a, **kw)

    monkeypatch.setattr(Path, "open", deny_read)
    with pytest.raises(LedgerFileError, match="cannot read ledger file"):
        EvidenceLedger.load(path)


def test_finite_scientific_ledger_fraction_retains_exact_parsed_number():
    assert _finite_json_float("1.2345678901") == pytest.approx(1.2345678901)


def test_signature_bridge_respects_existing_evidence_ledger_identity():
    existing = EvidenceLedger()
    returned, matches = run_signatures_into_ledger([], [], ledger=existing)
    assert returned is existing
    assert matches == []
    assert returned.entries == ()
