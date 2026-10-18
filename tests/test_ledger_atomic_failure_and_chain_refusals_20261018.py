"""Durable ledger write, strict JSON, tamper refusals and disk failure coverage."""

from __future__ import annotations

import dataclasses
import os
import stat
from pathlib import Path

import pytest

from nomosguard import ledger


def _claim(value):
    return ledger.Claim(kind="tool_call", payload={"action": value}, evidence=f"evidence:{value}")


def test_valid_finite_json_float_remains_numeric():
    assert ledger._finite_json_float("1.25") == 1.25
    assert ledger._strict_loads("{\"weight\":1.25}") == {"weight": 1.25}


def test_unreadable_ledger_digest_refuses_claim_of_integrity(tmp_path, monkeypatch):
    target = tmp_path / "ledger.jsonl"
    target.write_text("some data")
    actual = Path.read_bytes
    def deny(self, *args, **kwargs):
        if self == target:
            raise PermissionError("cannot read ledger")
        return actual(self, *args, **kwargs)
    monkeypatch.setattr(Path, "read_bytes", deny)
    with pytest.raises(ledger.LedgerFileError, match="cannot read ledger file"):
        ledger.ledger_digest(target)


def test_atomic_ledger_write_survives_directory_open_failure(tmp_path, monkeypatch):
    target = tmp_path / "ledger.jsonl"
    original = os.open
    def blocked(path, *args, **kwargs):
        if os.fspath(path) == str(tmp_path):
            raise PermissionError("directory fsync access refused")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(ledger.os, "open", blocked)
    ledger._atomic_write_lines(target, ["record"])
    assert target.read_text(encoding="utf-8") == "record\n"


def test_atomic_ledger_write_survives_directory_fsync_failure(tmp_path, monkeypatch):
    target = tmp_path / "ledger.jsonl"
    original = os.fsync
    def refuse_dir(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("directory flush denied")
        return original(fd)
    monkeypatch.setattr(ledger.os, "fsync", refuse_dir)
    ledger._atomic_write_lines(target, ["record"])
    assert target.read_text(encoding="utf-8") == "record\n"


def test_atomic_ledger_write_fails_without_replacing_target_on_rename_error(tmp_path, monkeypatch):
    target = tmp_path / "ledger.jsonl"
    target.write_text("original\n", encoding="utf-8")
    def fail(*args):
        raise OSError("rename denied")
    monkeypatch.setattr(ledger.os, "replace", fail)
    with pytest.raises(OSError, match="rename denied"):
        ledger._atomic_write_lines(target, ["new"])
    assert target.read_text() == "original\n"
    assert list(tmp_path.glob("*.tmp")) == []


def test_atomic_ledger_cleanup_error_never_hides_primary_failure(tmp_path, monkeypatch):
    target = tmp_path / "ledger.jsonl"
    def fail_replace(*args):
        raise OSError("original persist failure")
    def fail_unlink(*args):
        raise OSError("secondary cleanup failure")
    monkeypatch.setattr(ledger.os, "replace", fail_replace)
    monkeypatch.setattr(ledger.os, "unlink", fail_unlink)
    with pytest.raises(OSError, match="original persist failure"):
        ledger._atomic_write_lines(target, ["new"])


def test_non_object_final_ledger_line_is_torn_only_with_explicit_optin(tmp_path):
    raw = ledger._parse_line("[]", 2, tmp_path / "l.jsonl", torn_allowed=True)
    assert raw["torn"] is True
    assert raw["record"] is None
    with pytest.raises(ledger.LedgerFileError, match="not a JSON object"):
        ledger._parse_line("[]", 2, tmp_path / "l.jsonl", torn_allowed=False)


def test_empty_ledger_head_is_none_and_not_a_valid_record():
    state = ledger.EvidenceLedger()
    assert state.head is None
    assert state.head_hash == ""


def test_chain_sequence_tamper_is_detected():
    state = ledger.EvidenceLedger()
    state.append(_claim("read"))
    record = state._entries[0]
    state._entries[0] = dataclasses.replace(record, seq=3)
    ok, reason = state.verify()
    assert not ok
    assert "sequence broken" in reason


def test_chain_predecessor_tamper_is_detected_even_with_old_hash():
    state = ledger.EvidenceLedger()
    state.append(_claim("read"))
    state.append(_claim("write"))
    record = state._entries[1]
    state._entries[1] = dataclasses.replace(record, prev_hash="not-parent-hash")
    ok, reason = state.verify()
    assert not ok
    assert "prev_hash mismatch" in reason


def test_loading_existing_ledger_refuses_read_error(tmp_path, monkeypatch):
    target = tmp_path / "ledger.jsonl"
    state = ledger.EvidenceLedger()
    state.append(_claim("read"))
    state.save(target)
    original = Path.open
    def deny(self, *args, **kwargs):
        if self == target:
            raise PermissionError("existing but unreadable")
        return original(self, *args, **kwargs)
    monkeypatch.setattr(Path, "open", deny)
    with pytest.raises(ledger.LedgerFileError, match="cannot read ledger file"):
        ledger.EvidenceLedger.load(target)
