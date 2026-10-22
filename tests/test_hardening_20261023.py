"""Persisted-record strictness: bounded WAL reads and entry field validation."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from nomosguard import ledger_wal as wal
from nomosguard.ledger import (
    Claim,
    EvidenceLedger,
    LedgerFileError,
    wal_path_for,
)

CLAIM = Claim("tool_call", {"agent": "agent-0", "tool": "read"}, "observation 0")


def _ledger_bytes(
    *,
    timestamp: object = "2026-01-01T00:00:00+00:00",
    extra: dict | None = None,
) -> str:
    entry_hash = EvidenceLedger._entry_hash(1, CLAIM, "")
    record = {
        "seq": 1,
        "timestamp": timestamp,
        "claim": asdict(CLAIM),
        "entry_hash": entry_hash,
        "prev_hash": "",
    }
    if extra:
        record.update(extra)
    header = {
        "format": "nomosguard-ledger",
        "format_version": 1,
        "entries": 1,
        "head_hash": entry_hash,
    }
    return json.dumps(header) + "\n" + json.dumps(record) + "\n"


def _wal_record(
    *, timestamp: object = "2026-01-01T00:00:00+00:00", extra: dict | None = None
) -> dict:
    entry_hash = EvidenceLedger._entry_hash(1, CLAIM, "")
    record = {
        "seq": 1,
        "timestamp": timestamp,
        "claim": asdict(CLAIM),
        "entry_hash": entry_hash,
        "prev_hash": "",
    }
    if extra:
        record.update(extra)
    return record


def test_ledger_load_accepts_both_utc_designators(tmp_path: Path) -> None:
    for designator in ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00+00:00"):
        path = tmp_path / f"{designator[-1]}.jsonl"
        path.write_text(_ledger_bytes(timestamp=designator), encoding="utf-8")
        ledger = EvidenceLedger.load(path)
        assert ledger.entries[0].timestamp == designator


def test_ledger_load_refuses_naive_timestamp(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    path.write_text(
        _ledger_bytes(timestamp="2026-01-01T00:00:00"), encoding="utf-8"
    )
    with pytest.raises(LedgerFileError, match="ISO-8601 UTC"):
        EvidenceLedger.load(path)


def test_ledger_load_refuses_non_string_timestamp(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    path.write_text(_ledger_bytes(timestamp=123), encoding="utf-8")
    with pytest.raises(LedgerFileError, match="missing timestamp"):
        EvidenceLedger.load(path)


def test_ledger_load_refuses_unknown_entry_field(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    path.write_text(
        _ledger_bytes(extra={"note": "unhashed attacker-controlled field"}),
        encoding="utf-8",
    )
    with pytest.raises(LedgerFileError, match="unknown field"):
        EvidenceLedger.load(path)


def test_wal_recovery_refuses_naive_timestamp(tmp_path: Path) -> None:
    root = tmp_path / "ledger.jsonl"
    wal_path_for(root).write_text(
        json.dumps(_wal_record(timestamp="2026-01-01T00:00:00")) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(wal.WalError, match="ISO-8601 UTC"):
        wal.recover(root)


def test_wal_recovery_refuses_unknown_record_field(tmp_path: Path) -> None:
    root = tmp_path / "ledger.jsonl"
    wal_path_for(root).write_text(
        json.dumps(_wal_record(extra={"note": "forged"})) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(wal.WalError, match="unknown field"):
        wal.recover(root)


def test_wal_recovery_refuses_oversized_wal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(wal, "MAX_WAL_BYTES", 200)
    root = tmp_path / "ledger.jsonl"
    wal_path_for(root).write_text("#" * 150 + "\n" + "#" * 150 + "\n", encoding="utf-8")
    with pytest.raises(wal.WalError, match="WAL exceeds"):
        wal.recover(root)


def test_wal_recovery_refuses_single_oversized_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(wal, "MAX_WAL_BYTES", 200)
    root = tmp_path / "ledger.jsonl"
    wal_path_for(root).write_text("#" * 201 + "\n", encoding="utf-8")
    with pytest.raises(wal.WalError, match="WAL record exceeds"):
        wal.recover(root)
