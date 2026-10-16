"""Persisted evidence and write-ahead logs reject ambiguous JSON records."""

from __future__ import annotations

from pathlib import Path

import pytest

from nomosguard.ledger import (
    Claim,
    EvidenceLedger,
    LedgerFileError,
    _parse_line,
    ledger_digest,
)
from nomosguard.ledger_wal import WalError, _parse_wal_line


@pytest.fixture
def saved_ledger(tmp_path: Path) -> Path:
    path = tmp_path / "ledger.jsonl"
    ledger = EvidenceLedger()
    ledger.append(Claim("audit", {"verdict": "PASS"}, "observed result"))
    ledger.save(path)
    return path


@pytest.mark.parametrize(
    "needle,replacement",
    [
        ('"entries": 1', '"entries": 999, "entries": 1'),
        ('"head_hash": ', '"unknown": NaN, "head_hash": '),
        ('"entries": 1', '"entries": 1, "entries": 1'),
    ],
)
def test_ambiguous_header_is_never_trusted(
    saved_ledger: Path, needle: str, replacement: str
) -> None:
    original = saved_ledger.read_text(encoding="utf-8")
    assert needle in original
    saved_ledger.write_text(original.replace(needle, replacement, 1), encoding="utf-8")
    with pytest.raises(LedgerFileError, match="ledger header is not valid JSON"):
        EvidenceLedger.load(saved_ledger)


@pytest.mark.parametrize(
    "needle,replacement",
    [
        ('"claim": {', '"claim": null, "claim": {'),
        ('"payload": {', '"payload": null, "payload": {'),
        ('"verdict": "PASS"', '"verdict": "FAIL", "verdict": "PASS"'),
        ('"timestamp": ', '"extra": 1e9999, "timestamp": '),
    ],
)
def test_ambiguous_entry_is_not_misclassified_as_recoverable_tail(
    saved_ledger: Path, needle: str, replacement: str
) -> None:
    original = saved_ledger.read_text(encoding="utf-8")
    assert needle in original
    saved_ledger.write_text(original.replace(needle, replacement, 1), encoding="utf-8")
    # A matching digest of the *altered* bytes does not make the object safe:
    # duplicated fields are not a canonical, unique representation.
    with pytest.raises(LedgerFileError, match="invalid JSON content"):
        EvidenceLedger.load(
            saved_ledger,
            allow_torn_tail=True,
            expected_digest=ledger_digest(saved_ledger),
        )


@pytest.mark.parametrize(
    "record",
    [
        '{"seq":1,"seq":2}',
        '{"claim":{"kind":"a","kind":"b"}}',
        '{"seq":NaN}',
        '{"seq":1e9999}',
        '{"unicode":"\\ud800"}',
    ],
)
def test_wal_rejects_semantically_invalid_final_records(record: str) -> None:
    with pytest.raises(WalError, match="invalid JSON"):
        _parse_wal_line(record, 2, torn_allowed=True)


def test_ordinary_torn_wal_and_ledger_tail_are_still_recognized() -> None:
    assert _parse_wal_line('{"seq":', 2, torn_allowed=True) is None
    assert _parse_line('{"seq":', 2, "<test>", torn_allowed=True)["torn"] is True


def test_normal_multilingual_ledger_remains_recoverable(saved_ledger: Path) -> None:
    ledger = EvidenceLedger.load(saved_ledger)
    ledger.append(Claim("kontrol", {"dil": "Türkçe 日本語 😀"}, "açık kanıt"))
    ledger.save(saved_ledger)
    recovered = EvidenceLedger.load(saved_ledger, expected_digest=ledger_digest(saved_ledger))
    assert recovered.verify()[0] is True
    assert len(recovered.entries) == 2
