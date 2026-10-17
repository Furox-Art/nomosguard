"""Write-ahead log corruption and recovery cases on isolated temporary files."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nomosguard import ledger_wal as wal
from nomosguard.ledger import Claim, EvidenceLedger, wal_path_for


def _ledger(n: int = 2) -> EvidenceLedger:
    ledger = EvidenceLedger()
    for i in range(n):
        ledger.append(
            Claim(
                "tool_call",
                {"agent": f"agent-{i}", "tool": "read", "target": "db"},
                f"independent observation {i}",
            )
        )
    return ledger


def _wal(path: Path, records: list[object]) -> Path:
    walfile = wal_path_for(path)
    walfile.write_text(
        "\n".join(json.dumps(r) if not isinstance(r, str) else r for r in records)
        + "\n",
        encoding="utf-8",
    )
    return walfile


@pytest.mark.parametrize(
    ("text", "torn", "raises"),
    [
        ("", False, False),
        ("  ", False, False),
        ('{"seq":1}', False, False),
        ('{"seq":1', True, False),
        ('{"seq":1', False, True),
        ('{"seq":1,"seq":2}', True, True),
        ("NaN", True, True),
        ("[]", True, True),
    ],
)
def test_single_wal_row_parser_rejects_ambiguous_content(
    text: str,
    torn: bool,
    raises: bool,
) -> None:
    if raises:
        with pytest.raises(wal.WalError):
            wal._parse_wal_line(text, 3, torn_allowed=torn)
    else:
        value = wal._parse_wal_line(text, 3, torn_allowed=torn)
        assert value is None or isinstance(value, dict)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ({"seq": True}, "seq must"),
        ({"seq": 9}, "sequence gap"),
        ({"prev_hash": "forged"}, "broken chain"),
        ({"entry_hash": "forged"}, "hash mismatch"),
        ({"timestamp": None}, "missing timestamp"),
        ({"claim": None}, "malformed claim"),
        ({"claim": {}}, "claim missing"),
        (
            {"claim": {"kind": "tool_call", "payload": {}, "evidence": ""}},
            "invalid claim",
        ),
    ],
)
def test_wal_recovery_refuses_corrupted_hash_chain_and_forged_metadata(
    tmp_path: Path,
    mutation: dict,
    expected: str,
) -> None:
    root = tmp_path / "evidence.jsonl"
    record = _ledger(1).entries[0].to_dict()
    record.update(mutation)
    _wal(root, [record])
    with pytest.raises(wal.WalError, match=expected):
        wal.recover(root)


def test_recovery_reports_torn_final_line_without_guessing(
    tmp_path: Path,
) -> None:
    root = tmp_path / "ledger.jsonl"
    ledger = _ledger(1)
    _wal(root, [ledger.entries[0].to_dict(), '{"missing"'])
    state = wal.recover(root)
    assert state.dropped == 1
    assert state.truncated_after == 1
    assert len(state.pending) == 1
    assert "torn" in state.detail


def test_recovery_refuses_torn_middle_row(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    first = _ledger(1).entries[0].to_dict()
    _wal(path, [first, '{"torn"', first])
    with pytest.raises(wal.WalError, match="not valid JSON"):
        wal.recover(path)


def test_recovery_pending_can_be_checkpointed_only_after_main_is_complete(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.jsonl"
    ledger = _ledger(2)
    assert wal.write_wal(path, ledger.entries) == 2
    assert wal.write_wal(path, ledger.entries) == 0
    state = wal.recover(path)
    assert len(state.pending) == 2
    with pytest.raises(wal.WalError, match="refusing to checkpoint"):
        wal.checkpoint(path)
    ledger.save(path)
    assert wal.checkpoint(path) == 2
    assert wal_path_for(path).read_text() == ""
    assert wal.recover(path).pending == []


def test_write_wal_skips_already_applied_main_rows(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    ledger = _ledger(2)
    first = _ledger(1)
    first.save(path)
    assert wal.write_wal(path, ledger.entries) == 1
    records = wal_path_for(path).read_text().splitlines()
    assert [json.loads(row)["seq"] for row in records] == [2]


@pytest.mark.parametrize(
    "payload",
    [
        '{"seq":1,"seq":2}\n',
        '{"seq":NaN}\n',
    ],
)
def test_write_wal_refuses_existing_ambiguous_records(
    tmp_path: Path,
    payload: str,
) -> None:
    path = tmp_path / "ledger.jsonl"
    wal_path_for(path).write_text(payload)
    with pytest.raises(wal.WalError, match="ambiguous or invalid"):
        wal.write_wal(path, _ledger(1).entries)


def test_bounded_checkpoint_handles_absent_wal(tmp_path: Path) -> None:
    assert wal.checkpoint(tmp_path / "missing.jsonl") == 0
    assert wal.recover(tmp_path / "missing.jsonl").pending == []


def test_durable_save_executes_main_and_checkpoint_atomically(tmp_path: Path) -> None:
    path = tmp_path / "ledger.jsonl"
    assert wal.durable_save(_ledger(2), path) == 2
    assert len(EvidenceLedger.load(path).entries) == 2
    assert wal_path_for(path).read_text() == ""


def test_durable_save_must_not_swallow_non_wal_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args):
        raise RuntimeError("underlying failure")

    monkeypatch.setattr(wal, "checkpoint", fail)
    with pytest.raises(RuntimeError, match="underlying failure"):
        wal.durable_save(_ledger(1), tmp_path / "ledger.jsonl")


def test_wal_scanner_refuses_unverified_metadata_instead_of_skipping_evidence(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.jsonl"
    existing = wal_path_for(path)
    existing.write_text("\n{}\n\n", encoding="utf-8")
    snapshot = existing.read_bytes()
    with pytest.raises(wal.WalError, match="claim"):
        wal.write_wal(path, _ledger(1).entries)
    assert existing.read_bytes() == snapshot


def test_recover_ignores_blank_wal_lines_but_rejects_unverifiable_record(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.jsonl"
    entries = _ledger(1)
    record = json.dumps(entries.entries[0].to_dict())
    wal_path_for(path).write_text("\n" + record + "\n\n", encoding="utf-8")
    assert len(wal.recover(path).pending) == 1


def test_torn_existing_wal_cannot_be_appended_to_without_recovery(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.jsonl"
    wal_path_for(path).write_text('{"seq":1', encoding="utf-8")
    with pytest.raises(wal.WalError, match="torn"):
        wal.write_wal(path, _ledger(1).entries)
    assert wal_path_for(path).read_text() == '{"seq":1'


@pytest.mark.parametrize(
    "forgery",
    [
        {"seq": 1},
        {"seq": True},
        {"seq": 1, "entry_hash": "fake"},
        {"seq": 1, "claim": None},
    ],
)
def test_spoofed_wal_sequence_cannot_suppress_a_real_append(
    tmp_path: Path,
    forgery: dict,
) -> None:
    target = tmp_path / "ledger.jsonl"
    forged_path = _wal(target, [forgery])
    snapshot = forged_path.read_bytes()
    with pytest.raises(wal.WalError):
        wal.write_wal(target, _ledger(1).entries)
    assert forged_path.read_bytes() == snapshot
