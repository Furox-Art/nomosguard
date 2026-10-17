"""Reference CLI edge cases: no missing pin, corrupt policy or absent ledger may pass."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

import pytest

from nomosguard.ingest.cli import main


@pytest.fixture
def valid_log(tmp_path: Path) -> Path:
    path = tmp_path / "records.jsonl"
    path.write_text('{"agent":"a","tool":"t","target":"db"}\n', encoding="utf-8")
    return path


def test_invalid_policy_digest_manifest_rejected(
    valid_log: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        main([str(valid_log), "--policy", "none", "--policy-digest", "sha256:invalid"])
        == 2
    )
    assert "FATAL" in capsys.readouterr().err


def test_broken_policy_json_refused_without_ledger_change(
    tmp_path: Path,
    valid_log: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "invalid-policy.json"
    path.write_text("{invalid json")
    ledger = tmp_path / "never-created.json"
    assert main([str(valid_log), "--policy", str(path), "--ledger", str(ledger)]) == 2
    assert "broken policy" in capsys.readouterr().err
    assert not ledger.exists()


def test_bad_ledger_digest_is_not_silently_ignored(
    valid_log: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([str(valid_log), "--ledger-digest", "sha256:broken"]) == 2
    assert "bad --ledger-digest" in capsys.readouterr().err


def test_required_ledger_must_preexist(
    tmp_path: Path,
    valid_log: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "missing-ledger.json"
    assert main([str(valid_log), "--ledger", str(path), "--require-ledger"]) == 2
    assert "ledger file not found" in capsys.readouterr().err
    assert not path.exists()


def test_missing_log_is_explicit_ingest_failure(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([str(tmp_path / "missing.jsonl")]) == 2
    assert "FATAL" in capsys.readouterr().err


def test_mixed_invalid_log_records_are_reported_with_line_number(
    valid_log: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    valid_log.write_text(
        '{"agent":"a","tool":"t","target":"db"}\n{"agent":"incomplete"}\n',
        encoding="utf-8",
    )
    assert main([str(valid_log)]) == 0
    capture = capsys.readouterr()
    assert "REJECTED line 2" in capture.err
    assert '"accepted": 1' in capture.out


def test_ingest_direct_module_guard_executes_and_returns_exit_status(
    valid_log: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "argv", ["ingest", str(valid_log)])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("nomosguard.ingest.cli", run_name="__main__")
    assert exc.value.code == 0


@pytest.mark.parametrize(
    "pin",
    [
        "",
        "sha256:",
        "sha256:0",
        "sha256:deadbeef",
        "md5:" + "0" * 32,
        "sha256:" + "z" * 64,
        "sha256:" + "0" * 63,
        "sha256:" + "0" * 65,
    ],
)
def test_invalid_inline_sha256_pins_are_rejected_before_io(pin: str) -> None:
    from nomosguard.digest_pins import DigestPinError, resolve_digest_pin

    with pytest.raises(DigestPinError, match="64 hexadecimal digits"):
        resolve_digest_pin(pin, noun="ledger")


@pytest.mark.parametrize("hex_digest", ["0" * 64, "a" * 64, "F" * 64])
def test_valid_inline_sha256_pins_retain_exact_value(hex_digest: str) -> None:
    from nomosguard.digest_pins import resolve_digest_pin

    pin = "sha256:" + hex_digest
    assert resolve_digest_pin(pin, noun="policy") == pin
