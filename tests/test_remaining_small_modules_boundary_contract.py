"""Tight reference checks for the canonical demo and exact time/digest parsing."""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path

import pytest

from nomosguard import demo, temporal
from nomosguard.digest_pins import DigestPinError, resolve_digest_pin


def test_real_demo_produces_independently_verifiable_gate_decision() -> None:
    report = demo.run()
    assert report["ledger_verified"] is True
    assert report["entries"] == 2
    assert report["derived_facts"]
    assert report["gate_decision"]["decision"] == "BLOCK"


def test_direct_demo_entrypoint_is_readonly_and_json_serializable(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["nomosguard.demo"])
    runpy.run_module("nomosguard.demo", run_name="__main__")
    report = json.loads(capsys.readouterr().out)
    assert report["ledger_verified"] is True
    assert report["entries"] == 2


def test_temporal_invalid_calendar_day_is_not_coerced_to_event() -> None:
    assert temporal._to_seconds("2026-13-99T12:00:00 event") is None
    assert temporal._to_seconds("2026-10-17T14:52:11 event") is not None


def test_epoch_milliseconds_and_seconds_preserve_original_order() -> None:
    assert temporal._to_seconds("1729183930 event") == 1729183930
    assert temporal._to_seconds("1729183930000 event") == 1729183930
    assert temporal._to_seconds("not timestamped") is None
    assert temporal.TemporalResult().summary() == {"temporal_facts": 0}


def test_manifest_empty_and_named_entry_fail_closed(tmp_path: Path) -> None:
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text("# no digest data\n\n", encoding="utf-8")
    with pytest.raises(DigestPinError, match="empty"):
        resolve_digest_pin("@" + str(manifest))
    entry = "sha256:" + "c" * 64
    manifest.write_text(f"{entry} file.json\n")
    with pytest.raises(DigestPinError, match="no entry"):
        resolve_digest_pin(f"@{manifest}:missing.json")
    assert resolve_digest_pin(f"@{manifest}:file.json") == entry
    assert resolve_digest_pin(entry) == entry
    assert resolve_digest_pin(None) is None


def test_manifest_name_with_colon_uses_last_separator(tmp_path: Path) -> None:
    manifest = tmp_path / "name:with:colon.txt"
    digest = "sha256:" + "d" * 64
    manifest.write_text(f"{digest} source.json\n")
    assert resolve_digest_pin(f"@{manifest}:source.json") == digest
