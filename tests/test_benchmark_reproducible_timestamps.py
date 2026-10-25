"""Benchmark artifacts must be reproducible when SOURCE_DATE_EPOCH is set."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from nomosguard.benchmark import clock, security_run_suite

run_suite_module = importlib.import_module("nomosguard.benchmark.run_suite")

EPOCH = "1700000000"
EXPECTED = "2023-11-14T22:13:20+00:00"


def test_run_at_honors_source_date_epoch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", EPOCH)
    assert clock.run_at() == EXPECTED


def test_run_at_rejects_a_non_integer_source_date_epoch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "yesterday")
    with pytest.raises(ValueError, match="SOURCE_DATE_EPOCH"):
        clock.run_at()


def test_benchmark_artifacts_are_byte_identical_with_a_fixed_epoch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", EPOCH)
    first = tmp_path / "first"
    second = tmp_path / "second"

    summary = run_suite_module.run_suite(output_dir=first)
    security = security_run_suite.run_security_suite(output_dir=second)
    assert summary["run_at"] == EXPECTED
    assert security["run_at"] == EXPECTED

    # The second directory gets a full set from a separate invocation.
    run_suite_module.run_suite(output_dir=second)
    security_run_suite.run_security_suite(output_dir=first)

    for name in ("results.json", "RESULTS.md"):
        assert (first / name).read_bytes() == (second / name).read_bytes()
    assert (first / "security_results.json").read_bytes() == (
        second / "security_results.json"
    ).read_bytes()
