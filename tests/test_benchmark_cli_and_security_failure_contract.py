"""Independent benchmark command and security-metric verification."""

from __future__ import annotations

import importlib
import json
import runpy
import sys
from copy import deepcopy
from pathlib import Path

import pytest

benchmark_suite = importlib.import_module("nomosguard.benchmark.run_suite")
from nomosguard.benchmark import run_suite_main, security_main, security_run_suite
from nomosguard.benchmark.security_scenarios import build_security_scenarios


def test_security_suite_runs_real_security_scenarios_and_exports_results(
    tmp_path: Path,
) -> None:
    summary = security_run_suite.run_security_suite(output_dir=tmp_path / "artifacts")
    assert summary["all_passed"] is True
    assert summary["scenarios"] == len(build_security_scenarios())
    assert (
        summary["exec_code_recall"].split("/")[0]
        == summary["exec_code_recall"].split("/")[1]
    )
    assert (
        summary["can_access_recall"].split("/")[0]
        == summary["can_access_recall"].split("/")[1]
    )
    assert (
        summary["grants_recall"].split("/")[0] == summary["grants_recall"].split("/")[1]
    )
    assert summary["false_positives"] == 0
    serialized = json.loads(
        (tmp_path / "artifacts" / "security_results.json").read_text()
    )
    assert serialized["results"] == summary["results"]
    assert len(serialized["results"]) == summary["scenarios"]


def test_security_suite_detects_uncaught_derivation_and_false_positive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    pristine = security_run_suite.run_security_scenario
    altered = []

    def mutate(scenario):
        output = deepcopy(pristine(scenario))
        if output["exec_code_expected"]:
            output["exec_code_derived"] = set()
            altered.append(scenario.name)
        else:
            output["exec_code_derived"] = {("forged-host", "attacker")}
        return output

    monkeypatch.setattr(security_run_suite, "run_security_scenario", mutate)
    result = security_run_suite.run_security_suite(output_dir=tmp_path)
    assert altered
    assert result["all_passed"] is False
    assert result["false_positives"] > 0
    assert (
        result["exec_code_recall"].split("/")[0]
        != result["exec_code_recall"].split("/")[1]
    )
    assert any(row["passed"] is False for row in result["results"])
    assert (
        json.loads((tmp_path / "security_results.json").read_text())["all_passed"]
        is False
    )


@pytest.mark.parametrize("variant", ["empty", "wrong"])
def test_security_suite_empty_or_wrong_reference_is_explicit_failure(
    monkeypatch: pytest.MonkeyPatch,
    variant: str,
) -> None:
    if variant == "empty":
        monkeypatch.setattr(security_run_suite, "build_security_scenarios", list)
        result = security_run_suite.run_security_suite()
        assert result["exec_code_recall"] == "n/a"
        assert result["grants_recall"] == "n/a"
        assert result["scenarios"] == 0
        assert result["all_passed"] is False  # empty corpus cannot pass vacuously
    else:
        original = security_run_suite.run_security_scenario

        def tamper(scenario):
            payload = original(scenario)
            payload["can_access_derived"] = set()
            payload["grants_derived"] = set()
            return payload

        monkeypatch.setattr(security_run_suite, "run_security_scenario", tamper)
        result = security_run_suite.run_security_suite()
        assert result["all_passed"] is False


def test_nominal_benchmark_cli_writes_provenance_and_exits_zero(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        sys, "argv", ["run_suite_main.py", "--output", str(tmp_path / "benchmark")]
    )
    assert run_suite_main.main() == 0
    data = json.loads(capsys.readouterr().out)
    assert data["all_passed"] is True
    assert data["scenarios"] > 0
    assert (tmp_path / "benchmark" / "results.json").exists()
    assert (tmp_path / "benchmark" / "RESULTS.md").exists()


def test_security_cli_emits_truthful_summary_without_hidden_results(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        sys, "argv", ["security_main.py", "--output", str(tmp_path / "security")]
    )
    assert security_main.main() == 0
    data = json.loads(capsys.readouterr().out)
    assert data["all_passed"] is True
    assert "results" not in data
    assert (tmp_path / "security" / "security_results.json").is_file()


@pytest.mark.parametrize("module", [run_suite_main, security_main])
def test_cli_exits_nonzero_when_benchmark_fails(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    module: object,
) -> None:
    attr = "run_suite" if module is run_suite_main else "run_security_suite"
    summary = {
        "all_passed": False,
        "scenarios": 0,
        "recall": 0.0,
        "caught": 0,
        "expected_total": 1,
        "false_positives": 1,
        "fail_closed_ok": None,
        "fail_closed_scenarios": 0,
        "fail_closed_exercised": 0,
        "results": [],
    }
    monkeypatch.setattr(module, attr, lambda output_dir=None: summary)
    monkeypatch.setattr(sys, "argv", ["main.py"])
    assert module.main() == 1
    assert json.loads(capsys.readouterr().out)["all_passed"] is False


@pytest.mark.parametrize(
    ("module_path", "expected_file"),
    [
        ("nomosguard.benchmark.run_suite_main", "results.json"),
        ("nomosguard.benchmark.security_main", "security_results.json"),
    ],
)
def test_direct_python_module_entrypoints_execute_real_benchmarks(
    module_path: str,
    expected_file: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "module-run"
    monkeypatch.setattr(sys, "argv", ["-m", "--output", str(target)])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module(module_path, run_name="__main__")
    assert exc.value.code == 0
    assert (target / expected_file).is_file()


@pytest.mark.parametrize(
    ("exercised", "expected", "decision", "want"),
    [
        (0, 0, "BLOCK", "NOT EXERCISED"),
        (1, 0, "BLOCK", "exercised (BLOCK)"),
        (1, 1, "ALLOW", "exercised (should not have)"),
        (1, 0, "ALERT", "exercised"),
    ],
)
def test_benchmark_markdown_does_not_claim_unobserved_fail_closed_paths(
    exercised: int,
    expected: int,
    decision: str,
    want: str,
) -> None:
    report = benchmark_suite.run_suite()
    report["fail_closed_exercised"] = exercised
    report["fail_closed_scenarios"] = expected
    report["fail_closed_ok"] = bool(exercised and decision == "BLOCK")
    record = report["results"][0]
    record["fail_closed_exercised"] = bool(exercised)
    record["fail_closed_ok"] = bool(exercised)
    record["expected"] = [["target", "result"]] if expected else []
    record["gate_decision"] = decision
    assert want in benchmark_suite._render_markdown(report)
