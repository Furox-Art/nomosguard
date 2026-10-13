"""The fail-closed KPI must be derived from the verdict (H4).

`ScenarioResult.fail_closed_ok` used to default to True for every
scenario that was not flagged `incomplete` — a number inherited from a
sibling field of the scenario record, not read off the gate's verdict. A
suite with no incomplete scenario at all therefore reported
"fail-closed on incomplete evidence: OK" having proven nothing, and a
scenario whose evidence silently derived nothing still counted as a
healthy fail-closed result.

These tests pin the fixed contract: the KPI is computed from the gate's
own verdict (`policy_rule == FALLBACK`) for every scenario, in both
directions, and an unexercised corpus reports NOT EXERCISED rather than
OK.
"""

from __future__ import annotations

import importlib
from dataclasses import replace

import pytest

from nomosguard.benchmark.run_suite import run_scenario, run_suite
from nomosguard.benchmark.scenarios import Scenario, build_all_scenarios


def _corpus_without_failure_path() -> list[Scenario]:
    """The real corpus with its failure path stripped out.

    This is the contaminated record the old KPI could not see: every
    scenario now claims to be a normal one, so the corpus exercises the
    fail-closed path zero times.
    """
    return [replace(s, incomplete=False) for s in build_all_scenarios()]


class TestFailClosedKpiIsVerdictDerived:
    def test_incomplete_scenario_exercises_the_fallback_and_passes(self):
        scenario = next(s for s in build_all_scenarios() if s.incomplete)
        result = run_scenario(scenario)
        assert result.fail_closed_exercised is True
        assert result.fail_closed_ok is True
        assert result.gate_decision == "BLOCK"

    def test_scenario_with_evidence_must_not_fall_back(self):
        """A positive scenario that only BLOCKs by falling back is not a pass."""
        scenario = Scenario(
            name="synthetic_no_evidence",
            description="A tool call that derives nothing.",
            claims=build_all_scenarios()[0].claims[:1],
            expected_exposed=frozenset(),
            incomplete=False,
        )
        result = run_scenario(scenario)
        # the gate did fall back (no derived path) ...
        assert result.fail_closed_exercised is True
        # ... and this scenario did NOT claim to exercise the fallback,
        # so the KPI reports it rather than defaulting to True
        assert result.fail_closed_ok is False

    def test_positive_scenario_reports_no_fallback(self):
        scenario = next(
            s for s in build_all_scenarios() if s.name == "positive_vulnerable_exposure"
        )
        result = run_scenario(scenario)
        assert result.fail_closed_exercised is False
        assert result.fail_closed_ok is True
        assert result.gate_decision == "BLOCK"

    def test_every_scenario_has_a_verdict_derived_kpi(self):
        for scenario in build_all_scenarios():
            result = run_scenario(scenario)
            if scenario.incomplete:
                assert result.fail_closed_ok == (
                    result.fail_closed_exercised
                    and result.gate_decision == "BLOCK"
                ), f"{scenario.name}: KPI not derived from the verdict"
            else:
                assert result.fail_closed_ok == (
                    not result.fail_closed_exercised
                ), f"{scenario.name}: KPI not derived from the verdict"


class TestSuiteReportsWhatItProved:
    def test_headline_kpi_names_the_scenario_count(self):
        summary = run_suite()
        assert summary["fail_closed_ok"] is True
        assert summary["fail_closed_scenarios"] == 1
        assert summary["all_passed"] is True

    def test_corpus_without_failure_scenarios_reports_not_exercised(self):
        """The contaminated-record case that used to read as OK."""
        summary = run_suite()
        assert summary["fail_closed_scenarios"] == 1  # the real corpus

        # the same corpus with the failure path removed: the KPI must NOT
        # claim success it did not measure
        rs = importlib.import_module("nomosguard.benchmark.run_suite")

        original = rs.build_all_scenarios
        try:
            rs.build_all_scenarios = lambda: _corpus_without_failure_path()
            summary = rs.run_suite()
        finally:
            rs.build_all_scenarios = original
        assert summary["fail_closed_ok"] is None
        assert summary["fail_closed_scenarios"] == 0
        assert summary["all_passed"] is True

    def test_markdown_says_not_exercised_not_ok(self, tmp_path):
        rs = importlib.import_module("nomosguard.benchmark.run_suite")

        original = rs.build_all_scenarios
        try:
            rs.build_all_scenarios = lambda: _corpus_without_failure_path()
            rs.run_suite(output_dir=tmp_path)
        finally:
            rs.build_all_scenarios = original
        text = (tmp_path / "RESULTS.md").read_text(encoding="utf-8")
        assert "NOT EXERCISED" in text
        assert "OK" not in text.split("## Per-scenario")[0]

    def test_json_results_carry_the_count(self, tmp_path):
        import json

        run_suite(output_dir=tmp_path)
        summary = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
        assert summary["fail_closed_scenarios"] >= 1
        assert summary["fail_closed_ok"] is True
        for r in summary["results"]:
            assert "fail_closed_exercised" in r
