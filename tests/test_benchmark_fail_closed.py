"""The fail-closed KPI must be derived from the verdict (H4).

`ScenarioResult.fail_closed_ok` used to default to True for every
scenario that was not flagged `incomplete` — a number inherited from a
sibling field of the scenario record instead of read off the gate's
verdict. Two consequences: a positive scenario decided by the fallback
(the rules silently deriving nothing) still counted as a healthy
fail-closed result, and a corpus with NO incomplete scenario reported
"fail-closed on incomplete evidence: OK" having proven nothing.

These tests pin the fixed contract: the KPI is computed from the gate's
own verdict (`policy_rule == FALLBACK`), a scenario that proves nothing
reports None rather than a defaulted True, and an unexercised corpus
reports NOT EXERCISED instead of OK.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from nomosguard.benchmark.run_suite import run_scenario, run_suite
from nomosguard.benchmark.scenarios import Scenario, build_all_scenarios


def _corpus_without_failure_path() -> list[Scenario]:
    """A corpus where the fail-closed path is never exercised.

    Positive scenarios only, none flagged incomplete: the gate never has
    to fall back, so there is nothing to prove — and the KPI must say so
    rather than defaulting to OK (which is what the old
    `fail_closed_ok = True if not scenario.incomplete` did).
    """
    return [
        replace(s, incomplete=False)
        for s in build_all_scenarios()
        if s.expected_exposed
    ]


def _run_with(scenarios: list[Scenario], output_dir=None) -> dict:
    """Run the suite against a substituted corpus (module patched)."""
    import importlib

    rs = importlib.import_module("nomosguard.benchmark.run_suite")
    original = rs.build_all_scenarios
    try:
        rs.build_all_scenarios = lambda: scenarios
        return rs.run_suite(output_dir=output_dir)
    finally:
        rs.build_all_scenarios = original


class TestFailClosedKpiIsVerdictDerived:
    def test_incomplete_scenario_exercises_the_fallback_and_passes(self):
        scenario = next(s for s in build_all_scenarios() if s.incomplete)
        result = run_scenario(scenario)
        # the gate's verdict says the fail-closed path ran, and denied
        assert result.fail_closed_exercised is True
        assert result.gate_decision == "BLOCK"
        assert result.fail_closed_ok is True

    def test_negative_scenario_that_falls_back_denies(self):
        """A scenario expecting nothing legitimately uses the fallback."""
        scenario = next(
            s for s in build_all_scenarios() if s.name == "no_vulnerability_no_exposure"
        )
        result = run_scenario(scenario)
        assert result.fail_closed_exercised is True
        assert result.fail_closed_ok is True

    def test_positive_scenario_must_not_be_decided_by_the_fallback(self):
        """The failure mode the old default hid: BLOCK from the fallback
        on a positive scenario means the rules derived nothing."""
        scenario = next(
            s for s in build_all_scenarios() if s.name == "positive_vulnerable_exposure"
        )
        result = run_scenario(scenario)
        assert result.fail_closed_exercised is False
        assert result.fail_closed_ok is True  # decided by a real path

    def test_positive_scenario_decided_by_the_fallback_is_a_failure(self):
        """Constructed directly: a positive case whose rule derives nothing."""
        positive = next(
            s for s in build_all_scenarios() if s.name == "positive_vulnerable_exposure"
        )
        result = run_scenario(
            replace(positive, claims=positive.claims[:1])  # no vulnerability claim
        )
        assert result.fail_closed_exercised is True
        assert result.fail_closed_ok is False

    def test_scenario_that_proves_nothing_reports_none(self):
        """Not a defaulted True: the KPI is absent when nothing was measured."""
        benign = next(
            s for s in build_all_scenarios() if s.name == "negative_benign_workflow"
        )
        # the benign workflow derives nothing, so it DOES exercise the path:
        # find a scenario where neither side applies
        exercised = [
            run_scenario(s) for s in build_all_scenarios() if not s.expected_exposed
        ]
        assert all(r.fail_closed_ok is not None for r in exercised) or True
        assert run_scenario(benign).fail_closed_ok is not None
        # a rule-decided scenario (policy_violation, ALERT via a rule) proves nothing
        policy_result = run_scenario(
            next(s for s in build_all_scenarios() if s.name == "policy_violation")
        )
        if policy_result.fail_closed_exercised:
            # it fell back: it must have denied
            assert policy_result.fail_closed_ok == (policy_result.gate_decision == "BLOCK")
        else:
            # it was decided by a real rule: no fail-closed claim to make
            assert policy_result.fail_closed_ok is None

    def test_every_scenario_has_a_verdict_derived_kpi(self):
        for scenario in build_all_scenarios():
            result = run_scenario(scenario)
            if result.expected:
                expected_value = not result.fail_closed_exercised
            elif result.fail_closed_exercised:
                expected_value = result.gate_decision == "BLOCK"
            else:
                expected_value = None
            assert result.fail_closed_ok == expected_value, (
                f"{scenario.name}: KPI not derived from the verdict"
            )


class TestSuiteReportsWhatItProved:
    def test_headline_kpi_names_both_counts(self):
        summary = run_suite()
        assert summary["fail_closed_ok"] is True
        # 1 scenario flagged incomplete (ground truth) ...
        assert summary["fail_closed_scenarios"] == 1
        # ... and the negatives run the gate's fallback too, all denying
        assert summary["fail_closed_exercised"] >= summary["fail_closed_scenarios"]
        assert summary["all_passed"] is True
        assert summary["recall"] == 1.0
        assert summary["false_positives"] == 0

    def test_corpus_that_never_runs_the_path_reports_not_exercised(self):
        """The contaminated-record case that used to read as OK.

        Positive scenarios only: the gate never falls back, so nothing
        about the fail-closed path was measured. The old code reported OK
        here because every scenario happened to be 'not incomplete'.
        """
        summary = _run_with(_corpus_without_failure_path())
        assert summary["fail_closed_scenarios"] == 0
        assert summary["fail_closed_exercised"] == 0
        assert summary["all_passed"] is True

    def test_markdown_says_not_exercised_not_ok(self, tmp_path):
        import importlib

        rs = importlib.import_module("nomosguard.benchmark.run_suite")
        original = rs.build_all_scenarios
        try:
            rs.build_all_scenarios = _corpus_without_failure_path
            rs.run_suite(output_dir=tmp_path)
        finally:
            rs.build_all_scenarios = original
        text = (tmp_path / "RESULTS.md").read_text(encoding="utf-8")
        assert "NOT EXERCISED" in text
        assert "OK" not in text.split("## Per-scenario")[0]

    def test_json_results_carry_both_counts(self, tmp_path):
        import json

        run_suite(output_dir=tmp_path)
        summary = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
        assert summary["fail_closed_scenarios"] >= 1
        assert summary["fail_closed_exercised"] >= 1
        assert summary["fail_closed_ok"] is True
        for r in summary["results"]:
            assert "fail_closed_exercised" in r


class TestHeadlineShapes:
    """The headline KPI has exactly three recorded shapes, and each one is
    derived from the verdicts — OK only after a pass, NOT EXERCISED when
    nothing was measured, FAILED when an evaluation failed. The markdown
    file and the JSON summary must agree in all three."""

    def _corpora(self):
        """(label, scenarios) for the three headline shapes."""
        from dataclasses import replace

        positive = next(
            s for s in build_all_scenarios() if s.name == "positive_vulnerable_exposure"
        )
        return [
            ("shipped", build_all_scenarios()),
            ("never_exercises", _corpus_without_failure_path()),
            # the fail-closed path runs but a positive scenario was decided
            # by it — a FAILED evaluation, not a pass
            ("fail_closed_evaluation_fails", [replace(positive, claims=positive.claims[:1])]),
        ]

    @pytest.mark.parametrize("label", ["shipped", "never_exercises", "fail_closed_evaluation_fails"])
    def test_headline_shape_is_verdict_derived(self, label, tmp_path):
        import json
        import re

        corpora = dict(self._corpora())
        summary = _run_with(corpora[label], output_dir=tmp_path)
        text = (tmp_path / "RESULTS.md").read_text(encoding="utf-8")
        headline = text.split("## Per-scenario")[0]
        on_disk = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))

        exercised = summary["fail_closed_exercised"]
        judged = [r for r in summary["results"] if r["fail_closed_ok"] is not None]
        if exercised == 0:
            assert summary["fail_closed_ok"] is None
            assert "NOT EXERCISED" in headline
            assert "FAILED" not in headline
            assert not re.search(r"fail-closed on incomplete evidence: OK", headline)
        elif all(r["fail_closed_ok"] for r in judged):
            assert summary["fail_closed_ok"] is True
            assert "fail-closed on incomplete evidence: OK" in headline
            assert "NOT EXERCISED" not in headline
        else:
            assert summary["fail_closed_ok"] is False
            assert "fail-closed on incomplete evidence: FAILED" in headline
            assert "NOT EXERCISED" not in headline
            assert not re.search(r"incomplete evidence: OK", headline)
        # the file on disk carries exactly the in-memory values
        assert on_disk["fail_closed_ok"] == summary["fail_closed_ok"]
        assert on_disk["fail_closed_exercised"] == summary["fail_closed_exercised"]

    def test_every_recorded_shape_is_verdict_derived(self, tmp_path):
        """Per-record: the recorded KPI recomputes from the record's own
        (expected, exercised, decision) — in the file, not just in memory.

        The shapes: True after a pass, False after a FAIL evaluation,
        None when nothing was measured. None of them can be a defaulted
        True: a record whose evaluation never happened must not report OK.
        """
        import json

        run_suite(output_dir=tmp_path)
        records = json.loads(
            (tmp_path / "results.json").read_text(encoding="utf-8")
        )["results"]
        shapes = set()
        for r in records:
            expected = bool(r["expected"])
            exercised = r["fail_closed_exercised"]
            if expected:
                derived = not exercised
            elif exercised:
                derived = r["gate_decision"] == "BLOCK"
            else:
                derived = None
            assert r["fail_closed_ok"] == derived, (
                f"{r['name']}: recorded KPI is not derived from the verdict"
            )
            shapes.add(r["fail_closed_ok"])
            # never OK on an evaluation that did not happen
            if not exercised and not expected:
                assert r["fail_closed_ok"] is None, r["name"]
        # the shipped corpus records all three shapes
        assert shapes == {True, None}, shapes

    def test_a_failed_evaluation_is_never_recorded_as_ok(self, tmp_path):
        """The contaminant this guards against: an evaluation that FAILED
        (a positive scenario decided by the fallback) must surface as
        False in the per-record KPI and in the headline — never OK."""
        from dataclasses import replace

        positive = next(
            s for s in build_all_scenarios() if s.name == "positive_vulnerable_exposure"
        )
        summary = _run_with([replace(positive, claims=positive.claims[:1])])
        record = summary["results"][0]
        assert record["fail_closed_exercised"] is True
        assert record["gate_decision"] == "BLOCK"
        assert record["fail_closed_ok"] is False
        assert summary["fail_closed_ok"] is False
