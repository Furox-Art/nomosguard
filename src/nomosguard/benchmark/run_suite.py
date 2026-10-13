"""Run the benchmark corpus and measure recall / false-positive / fail-closed.

Every number in the results file comes from actually running the scenarios
through the real engine and gate. Nothing is hand-computed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..constants import tool_call_gate_rules, tool_call_rules
from ..gate import Decision, PolicyGate, PolicyRule
from ..ledger import Claim, EvidenceLedger
from ..rules import Rule, RuleEngine
from .scenarios import Scenario, build_all_scenarios


def default_rules() -> list[Rule]:
    """The canonical tool-call rule set (nomosguard.constants), not a copy."""
    return tool_call_rules()


def default_policy_rules() -> list[PolicyRule]:
    """The canonical gate rules for the tool-call vocabulary."""
    return tool_call_gate_rules()


@dataclass
class ScenarioResult:
    name: str
    expected: set
    derived: set
    passed: bool
    fail_closed_ok: bool
    gate_decision: str
    # Did the gate actually FALL BACK (the fail-closed path) on this
    # scenario? Derived from the verdict (`policy_rule == "FALLBACK"`),
    # never assumed. A KPI that says "fail-closed OK" without a fallback
    # having fired is a KPI reporting success on an evaluation that never
    # happened.
    fail_closed_exercised: bool = False


def run_scenario(scenario: Scenario) -> ScenarioResult:
    ledger = EvidenceLedger()
    for spec in scenario.claims:
        ledger.append(Claim(kind=spec.kind, payload=spec.payload, evidence=spec.evidence))

    engine = RuleEngine(rules=default_rules())
    engine.add_facts_from_ledger(ledger)
    engine.derive()

    derived = {
        (f.subject, f.object) for f in engine.facts if f.relation == "exposes"
    }
    gate = PolicyGate(policy_rules=default_policy_rules(), fallback=Decision.BLOCK)
    decision = gate.evaluate_with_fallback(engine)

    expected = set(scenario.expected_exposed)
    passed = derived == expected

    # The verdict itself says whether the fail-closed path ran: the gate
    # substitutes its fallback decision only when NO policy rule matched.
    exercised = decision["policy_rule"] == "FALLBACK"

    # fail-closed correctness is derived from the verdict for EVERY
    # scenario, in both directions:
    #   - an incomplete-evidence scenario MUST have fallen back to BLOCK
    #   - a scenario with evidence MUST NOT have fallen back (falling back
    #     there means the rules silently derived nothing)
    if scenario.incomplete:
        fail_closed_ok = exercised and decision["decision"] == "BLOCK"
    else:
        fail_closed_ok = not exercised

    return ScenarioResult(
        name=scenario.name,
        expected=expected,
        derived=derived,
        passed=passed,
        fail_closed_ok=fail_closed_ok,
        gate_decision=decision["decision"],
        fail_closed_exercised=exercised,
    )


def run_suite(output_dir: str | Path | None = None) -> dict[str, Any]:
    """Run every scenario, compute metrics, optionally write results files.

    Metrics (all measured, never asserted):
    - recall: caught positives / total expected positives
    - false_positive: derived on scenarios expecting nothing
    - fail_closed: incomplete-evidence scenarios that fell back to BLOCK

    `fail_closed_scenarios` reports HOW MANY scenarios exercised the
    fail-closed path, so the headline KPI cannot claim coverage it does
    not have: a corpus with zero such scenarios reports
    `fail_closed_ok: None` ("not exercised"), not OK.
    """
    scenarios = build_all_scenarios()
    results = [run_scenario(s) for s in scenarios]

    total_expected = sum(len(r.expected) for r in results)
    total_derived = sum(len(r.derived) for r in results)
    caught = sum(len(r.expected & r.derived) for r in results)
    false_positives = sum(
        1 for r in results if r.expected == set() and r.derived != set()
    )
    incomplete = [r for r in results if any(s.incomplete for s in scenarios if s.name == r.name)]
    fail_closed_ok = (
        all(r.fail_closed_ok for r in incomplete) if incomplete else None
    )

    recall = caught / total_expected if total_expected else 1.0

    summary = {
        "scenarios": len(results),
        "recall": recall,
        "caught": caught,
        "expected_total": total_expected,
        "derived_total": total_derived,
        "false_positives": false_positives,
        # None = "not exercised", never a claim of success
        "fail_closed_ok": fail_closed_ok,
        "fail_closed_scenarios": len(incomplete),
        "all_passed": all(r.passed for r in results),
        "run_at": datetime.now(timezone.utc).isoformat(),
        "results": [
            {
                "name": r.name,
                "expected": sorted(list(p) for p in r.expected),
                "derived": sorted(list(p) for p in r.derived),
                "passed": r.passed,
                "fail_closed_ok": r.fail_closed_ok,
                "fail_closed_exercised": r.fail_closed_exercised,
                "gate_decision": r.gate_decision,
            }
            for r in results
        ],
    }

    if output_dir is not None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        (out / "RESULTS.md").write_text(_render_markdown(summary), encoding="utf-8")

    return summary


def _render_markdown(summary: dict[str, Any]) -> str:
    if summary["fail_closed_ok"] is None:
        fail_closed = "NOT EXERCISED (0 scenarios)"
    elif summary["fail_closed_ok"]:
        fail_closed = f"OK ({summary['fail_closed_scenarios']} scenario(s))"
    else:
        fail_closed = "FAILED"
    lines = [
        "# NomosGuard benchmark results",
        "",
        f"Run at: {summary['run_at']}",
        f"Scenarios: {summary['scenarios']}",
        "",
        "## Metrics (measured, not asserted)",
        "",
        f"- recall: {summary['caught']}/{summary['expected_total']} = {summary['recall']:.1%}",
        f"- false positives: {summary['false_positives']}",
        f"- fail-closed on incomplete evidence: {fail_closed}",
        "",
        "## Per-scenario",
        "",
        "| scenario | expected | derived | passed | fail-closed |",
        "|---|---|---|---|---|",
    ]
    for r in summary["results"]:
        if r["fail_closed_exercised"]:
            exercised = "exercised (BLOCK)" if r["gate_decision"] == "BLOCK" else "exercised"
        else:
            exercised = "n/a"
        lines.append(
            f"| {r['name']} | {r['expected']} | {r['derived']} | "
            f"{'PASS' if r['passed'] else 'FAIL'} | {exercised} |"
        )
    return "\n".join(lines) + "\n"
