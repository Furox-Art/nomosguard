"""Run the benchmark corpus and measure recall / false-positive / fail-closed.

Every number in the results file comes from actually running the scenarios
through the real engine and gate. Nothing is hand-computed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..ledger import Claim, EvidenceLedger
from ..rules import Pattern, Rule, RuleEngine
from ..gate import Decision, PolicyGate, PolicyRule
from .scenarios import Scenario, build_all_scenarios


def default_rules() -> list[Rule]:
    return [
        Rule(
            name="tool_on_vulnerable_component",
            body=(
                Pattern("?agent", "calls", "?tool"),
                Pattern("?agent", "operates_on", "?component"),
                Pattern("?component", "has_vulnerability", "?cve"),
            ),
            head=Pattern("?agent", "exposes", "?component"),
            description="An agent operating a tool on a vulnerable component exposes it.",
            ),
            Rule(
                name="reaches_base",
                body=(Pattern("?from", "operates_on", "?to"),),
                head=Pattern("?from", "reaches", "?to"),
                description="Direct operation implies reachability.",
            ),
            Rule(
                name="reaches_transitive",
                body=(
                    Pattern("?from", "reaches", "?mid"),
                    Pattern("?mid", "reaches", "?to"),
                ),
                head=Pattern("?from", "reaches", "?to"),
                description="Transitive reachability: X reaches Z when X reaches Y and Y reaches Z.",
            ),
            Rule(
                name="transitive_exposure",
                body=(
                    Pattern("?agent", "calls", "?tool"),
                    Pattern("?agent", "reaches", "?component"),
                    Pattern("?component", "has_vulnerability", "?cve"),
                ),
                head=Pattern("?agent", "exposes", "?component"),
                description="An agent that can reach a vulnerable component (directly or through a chain) exposes it.",
            ),
        Rule(
            name="policy_denied_action",
            body=(
                Pattern("?agent", "calls", "?tool"),
                Pattern("?agent", "policy_denies", "?action"),
            ),
            head=Pattern("?agent", "violates", "policy"),
            description="An agent calling a tool whose action is policy-denied violates policy.",
        ),
    ]


def default_policy_rules() -> list[PolicyRule]:
    return [
        PolicyRule(
            name="block_vulnerable_exposure",
            match_relation="exposes",
            decision=Decision.BLOCK,
            description="Exposure of a vulnerable component is blocked.",
        ),
        PolicyRule(
            name="alert_policy_violation",
            match_relation="violates",
            decision=Decision.ALERT,
            description="Policy violations raise an alert.",
        ),
    ]


@dataclass
class ScenarioResult:
    name: str
    expected: set
    derived: set
    passed: bool
    fail_closed_ok: bool
    gate_decision: str


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

    # fail-closed correctness: with no derived path the gate must BLOCK
    fail_closed_ok = True
    if scenario.incomplete:
        fail_closed_ok = (
            derived == set()
            and decision["decision"] == "BLOCK"
            and decision["policy_rule"] == "FALLBACK"
        )

    return ScenarioResult(
        name=scenario.name,
        expected=expected,
        derived=derived,
        passed=passed,
        fail_closed_ok=fail_closed_ok,
        gate_decision=decision["decision"],
    )


def run_suite(output_dir: str | Path | None = None) -> dict[str, Any]:
    """Run every scenario, compute metrics, optionally write results files.

    Metrics (all measured, never asserted):
    - recall: caught positives / total expected positives
    - false_positive: derived on scenarios expecting nothing
    - fail_closed: incomplete-evidence scenarios that fell back to BLOCK
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
    fail_closed_ok = all(r.fail_closed_ok for r in incomplete) if incomplete else True

    recall = caught / total_expected if total_expected else 1.0

    summary = {
        "scenarios": len(results),
        "recall": recall,
        "caught": caught,
        "expected_total": total_expected,
        "derived_total": total_derived,
        "false_positives": false_positives,
        "fail_closed_ok": fail_closed_ok,
        "all_passed": all(r.passed for r in results),
        "run_at": datetime.now(timezone.utc).isoformat(),
        "results": [
            {
                "name": r.name,
                "expected": sorted(list(p) for p in r.expected),
                "derived": sorted(list(p) for p in r.derived),
                "passed": r.passed,
                "fail_closed_ok": r.fail_closed_ok,
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
        f"- fail-closed on incomplete evidence: {'OK' if summary['fail_closed_ok'] else 'FAILED'}",
        "",
        "## Per-scenario",
        "",
        "| scenario | expected | derived | passed |",
        "|---|---|---|---|",
    ]
    for r in summary["results"]:
        lines.append(
            f"| {r['name']} | {r['expected']} | {r['derived']} | {'PASS' if r['passed'] else 'FAIL'} |"
        )
    return "\n".join(lines) + "\n"
