"""Run the security benchmark corpus and measure containment decisions.

Measures (all from actual runs, never asserted):
- execCode recall:    caught / total expected code-execution facts
- canAccess recall:   caught / total expected access-path facts
- grants recall:      caught / total expected privilege facts
- false positives:    derived on scenarios expecting nothing
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..ledger import Claim, EvidenceLedger
from ..rules import RuleEngine
from ..rules_security import security_rules
from ..gate import Decision, PolicyGate
from ..policy_security import containment_policy_rules
from .. import facts_security  # noqa: F401  — registers the security extractors
from .security_scenarios import SecurityScenario, build_security_scenarios


def run_security_scenario(scenario: SecurityScenario) -> dict[str, Any]:
    ledger = EvidenceLedger()
    for spec in scenario.claims:
        ledger.append(Claim(kind=spec.kind, payload=spec.payload, evidence=spec.evidence))

    engine = RuleEngine(rules=security_rules())
    engine.add_facts_from_ledger(ledger)
    engine.derive()

    exec_code = {(f.subject, f.object) for f in engine.facts if f.relation == "execCode"}
    can_access = {(f.subject, f.object) for f in engine.facts if f.relation == "canAccessHost"}
    grants = {(f.subject, f.object) for f in engine.facts if f.relation == "grantsPrivilege"}

    gate = PolicyGate(policy_rules=containment_policy_rules(), fallback=Decision.ALERT)
    decisions = gate.evaluate(engine)

    return {
        "name": scenario.name,
        "exec_code_expected": set(scenario.expected_exec_code),
        "exec_code_derived": exec_code,
        "can_access_expected": set(scenario.expected_can_access),
        "can_access_derived": can_access,
        "grants_expected": set(scenario.expected_grants),
        "grants_derived": grants,
        "decisions": [d.decision.value for d in decisions],
    }


def run_security_suite(output_dir: str | Path | None = None) -> dict[str, Any]:
    scenarios = build_security_scenarios()
    results = [run_security_scenario(s) for s in scenarios]

    def recall(field: str):
        caught = sum(len(r[f"{field}_expected"] & r[f"{field}_derived"]) for r in results)
        total = sum(len(r[f"{field}_expected"]) for r in results)
        return caught, total

    ec_caught, ec_total = recall("exec_code")
    ca_caught, ca_total = recall("can_access")
    gr_caught, gr_total = recall("grants")

    false_positives = sum(
        1 for r in results
        if r["exec_code_expected"] == set() and r["exec_code_derived"] != set()
    )

    all_passed = all(
        r["exec_code_derived"] == r["exec_code_expected"]
        and r["can_access_derived"] == r["can_access_expected"]
        and r["grants_derived"] == r["grants_expected"]
        for r in results
    )

    summary = {
        "scenarios": len(results),
        "exec_code_recall": (f"{ec_caught}/{ec_total}" if ec_total else "n/a"),
        "can_access_recall": (f"{ca_caught}/{ca_total}" if ca_total else "n/a"),
        "grants_recall": (f"{gr_caught}/{gr_total}" if gr_total else "n/a"),
        "false_positives": false_positives,
        "all_passed": all_passed,
        "run_at": datetime.now(timezone.utc).isoformat(),
        "results": [
            {
                "name": r["name"],
                "exec_code": sorted(list(p) for p in r["exec_code_derived"]),
                "can_access": sorted(list(p) for p in r["can_access_derived"]),
                "grants": sorted(list(p) for p in r["grants_derived"]),
                "decisions": r["decisions"],
                "passed": (
                    r["exec_code_derived"] == r["exec_code_expected"]
                    and r["can_access_derived"] == r["can_access_expected"]
                    and r["grants_derived"] == r["grants_expected"]
                ),
            }
            for r in results
        ],
    }

    if output_dir is not None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "security_results.json").write_text(json.dumps(summary, indent=2, default=list), encoding="utf-8")

    return summary
