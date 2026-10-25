"""Deterministic security-pipeline workload sampled by the determinism matrix."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import sys
from pathlib import Path
from typing import Any

SCENARIO = [
    (
        "network",
        {
            "host": "web01",
            "protocol": "ssh",
            "port": 22,
            "allowed_from": "203.0.113.77",
        },
        "fw log line A",
    ),
    ("vuln_host", {"host": "web01", "cve": "CVE-2026-31142"}, "nvd line B"),
    (
        "network",
        {
            "host": "db02",
            "protocol": "postgres",
            "port": 5432,
            "allowed_from": "web01 (10.0.4.21)",
        },
        "netflow line C",
    ),
    ("exec_code", {"host": "web01", "user": "deploy"}, "iam line D"),
    (
        "network",
        {
            "host": "web02",
            "protocol": "https",
            "port": 443,
            "allowed_from": "203.0.113.77",
        },
        "fw log line E",
    ),
]


def _benchmark_digests() -> dict[str, str]:
    """Exercise both benchmark suites under a pinned SOURCE_DATE_EPOCH."""
    run_suite_module = importlib.import_module("nomosguard.benchmark.run_suite")
    from nomosguard.benchmark import security_run_suite

    previous = os.environ.get("SOURCE_DATE_EPOCH")
    os.environ["SOURCE_DATE_EPOCH"] = "1700000000"
    try:
        tool_call = run_suite_module.run_suite()
        security = security_run_suite.run_security_suite()
    finally:
        if previous is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = previous
    if not tool_call["all_passed"] or not security["all_passed"]:
        raise SystemExit("benchmark suites failed under the determinism workload")
    return {
        "tool_call_benchmark": hashlib.sha256(
            json.dumps(tool_call, sort_keys=True).encode("utf-8")
        ).hexdigest(),
        "security_benchmark": hashlib.sha256(
            json.dumps(security, sort_keys=True, default=list).encode("utf-8")
        ).hexdigest(),
    }


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root / "src"))

    # Security extractors register themselves on import; without this the engine
    # derives no facts from the ledger and the workload is vacuous.
    importlib.import_module("nomosguard.facts_security")

    from nomosguard.gate import Decision, PolicyGate
    from nomosguard.ledger import Claim, EvidenceLedger
    from nomosguard.policy_security import containment_policy_rules
    from nomosguard.rules import RuleEngine
    from nomosguard.rules_security import security_rules

    ledger = EvidenceLedger()
    for kind, payload, evidence in SCENARIO:
        ledger.append(Claim(kind=kind, payload=payload, evidence=evidence))
    ok, _ = ledger.verify()

    engine = RuleEngine(rules=security_rules())
    engine.add_facts_from_ledger(ledger)
    engine.derive()

    gate = PolicyGate(policy_rules=containment_policy_rules(), fallback=Decision.ALERT)
    result = gate.evaluate_with_fallback(engine)

    payload: dict[str, Any] = {
        "ledger_ok": ok,
        "ledger_size": len(ledger.entries),
        "ledger_hashes": [entry.entry_hash for entry in ledger.entries],
        "derived_facts": sorted(str(fact) for fact in engine.facts if fact.sources),
        "gate_decision": str(result["decision"]),
        "gate_decisions": sorted(
            (decision["subject"], str(decision["decision"]), decision["policy_rule"])
            for decision in result.get("all_decisions", [])
        ),
        "benchmark_digests": _benchmark_digests(),
    }
    if (
        not ok
        or payload["ledger_size"] != len(SCENARIO)
        or not payload["derived_facts"]
        or not payload["gate_decisions"]
    ):
        raise SystemExit("workload produced an unverifiable decision; it is vacuous")
    artifact_dir = os.environ.get("DETERMINISM_ARTIFACT_DIR")
    if artifact_dir:
        Path(artifact_dir, "payload.json").write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
            newline="\n",
        )
    print(json.dumps(payload, ensure_ascii=False))


if __name__ == "__main__":
    main()
