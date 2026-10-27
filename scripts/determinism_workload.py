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


LOG_LINES = [
    "[08:14:01] auth: src=203.0.113.77:1234 failed password for admin",
    "[08:14:05] auth: src=203.0.113.77:1234 failed password for admin",
    "[08:14:09] auth: src=203.0.113.77:1234 failed password for root",
    "[08:14:12] auth: src=203.0.113.77:1234 failed password for guest",
    "[08:14:18] auth: src=203.0.113.77:1234 failed password for deploy",
    "[08:15:02] fw: src=198.51.100.9:443 action=SCAN target=web01 dbytes=120",
    "[08:15:04] fw: src=198.51.100.9:443 action=SCAN target=web01 dbytes=121",
    "<134>Oct 27 08:16:00 host sshd[1]: Failed password for admin from 203.0.113.77 port 1234",
    "CEF:0|Acme|fw|1.0|100|scan|5|src=198.51.100.9 spt=443 dbytes=99",
    '{"time":"08:17:00","src":"203.0.113.77:1234","event":"failed password"}',
    "time=08:18:00 src=203.0.113.77:1234 event=failed password user=admin",
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

    from nomosguard.evidence_export import export_bundle, verify_export_bundle
    from nomosguard.gate import Decision, PolicyGate
    from nomosguard.hypothesis import HypothesisTracker
    from nomosguard.ledger import Claim, EvidenceLedger
    from nomosguard.log_normalize import normalize_logs
    from nomosguard.policy_security import containment_policy_rules
    from nomosguard.rules import RuleEngine
    from nomosguard.rules_security import security_rules
    from nomosguard.signatures import match_all
    from nomosguard.signatures_builtin import builtin_signatures
    from nomosguard.temporal import default_temporal_rules, evaluate_temporal

    ledger = EvidenceLedger()
    for kind, payload, evidence in SCENARIO:
        ledger.append(Claim(kind=kind, payload=payload, evidence=evidence))
    ok, _ = ledger.verify()

    engine = RuleEngine(rules=security_rules())
    engine.add_facts_from_ledger(ledger)
    engine.derive()

    gate = PolicyGate(policy_rules=containment_policy_rules(), fallback=Decision.ALERT)
    result = gate.evaluate_with_fallback(engine)

    # The model-free evidence sources (signature matcher, log normalization and
    # temporal rules) and the reproducible export bundle are documented as
    # byte-stable but were never sampled by the matrix. One fixed corpus keeps
    # their output order in the cross-OS payload.
    normalized = normalize_logs(LOG_LINES)
    matches = match_all(LOG_LINES, builtin_signatures())
    temporal = evaluate_temporal(LOG_LINES, default_temporal_rules())
    export_ledger = EvidenceLedger()
    for index, line in enumerate(LOG_LINES):
        export_ledger.append(
            Claim(
                kind="network",
                payload={"host": f"web{index % 3}", "port": 22},
                evidence=line,
            )
        )
    bundle = export_bundle(export_ledger)
    export_verdict = verify_export_bundle(bundle)

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
        "signatures": [
            [match.signature_id, match.line, list(match.captured)] for match in matches
        ],
        "normalized": normalized,
        "temporal": {
            "facts": [[key, relation, obj] for key, relation, obj in temporal.facts],
            "report": temporal.report,
        },
        "hypothesis": HypothesisTracker.from_engine(engine).summary(),
        "export": {
            "digest": bundle["digest"],
            "verified": export_verdict,
            "entries": bundle["metadata"]["entry_count"],
        },
    }
    if (
        not ok
        or payload["ledger_size"] != len(SCENARIO)
        or not payload["derived_facts"]
        or not payload["gate_decisions"]
    ):
        raise SystemExit("workload produced an unverifiable decision; it is vacuous")
    if (
        not matches
        or len(normalized) != len(LOG_LINES)
        or not temporal.facts
        or bundle["digest"] not in export_verdict
    ):
        raise SystemExit("a model-free evidence source produced nothing; it is vacuous")
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
