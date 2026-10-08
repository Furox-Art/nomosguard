"""CLI: ingest a tool-call JSONL log, derive paths, decide, explain.

Usage:
    python -m nomosguard.ingest.toolcall_jsonl LOGFILE [--ledger PATH]

The log is ingested into a ledger (in-memory unless --ledger is given),
the rule engine derives attack/access paths, and the fail-closed gate
produces a decision with its full derivation chain.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..ledger import EvidenceLedger, LedgerFileError
from ..rules import Pattern, Rule, RuleEngine
from ..gate import Decision, PolicyGate, PolicyRule
from .toolcall_jsonl import ingest_toolcall_jsonl, IngestError


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nomosguard-ingest", description=__doc__)
    parser.add_argument("logfile", help="JSONL tool-call log to ingest")
    parser.add_argument("--ledger", default=None, help="Persistent ledger path (created if absent)")
    parser.add_argument("--policy", default=None, help="Policy config file (JSON). Defaults to the built-in policy.")
    args = parser.parse_args(argv)

    from ..policy import PolicyConfigError, load_policy, default_policy

    try:
        rules, gate_rules = load_policy(args.policy) if args.policy else default_policy()
    except PolicyConfigError as exc:
        print(f"FATAL: refusing to run with a broken policy file: {exc}", file=sys.stderr)
        return 2

    ledger_path = Path(args.ledger) if args.ledger else None
    try:
        ledger = EvidenceLedger.load(ledger_path) if ledger_path and ledger_path.is_file() else EvidenceLedger()
    except LedgerFileError as exc:
        print(f"FATAL: refusing to load a ledger that does not verify: {exc}", file=sys.stderr)
        return 2

    try:
        result = ingest_toolcall_jsonl(ledger, args.logfile)
    except IngestError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2

    print("=== Ingestion ===")
    print(json.dumps(result.to_dict(), indent=2))
    for rej in result.rejected:
        print(f"  REJECTED line {rej['line']}: {rej['reason']}", file=sys.stderr)

    if ledger_path is not None:
        ledger.save(ledger_path)
        print(f"ledger persisted to {ledger_path}")

    engine = RuleEngine(rules=rules)
    engine.add_facts_from_ledger(ledger)
    derivation = engine.derive()

    print("\n=== Derivation ===")
    print(json.dumps(derivation, indent=2, default=str))

    gate = PolicyGate(policy_rules=gate_rules, fallback=Decision.BLOCK)
    decision = gate.evaluate_with_fallback(engine)
    print("\n=== Decision ===")
    print(json.dumps(decision, indent=2, default=str))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
