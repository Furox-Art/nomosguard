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

from ..constants import tool_call_gate_rules, tool_call_rules
from ..gate import Decision, PolicyGate, PolicyRule
from ..ledger import EvidenceLedger, LedgerFileError
from ..rules import Rule, RuleEngine
from .toolcall_jsonl import IngestError, ingest_toolcall_jsonl


def default_rules() -> list[Rule]:
    """The canonical tool-call rule set (nomosguard.constants), not a copy."""
    return tool_call_rules()


def default_policy_rules() -> list[PolicyRule]:
    """The canonical gate rules for the tool-call vocabulary."""
    return tool_call_gate_rules()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nomosguard-ingest", description=__doc__)
    parser.add_argument("logfile", help="JSONL tool-call log to ingest")
    parser.add_argument("--ledger", default=None, help="Persistent ledger path (created if absent)")
    parser.add_argument("--policy", default=None, help="Policy config file (JSON). Defaults to the built-in policy.")
    args = parser.parse_args(argv)

    from ..policy import PolicyConfigError, default_policy, load_policy

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
