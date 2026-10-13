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
from ..mcp_server import _writable_ledger_target
from ..policy import PolicyConfigError
from ..rules import Rule, RuleEngine
from .toolcall_jsonl import IngestError, ingest_toolcall_jsonl


def default_rules() -> list[Rule]:
    """The canonical tool-call rule set (nomosguard.constants), not a copy."""
    return tool_call_rules()


def default_policy_rules() -> list[PolicyRule]:
    """The canonical gate rules for the tool-call vocabulary."""
    return tool_call_gate_rules()


def _resolve_policy_digest(pin: str | None) -> str | None:
    """Read a policy digest pin: `sha256:<hex>` or `@<manifest file>`.

    The manifest form is one `sha256:<hex>  <filename>` per line (comments
    allowed), which is what an operator commits next to the policy file and
    diffs in review — the digests travel with the corpus instead of living
    in code. `@file` selects the manifest's only entry; `@file:name`
    selects one by filename when the manifest holds several.
    """
    if pin is None:
        return None
    if not pin.startswith("@"):
        return pin
    manifest_ref = pin[1:]
    name: str | None = None
    # A ":" may also be a Windows drive letter (C:\...), so the split is
    # on the LAST colon, and only counts when what precedes it is a file.
    if ":" in manifest_ref:
        head, _, tail = manifest_ref.rpartition(":")
        if Path(head).is_file():
            manifest_ref, name = head, tail
    manifest = Path(manifest_ref)
    entries: dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        digest = parts[0]
        entry_name = parts[1] if len(parts) > 1 else ""
        entries[entry_name] = digest
    if not entries:
        raise PolicyConfigError(f"policy digest manifest is empty: {manifest}")
    if name is not None:
        if name not in entries:
            raise PolicyConfigError(
                f"policy digest manifest {manifest} has no entry for {name!r} "
                f"(has {sorted(entries)})"
            )
        return entries[name]
    if len(entries) > 1:
        raise PolicyConfigError(
            f"policy digest manifest {manifest} holds {len(entries)} entries; "
            f"name one with @{manifest}:<filename>"
        )
    return next(iter(entries.values()))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nomosguard-ingest", description=__doc__)
    parser.add_argument("logfile", help="JSONL tool-call log to ingest")
    parser.add_argument(
        "--ledger",
        default=None,
        help="Persistent ledger path. Created if absent (use --require-ledger "
        "to refuse a path that is not there yet).",
    )
    parser.add_argument(
        "--require-ledger",
        action="store_true",
        help="Refuse to start unless the ledger file already exists: a "
        "missing file is a configuration error, not an empty ledger.",
    )
    parser.add_argument(
        "--policy",
        default=None,
        help="Policy config file (JSON). Defaults to the built-in policy.",
    )
    parser.add_argument(
        "--policy-digest",
        default=None,
        help="Pin the policy file by digest (sha256:<hex>, or @PATH to read "
        "it from a manifest file). Load fails closed on a mismatch.",
    )
    args = parser.parse_args(argv)

    from ..policy import PolicyConfigError, default_policy, load_policy

    try:
        if args.policy:
            expected = _resolve_policy_digest(args.policy_digest)
            rules, gate_rules = load_policy(args.policy, expected_digest=expected)
        else:
            if args.policy_digest:
                print(
                    "FATAL: --policy-digest requires --policy (the built-in "
                    "policy is not a file)",
                    file=sys.stderr,
                )
                return 2
            rules, gate_rules = default_policy()
    except PolicyConfigError as exc:
        print(f"FATAL: refusing to run with a broken policy file: {exc}", file=sys.stderr)
        return 2

    ledger_path = Path(args.ledger) if args.ledger else None
    try:
        if ledger_path is None:
            ledger = EvidenceLedger()
        elif ledger_path.is_file():
            ledger = EvidenceLedger.load(ledger_path)
        elif args.require_ledger:
            # fail closed: a missing ledger is a broken configuration
            raise LedgerFileError(
                f"ledger file not found: {ledger_path} "
                "(drop --require-ledger to create it)"
            )
        else:
            _writable_ledger_target(ledger_path)
            ledger = EvidenceLedger()
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
