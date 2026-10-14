"""CLI: ingest a JSONL log, derive paths, decide, explain.

Usage:
    python -m nomosguard.ingest.cli LOGFILE [--ledger PATH]
        [--log-kind toolcall|vuln|policy] [--security]
        [--ledger-digest sha256:<hex>|@MANIFEST]

The log is ingested into a ledger (in-memory unless --ledger is given),
the rule engine derives attack/access paths, and the fail-closed gate
produces a decision with its full derivation chain.

--log-kind selects the ingestion adapter (tool-call logs, CVE/vulnerability
records, or policy-rule records) — the same three adapters the library
exposes, reachable from the tool. --security selects the built-in security
rule set (tool-call + attack-graph rules), matching the MCP server
defaults. --ledger-digest pins the ledger file so a file that is not the
reviewed one (or a truncated one) is refused.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..constants import tool_call_gate_rules, tool_call_rules
from ..digest_pins import DigestPinError, resolve_digest_pin
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

    Thin wrapper over `nomosguard.digest_pins.resolve_digest_pin` that
    re-raises as the policy loader's error type.
    """
    try:
        return resolve_digest_pin(pin, noun="policy")
    except DigestPinError as exc:
        raise PolicyConfigError(str(exc)) from exc


def _security_rules() -> tuple[list[Rule], list[PolicyRule]]:
    """The built-in security set: tool-call + attack-graph rules + gate.

    The same composition the MCP server runs (`mcp_server.default_rules`
    / `default_policy_rules`), so the CLI and the MCP surface decide on
    one rule set instead of two dialects of it.
    """
    from ..mcp_server import default_policy_rules, default_rules

    return default_rules(), default_policy_rules()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nomosguard-ingest", description=__doc__)
    parser.add_argument("logfile", help="JSONL log to ingest")
    parser.add_argument(
        "--log-kind",
        choices=("toolcall", "vuln", "policy"),
        default="toolcall",
        help="Which ingestion adapter to use: tool-call records (default), "
        "CVE/vulnerability records, or policy-rule records.",
    )
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
        "--ledger-digest",
        default=None,
        help="Pin the ledger file by digest (sha256:<hex>, or @PATH to read "
        "it from a manifest file). Load fails closed on a mismatch; an "
        "unpinned truncated ledger is refused too.",
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
    parser.add_argument(
        "--security",
        action="store_true",
        help="Use the built-in security rule set (tool-call + attack-graph "
        "rules and containment gate) instead of the tool-call-only default "
        "— the same composition the MCP server runs. Cannot be combined "
        "with --policy.",
    )
    args = parser.parse_args(argv)

    from ..policy import PolicyConfigError, default_policy, load_policy

    try:
        if args.policy:
            if args.security:
                print(
                    "FATAL: --security selects the built-in security rule "
                    "set; it cannot be combined with --policy",
                    file=sys.stderr,
                )
                return 2
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
            if args.security:
                rules, gate_rules = _security_rules()
            else:
                rules, gate_rules = default_policy()
    except PolicyConfigError as exc:
        print(f"FATAL: refusing to run with a broken policy file: {exc}", file=sys.stderr)
        return 2

    try:
        ledger_digest = resolve_digest_pin(args.ledger_digest, noun="ledger")
    except DigestPinError as exc:
        print(f"FATAL: bad --ledger-digest pin: {exc}", file=sys.stderr)
        return 2
    if ledger_digest is not None and not args.ledger:
        print(
            "FATAL: --ledger-digest requires --ledger (the in-memory ledger "
            "is not a file)",
            file=sys.stderr,
        )
        return 2

    ledger_path = Path(args.ledger) if args.ledger else None
    try:
        if ledger_path is None:
            ledger = EvidenceLedger()
        elif ledger_path.is_file():
            ledger = EvidenceLedger.load(ledger_path, expected_digest=ledger_digest)
        elif args.require_ledger:
            # fail closed: a missing ledger is a broken configuration
            raise LedgerFileError(
                f"ledger file not found: {ledger_path} "
                "(drop --require-ledger to create it)"
            )
        elif ledger_digest is not None:
            # a pin names an existing file's bytes; creating a new ledger
            # under a pin would leave the pin silently unused
            raise LedgerFileError(
                f"ledger file not found: {ledger_path} (a digest pin cannot "
                "be applied to a ledger that is about to be created)"
            )
        else:
            _writable_ledger_target(ledger_path)
            ledger = EvidenceLedger()
    except LedgerFileError as exc:
        print(f"FATAL: refusing to load a ledger that does not verify: {exc}", file=sys.stderr)
        return 2

    try:
        if args.log_kind == "vuln":
            from .vuln_jsonl import ingest_vuln_jsonl

            result = ingest_vuln_jsonl(ledger, args.logfile)
        elif args.log_kind == "policy":
            from .policy_jsonl import ingest_policy_jsonl

            result = ingest_policy_jsonl(ledger, args.logfile)
        else:
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
