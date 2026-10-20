#!/usr/bin/env python3
"""End-to-end demo: raw logs through the whole deterministic chain.

One incident, every layer of the system working together:

    raw telemetry (auth log + firewall log + NVD-backed vuln data)
      -> signature matching    (model-free pattern evidence)
      -> NVD enrichment        (real CVE severity)
      -> temporal correlation  (brute-force burst in the time dimension)
      -> rule engine           (MulVAL-style attack graph)
      -> policy gate           (fail-closed, evidence completeness)
      -> containment plan      (operator-reviewable action plan)

Run: python -m nomosguard.demo_e2e

The printed report is the actual tool output — nothing hand-written.
"""

from __future__ import annotations

import importlib
import json
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

# Register the security + temporal extractors at import time — without
# these, the engine has no extractor for `network` / `vuln_severity` /
# `temporal_*` claim kinds and the attack graph silently lacks the
# canAccessHost facts the brute-force rule needs.
from nomosguard.containment import render_plan
from nomosguard.gate import Decision, PolicyGate
from nomosguard.hypothesis import HypothesisTracker
from nomosguard.ingest.toolcall_jsonl import ingest_toolcall_jsonl
from nomosguard.ledger import (
    Claim,
    EvidenceLedger,
    LedgerFileError,
    UnevidencedClaimError,
    ledger_digest,
    wal_path_for,
)
from nomosguard.ledger_wal import WalError, recover
from nomosguard.mcp_server import NomosGuardSession
from nomosguard.policy import PolicyConfigError
from nomosguard.policy_security import containment_policy_rules
from nomosguard.rules import Pattern, Rule, RuleEngine
from nomosguard.rules_security import security_rules
from nomosguard.signatures import Match, match_all
from nomosguard.signatures_builtin import builtin_signatures
from nomosguard.temporal import default_temporal_rules
from nomosguard.temporal_bridge import run_temporal_into_ledger

importlib.import_module("nomosguard.facts_security")  # registers security extractors

# -- the incident -------------------------------------------------------------
# A single attacker (203.0.113.77) brute-forces web01, which carries a
# real CVE; the firewall lets them reach it; exfil-sized transfers start.

RAW_LOGS = [
    "[08:14:01] auth: src=203.0.113.77:1234 failed password for admin",
    "[08:14:05] auth: src=203.0.113.77:1234 failed password for root",
    "[08:14:09] auth: src=203.0.113.77:1234 failed password for admin",
    "[08:14:13] auth: src=203.0.113.77:1234 failed password for oracle",
    "[08:14:17] auth: src=203.0.113.77:1234 failed password for deploy",
    "[08:14:25] auth: src=203.0.113.77:1234 SUCCESS password for admin",
    "[08:20:11] netflow: src=web01:55122 dst=db02:5432 dbytes=3500000 state=ESTABLISHED",
    "[08:33:10] firewall: src=203.0.113.77 dst=web02:443 action=SCAN proto=tcp",
]

# Firewall policy (the network evidence, as an analyst would record it):
NETWORK_CLAIMS = [
    ("network", {"host": "web01", "protocol": "ssh", "port": 22,
                 "allowed_from": "203.0.113.77"},
     "firewall rule: 203.0.113.77 -> web01:22 allowed"),
    ("network", {"host": "web02", "protocol": "https", "port": 443,
                 "allowed_from": "203.0.113.77"},
     "firewall rule: 203.0.113.77 -> web02:443 allowed"),
]

# The vulnerability record: a real, CRITICAL CVE on web01.
VULN_CLAIMS = [
    ("vuln_severity", {"host": "web01", "cve": "CVE-2024-6387",
                       "cvss": 8.1, "severity": "HIGH"},
     "NVD: CVE-2024-6387 regreSSHion, CVSS 8.1 HIGH"),
]


def main() -> int:
    print("=" * 72)
    print("NOMOSGUARD — END-TO-END DEMO")
    print("=" * 72)
    print()
    print("Incident: brute force from 203.0.113.77 against web01 (real CVE),")
    print("firewall allows the path, large transfers begin. Raw logs below.")
    print()
    for ln in RAW_LOGS:
        print(f"  {ln}")
    print()

    # -- stage 1: signatures (model-free) -------------------------------------
    ledger = EvidenceLedger()
    sigs = builtin_signatures()
    by_id = {s.id: s for s in sigs}
    matches: list[Match] = match_all(RAW_LOGS, sigs)
    print(f"[1] signature matching: {len(matches)} match(es) from {len(sigs)} signatures")
    grouped: dict[str, int] = {}
    for m in matches:
        grouped[m.signature_id] = grouped.get(m.signature_id, 0) + 1
    for sid, count in sorted(grouped.items()):
        sig = by_id.get(sid)
        level = sig.level if sig else "?"
        title = sig.title if sig else "?"
        print(f"      {sid} [{level}] {title} — {count} line(s)")
    print()

    # -- stage 2: temporal correlation ----------------------------------------
    ledger, temporal = run_temporal_into_ledger(
        RAW_LOGS, default_temporal_rules(), ledger
    )
    fired = [
        (name, detail["fired_for"])
        for name, detail in temporal.report.items() if detail.get("fired_for")
    ]
    print(f"[2] temporal correlation: {len(fired)} pattern(s) in the time dimension")
    for name, subjects in fired:
        print(f"      {name}: {subjects}")
    print()

    # -- stage 3: network + vulnerability evidence ------------------------------
    for kind, payload, evidence in NETWORK_CLAIMS + VULN_CLAIMS:
        ledger.append(Claim(kind=kind, payload=payload, evidence=evidence))
    print(f"[3] evidence: {len(NETWORK_CLAIMS)} network rule(s), "
          f"{len(VULN_CLAIMS)} vulnerability record(s) — ledger holds "
          f"{len(ledger.entries)} entries, chain "
          f"{'VERIFIED' if ledger.verify()[0] else 'BROKEN'}")
    print()

    # -- stage 4: derive the attack graph ---------------------------------------
    engine = RuleEngine(rules=security_rules())
    engine.add_facts_from_ledger(ledger)
    engine.derive()
    derived = [f for f in engine.facts if f.sources]
    print(f"[4] attack graph: {len(derived)} derived fact(s)")
    for f in derived:
        print(f"      {f}")
    print()

    # -- stage 5: the gate decides -------------------------------------------------
    gate = PolicyGate(policy_rules=containment_policy_rules(),
                      fallback=Decision.ALERT)
    result = gate.evaluate_with_fallback(engine)
    print(f"[5] gate decision: {result['decision']}")
    for d in result.get("all_decisions", []):
        print(f"      {d['decision']}({d['subject']}) via {d['policy_rule']}")
    print(f"      missing evidence: {result['missing_evidence'] or 'none — chain complete'}")
    print()

    # -- stage 6: how many independent evidence chains? ---------------------------
    tracker = HypothesisTracker.from_engine(engine)
    strongest = tracker.strongest()
    if strongest:
        print(f"[6] strongest hypothesis: {strongest.fact} "
              f"({strongest.chain_count} independent chain(s))")
    else:
        print("[6] no hypothesis tracked")
    print()

    # -- stage 7: the containment plan -------------------------------------------------
    plan = render_plan(result)
    print(f"[7] containment plan ({plan['count']} command(s), dry-run):")
    for c in plan["commands"]:
        print(f"      {' '.join(c['argv'])}")
        print(f"        reason: {c['description']}")
        if c["undo"]:
            print(f"        undo:   {' '.join(c['undo'])}")
    print()
    print("=" * 72)
    print("The model never appears in this chain. Every step is deterministic;")
    print("the same logs always produce the same decision and plan.")
    print("=" * 72)
    failure_modes()
    return 0


# -- stage 8: the failure paths, as data ------------------------------------
#
# The demo used to claim "every failure mode fails closed" while exercising
# seven hand-written cases inline. The modes are now ONE registry: the demo
# prints it, tests/test_demo_e2e.py asserts it, and the README's fail-closed
# table is pinned to it (a documented mode without a scenario, or a scenario
# without a doc row, fails the suite). Adding a failure mode therefore means
# adding it in exactly one place.

#: The decisions a failure mode may produce and still count as failing
#: closed. A failure mode never yields ALLOW/ALERT/PASS: silence from the
#: chain is a denial, not a shrug.
FAIL_CLOSED_DECISIONS = frozenset({"BLOCK"})


@dataclass(frozen=True)
class FailureModeOutcome:
    """What came back when one failure mode was triggered.

    `refused` — the failure was refused/denied, not accepted.
    `decision` — the gate decision when one was produced (None when the
    failure was refused before any decision could be made); must be one
    of `FAIL_CLOSED_DECISIONS`.
    `ledger_entries` / `ledger_verified` — the ledger state after the
    failure, when a ledger was in play: the recorded evidence still
    verifies, so a refusal never quietly discards what came before.
    """

    refused: bool
    detail: str
    decision: str | None = None
    ledger_entries: int | None = None
    ledger_verified: bool = False

    def fails_closed(self) -> bool:
        if not self.refused:
            return False
        if self.decision is not None and self.decision not in FAIL_CLOSED_DECISIONS:
            return False
        return self.ledger_entries is None or self.ledger_verified


@dataclass(frozen=True)
class FailureModeScenario:
    """One documented failure mode and the code that triggers it."""

    name: str
    description: str
    run: Callable[[], FailureModeOutcome]


def _default_session(**kwargs) -> NomosGuardSession:
    from nomosguard.mcp_server import default_policy_rules, default_rules

    return NomosGuardSession(
        rules=default_rules(), policy_rules=default_policy_rules(), **kwargs
    )


def _seeded_ledger(path: Path, entries: int = 2) -> EvidenceLedger:
    """A small valid ledger, saved to `path`."""
    ledger = EvidenceLedger()
    ledger.append(Claim("tool_call", {"agent": "a", "tool": "t"}, "log line 1"))
    if entries > 1:
        ledger.append(Claim("tool_call", {"agent": "b", "tool": "t"}, "log line 2"))
    ledger.save(path)
    return ledger


# -- the scenario runners -----------------------------------------------------


def _run_unevidenced_claim() -> FailureModeOutcome:
    try:
        EvidenceLedger().append(Claim("tool_call", {"agent": "a", "tool": "t"}, ""))
    except UnevidencedClaimError as exc:
        return FailureModeOutcome(refused=True, detail=f"refused at append: {exc}")
    return FailureModeOutcome(refused=False, detail="ACCEPTED an unevidenced claim")


def _run_tampered_ledger_file() -> FailureModeOutcome:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ledger.jsonl"
        ledger = _seeded_ledger(path)
        records = [json.loads(line) for line in path.read_text().splitlines()]
        records[1]["claim"]["evidence"] = ""
        # keep the header's count and head hash: the file must be refused
        # on the CLAIM, not only on the chain
        path.write_text("\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n")
        try:
            EvidenceLedger.load(path)
        except LedgerFileError as exc:
            # the pre-tamper ledger is still what verifies: the refusal
            # never touches the evidence that was already recorded
            ok, _ = ledger.verify()
            return FailureModeOutcome(
                refused=True,
                detail=f"refused on load: {exc}",
                ledger_entries=len(ledger.entries),
                ledger_verified=ok,
            )
        return FailureModeOutcome(refused=False, detail="LOADED a tampered ledger")


def _run_missing_ledger_path() -> FailureModeOutcome:
    with tempfile.TemporaryDirectory() as td:
        missing = Path(td) / "never_created.jsonl"
        try:
            _default_session(ledger_path=missing)
        except LedgerFileError as exc:
            return FailureModeOutcome(refused=True, detail=f"refused at startup: {exc}")
        return FailureModeOutcome(refused=False, detail="STARTED EMPTY")


def _run_gate_with_no_derived_path() -> FailureModeOutcome:
    session = _default_session()
    result = session.decide()
    return FailureModeOutcome(
        refused=result["decision"] in FAIL_CLOSED_DECISIONS,
        detail=f"gate denied by default: {result['reason']}",
        decision=result["decision"],
        ledger_entries=len(session.ledger.entries),
        ledger_verified=session.ledger.verify()[0],
    )


def _run_policy_digest_pin() -> FailureModeOutcome:
    from nomosguard.policy import load_policy, policy_digest

    with tempfile.TemporaryDirectory() as td:
        policy_path = Path(td) / "policy.json"
        policy_path.write_text(json.dumps({
            "rules": [{
                "name": "r",
                "body": [["?a", "calls", "?t"]],
                "head": ["?a", "calls", "?t"],
            }],
            "gate": [{"name": "g", "match_relation": "calls", "decision": "BLOCK"}],
        }))
        pinned = policy_digest(policy_path)
        policy_path.write_text(json.dumps({
            "rules": [{
                "name": "r",
                "body": [["?a", "calls", "?t"]],
                "head": ["?a", "exposes", "?t"],
            }],
            "gate": [{"name": "g", "match_relation": "exposes", "decision": "ALERT"}],
        }))
        try:
            load_policy(policy_path, expected_digest=pinned)
        except PolicyConfigError as exc:
            return FailureModeOutcome(refused=True, detail=f"refused at load: {exc}")
        return FailureModeOutcome(refused=False, detail="LOADED an unpinned-for policy")


def _run_unknown_fallback_decision() -> FailureModeOutcome:
    session = _default_session()
    denied = session.decide(fallback="NOT_A_DECISION")
    ok = denied["denied"] and denied["decision"] in FAIL_CLOSED_DECISIONS
    return FailureModeOutcome(
        refused=ok,
        detail="denied at the boundary" if ok else f"{denied['decision']} (guessed!)",
        decision=denied["decision"],
        ledger_entries=len(session.ledger.entries),
        ledger_verified=session.ledger.verify()[0],
    )


def _run_uninterpretable_claim() -> FailureModeOutcome:
    session = _default_session()
    session.assert_claim(
        "policy_rule",
        {"subject": "a", "action": "sql", "resource": "db", "effect": "maybe"},
        "policy doc line 1",
    )
    denied = session.decide()
    ok = denied["denied"] and denied["decision"] in FAIL_CLOSED_DECISIONS
    return FailureModeOutcome(
        refused=ok,
        detail=(
            "refused at extraction" if ok else f"{denied['decision']} (coerced!)"
        ),
        decision=denied["decision"],
        ledger_entries=len(session.ledger.entries),
        ledger_verified=session.ledger.verify()[0],
    )


def _run_malformed_rule_set() -> FailureModeOutcome:
    bad = Rule(
        name="never_fires",
        body=(Pattern("?a", "calls", "?b"),),
        # head variables not bound in the body: the rule can never fire
        head=Pattern("?x", "exposes", "?y"),
    )
    session = NomosGuardSession(rules=[bad], policy_rules=[])
    result = session.decide()
    ok = result["denied"] and result["decision"] in FAIL_CLOSED_DECISIONS
    return FailureModeOutcome(
        refused=ok,
        detail=(
            f"denied at the boundary: {result['reason']}"
            if ok else f"{result['decision']} (raised!)"
        ),
        decision=result["decision"],
        ledger_entries=len(session.ledger.entries),
        ledger_verified=session.ledger.verify()[0],
    )


def _run_tampered_wal() -> FailureModeOutcome:
    import hashlib

    with tempfile.TemporaryDirectory() as td:
        ledger_path = Path(td) / "ledger.jsonl"
        ledger = _seeded_ledger(ledger_path, entries=1)
        # forge a WAL record that links cleanly to the ledger head: a
        # consistent chain is exactly what a re-hashing attacker produces
        claim = {"kind": "tool_call", "payload": {"agent": "c"}, "evidence": ""}
        body = json.dumps(
            {"seq": 2, "claim": claim, "prev_hash": ledger.head_hash},
            sort_keys=True,
            separators=(",", ":"),
        )
        entry_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        wal_path_for(ledger_path).write_text(
            json.dumps(
                {
                    "seq": 2,
                    "timestamp": "2026-01-01T00:00:00+00:00",
                    "claim": claim,
                    "entry_hash": entry_hash,
                    "prev_hash": ledger.head_hash,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        try:
            recover(ledger_path)
        except WalError as exc:
            ok, _ = ledger.verify()
            return FailureModeOutcome(
                refused=True,
                detail=f"refused at recovery: {exc}",
                ledger_entries=len(ledger.entries),
                ledger_verified=ok,
            )
        return FailureModeOutcome(refused=False, detail="REPLAYED a forged WAL record")


def _run_ledger_path_is_a_directory() -> FailureModeOutcome:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td)
        try:
            _default_session(ledger_path=path, create_if_missing=True)
        except LedgerFileError as exc:
            return FailureModeOutcome(refused=True, detail=f"refused at startup: {exc}")
        return FailureModeOutcome(refused=False, detail="STARTED on a directory path")


def _run_ledger_parent_is_not_a_directory() -> FailureModeOutcome:
    with tempfile.TemporaryDirectory() as td:
        # the parent of the configured path exists, but it is a FILE
        blocker = Path(td) / "blocker"
        blocker.write_text("not a directory\n", encoding="utf-8")
        path = blocker / "ledger.jsonl"
        try:
            _default_session(ledger_path=path, create_if_missing=True)
        except LedgerFileError as exc:
            return FailureModeOutcome(refused=True, detail=f"refused at startup: {exc}")
        return FailureModeOutcome(refused=False, detail="STARTED under a non-directory")


def _run_ledger_digest_pin() -> FailureModeOutcome:
    import hashlib

    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "ledger.jsonl"
        ledger = _seeded_ledger(path)
        pinned = ledger_digest(path)
        # a full, internally consistent REWRITE: every claim changed, every
        # hash re-sealed, the header recomputed — the chain alone cannot
        # see it (that is what a hash chain proves: records agree with
        # each other), the pin held outside the file can
        records = [json.loads(line) for line in path.read_text().splitlines()]
        header, body = records[0], records[1:]
        for record in body:
            record["claim"]["payload"]["agent"] = "attacker"
        prev_hash = ""
        for record in body:
            chain_body = json.dumps(
                {"seq": record["seq"], "claim": record["claim"], "prev_hash": prev_hash},
                sort_keys=True,
                separators=(",", ":"),
            )
            record["entry_hash"] = hashlib.sha256(chain_body.encode("utf-8")).hexdigest()
            record["prev_hash"] = prev_hash
            prev_hash = record["entry_hash"]
        header["head_hash"] = prev_hash
        path.write_text(
            "\n".join(json.dumps(r, sort_keys=True) for r in [header] + body) + "\n",
            encoding="utf-8",
        )

        try:
            NomosGuardSession(
                rules=security_rules(),
                policy_rules=containment_policy_rules(),
                ledger_path=path,
                ledger_digest=pinned,
            )
        except LedgerFileError as exc:
            # the pre-rewrite ledger is still what verifies: the refusal
            # never loaded the rewritten file, so nothing was replaced
            ok, _ = ledger.verify()
            return FailureModeOutcome(
                refused=True,
                detail=f"refused at startup: {exc}",
                ledger_entries=len(ledger.entries),
                ledger_verified=ok,
            )
        return FailureModeOutcome(
            refused=False, detail="STARTED against a rewritten ledger"
        )


def _run_malformed_log_line() -> FailureModeOutcome:
    with tempfile.TemporaryDirectory() as td:
        log_path = Path(td) / "log.jsonl"
        log_path.write_text(
            '{"agent": "a", "tool": "sql_query", "target": "db"}\n'  # ok
            '{"agent": "a", "tool": 7, "target": "db"}\n'           # tool: must be a string
            "not json at all\n",                                     # not an object
            encoding="utf-8",
        )
        session = _default_session()
        result = ingest_toolcall_jsonl(session.ledger, log_path)
        decision = session.decide()
        refused = (
            result.accepted == 1
            and len(result.rejected) == 2
            and all(r["reason"].startswith("line ") for r in result.rejected)
            and any("field" in r["reason"] for r in result.rejected)
            and decision["decision"] in FAIL_CLOSED_DECISIONS
        )
        return FailureModeOutcome(
            refused=refused,
            detail=(
                f"{len(result.rejected)} line(s) rejected with field+reason, "
                f"{result.accepted} accepted; gate denied"
                if refused
                else f"accepted={result.accepted}, rejected={len(result.rejected)}"
            ),
            decision=decision["decision"],
            ledger_entries=len(session.ledger.entries),
            ledger_verified=session.ledger.verify()[0],
        )


def failure_mode_scenarios() -> tuple[FailureModeScenario, ...]:
    """Every documented failure mode, as data — the single definition.

    Order is stable: the demo prints them in this order and the README's
    fail-closed table is cross-checked against these names.
    """
    return (
        FailureModeScenario(
            "unevidenced claim",
            "a claim asserted without an evidence fragment is refused at the ledger",
            _run_unevidenced_claim,
        ),
        FailureModeScenario(
            "tampered ledger file",
            "a saved ledger whose claim bodies are invalid is refused on load",
            _run_tampered_ledger_file,
        ),
        FailureModeScenario(
            "missing ledger path",
            "a configured ledger path that is not there refuses to start",
            _run_missing_ledger_path,
        ),
        FailureModeScenario(
            "gate with no derived path",
            "a gate with nothing derived denies by default",
            _run_gate_with_no_derived_path,
        ),
        FailureModeScenario(
            "policy bundle digest pin",
            "a policy file that is not the one you pinned is refused",
            _run_policy_digest_pin,
        ),
        FailureModeScenario(
            "unknown fallback decision",
            "an unknown decision name is refused, not guessed",
            _run_unknown_fallback_decision,
        ),
        FailureModeScenario(
            "uninterpretable claim",
            "a claim the extractors cannot read is refused, not coerced",
            _run_uninterpretable_claim,
        ),
        FailureModeScenario(
            "malformed rule set",
            "a malformed rule set denies at the SDK boundary instead of raising",
            _run_malformed_rule_set,
        ),
        FailureModeScenario(
            "tampered WAL",
            "a forged WAL record is refused at recovery, never replayed",
            _run_tampered_wal,
        ),
        FailureModeScenario(
            "ledger path is a directory",
            "a ledger path that is a directory refuses to start",
            _run_ledger_path_is_a_directory,
        ),
        FailureModeScenario(
            "ledger parent is not a directory",
            "a ledger path whose parent is not a directory refuses to start",
            _run_ledger_parent_is_not_a_directory,
        ),
        FailureModeScenario(
            "ledger digest pin",
            "a ledger file that is not the one you pinned is refused",
            _run_ledger_digest_pin,
        ),
        FailureModeScenario(
            "malformed log line",
            "a malformed log line is rejected with field + reason, never silently skipped",
            _run_malformed_log_line,
        ),
    )


def failure_modes() -> int:
    """Stage 8: the failure paths, exercised rather than asserted.

    The happy path above proves derivation works. This section proves the
    other half of the contract — that every documented failure mode fails
    CLOSED — by actually triggering each one from the single registry
    (`failure_mode_scenarios`) and printing what came back. Nothing here
    is a claim about behaviour: it is the behaviour. Returns non-zero if
    any mode stops failing closed.
    """
    print()
    print("=" * 72)
    print("STAGE 8: failure modes — each one is triggered here, not promised")
    print("=" * 72)
    failures: list[str] = []
    for scenario in failure_mode_scenarios():
        outcome = scenario.run()
        verdict = "OK" if outcome.fails_closed() else "FAIL"
        if verdict != "OK":
            failures.append(scenario.name)
        print(f"      [{verdict:4}] {scenario.name:32} -> {outcome.detail}")
    print()
    if failures:
        print(f"  FAILED: {len(failures)} failure mode(s) did not fail closed: {failures}")
        return 1
    print(
        f"  {len(failure_mode_scenarios())} failure modes exercised, "
        "all fail closed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
