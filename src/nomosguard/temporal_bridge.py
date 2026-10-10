"""Temporal bridge: wire time-window findings into the reasoning chain.

`temporal.py` finds patterns that exist only in the time dimension
(brute force, scan bursts, exfil bursts). On its own that is an
interesting fact — but it is NOT yet part of the attack graph.

This module closes the loop:

    raw log lines
      -> temporal rules          (deterministic time-window correlation)
      -> ledger claims           (each finding cited by the events that
                                  triggered it — the same evidence
                                  discipline as every other claim kind)
      -> registered extractors   (temporal claim kinds -> engine facts)
      -> rule engine             (new rules: brute force + reachability
                                  -> escalation candidate, etc.)
      -> policy gate             (ESCALATE / REVOKE_ACCESS / ALERT)

Nothing here is probabilistic. Same events + same rules -> same claims
-> same facts -> same decisions, always.
"""

from __future__ import annotations

from typing import Any

from .ledger import Claim
from .rules import Fact, register_extractor
from .temporal import TemporalResult, TemporalRule, evaluate_temporal

# claim kinds produced by temporal findings
CLAIM_KIND_PREFIX = "temporal_"


def temporal_claims(result: TemporalResult) -> list[Claim]:
    """Convert temporal findings into evidenced ledger claims.

    Each claim cites the rule that fired and the grouped events — the
    evidence field is deterministic and self-describing, so a reviewer
    can see exactly why the finding exists.
    """
    claims: list[Claim] = []
    for rule_name, detail in result.report.items():
        for subject in detail.get("fired_for", []):
            kind = f"{CLAIM_KIND_PREFIX}{rule_name}"
            evidence = (
                f"temporal rule {rule_name}: {subject} exceeded "
                f"{detail.get('threshold', '?')} events in window "
                f"({detail.get('groups', '?')} group(s) scanned)"
            )
            claims.append(
                Claim(
                    kind=kind,
                    payload={
                        "subject": subject,
                        "rule": rule_name,
                        "event_count": detail.get("event_count"),
                        "window_s": detail.get("window_s"),
                    },
                    evidence=evidence,
                )
            )
    return claims


# -- extractors: temporal claim kinds -> engine facts ------------------------
#
# A brute-force finding means an actor (the source) exhibited the
# behaviour. The fact model keeps it behavioural, not conclusive:
#     (actor, bruteForceDetected, brute_force)
# The rule engine then decides what that MEANS given the access graph.

@register_extractor("temporal_brute_force")
def _extract_brute_force(payload: dict[str, Any], evidence: str) -> list[Fact]:
    actor = str(payload.get("subject", ""))
    facts = []
    if actor:
        facts.append(Fact(actor, "bruteForceDetected", "brute_force", ("temporal_brute_force",)))
    return facts


@register_extractor("temporal_port_scan")
def _extract_port_scan(payload: dict[str, Any], evidence: str) -> list[Fact]:
    actor = str(payload.get("subject", ""))
    facts = []
    if actor:
        facts.append(Fact(actor, "scanDetected", "port_scan", ("temporal_port_scan",)))
    return facts


@register_extractor("temporal_exfil_burst")
def _extract_exfil_burst(payload: dict[str, Any], evidence: str) -> list[Fact]:
    actor = str(payload.get("subject", ""))
    facts = []
    if actor:
        facts.append(Fact(actor, "exfilSuspected", "exfiltration", ("temporal_exfil_burst",)))
    return facts


def run_temporal_into_ledger(
    lines: list[str],
    rules: list[TemporalRule] | None = None,
    ledger: Any = None,
) -> Any:
    """Run temporal rules and append their findings to a ledger.

    Returns (ledger, TemporalResult). If `ledger` is None a fresh one
    is created.
    """
    from .ledger import EvidenceLedger

    if ledger is None:
        ledger = EvidenceLedger()
    result = evaluate_temporal(lines, rules)
    for claim in temporal_claims(result):
        ledger.append(claim)
    return ledger, result
