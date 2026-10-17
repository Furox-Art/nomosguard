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

from .constants import (
    CLAIM_KIND_TEMPORAL_BRUTE_FORCE,
    CLAIM_KIND_TEMPORAL_EXFIL_BURST,
    CLAIM_KIND_TEMPORAL_PORT_SCAN,
    CLAIM_KIND_TEMPORAL_PREFIX,
)
from .ledger import Claim
from .rules import Fact, _string_field, register_extractor
from .temporal import (
    TemporalResult,
    TemporalRule,
    default_temporal_rules,
    evaluate_temporal,
)

# claim kinds produced by temporal findings
CLAIM_KIND_PREFIX = CLAIM_KIND_TEMPORAL_PREFIX


def temporal_claims(result: TemporalResult) -> list[Claim]:
    """Convert temporal findings into evidenced ledger claims.

    Each claim cites the rule that fired, the subject's own event count
    (from `fired_events`, never a rule-level maximum across other
    subjects), and the actual event lines that crossed the threshold —
    raw fragments, not a paraphrase, so the finding is reproducible from
    the claim's evidence alone.
    """
    claims: list[Claim] = []
    for rule_name, detail in result.report.items():
        fired_events = detail.get("fired_events", {})
        for subject in detail.get("fired_for", []):
            ev = fired_events.get(subject, {})
            count = ev.get("event_count", "?")
            lines = ev.get("lines", [])
            kind = f"{CLAIM_KIND_PREFIX}{rule_name}"
            evidence = (
                f"temporal rule {rule_name}: {subject} exceeded "
                f"{detail.get('threshold', '?')} events in window "
                f"({detail.get('groups', '?')} group(s) scanned, "
                f"{count} in the firing window); events: " + " | ".join(lines)
            )
            claims.append(
                Claim(
                    kind=kind,
                    payload={
                        "subject": subject,
                        "rule": rule_name,
                        "event_count": ev.get("event_count"),
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


@register_extractor(CLAIM_KIND_TEMPORAL_BRUTE_FORCE)
def _extract_brute_force(payload: dict[str, Any], evidence: str) -> list[Fact]:
    actor = _string_field(payload, "subject", CLAIM_KIND_TEMPORAL_BRUTE_FORCE)
    facts = []
    if actor and actor.strip():
        facts.append(
            Fact(
                actor,
                "bruteForceDetected",
                "brute_force",
                (CLAIM_KIND_TEMPORAL_BRUTE_FORCE,),
            )
        )
    return facts


@register_extractor(CLAIM_KIND_TEMPORAL_PORT_SCAN)
def _extract_port_scan(payload: dict[str, Any], evidence: str) -> list[Fact]:
    actor = _string_field(payload, "subject", CLAIM_KIND_TEMPORAL_PORT_SCAN)
    facts = []
    if actor and actor.strip():
        facts.append(
            Fact(actor, "scanDetected", "port_scan", (CLAIM_KIND_TEMPORAL_PORT_SCAN,))
        )
    return facts


@register_extractor(CLAIM_KIND_TEMPORAL_EXFIL_BURST)
def _extract_exfil_burst(payload: dict[str, Any], evidence: str) -> list[Fact]:
    actor = _string_field(payload, "subject", CLAIM_KIND_TEMPORAL_EXFIL_BURST)
    facts = []
    if actor and actor.strip():
        facts.append(
            Fact(
                actor,
                "exfilSuspected",
                "exfiltration",
                (CLAIM_KIND_TEMPORAL_EXFIL_BURST,),
            )
        )
    return facts


def run_temporal_into_ledger(
    lines: list[str],
    rules: list[TemporalRule] | None = None,
    ledger: Any = None,
) -> Any:
    """Run temporal rules and append their findings to a ledger.

    Returns (ledger, TemporalResult). If `ledger` is None a fresh one
    is created; if `rules` is None the built-in temporal rules are used
    (calling this without rules used to crash with a TypeError deep
    inside `evaluate_temporal`).
    """
    from .ledger import EvidenceLedger

    if ledger is None:
        ledger = EvidenceLedger()
    if rules is None:
        rules = default_temporal_rules()
    result = evaluate_temporal(lines, rules)
    for claim in temporal_claims(result):
        ledger.append(claim)
    return ledger, result
