"""Signature bridge: wire signature matches into the reasoning chain.

`signatures.py` decides whether a log line matches a rule. On its own
that is a yes/no about a line — not yet part of the attack graph.

This module closes the loop, exactly as `temporal_bridge.py` does for
time-window findings:

    raw log lines
      -> signature matching     (deterministic regex, no model)
      -> ledger claims          (each match cited by the exact line that
                                 matched — the same evidence discipline as
                                 every other claim kind)
      -> registered extractors  (signature claim kinds -> engine facts)
      -> rule engine            (new rules: critical signature +
                                 reachability -> escalation candidate)
      -> policy gate            (ESCALATE / REVOKE_ACCESS / ALERT)

Nothing here is probabilistic. Same lines + same signatures -> same
claims -> same facts -> same decisions, always. There is no model call
anywhere in this path: the signature layer is an evidence source that
works with zero LLM involvement.

Evidence discipline (the rule that makes this auditable)
--------------------------------------------------------
Every claim produced here cites THE EXACT LINE IT MATCHED as its
evidence. Not a summary, not a pointer to a file and offset — the line
itself. A reviewer looking at a ledger entry can re-run the signature
against the quoted line and see it fire.

Claim payload convention
------------------------
    {
      "signature_id": sig.id,      # "NG-0003"
      "level":        sig.level,   # "critical"
      "logsource":    sig.logsource,
      "title":        sig.title,
      "status":       sig.status,
      "subject":      <src= value, or the whole line when none>
    }

`subject` is the actor the signature attached to. For the semi-structured
lines this project sees, that is the ``src=`` value when one exists and
the whole line otherwise — the whole line is a poor actor name but it is
an honest one, and it keeps the claim reviewable without inventing an
identity the line does not state.
"""

from __future__ import annotations

import re
from typing import Any

from .ledger import Claim
from .rules import Fact, register_extractor
from .signatures import Match, Signature, match_all
from .signatures_builtin import builtin_signatures

# claim kinds produced by signature matches: "signature_ng-0003"
CLAIM_KIND_PREFIX = "signature_"

# The source-address field, when a line has one. This is the pragmatic
# "who acted" for log lines that carry no structured actor field.
_SRC_RE = re.compile(r"src=(\S+)")

# claim kinds whose signature is critical-level -> also emit
# (actor, maliciousActivity, <title>)
MALICIOUS_ACTIVITY_LEVEL = "critical"


def claim_kind(signature_id: str) -> str:
    """The ledger claim kind for a signature id: ``signature_ng-0003``.

    Lowercased, per the claim-kind convention in this project
    (``temporal_brute_force``, ``signature_ng-0003``). The claim kind IS
    the namespace: two signatures with the same id would be
    indistinguishable in the ledger, which is why ids are unique.
    """
    return f"{CLAIM_KIND_PREFIX}{signature_id.lower()}"


def subject_of(line: str) -> str:
    """The actor a matched line attaches to.

    The ``src=`` value when the line has one (stripped of a trailing
    ``:port`` when present, so ``src=203.0.113.77:1234`` and
    ``src=203.0.113.77`` describe the same actor), otherwise the whole
    line.
    """
    m = _SRC_RE.search(line)
    if m is None:
        return line
    src = m.group(1)
    # strip a trailing :port — a source address is an actor, its port is not
    if ":" in src and src.rstrip().split(":")[-1].isdigit():
        src = src.rsplit(":", 1)[0]
    return src


def signature_claims(
    lines: list[str],
    sigs: list[Signature],
    matches: list[Match] | None = None,
) -> list[Claim]:
    """Convert signature matches into evidenced ledger claims.

    Each claim cites the exact matching line as its evidence. If
    `matches` is supplied it is used as-is (so a caller can run the
    matcher once and build claims from a filtered subset); otherwise the
    matcher is run here over (lines, sigs).
    """
    if matches is None:
        matches = match_all(lines, sigs)

    sigs_by_id = {sig.id: sig for sig in sigs}
    claims: list[Claim] = []
    for m in matches:
        sig = sigs_by_id.get(m.signature_id)
        if sig is None:
            # A match referencing a signature not in the set cannot be
            # described honestly, so it is skipped rather than guessed at.
            continue
        claims.append(
            Claim(
                kind=claim_kind(sig.id),
                payload={
                    "signature_id": sig.id,
                    "level": sig.level,
                    "logsource": sig.logsource,
                    "title": sig.title,
                    "status": sig.status,
                    "subject": subject_of(m.line),
                },
                evidence=m.line,
            )
        )
    return claims


# -- extractors: signature claim kinds -> engine facts ------------------------
#
# A signature match says an ACTOR (the src= of the matched line) exhibited
# the detected behaviour. The fact model stays behavioural, not conclusive:
#
#     (actor, signatureMatched, "NG-0003")
#
# For a critical-level signature, a second fact records that the behaviour
# is not merely detected but classified as malicious activity:
#
#     (actor, maliciousActivity, <signature title>)
#
# The rule engine then decides what that MEANS given the access graph. A
# signature fact never asserts compromise by itself — exactly the
# discipline the temporal extractors use for brute_force and port_scan.


def _extract_signature_claim(
    payload: dict[str, Any], evidence: str
) -> list[Fact]:
    """Extract facts from a signature-match claim.

    Payload convention (see the module docstring):
      {"signature_id": str, "level": str, "subject": str, "title": str, ...}

    Produces:
      (actor, signatureMatched, signature_id)
      and, when the signature is critical-level:
      (actor, maliciousActivity, title)

    Robustness contract: an unknown signature id does NOT crash. It is
    not this extractor's job to know the signature set — a claim
    referencing NG-9999 from a future rule set still yields the
    behavioural fact it describes. Only the critical-level extra fact
    depends on `level`, and a missing level simply means "not critical".
    """
    subject = str(payload.get("subject", "")).strip()
    if not subject:
        return []
    signature_id = str(payload.get("signature_id", "")).strip()
    if not signature_id:
        return []
    level = str(payload.get("level", "")).strip().lower()
    title = str(payload.get("title", "")).strip() or signature_id

    facts = [
        Fact(
            subject,
            "signatureMatched",
            signature_id,
            (claim_kind(signature_id),),
        )
    ]
    if level == MALICIOUS_ACTIVITY_LEVEL:
        facts.append(
            Fact(
                subject,
                "maliciousActivity",
                title,
                (claim_kind(signature_id),),
            )
        )
    return facts


# The claim kind is per-signature ("signature_ng-0003"), and
# rules._extract_facts dispatches on an EXACT kind match — there is no
# prefix dispatch and no fallback extractor. So the extractor is
# registered under every built-in signature's kind. A claim for an
# unknown id simply finds no registered extractor and yields no facts:
# that is the engine's existing contract for unrecognised claim kinds,
# and it is why the robustness test below uses the extractor directly.
for _sig in builtin_signatures():
    register_extractor(claim_kind(_sig.id))(_extract_signature_claim)


def run_signatures_into_ledger(
    lines: list[str],
    sigs: list[Signature],
    ledger: Any = None,
) -> Any:
    """Run signature matching and append the claims to a ledger.

    Returns (ledger, matches). If `ledger` is None a fresh one is
    created. Mirrors `temporal_bridge.run_temporal_into_ledger`.
    """
    from .ledger import EvidenceLedger

    if ledger is None:
        ledger = EvidenceLedger()
    matches = match_all(lines, sigs)
    for claim in signature_claims(lines, sigs, matches):
        ledger.append(claim)
    return ledger, matches
