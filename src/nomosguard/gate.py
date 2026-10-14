"""Fail-closed policy gate.

The gate consumes the rule engine's derived facts and produces one of
three decisions: ALLOW, ALERT, BLOCK. It applies policy rules to the
derived attack/access paths.

The fail-closed discipline (the whole point of the project):

1. When evidence is incomplete, the gate does NOT default to allow.
   It defaults to the configured fallback decision, which for security
   contexts is BLOCK.
2. Every decision carries the full derivation chain — which facts, which
   rules, which policy rule produced it. A decision without a chain is
   not a decision; it is an accident.
3. The gate never consults a language model. If the explanation layer
   (elsewhere) disagrees with the chain, the chain wins.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .rules import Fact, RuleEngine


class Decision(str, Enum):
    ALLOW = "ALLOW"
    ALERT = "ALERT"
    BLOCK = "BLOCK"
    # security containment decisions (MulVAL-style attack response)
    ISOLATE_HOST = "ISOLATE_HOST"
    REVOKE_ACCESS = "REVOKE_ACCESS"
    ESCALATE = "ESCALATE"


class GateDenied(ValueError):
    """Raised when the gate cannot produce a decision it can defend.

    This is the gate refusing to *invent* a decision — an unknown
    fallback, a decision name it does not recognise. It is deliberately a
    typed error so an SDK caller can distinguish "the gate denied because
    it refused to guess" from an arbitrary crash; the SDK boundary
    (NomosGuardSession) converts it into a fail-closed GateResult instead
    of letting it escape to the caller.
    """


def resolve_decision(value: Any, *, field: str = "decision") -> Decision:
    """Coerce a decision name to a Decision, or refuse loudly.

    Accepts a Decision as-is and a string naming one. Anything else — a
    typo, a number, a name the gate does not know — raises GateDenied
    rather than defaulting to ALLOW. A gate that guesses is a gate that
    can be walked through by a misspelling.
    """
    if isinstance(value, Decision):
        return value
    if isinstance(value, str):
        try:
            return Decision(value)
        except ValueError:
            pass
    allowed = sorted(d.value for d in Decision)
    from .schema import msg_enum

    raise GateDenied(msg_enum("gate", field, allowed, value))


@dataclass(frozen=True)
class PolicyRule:
    """A gate rule: if a derived fact matches, emit this decision.

    `match_relation` matches the derived fact's relation; `match_object`
    (optional) further constrains the object. `decision` is emitted.

    `requires` lists the claim kinds that must be present for this
    decision to be considered complete. A decision derived without them
    is flagged with `missing_evidence` — it may be correct, but the
    chain is thinner than the policy demands.
    """

    name: str
    match_relation: str
    decision: Decision
    match_object: str | None = None
    description: str = ""
    requires: tuple[str, ...] = ()


@dataclass(frozen=True)
class GateDecision:
    """One decision, with the full derivation chain that produced it."""

    decision: Decision
    subject: str
    chain: tuple[str, ...]          # human-readable derivation steps
    policy_rule: str                # which policy rule fired
    derived_from: tuple[str, ...]   # claim kinds that backed the derivation
    missing_evidence: tuple[str, ...] = ()  # required kinds absent from the chain


class PolicyGate:
    """Fail-closed decision gate over derived facts."""

    def __init__(
        self,
        policy_rules: list[PolicyRule],
        fallback: Decision | str = Decision.BLOCK,
    ) -> None:
        self.policy_rules = list(policy_rules)
        # Resolved once, loudly: an unknown fallback is a GateDenied at
        # construction time, not a silently different decision later.
        self.fallback = resolve_decision(fallback, field="fallback")
        # Duplicate names are refused here too (load_policy validates the
        # same rule for files): a name-keyed evaluation would let two rules
        # under one name silently merge their facts, and only the last
        # rule's decision would survive — a dropped decision, not a style
        # question.
        seen: set[str] = set()
        for rule in self.policy_rules:
            if rule.name in seen:
                raise GateDenied(
                    f"duplicate policy rule name {rule.name!r} — two rules "
                    "under one name silently drop decisions; rename one"
                )
            seen.add(rule.name)

    def evaluate(self, engine: RuleEngine) -> list[GateDecision]:
        """Evaluate all derived facts against policy rules.

        Deterministic: same engine state -> same decisions, always.
        EVERY matching rule fires (no first-match shadowing): a broad rule
        (`match_object=None`) no longer hides a specific rule on the same
        relation, and `evaluate_with_fallback` merges the results
        worst-wins, so broad+weak + specific+strong can only strengthen
        the outcome, never silently weaken it.
        """
        decisions: list[GateDecision] = []

        # Collect facts per (policy rule, subject), UNIONING sources across
        # every fact that matches — a subject may derive the same relation
        # through several independent chains, and the evidence base is the
        # union of all of them, never just the first one seen.
        grouped: dict[tuple[int, str], list[Fact]] = {}
        for fact in engine.facts:
            for idx, policy in enumerate(self.policy_rules):
                if fact.relation != policy.match_relation:
                    continue
                if policy.match_object is not None and fact.object != policy.match_object:
                    continue
                grouped.setdefault((idx, fact.subject), []).append(fact)

        for (idx, subject), facts in sorted(grouped.items()):
            policy = self.policy_rules[idx]
            # Union of every source kind backing any fact for this subject
            present: set[str] = set()
            for f in facts:
                present.update(f.sources)
            missing = tuple(k for k in policy.requires if k not in present)
            chain: list[str] = []
            for f in facts:
                chain.extend(self._build_chain(f, engine))
            decisions.append(
                GateDecision(
                    decision=policy.decision,
                    subject=subject,
                    chain=tuple(chain),
                    policy_rule=policy.name,
                    derived_from=tuple(sorted(present)),
                    missing_evidence=missing,
                )
            )

        return decisions

    def evaluate_with_fallback(self, engine: RuleEngine) -> dict[str, Any]:
        """Evaluate, and when NO derived path exists, apply the fallback.

        This is the fail-closed path: silence from the engine is treated
        as 'insufficient evidence', and the gate errs on the side of the
        configured fallback (default: BLOCK).
        """
        decisions = self.evaluate(engine)
        if not decisions:
            return {
                "decision": self.fallback.value,
                "reason": "no derived paths — fail-closed default applied",
                "policy_rule": "FALLBACK",
                "chain": [],
                "derived_from": (),
            }
        # Merge: if any BLOCK present, overall decision is BLOCK; else any
        # ALERT -> ALERT; else ALLOW.
        # Severity ordering: containment decisions outrank plain alerts.
        # ISOLATE_HOST (a host is compromised) is the most severe;
        # ESCALATE next (privileged, needs a human); REVOKE_ACCESS then
        # (an access path exists but may not be exploited yet); BLOCK and
        # ALERT follow for the tool-call vocabulary; ALLOW is least.
        order = {
            Decision.ISOLATE_HOST: 6,
            Decision.ESCALATE: 5,
            Decision.REVOKE_ACCESS: 4,
            Decision.BLOCK: 3,
            Decision.ALERT: 2,
            Decision.ALLOW: 1,
        }
        worst = max(decisions, key=lambda d: order[d.decision])
        # Aggregate missing evidence across all decisions — an incomplete
        # chain is reported, never silently swallowed.
        all_missing: list[str] = []
        for d in decisions:
            for kind in d.missing_evidence:
                if kind not in all_missing:
                    all_missing.append(kind)
        return {
            "decision": worst.decision.value,
            "reason": f"{len(decisions)} decision(s); strongest is {worst.decision.value}",
            "policy_rule": worst.policy_rule,
            "chain": list(worst.chain),
            "derived_from": list(worst.derived_from),
            "missing_evidence": all_missing,
            "all_decisions": [
                {
                    "subject": d.subject,
                    "decision": d.decision.value,
                    "policy_rule": d.policy_rule,
                    "chain": list(d.chain),
                    "derived_from": list(d.derived_from),
                    "missing_evidence": list(d.missing_evidence),
                }
                for d in decisions
            ],
        }

    @staticmethod
    def _build_chain(fact: Fact, engine: RuleEngine) -> list[str]:
        """Trace a derived fact back through the derivation steps."""
        chain = [f"derived: {fact.subject} -{fact.relation}-> {fact.object}"]
        for step in engine.derivation_trace:
            if str(fact) in step["derived"]:
                chain.append(f"  rule {step['rule']}: matched {step['matched_on']}")
        return chain
