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
        fallback: Decision = Decision.BLOCK,
    ) -> None:
        self.policy_rules = list(policy_rules)
        self.fallback = fallback

    def evaluate(self, engine: RuleEngine) -> list[GateDecision]:
        """Evaluate all derived facts against policy rules.

        Deterministic: same engine state -> same decisions, always.
        """
        decisions: list[GateDecision] = []

        # Collect facts per (policy rule, subject), UNIONING sources across
        # every fact that matches — a subject may derive the same relation
        # through several independent chains, and the evidence base is the
        # union of all of them, never just the first one seen.
        grouped: dict[tuple[str, str], list[Fact]] = {}
        policy_of: dict[tuple[str, str], PolicyRule] = {}
        for fact in engine.facts:
            for policy in self.policy_rules:
                if fact.relation != policy.match_relation:
                    continue
                if policy.match_object is not None and fact.object != policy.match_object:
                    continue
                key = (policy.name, fact.subject)
                grouped.setdefault(key, []).append(fact)
                policy_of[key] = policy
                break  # first matching policy rule wins for this fact

        for (policy_name, subject), facts in sorted(grouped.items()):
            policy = policy_of[(policy_name, subject)]
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
                    policy_rule=policy_name,
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
