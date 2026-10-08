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


@dataclass(frozen=True)
class PolicyRule:
    """A gate rule: if a derived fact matches, emit this decision.

    `match_relation` matches the derived fact's relation; `match_object`
    (optional) further constrains the object. `decision` is emitted.
    """

    name: str
    match_relation: str
    decision: Decision
    match_object: str | None = None
    description: str = ""


@dataclass(frozen=True)
class GateDecision:
    """One decision, with the full derivation chain that produced it."""

    decision: Decision
    subject: str
    chain: tuple[str, ...]          # human-readable derivation steps
    policy_rule: str                # which policy rule fired
    derived_from: tuple[str, ...]   # claim kinds that backed the derivation


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
        seen: set[tuple[str, str]] = set()

        for fact in engine.facts:
            for policy in self.policy_rules:
                if fact.relation != policy.match_relation:
                    continue
                if policy.match_object is not None and fact.object != policy.match_object:
                    continue
                key = (fact.subject, fact.relation)
                if key in seen:
                    continue
                seen.add(key)
                chain = self._build_chain(fact, engine)
                decisions.append(
                    GateDecision(
                        decision=policy.decision,
                        subject=fact.subject,
                        chain=tuple(chain),
                        policy_rule=policy.name,
                        derived_from=fact.sources,
                    )
                )
                break  # first matching policy rule wins for this fact

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
        order = {Decision.BLOCK: 3, Decision.ALERT: 2, Decision.ALLOW: 1}
        worst = max(decisions, key=lambda d: order[d.decision])
        return {
            "decision": worst.decision.value,
            "reason": f"{len(decisions)} decision(s); strongest is {worst.decision.value}",
            "policy_rule": worst.policy_rule,
            "chain": list(worst.chain),
            "derived_from": list(worst.derived_from),
            "all_decisions": [
                {
                    "subject": d.subject,
                    "decision": d.decision.value,
                    "policy_rule": d.policy_rule,
                    "chain": list(d.chain),
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
