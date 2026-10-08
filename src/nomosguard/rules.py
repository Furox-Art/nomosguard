"""Deterministic attack/access path derivation engine.

MulVAL-style logical inference: given a set of evidenced claims about the
security state, derive *which attack/access paths exist* by pure logical
rules. No randomness, no model, no heuristics — every derived path traces
back to the evidence entries that produced it.

The engine is deliberately small and general:

- Facts are (subject, relation, object) triples extracted from claims.
- Rules are logical implications: (body_patterns) -> (head_pattern).
- Derivation is fixpoint forward chaining over the fact set.
- Every derived fact carries the chain of source claims that produced it.

This is inference, not detection: the engine only asserts what *follows*
from the evidence. If the evidence is incomplete, the engine is silent —
the policy gate then applies its fail-closed default.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .ledger import EvidenceLedger


class Fact:
    """An atomic (subject, relation, object) assertion."""

    __slots__ = ("subject", "relation", "object", "sources")

    def __init__(self, subject: str, relation: str, object: str, sources: tuple[str, ...] = ()) -> None:
        self.subject = subject
        self.relation = relation
        self.object = object
        self.sources = tuple(sources)  # claim kinds that produced this fact

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.subject, self.relation, self.object)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Fact) and self.key == other.key

    def __hash__(self) -> int:
        return hash(self.key)

    def __repr__(self) -> str:
        return f"Fact({self.subject} -{self.relation}-> {self.object})"


@dataclass(frozen=True)
class Rule:
    """A logical implication: if all body facts match, derive head fact.

    `body` is a list of (relation, object) pairs, all of which must be
    present for some subject for the rule to fire. `head` is the derived
    (relation, object). Matches are computed by substitution over subjects.
    """

    name: str
    body: tuple[tuple[str, str], ...]   # [(relation, object), ...]
    head: tuple[str, str]               # (relation, object)
    description: str = ""


class RuleEngine:
    """Forward-chaining rule engine over evidenced facts."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules: list[Rule] = list(rules) if rules else []
        self._facts: dict[tuple[str, str, str], Fact] = {}
        self._derivation_trace: list[dict[str, Any]] = []

    # -- fact management ------------------------------------------------------

    def add_fact(self, fact: Fact) -> None:
        """Add a base fact (from an evidence claim). Idempotent."""
        if fact.key not in self._facts:
            self._facts[fact.key] = fact

    def add_facts_from_ledger(self, ledger: EvidenceLedger) -> None:
        """Extract base facts from all ledger claims.

        The extraction is deterministic: for each claim kind, a fixed
        extractor converts the claim payload into zero or more facts.
        """
        for entry in ledger.entries:
            for fact in _extract_facts(entry.claim.kind, entry.claim.payload, entry.claim.evidence):
                self.add_fact(fact)

    @property
    def facts(self) -> tuple[Fact, ...]:
        return tuple(self._facts.values())

    @property
    def derivation_trace(self) -> list[dict[str, Any]]:
        """Every derivation step, in order: which rule fired, on which facts."""
        return list(self._derivation_trace)

    # -- inference ------------------------------------------------------------

    def derive(self) -> dict[str, Any]:
        """Run forward chaining to fixpoint.

        Returns a summary: {new_facts: N, rules_fired: {rule_name: count},
        trace: [...]}. Deterministic: same ledger -> same result, always.
        """
        self._derivation_trace.clear()
        changed = True
        while changed:
            changed = False
            for rule in self.rules:
                for match in self._match_rule(rule):
                    head_fact = self._derive_fact(rule, match)
                    if head_fact.key not in self._facts:
                        self._facts[head_fact.key] = head_fact
                        changed = True
                        self._derivation_trace.append(
                            {
                                "rule": rule.name,
                                "matched_on": [str(f) for f in match["body_facts"]],
                                "derived": str(head_fact),
                            }
                        )
        fired: dict[str, int] = {}
        for step in self._derivation_trace:
            fired[step["rule"]] = fired.get(step["rule"], 0) + 1
        return {
            "new_facts": sum(1 for f in self._facts.values() if f.sources),
            "rules_fired": fired,
            "trace": self._derivation_trace,
        }

    # -- internal matching ----------------------------------------------------

    def _match_rule(self, rule: Rule) -> list[dict[str, Any]]:
        """Find all substitutions that satisfy the rule body.

        A substitution maps every variable in the body to a concrete
        subject present in the fact set. Variables are (relation, object)
        slots where the object is a placeholder name starting with '?'.
        """
        # Collect candidate subjects per body literal
        candidates: list[set[str]] = []
        for relation, obj in rule.body:
            subs = {
                f.subject
                for f in self._facts.values()
                if f.relation == relation and (obj == f.object or obj.startswith("?"))
            }
            if not subs:
                return []
            candidates.append(subs)

        # Cartesian product of subjects across body literals (small rule
        # bodies -> small products; this is inference, not brute force)
        matches: list[dict[str, Any]] = []
        _cartesian(candidates, 0, [], matches)

        results = []
        for combo in matches:
            # Check consistency: each (relation, object) literal must have
            # a fact for the chosen subject. A body object may be a concrete
            # value (must match exactly) or a variable placeholder starting
            # with '?' (matches any value, binding the variable).
            body_facts = []
            bindings: dict[str, str] = {}
            ok = True
            for (relation, obj), subject in zip(rule.body, combo):
                fact = self._facts.get((subject, relation, obj))
                if fact is None and obj.startswith("?"):
                    # variable slot: find the fact by relation alone
                    fact = next(
                        (f for f in self._facts.values()
                         if f.subject == subject and f.relation == relation),
                        None,
                    )
                    if fact is not None:
                        bindings[obj] = fact.object
                if fact is None:
                    ok = False
                    break
                body_facts.append(fact)
            if ok:
                results.append(
                    {"subject": combo[0], "body_facts": body_facts, "bindings": bindings}
                )
        return results

    def _derive_fact(self, rule: Rule, match: dict[str, Any]) -> Fact:
        subject = match["subject"]
        relation, obj = rule.head
        sources = tuple(sorted({s for f in match["body_facts"] for s in f.sources}))
        return Fact(subject, relation, obj, sources)


# -- fact extraction -----------------------------------------------------------

# Deterministic extractors: claim kind -> list of Fact. Each extractor is a
# pure function of the claim payload; no randomness, no model calls.
_EXTRACTORS: dict[str, Callable[[dict[str, Any], str], list[Fact]]] = {}


def register_extractor(kind: str):
    """Decorator to register a fact extractor for a claim kind."""

    def deco(fn: Callable[[dict[str, Any], str], list[Fact]]):
        _EXTRACTORS[kind] = fn
        return fn

    return deco


def _extract_facts(kind: str, payload: dict[str, Any], evidence: str) -> list[Fact]:
    extractor = _EXTRACTORS.get(kind)
    if extractor is None:
        return []
    return extractor(payload, evidence)


def _cartesian(candidates: list[set[str]], idx: int, acc: list[str], out: list[list[str]]) -> None:
    if idx == len(candidates):
        out.append(list(acc))
        return
    for subj in sorted(candidates[idx]):  # sorted for determinism
        acc.append(subj)
        _cartesian(candidates, idx + 1, acc, out)
        acc.pop()


# -- built-in extractors (tool-call evidence, the v1 ingestion path) -----------

@register_extractor("tool_call")
def _extract_tool_call(payload: dict[str, Any], evidence: str) -> list[Fact]:
    """Extract facts from an MCP tool-call record.

    Payload convention:
      {"agent": str, "tool": str, "target": str, "args": {...}}
    Produces: (agent, calls, tool), (tool, operates_on, target).
    """
    agent = str(payload.get("agent", ""))
    tool = str(payload.get("tool", ""))
    target = str(payload.get("target", ""))
    facts = []
    if agent and tool:
        facts.append(Fact(agent, "calls", tool, ("tool_call",)))
    if tool and target:
        facts.append(Fact(tool, "operates_on", target, ("tool_call",)))
    return facts


@register_extractor("vulnerability")
def _extract_vulnerability(payload: dict[str, Any], evidence: str) -> list[Fact]:
    """Extract facts from a CVE/vulnerability record.

    Payload convention: {"component": str, "cve": str, "severity": str}
    Produces: (component, has_vulnerability, cve).
    """
    component = str(payload.get("component", ""))
    cve = str(payload.get("cve", ""))
    facts = []
    if component and cve:
        facts.append(Fact(component, "has_vulnerability", cve, ("vulnerability",)))
    return facts


@register_extractor("policy_rule")
def _extract_policy_rule(payload: dict[str, Any], evidence: str) -> list[Fact]:
    """Extract facts from a policy rule record.

    Payload convention: {"subject": str, "action": str, "resource": str,
    "effect": "allow"|"deny"}
    Produces: (subject, policy_allows, resource) or (subject, policy_denies, resource).
    """
    subject = str(payload.get("subject", ""))
    action = str(payload.get("action", ""))
    resource = str(payload.get("resource", ""))
    effect = str(payload.get("effect", ""))
    facts = []
    if subject and action and resource:
        relation = "policy_allows" if effect == "allow" else "policy_denies"
        facts.append(Fact(subject, relation, f"{action}:{resource}", ("policy_rule",)))
    return facts
