"""Deterministic attack/access path derivation engine.

MulVAL-style logical inference: given a set of evidenced claims about the
security state, derive *which attack/access paths exist* by pure logical
rules. No randomness, no model, no heuristics — every derived path traces
back to the evidence entries that produced it.

The engine implements forward chaining with unification:

- Facts are (subject, relation, object) triples extracted from claims.
- Rules are logical implications: (body_patterns) -> (head_pattern).
- Any position in a pattern may be a *variable* (``?name``), which binds to
  the matching fact's value at that position. The same variable appearing in
  several body literals or in the head must unify to the same value — a
  variable never binds to two different values within one match.
- Derivation is fixpoint forward chaining over the fact set.
- Every derived fact carries the chain of source claims that produced it.

This is inference, not detection: the engine only asserts what *follows*
from the evidence. If the evidence is incomplete, the engine is silent —
the policy gate then applies its fail-closed default.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .ledger import EvidenceLedger


def _is_variable(token: str) -> bool:
    """Whether a pattern position is a variable (``?name``)."""
    return isinstance(token, str) and token.startswith("?")


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

    def to_dict(self) -> dict[str, Any]:
        return {"subject": self.subject, "relation": self.relation,
                "object": self.object, "sources": list(self.sources)}


class RuleDefinitionError(ValueError):
    """Raised when a rule is malformed (e.g. unbound head variable)."""


@dataclass(frozen=True)
class Pattern:
    """A (subject, relation, object) pattern; any position may be a variable.

    Example — "some agent calls some tool":
        Pattern("?agent", "calls", "?tool")

    Example — "orders_db has CVE-2026-1234 specifically":
        Pattern("orders_db", "has_vulnerability", "CVE-2026-1234")
    """

    subject: str
    relation: str
    object: str

    def to_tuple(self) -> tuple[str, str, str]:
        return (self.subject, self.relation, self.object)

    def variables(self) -> tuple[str, ...]:
        return tuple(v for v in self.to_tuple() if _is_variable(v))

    def unify(self, fact: Fact, bindings: dict[str, str]) -> dict[str, str] | None:
        """Try to unify this pattern against a concrete fact.

        Returns the extended bindings on success, or None on failure.
        Existing bindings are never mutated.
        """
        new_bindings = dict(bindings)
        for pattern_token, fact_token in zip(self.to_tuple(), fact.key):
            if _is_variable(pattern_token):
                existing = new_bindings.get(pattern_token)
                if existing is not None and existing != fact_token:
                    return None  # same variable, conflicting value
                new_bindings[pattern_token] = fact_token
            elif pattern_token != fact_token:
                return None
        return new_bindings

    def substitute(self, bindings: dict[str, str]) -> tuple[str, str, str]:
        """Resolve the pattern into a concrete triple using the bindings."""
        resolved: list[str] = []
        for token in self.to_tuple():
            if _is_variable(token):
                value = bindings.get(token)
                if value is None:
                    raise RuleDefinitionError(
                        f"pattern variable {token} is unbound; "
                        "every head variable must also appear in the body"
                    )
                resolved.append(value)
            else:
                resolved.append(token)
        return resolved[0], resolved[1], resolved[2]


@dataclass(frozen=True)
class Rule:
    """A logical implication: if all body patterns match, derive the head.

    Example — an agent that calls a tool operating on a vulnerable
    component exposes that component:

        Rule(
            name="tool_on_vulnerable_component",
            body=(
                Pattern("?agent", "calls", "?tool"),
                Pattern("?agent", "operates_on", "?component"),
                Pattern("?component", "has_vulnerability", "?cve"),
            ),
            head=Pattern("?agent", "exposes", "?component"),
        )

    Variables are shared by name across the whole rule: ``?tool`` must bind
    to the same value in every literal. Every head variable must also appear
    in the body, otherwise the rule can never fire (substitute raises
    RuleDefinitionError).
    """

    name: str
    body: tuple[Pattern, ...]
    head: Pattern
    description: str = ""


class Match:
    """One successful body unification: bindings + the facts it consumed."""

    __slots__ = ("bindings", "body_facts")

    def __init__(self, bindings: dict[str, str], body_facts: tuple[Fact, ...]) -> None:
        self.bindings = bindings
        self.body_facts = body_facts


class RuleEngine:
    """Forward-chaining rule engine over evidenced facts."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules: list[Rule] = list(rules) if rules else []
        self._facts: dict[tuple[str, str, str], Fact] = {}
        self._derivation_trace: list[dict[str, Any]] = []
        # lookup indexes, rebuilt at the start of each fixpoint round
        self._index_ro: dict[tuple[str, str], list[Fact]] = {}
        self._index_sr: dict[tuple[str, str], list[Fact]] = {}

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
            self._rebuild_index()  # facts grew since the last round
            for rule in self.rules:
                for match in self._match_rule(rule):
                    subject, relation, obj = rule.head.substitute(match.bindings)
                    sources = tuple(sorted({s for f in match.body_facts for s in f.sources}))
                    head_fact = Fact(subject, relation, obj, sources)
                    if head_fact.key not in self._facts:
                        self._facts[head_fact.key] = head_fact
                        changed = True
                        self._derivation_trace.append(
                            {
                                "rule": rule.name,
                                "matched_on": [str(f) for f in match.body_facts],
                                "bindings": dict(match.bindings),
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

    def _rebuild_index(self) -> None:
        """Build lookup indexes over the current fact set.

        Two indexes:
        - by_relation_object: (relation, object) -> facts  — used when the
          pattern's object position is concrete
        - by_subject_relation: (subject, relation) -> facts — used when the
          subject position is concrete (already bound)

        Both are rebuilt lazily before each fixpoint round (facts only grow
        within a round, and the round re-iterates until no new facts appear).
        """
        by_ro: dict[tuple[str, str], list[Fact]] = {}
        by_sr: dict[tuple[str, str], list[Fact]] = {}
        for fact in self._facts.values():
            by_ro.setdefault((fact.relation, fact.object), []).append(fact)
            by_sr.setdefault((fact.subject, fact.relation), []).append(fact)
        for lst in by_ro.values():
            lst.sort(key=lambda f: f.key)
        for lst in by_sr.values():
            lst.sort(key=lambda f: f.key)
        self._index_ro = by_ro
        self._index_sr = by_sr

    def _candidates(self, pattern: Pattern, bindings: dict[str, str]) -> list[Fact]:
        """Narrow the candidate facts for a pattern using the indexes.

        Selection logic (most selective first):
        1. If the subject position is already bound (variable with a known
           value), look up by (subject, relation).
        2. Else if the subject position is concrete (non-variable), look up
           by (subject, relation) as well.
        3. Else if the relation+object are concrete, look up by
           (relation, object).
        4. Otherwise fall back to all facts (fully-variable pattern).
        """
        subj = pattern.subject
        relation = pattern.relation

        # subject concrete or already bound -> index by (subject, relation)
        if not _is_variable(subj):
            return self._index_sr.get((subj, relation), [])
        bound_subj = bindings.get(subj)
        if bound_subj is not None:
            return self._index_sr.get((bound_subj, relation), [])

        # relation+object concrete -> index by (relation, object)
        obj = pattern.object
        if not _is_variable(obj):
            return self._index_ro.get((relation, obj), [])
        bound_obj = bindings.get(obj)
        if bound_obj is not None:
            return self._index_ro.get((relation, bound_obj), [])

        # fully-variable pattern: scan all facts with this relation
        all_with_rel: list[Fact] = []
        for (r, _o), facts in self._index_ro.items():
            if r == relation:
                all_with_rel.extend(facts)
        all_with_rel.sort(key=lambda f: f.key)
        return all_with_rel

    def _match_rule(self, rule: Rule) -> list[Match]:
        """Find all substitutions satisfying the rule body.

        Backtracking unification: for each body literal, only index-selected
        candidate facts are tried (deterministic sorted order); a candidate
        survives only if it unifies with the bindings accumulated from the
        previous literals. The same variable binding to two different facts
        is rejected, so body literals cannot silently select different
        entities.
        """
        matches: list[Match] = []
        self._unify_body(rule.body, 0, {}, [], matches)
        return matches

    def _unify_body(
        self,
        body: tuple[Pattern, ...],
        idx: int,
        bindings: dict[str, str],
        facts_so_far: list[Fact],
        out: list[Match],
    ) -> None:
        if idx == len(body):
            out.append(Match(dict(bindings), tuple(facts_so_far)))
            return
        pattern = body[idx]
        for fact in self._candidates(pattern, bindings):
            new_bindings = pattern.unify(fact, bindings)
            if new_bindings is not None:
                facts_so_far.append(fact)
                self._unify_body(body, idx + 1, new_bindings, facts_so_far, out)
                facts_so_far.pop()


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


# -- built-in extractors (tool-call evidence, the v1 ingestion path) -----------

@register_extractor("tool_call")
def _extract_tool_call(payload: dict[str, Any], evidence: str) -> list[Fact]:
    """Extract facts from an MCP tool-call record.

    Payload convention:
      {"agent": str, "tool": str, "target": str, "args": {...}}

    Produces:
      (agent, calls, tool)                 — the agent invoked the tool
      (agent, operates_on, target)         — the AGENT operates on the target

    The second fact is deliberately agent-scoped, NOT tool-scoped. An
    earlier model emitted (tool, operates_on, target), which meant a tool
    invoked by two agents on different targets made BOTH agents "operate
    on" both targets — the tool became a hub that laundered access between
    agents. The agent-scoped fact model keeps the evidence honest: an
    agent operates only on the targets it actually called.
    """
    agent = str(payload.get("agent", ""))
    tool = str(payload.get("tool", ""))
    target = str(payload.get("target", ""))
    facts = []
    if agent and tool:
        facts.append(Fact(agent, "calls", tool, ("tool_call",)))
    if agent and target:
        facts.append(Fact(agent, "operates_on", target, ("tool_call",)))
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
