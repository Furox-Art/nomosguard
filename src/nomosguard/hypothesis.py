"""Hypothesis tracking: how many independent evidence chains support each derived fact.

The rule engine records every derivation step. This module groups those
steps per derived fact, so the answer to "why do we believe researcher
exposes orders_db?" is "because of these N independent evidence chains,
each traceable to its source claims."

This is the deterministic core's answer to the question a skeptic always
asks: show me the evidence, not the assertion. It is also what the agent
skill contract reads when it explains a decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .rules import Fact, RuleEngine


@dataclass
class Hypothesis:
    """One derived fact and all the evidence chains that produced it.

    `fact` is the derived fact. `chains` is a list of derivations, each a
    list of (rule_name, source_claim_kinds) — the path from base facts to
    this conclusion. `chain_count` is the number of independent chains.
    """

    fact: Fact
    chains: list[list[tuple[str, tuple[str, ...]]]] = field(default_factory=list)

    @property
    def chain_count(self) -> int:
        return len(self.chains)

    @property
    def all_sources(self) -> set[str]:
        return {src for chain in self.chains for _, srcs in chain for src in srcs}


class HypothesisTracker:
    """Groups derivation-trace steps by the fact they produced.

    Deterministic: the same engine trace always produces the same tracker
    state. No randomness, no model.
    """

    def __init__(self) -> None:
        self._hypotheses: dict[tuple[str, str, str], Hypothesis] = {}

    @classmethod
    def from_engine(cls, engine: RuleEngine) -> "HypothesisTracker":
        """Build a tracker from an engine's derivation trace."""
        tracker = cls()
        for step in engine.derivation_trace:
            # parse the derived fact from the step's string repr
            # format: "Fact(subject -relation-> object)"
            derived_str = step["derived"]
            # match against the engine's actual facts
            for fact in engine.facts:
                if str(fact) == derived_str:
                    key = fact.key
                    if key not in tracker._hypotheses:
                        tracker._hypotheses[key] = Hypothesis(fact=fact)
                    chain = [
                        (step["rule"], tuple(sorted({s for f in engine.facts
                                                     if str(f) in step["matched_on"]
                                                     for s in f.sources})))
                    ]
                    tracker._hypotheses[key].chains.append(chain)
                    break
        return tracker

    @property
    def hypotheses(self) -> tuple[Hypothesis, ...]:
        """All tracked hypotheses, sorted by fact key (deterministic)."""
        return tuple(self._hypotheses[k] for k in sorted(self._hypotheses))

    def strongest(self) -> Hypothesis | None:
        """The hypothesis with the most independent evidence chains."""
        hyps = self.hypotheses
        if not hyps:
            return None
        return max(hyps, key=lambda h: (h.chain_count, h.fact.key))

    def summary(self) -> dict[str, Any]:
        """A summary dict for reports and the explain tool."""
        return {
            "total_hypotheses": len(self._hypotheses),
            "hypotheses": [
                {
                    "fact": str(h.fact),
                    "chain_count": h.chain_count,
                    "sources": sorted(h.all_sources),
                }
                for h in self.hypotheses
            ],
        }
