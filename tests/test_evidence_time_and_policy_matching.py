"""Regression checks for policy object constraints and temporal units."""

from nomosguard.gate import Decision, PolicyGate, PolicyRule
from nomosguard.rules import Fact, RuleEngine
from nomosguard.temporal import _to_seconds


def test_epoch_milliseconds_and_seconds_represent_the_same_instant() -> None:
    assert _to_seconds("1728466442000 event") == 1_728_466_442
    assert _to_seconds("1728466442 event") == 1_728_466_442


def test_object_specific_policy_does_not_match_an_unrelated_resource() -> None:
    engine = RuleEngine()
    engine.add_fact(Fact("operator", "reaches", "public", ("tool_call",)))
    gate = PolicyGate(
        [
            PolicyRule(
                name="isolate-sensitive-target",
                match_relation="reaches",
                match_object="private",
                decision=Decision.ISOLATE_HOST,
            )
        ]
    )
    assert gate.evaluate(engine) == []
    assert gate.evaluate_with_fallback(engine)["decision"] == "BLOCK"
    engine.add_fact(Fact("operator", "reaches", "private", ("tool_call",)))
    matches = gate.evaluate(engine)
    assert len(matches) == 1
    assert matches[0].policy_rule == "isolate-sensitive-target"
    assert matches[0].decision is Decision.ISOLATE_HOST
