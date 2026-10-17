"""Direct deterministic branch contracts for rule inference and signature decisions."""

from __future__ import annotations

import pytest

from nomosguard.gate import Decision, PolicyGate, PolicyRule
from nomosguard.rules import (
    Fact,
    Pattern,
    Rule,
    RuleDefinitionError,
    RuleEngine,
    _extract_policy_rule,
    _extract_vulnerability,
)
from nomosguard.signatures import Match, Signature, SignatureError


def test_fact_equality_and_hash_derive_from_triple_not_claim_sources():
    left = Fact("a", "uses", "tool", ("tool_call",))
    right = Fact("a", "uses", "tool", ("vulnerability",))
    third = Fact("a", "uses", "another")
    assert left == right
    assert left != third
    assert left != ("a", "uses", "tool")
    assert hash(left) == hash(right)
    assert len({left, right, third}) == 2
    assert left.to_dict()["sources"] == ["tool_call"]


def test_pattern_substitution_unbound_head_is_never_guessed():
    with pytest.raises(RuleDefinitionError, match="unbound"):
        Pattern("?agent", "calls", "?tool").substitute({"?agent": "alice"})


def test_rule_with_empty_premises_is_refused_as_unsupported_fact_generation():
    invalid = Rule(name="unconditional", body=(), head=Pattern("root", "allows", "all"))
    with pytest.raises(RuleDefinitionError, match="empty body"):
        invalid.validate()


def test_rule_candidate_index_handles_explicit_concrete_subject():
    engine = RuleEngine()
    engine.add_fact(Fact("alice", "calls", "tool"))
    engine.add_fact(Fact("bob", "calls", "other"))
    engine._rebuild_index()
    matches = engine._candidates(Pattern("alice", "calls", "?tool"), {})
    assert [v.object for v in matches] == ["tool"]


@pytest.mark.parametrize(
    ("input_claim", "expected_relation"),
    [
        ({"component": "database", "cve": "CVE-2026-1234"}, "has_vulnerability"),
        ({"component": "database"}, None),
        ({"cve": "CVE-2026-1234"}, None),
    ],
)
def test_vulnerability_extractor_requires_both_observed_fields(
    input_claim, expected_relation
):
    facts = _extract_vulnerability(input_claim, "source-line")
    assert [fact.relation for fact in facts] == (
        [expected_relation] if expected_relation else []
    )


@pytest.mark.parametrize(
    ("raw", "relations"),
    [
        (
            {"subject": "alice", "action": "read", "resource": "db", "effect": "deny"},
            ["policy_denies", "policy_denies_action"],
        ),
        (
            {"subject": "alice", "action": "read", "resource": "db", "effect": "allow"},
            ["policy_allows", "policy_allows_action"],
        ),
        (
            {"subject": "alice", "action": "read", "effect": "deny"},
            ["policy_denies_action"],
        ),
        ({"action": "read", "resource": "db", "effect": "deny"}, []),
        ({"subject": "alice", "resource": "db", "effect": "deny"}, []),
    ],
)
def test_policy_fact_extractor_does_not_invent_missing_actor_action_or_resource(
    raw, relations
):
    assert [f.relation for f in _extract_policy_rule(raw, "evidence")] == relations


@pytest.mark.parametrize(
    ("id_value", "status", "pattern"),
    [
        ("", "stable", "non-empty string"),
        (None, "stable", "non-empty string"),
        ("sig-one", "unapproved", "status"),
    ],
)
def test_signature_definition_requires_known_identity_and_status(
    id_value, status, pattern
):
    signature = Signature(id=id_value, title="test", status=status)
    with pytest.raises(SignatureError, match=pattern):
        signature.validate()


def test_signature_dictionary_is_stable_with_captures_and_critical_severity():
    signature = Signature(
        id="NG-DIRECT",
        title="danger",
        level="critical",
        detection=(("user", "root"),),
        filter=(("known", "benign"),),
    )
    signature.validate()
    assert signature.is_critical is True
    assert signature.to_dict()["detection"] == [["user", "root"]]
    assert signature.to_dict()["filter"] == [["known", "benign"]]
    observation = Match("NG-DIRECT", "user=root", ("root",))
    assert observation.to_dict()["captured"] == ["root"]


def test_gate_matching_relation_does_not_override_explicit_object_restriction():
    engine = RuleEngine()
    engine.add_fact(Fact("alice", "calls", "allowed"))
    engine.add_fact(Fact("alice", "calls", "blocked"))
    policy = PolicyGate(
        [
            PolicyRule(
                name="only_blocked",
                match_relation="calls",
                match_object="blocked",
                decision=Decision.BLOCK,
            )
        ]
    )
    decisions = policy.evaluate(engine)
    assert len(decisions) == 1
    assert decisions[0].decision == Decision.BLOCK
    assert decisions[0].subject == "alice"
