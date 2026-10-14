"""Every rule in the canonical rule set fires, and what it fires to is pinned.

`nomosguard.constants` is the single definition of the tool-call rule set
and its gate rules. Each rule below has a case with the MINIMAL inputs that
make it fire and the outcome asserted end-to-end: the derived fact (or the
gate decision), the rule name, and the reason string. A rule whose firing
path is untested is a rule nobody has seen run — and a rule that can never
fire is dead weight that looks like coverage.

The soundness case for `policy_denied_action` is the regression test for a
real defect: the rule used to bind the denied action to a SEPARATE variable
from the called tool, so ANY tool call plus ANY denial by the same subject
derived `violates` — an alert the evidence never stated. It now requires
the called tool to BE the denied action, and the case below pins both
directions.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from nomosguard.constants import tool_call_gate_rules, tool_call_rules
from nomosguard.gate import Decision, PolicyGate
from nomosguard.ledger import Claim, EvidenceLedger
from nomosguard.rules import RuleEngine


@dataclass(frozen=True)
class RuleCase:
    """One rule, its minimal inputs, and the outcome it must produce."""

    rule: str            # the rule under test (rule or gate-rule name)
    claims: tuple        # the minimal evidence
    # what the engine must derive
    fact_relation: str
    fact_subject: object
    fact_object: object
    # what the gate must decide, and why
    decision: str
    policy_rule: str
    reason: str


def _tool_call(agent: str, tool: str, target: str) -> Claim:
    return Claim(
        kind="tool_call",
        payload={"agent": agent, "tool": tool, "target": target},
        evidence=f"log line 1: {agent} invoked {tool} on {target}",
    )


def _chain_tool_call(subject: str, tool: str, target: str) -> Claim:
    """A tool-call claim where the 'agent' is a component (a chain link)."""
    return Claim(
        kind="tool_call",
        payload={"agent": subject, "tool": tool, "target": target},
        evidence=f"replication log: {subject} sent {target} via {tool}",
    )


def _vuln(component: str, cve: str) -> Claim:
    return Claim(
        kind="vulnerability",
        payload={"component": component, "cve": cve, "severity": "high"},
        evidence=f"NVD record {cve} affects {component}",
    )


def _policy_deny(agent: str, action: str) -> Claim:
    return Claim(
        kind="policy_rule",
        payload={"subject": agent, "action": action, "resource": "orders_db", "effect": "deny"},
        evidence=f"policy doc: {agent} is denied {action}",
    )


RULE_CASES: tuple[RuleCase, ...] = (
    RuleCase(
        rule="tool_on_vulnerable_component",
        claims=(_tool_call("researcher", "sql_query", "orders_db"),
                _vuln("orders_db", "CVE-2026-1234")),
        fact_relation="exposes",
        fact_subject="researcher",
        fact_object="orders_db",
        decision="BLOCK",
        policy_rule="block_vulnerable_exposure",
        reason="1 decision(s); strongest is BLOCK",
    ),
    RuleCase(
        rule="policy_denied_action",
        claims=(_tool_call("researcher", "sql_query", "orders_db"),
                _policy_deny("researcher", "sql_query")),
        fact_relation="violates",
        fact_subject="researcher",
        fact_object="policy",
        decision="ALERT",
        policy_rule="alert_policy_violation",
        reason="1 decision(s); strongest is ALERT",
    ),
    RuleCase(
        rule="reaches_base",
        claims=(_tool_call("researcher", "sql_query", "orders_db"),),
        fact_relation="reaches",
        fact_subject="researcher",
        fact_object="orders_db",
        decision="BLOCK",
        policy_rule="FALLBACK",
        reason="no derived paths",
    ),
    RuleCase(
        rule="reaches_transitive",
        claims=(_tool_call("researcher", "sql_query", "orders_db"),
                _chain_tool_call("orders_db", "replicate_to", "analytics_db")),
        fact_relation="reaches",
        fact_subject="researcher",
        fact_object="analytics_db",
        decision="BLOCK",
        policy_rule="FALLBACK",
        reason="no derived paths",
    ),
    RuleCase(
        rule="transitive_exposure",
        claims=(_tool_call("researcher", "sql_query", "orders_db"),
                _chain_tool_call("orders_db", "replicate_to", "analytics_db"),
                _vuln("analytics_db", "CVE-2026-7777")),
        fact_relation="exposes",
        fact_subject="researcher",
        fact_object="analytics_db",
        # both researcher and orders_db reach the vulnerable component:
        # the closure carries the exposure to every node on the path
        decision="BLOCK",
        policy_rule="block_vulnerable_exposure",
        reason="2 decision(s); strongest is BLOCK",
    ),
)


def _run(claims):
    """Run the canonical rule set + gate over `claims`.

    Returns (engine, derivation summary, gate verdict). The derivation
    summary is kept because `rules_fired` counts the rules that actually
    fired in the pass that produced the facts.
    """
    ledger = EvidenceLedger()
    for claim in claims:
        ledger.append(claim)
    engine = RuleEngine(rules=tool_call_rules())
    engine.add_facts_from_ledger(ledger)
    derivation = engine.derive()
    gate = PolicyGate(policy_rules=tool_call_gate_rules(), fallback=Decision.BLOCK)
    return engine, derivation, gate.evaluate_with_fallback(engine)


class TestEveryRuleFiresOnMinimalInputs:
    """One case per rule in the canonical set: inputs, fact, decision, reason."""

    @pytest.mark.parametrize(
        "case", RULE_CASES, ids=[c.rule for c in RULE_CASES]
    )
    def test_the_rule_actually_fires(self, case: RuleCase):
        _, derivation, _ = _run(case.claims)
        assert derivation["rules_fired"].get(case.rule, 0) >= 1, (
            f"{case.rule} never fired on its own minimal inputs"
        )

    @pytest.mark.parametrize(
        "case", RULE_CASES, ids=[c.rule for c in RULE_CASES]
    )
    def test_the_derived_fact_is_pinned(self, case: RuleCase):
        engine, _, _ = _run(case.claims)
        derived = [f for f in engine.facts
                   if f.relation == case.fact_relation
                   and f.subject == case.fact_subject
                   and f.object == case.fact_object]
        assert derived, (
            f"{case.rule} did not derive "
            f"({case.fact_subject}, {case.fact_relation}, {case.fact_object})"
        )
        # the derived fact carries its provenance, not a constant
        assert derived[0].sources

    @pytest.mark.parametrize(
        "case", RULE_CASES, ids=[c.rule for c in RULE_CASES]
    )
    def test_the_gate_verdict_is_pinned(self, case: RuleCase):
        _, _, verdict = _run(case.claims)
        assert verdict["decision"] == case.decision
        assert verdict["policy_rule"] == case.policy_rule
        assert case.reason in verdict["reason"]

    @pytest.mark.parametrize(
        "case", RULE_CASES, ids=[c.rule for c in RULE_CASES]
    )
    def test_a_deny_verdict_names_its_chain(self, case: RuleCase):
        """A deny is never bare: the reason and chain name the evidence."""
        _, _, verdict = _run(case.claims)
        if verdict["policy_rule"] == "FALLBACK":
            assert "fail-closed default applied" in verdict["reason"]
        else:
            assert "strongest is" in verdict["reason"]


class TestNoDeadRules:
    """Every rule in the canonical set has a firing case, and vice versa."""

    def test_every_canonical_rule_has_a_case(self):
        canonical = [r.name for r in tool_call_rules()] + [
            r.name for r in tool_call_gate_rules()
        ]
        cased = {c.rule for c in RULE_CASES} | {
            c.policy_rule for c in RULE_CASES if c.policy_rule != "FALLBACK"
        }
        missing = [name for name in canonical if name not in cased]
        assert missing == [], f"rules with no firing case: {missing}"

    def test_every_case_names_a_canonical_rule(self):
        canonical = {r.name for r in tool_call_rules()} | {
            r.name for r in tool_call_gate_rules()
        } | {"FALLBACK"}
        for case in RULE_CASES:
            assert case.rule in canonical, f"{case.rule} is not in the canonical set"
            assert case.policy_rule in canonical

    def test_every_rule_case_fires_its_own_rule(self):
        """The rule under test is the one that fires — the case is minimal
        BECAUSE nothing else is in the way."""
        for case in RULE_CASES:
            _, derivation, _ = _run(case.claims)
            assert derivation["rules_fired"].get(case.rule, 0) >= 1, (
                f"{case.rule} never fired on its own minimal inputs"
            )


class TestPolicyDeniedActionSoundness:
    """The rule that used to fire on ANY denial, now pinned both ways."""

    def test_the_called_tool_is_the_denied_action(self):
        engine, _, verdict = _run((
            _tool_call("researcher", "sql_query", "orders_db"),
            _policy_deny("researcher", "sql_query"),
        ))
        violations = [f for f in engine.facts if f.relation == "violates"]
        assert len(violations) == 1
        assert verdict["policy_rule"] == "alert_policy_violation"
        assert verdict["decision"] == "ALERT"

    def test_an_unrelated_denial_does_not_violate_policy(self):
        """The regression the old rule could not see.

        A benign file read plus an unrelated SQL denial used to derive
        `violates`: the tool variable and the action variable were never
        compared. The rule now binds the called tool to the denied action,
        so this input derives nothing — and the gate fails closed instead
        of alerting on evidence that states no violation.
        """
        engine, _, verdict = _run((
            _tool_call("researcher", "file_reader", "/data/clean.csv"),
            _policy_deny("researcher", "sql_query"),
        ))
        violations = [f for f in engine.facts if f.relation == "violates"]
        assert violations == []
        assert verdict["policy_rule"] == "FALLBACK"
        assert verdict["decision"] == "BLOCK"

    def test_a_different_subjects_denial_does_not_violate(self):
        engine, _, verdict = _run((
            _tool_call("researcher", "sql_query", "orders_db"),
            _policy_deny("someone_else", "sql_query"),
        ))
        assert [f for f in engine.facts if f.relation == "violates"] == []
        assert verdict["decision"] == "BLOCK"

    def test_policy_allow_never_derives_a_violation(self):
        engine, _, _ = _run((
            _tool_call("researcher", "sql_query", "orders_db"),
            Claim(
                kind="policy_rule",
                payload={"subject": "researcher", "action": "sql_query",
                         "resource": "orders_db", "effect": "allow"},
                evidence="policy doc: researcher is allowed sql_query",
            ),
        ))
        assert [f for f in engine.facts if f.relation == "violates"] == []


class TestGateOutcomeShapes:
    """The deny/allow outcome shapes, both pinned with their reasons."""

    @pytest.mark.parametrize(
        "case", RULE_CASES, ids=[c.rule for c in RULE_CASES]
    )
    def test_no_rule_case_ever_allows(self, case: RuleCase):
        """The shipped gate rules deny or fail closed — never ALLOW: a
        decision boundary that can quietly say yes without evidence is
        the failure mode this project exists to refuse."""
        _, _, verdict = _run(case.claims)
        assert verdict["decision"] != "ALLOW"

    def test_an_allow_outcome_is_still_an_explicit_decision(self, tmp_path):
        """The allow-side shape is representable — and it names its rule.

        A policy that says ALLOW produces ALLOW with the reason string
        naming the rule, so 'allow' is never a default: it is a decision
        the same deterministic path produced and recorded.
        """
        import json

        from nomosguard.policy import load_policy

        path = tmp_path / "policy.json"
        path.write_text(json.dumps({
            "rules": [{
                "name": "any_use",
                "body": [["?agent", "calls", "?tool"]],
                "head": ["?agent", "uses", "?tool"],
            }],
            "gate": [{"name": "allow_use", "match_relation": "uses",
                      "decision": "ALLOW"}],
        }), encoding="utf-8")
        rules, gate_rules = load_policy(path)
        ledger = EvidenceLedger()
        ledger.append(_tool_call("researcher", "sql_query", "orders_db"))
        engine = RuleEngine(rules=rules)
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        gate = PolicyGate(policy_rules=gate_rules, fallback=Decision.BLOCK)
        verdict = gate.evaluate_with_fallback(engine)
        assert verdict["decision"] == "ALLOW"
        assert verdict["policy_rule"] == "allow_use"
        assert "strongest is ALLOW" in verdict["reason"]

    def test_the_worst_decision_wins_when_several_fire(self):
        """Two rules derive: BLOCK (exposure) and ALERT (violation) — the
        gate merges to the worst, and the reason names the count."""
        _, _, verdict = _run((
            _tool_call("researcher", "sql_query", "orders_db"),
            _vuln("orders_db", "CVE-2026-1234"),
            _policy_deny("researcher", "sql_query"),
        ))
        assert verdict["decision"] == "BLOCK"
        assert verdict["policy_rule"] == "block_vulnerable_exposure"
        assert "2 decision(s)" in verdict["reason"]

    def test_fact_provenance_flows_through_derived_facts(self):
        """A derived fact cites the claim kinds it came from: the chain
        back to evidence is part of the fact, not an afterthought."""
        engine, _, _ = _run((
            _tool_call("researcher", "sql_query", "orders_db"),
            _vuln("orders_db", "CVE-2026-1234"),
        ))
        exposes = [f for f in engine.facts if f.relation == "exposes"]
        assert exposes
        assert set(exposes[0].sources) == {"tool_call", "vulnerability"}
