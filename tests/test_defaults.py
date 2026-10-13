"""One definition of the rule sets and the claim vocabulary (no copies).

The tool-call rule set and its gate rules used to be written out in five
modules. They had already drifted (the demo's copy had lost
`policy_denied_action`), so these tests pin the single definition: every
consumer must see the SAME objects, and every evidence requirement the
policy gate names must be a claim kind the shipped extractors can emit.
"""

from __future__ import annotations

from nomosguard import constants
from nomosguard.benchmark.run_suite import (
    default_policy_rules as benchmark_policy_rules,
    default_rules as benchmark_rules,
)
from nomosguard.constants import (
    CLAIM_KIND_SIGNATURE_PREFIX,
    CLAIM_KIND_TEMPORAL_PREFIX,
    tool_call_gate_rules,
    tool_call_rules,
)
from nomosguard.demo import run as demo_run
from nomosguard.ingest.cli import (
    default_policy_rules as cli_policy_rules,
    default_rules as cli_rules,
)
from nomosguard.ledger import Claim, EvidenceLedger
from nomosguard.mcp_server import (
    NomosGuardSession,
    default_policy_rules,
    default_rules,
)
from nomosguard.policy import default_policy, load_policy
from nomosguard.policy_security import containment_policy_rules
from nomosguard.rules import RuleEngine
from nomosguard.signatures_builtin import builtin_signatures


def _names(rules) -> list[str]:
    return [r.name for r in rules]


class TestSingleRuleSetDefinition:
    """Every consumer runs the same rule objects, not its own copy."""

    def test_constants_module_is_the_source(self):
        assert _names(tool_call_rules()) == [
            "tool_on_vulnerable_component",
            "policy_denied_action",
            "reaches_base",
            "reaches_transitive",
            "transitive_exposure",
        ]
        assert _names(tool_call_gate_rules()) == [
            "block_vulnerable_exposure",
            "alert_policy_violation",
        ]

    def test_policy_default_uses_the_canonical_objects(self):
        rules, gate = default_policy()
        assert rules is not None and len(rules) == 5
        # identity, not just equality: the SAME Rule instances
        for got, want in zip(rules, constants._TOOL_CALL_RULES):
            assert got is want
        for got, want in zip(gate, constants._TOOL_CALL_GATE_RULES):
            assert got is want

    def test_mcp_server_uses_the_canonical_objects(self):
        rules = default_rules()
        assert rules[:5] == list(constants._TOOL_CALL_RULES)
        for got, want in zip(rules[:5], constants._TOOL_CALL_RULES):
            assert got is want
        assert rules[5:] != []  # the security half is appended after

    def test_benchmark_uses_the_canonical_objects(self):
        for got, want in zip(benchmark_rules(), constants._TOOL_CALL_RULES):
            assert got is want
        for got, want in zip(benchmark_policy_rules(), constants._TOOL_CALL_GATE_RULES):
            assert got is want

    def test_cli_uses_the_canonical_objects(self):
        for got, want in zip(cli_rules(), constants._TOOL_CALL_RULES):
            assert got is want
        for got, want in zip(cli_policy_rules(), constants._TOOL_CALL_GATE_RULES):
            assert got is want

    def test_demo_runs_the_full_canonical_rule_set(self):
        """The demo used to carry its own copy that had lost a rule."""
        result = demo_run()
        assert result["ledger_verified"] is True
        assert result["gate_decision"]["decision"] == "BLOCK"
        assert any(
            "researcher -exposes-> orders_db" in f for f in result["derived_facts"]
        )
        # the rule the demo's local copy had dropped is present and loadable
        engine = RuleEngine(rules=tool_call_rules())
        assert "policy_denied_action" in _names(engine.rules)

    def test_all_consumers_agree_on_the_rule_set(self):
        """The same (name, description) sequence in every consumer."""
        policy_rules, _ = default_policy()
        mcp_rules = default_rules()
        benchmark = benchmark_rules()
        cli = cli_rules()
        canonical = list(constants._TOOL_CALL_RULES)
        for consumer in (policy_rules, mcp_rules[:5], benchmark, cli):
            assert _names(consumer) == _names(canonical)
            for got, want in zip(consumer, canonical):
                assert got.description == want.description

    def test_session_runs_the_same_policy_as_the_cli(self):
        session = NomosGuardSession(
            rules=default_rules(), policy_rules=default_policy_rules()
        )
        session.assert_claim(
            "tool_call",
            {"agent": "researcher", "tool": "sql_query", "target": "orders_db"},
            "agent log line 42: researcher invoked sql_query on orders_db",
        )
        session.assert_claim(
            "vulnerability",
            {"component": "orders_db", "cve": "CVE-2026-1234"},
            "NVD record CVE-2026-1234 affects orders_db (SQL injection)",
        )
        decision = session.decide()
        assert decision["decision"] == "BLOCK"
        assert decision["policy_rule"] == "block_vulnerable_exposure"


class TestClaimKindVocabulary:
    """The required-evidence kinds must be emittable, not aspirational."""

    def test_containment_requirements_are_known_kinds(self):
        """No gate rule may demand evidence no extractor can produce.

        A `requires` entry that names a kind the extractors never emit
        would make that decision permanently 'incomplete evidence' —
        a fail-closed default masquerading as a real chain.
        """
        from nomosguard import facts_security, signature_bridge, temporal_bridge  # noqa: F401
        for rule in containment_policy_rules():
            for kind in rule.requires:
                assert constants.is_known_claim_kind(kind) or (
                    kind.startswith(CLAIM_KIND_SIGNATURE_PREFIX)
                ), f"{rule.name} requires unknown claim kind {kind!r}"

    def test_signature_requirements_name_a_real_signature(self):
        """`requires=("signature_ng-0003", ...)` must exist as a signature."""
        known = {s.id.lower() for s in builtin_signatures()}
        for rule in containment_policy_rules():
            for kind in rule.requires:
                if kind.startswith(CLAIM_KIND_SIGNATURE_PREFIX):
                    sig_id = kind[len(CLAIM_KIND_SIGNATURE_PREFIX):]
                    assert sig_id in known, (
                        f"{rule.name} requires {kind!r} but no such signature "
                        "exists — the requirement could never be satisfied"
                    )

    def test_temporal_requirement_matches_a_registered_extractor(self):
        from nomosguard.rules import _EXTRACTORS

        for rule in containment_policy_rules():
            for kind in rule.requires:
                if kind.startswith(CLAIM_KIND_TEMPORAL_PREFIX):
                    assert kind in _EXTRACTORS, (
                        f"{rule.name} requires {kind!r} but no extractor is "
                        "registered for it"
                    )

    def test_every_requirement_is_satisfiable_from_real_claims(self):
        """Each required kind appears as a fact source when claimed."""
        from nomosguard import facts_security, temporal_bridge  # noqa: F401

        sources = set()
        ledger = EvidenceLedger()
        ledger.append(Claim("network", {"host": "h", "protocol": "tcp", "port": 22,
                                        "allowed_from": "attacker"}, "fw rule"))
        ledger.append(Claim("exec_code", {"host": "h", "user": "u"}, "proc log"))
        ledger.append(Claim("privilege", {"user": "u", "privilege": "admin"}, "iam"))
        ledger.append(Claim("vuln_host", {"host": "h", "cve": "CVE-2026-1"}, "nvd"))
        engine = RuleEngine(rules=[])
        engine.add_facts_from_ledger(ledger)
        for fact in engine.facts:
            sources.update(fact.sources)
        for required in ("network", "exec_code", "privilege"):
            assert required in sources


class TestCommittedPolicyFileMatchesTheCanonicalSet:
    """The example policy file is the same policy, expressed as data."""

    def test_committed_file_matches_defaults(self):
        from pathlib import Path

        path = Path(__file__).resolve().parents[1] / "examples" / "default_policy.json"
        rules, gate = load_policy(path)
        default_rules_list, default_gate = default_policy()
        assert _names(rules) == _names(default_rules_list)
        assert _names(gate) == _names(default_gate)
