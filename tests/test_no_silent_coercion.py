"""An unknown value is refused, never coerced (M5).

`_extract_policy_rule` read `effect` and mapped *anything that was not
"allow"* to `policy_denies`. A policy claim with a misspelled effect —
or no effect at all — therefore produced an authoritative DENIAL the
claim never stated, silently changing a number the gate then reasons
over. That is the "silently coerces the value" failure mode.

The extractor now refuses: it raises ClaimValueError naming the field,
the allowed vocabulary, and the value it saw.
"""

from __future__ import annotations

import pytest

from nomosguard.constants import VALID_POLICY_EFFECTS
from nomosguard.ledger import Claim, EvidenceLedger
from nomosguard.rules import ClaimValueError, RuleEngine, _extract_policy_rule


class TestExtractorRefusesToGuess:
    def test_missing_effect_is_refused(self):
        with pytest.raises(ClaimValueError, match="field 'effect'"):
            _extract_policy_rule(
                {"subject": "a", "action": "sql", "resource": "db"}, "policy doc"
            )

    def test_unknown_effect_is_refused(self):
        with pytest.raises(ClaimValueError, match="must be one of"):
            _extract_policy_rule(
                {"subject": "a", "action": "sql", "resource": "db", "effect": "maybe"},
                "policy doc",
            )

    def test_case_variants_are_normalised_not_coerced(self):
        facts = _extract_policy_rule(
            {"subject": "a", "action": "sql", "resource": "db", "effect": "DENY"},
            "policy doc",
        )
        assert facts[0].relation == "policy_denies"

        facts = _extract_policy_rule(
            {"subject": "a", "action": "sql", "resource": "db", "effect": " Allow "},
            "policy doc",
        )
        assert facts[0].relation == "policy_allows"

    def test_valid_effects_still_work(self):
        for effect, relation in (("allow", "policy_allows"), ("deny", "policy_denies")):
            facts = _extract_policy_rule(
                {"subject": "a", "action": "sql", "resource": "db", "effect": effect},
                "policy doc",
            )
            assert facts[0].relation == relation
        assert VALID_POLICY_EFFECTS == ("allow", "deny")

    def test_error_names_the_vocabulary_and_the_value(self):
        with pytest.raises(ClaimValueError) as exc:
            _extract_policy_rule(
                {"subject": "a", "action": "sql", "resource": "db", "effect": "ALLOW!"},
                "policy doc",
            )
        message = str(exc.value)
        assert "'effect'" in message
        assert "'allow'" in message and "'deny'" in message
        assert "'ALLOW!'" in message


class TestLedgerWideRefusal:
    """The refusal surfaces from derive(), not from one extractor call."""

    def test_malformed_policy_claim_refused_before_it_becomes_a_fact(self):
        """The refusal fires where the claim is read, not silently later."""
        ledger = EvidenceLedger()
        ledger.append(
            Claim(
                "policy_rule",
                {"subject": "a", "action": "sql", "resource": "db"},
                "policy doc with no effect at all",
            )
        )
        engine = RuleEngine(rules=[])
        with pytest.raises(ClaimValueError):
            engine.add_facts_from_ledger(ledger)

    def test_well_formed_policy_claim_derives(self):
        ledger = EvidenceLedger()
        ledger.append(
            Claim(
                "policy_rule",
                {"subject": "researcher", "action": "sql_query",
                 "resource": "orders_db", "effect": "deny"},
                "policy document line 12",
            )
        )
        engine = RuleEngine(rules=[])
        engine.add_facts_from_ledger(ledger)
        engine.derive()
        relations = {(f.subject, f.relation) for f in engine.facts}
        assert ("researcher", "policy_denies") in relations


class TestIngestAdapterRefusesFirst:
    """The ingest path rejects the same malformed record before the ledger."""

    def test_ingest_refuses_a_policy_line_without_effect(self):
        import tempfile
        from pathlib import Path

        from nomosguard.ingest import ingest_policy_jsonl

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "policies.jsonl"
            path.write_text(
                '{"subject": "a", "action": "sql", "resource": "db"}\n',
                encoding="utf-8",
            )
            ledger = EvidenceLedger()
            result = ingest_policy_jsonl(ledger, path)
            assert result.accepted == 0
            assert result.rejected[0]["reason"].startswith("line 1: field 'effect'")


class TestSdkBoundaryConvertsTheRefusal:
    """An agent asserting a malformed claim gets a result, not a crash."""

    def test_assert_claim_with_unknown_effect_is_refused(self):
        from nomosguard.mcp_server import (
            NomosGuardSession,
            default_policy_rules,
            default_rules,
        )

        session = NomosGuardSession(
            rules=default_rules(), policy_rules=default_policy_rules()
        )
        result = session.assert_claim(
            "policy_rule",
            {"subject": "a", "action": "sql", "resource": "db", "effect": "maybe"},
            "policy doc",
        )
        # the claim is recorded (evidence is evidence) ...
        assert result["accepted"] is True
        # ... and every decision path refuses it instead of guessing
        decision = session.decide()
        assert decision["decision"] == "BLOCK"
        assert decision["denied"] is True
        assert "uninterpretable claim" in decision["reason"]
        assert "effect" in decision["reason"]
        derived = session.derive_paths()
        assert derived["denied"] is True
        assert derived["derived_facts"] == []
        assert session.explain()["denied"] is True


class TestStringFieldsAreNotStringified:
    """`str(payload.get(...))` invented values: 42 became the agent "42"."""

    def test_tool_call_agent_number_is_refused(self):
        from nomosguard.rules import _extract_tool_call

        with pytest.raises(ClaimValueError, match="field 'agent' must be a string, got 42"):
            _extract_tool_call({"agent": 42, "tool": "t", "target": "db"}, "log")

    def test_tool_call_null_field_keeps_no_fact_semantics(self):
        from nomosguard.rules import _extract_tool_call

        # absent/null stays the documented "no fact" case (no invented "None")
        assert _extract_tool_call({"agent": None, "tool": "t"}, "log") == []

    def test_network_port_boolean_is_refused(self):
        """True is an int in Python: port=True used to become "tcp:True"."""
        import nomosguard.facts_security  # noqa: F401 — registers extractors
        from nomosguard.rules import _extract_facts

        with pytest.raises(ClaimValueError, match="field 'port' must be an integer, got True"):
            _extract_facts("network", {"host": "h", "protocol": "tcp", "port": True}, "fw")

    def test_network_port_string_is_refused(self):
        import nomosguard.facts_security  # noqa: F401
        from nomosguard.rules import _extract_facts

        with pytest.raises(ClaimValueError, match="field 'port' must be an integer, got '443'"):
            _extract_facts("network", {"host": "h", "protocol": "tcp", "port": "443"}, "fw")

    def test_vuln_severity_number_is_refused(self):
        import nomosguard.facts_security  # noqa: F401
        from nomosguard.rules import _extract_facts

        with pytest.raises(ClaimValueError, match="field 'severity' must be a string, got 9"):
            _extract_facts("vuln_severity",
                           {"host": "h", "severity": 9}, "nvd")

    def test_host_services_items_must_be_strings(self):
        import nomosguard.facts_security  # noqa: F401
        from nomosguard.rules import _extract_facts

        with pytest.raises(ClaimValueError, match="'services' must contain strings"):
            _extract_facts("host", {"hostname": "h", "services": ["ssh", 42]}, "inv")


class TestUnknownClaimKindsAreReported:
    """A claim kind with no extractor derived nothing — silently. Now counted."""

    def _engine_with(self, kind: str):
        ledger = EvidenceLedger()
        ledger.append(Claim(kind, {"x": 1}, "raw record"))
        ledger.append(
            Claim("tool_call", {"agent": "a", "tool": "t", "target": "db"}, "log")
        )
        engine = RuleEngine(rules=[])
        engine.add_facts_from_ledger(ledger)
        return engine

    def test_engine_counts_claims_no_extractor_understands(self):
        engine = self._engine_with("mystery_record")
        assert engine.unknown_claim_kinds == {"mystery_record": 1}
        summary = engine.derive()
        assert summary["unknown_claim_kinds"] == {"mystery_record": 1}

    def test_known_kinds_are_not_counted(self):
        engine = self._engine_with("tool_call")
        assert engine.unknown_claim_kinds == {}

    def test_session_derive_paths_surfaces_the_counts(self):
        from nomosguard.mcp_server import (
            NomosGuardSession,
            default_policy_rules,
            default_rules,
        )

        session = NomosGuardSession(
            rules=default_rules(), policy_rules=default_policy_rules()
        )
        session.assert_claim("mystery_record", {"x": 1}, "raw record")
        derived = session.derive_paths()
        assert derived["unknown_claim_kinds"] == {"mystery_record": 1}
