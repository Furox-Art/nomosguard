"""Tests for declarative policy configuration: valid loads, fail-closed rejection."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from nomosguard.policy import PolicyConfigError, load_policy, default_policy


class TestDefaultPolicy:
    def test_default_policy_loads(self):
        rules, gate = default_policy()
        assert len(rules) == 2
        assert len(gate) == 2


class TestLoadValidPolicy:
    def test_committed_default_file_loads(self):
        path = Path(__file__).resolve().parents[1] / "examples" / "default_policy.json"
        rules, gate = load_policy(path)
        assert len(rules) == 2
        assert len(gate) == 2
        assert rules[0].name == "tool_on_vulnerable_component"

    def test_minimal_valid_policy(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "policy.json"
            path.write_text(json.dumps({
                "rules": [
                    {
                        "name": "r1",
                        "body": [["?a", "calls", "?t"], ["?a", "operates_on", "?c"]],
                        "head": ["?a", "exposes", "?c"],
                    }
                ],
                "gate": [{"name": "g1", "match_relation": "exposes", "decision": "BLOCK"}],
            }))
            rules, gate = load_policy(path)
            assert len(rules) == 1
            assert len(gate) == 1


class TestFailClosedRejection:
    def _write(self, td, data) -> Path:
        path = Path(td) / "policy.json"
        path.write_text(json.dumps(data))
        return path

    def test_missing_file_rejected(self):
        with pytest.raises(PolicyConfigError, match="policy file not found"):
            load_policy(Path("/nonexistent/policy.json"))

    def test_invalid_json_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "policy.json"
            path.write_text("{not json")
            with pytest.raises(PolicyConfigError, match="not valid JSON"):
                load_policy(path)

    def test_non_object_root_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "policy.json"
            path.write_text("[1, 2, 3]")
            with pytest.raises(PolicyConfigError, match="must be a JSON object"):
                load_policy(path)

    def test_rule_missing_name_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, {"rules": [{"body": [["?a", "calls", "?t"]], "head": ["?a", "x", "y"]}]})
            with pytest.raises(PolicyConfigError, match="missing or invalid 'name'"):
                load_policy(path)

    def test_rule_empty_body_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, {"rules": [{"name": "r", "body": [], "head": ["?a", "x", "y"]}]})
            with pytest.raises(PolicyConfigError, match="'body' must be a non-empty list"):
                load_policy(path)

    def test_malformed_pattern_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, {"rules": [{"name": "r", "body": [["?a", "calls"]], "head": ["?a", "x", "y"]}]})
            with pytest.raises(PolicyConfigError, match="pattern must be a"):
                load_policy(path)

    def test_unbound_head_variable_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, {
                "rules": [{
                    "name": "r",
                    "body": [["?a", "calls", "?t"]],
                    "head": ["?a", "exposes", "?nowhere"],  # ?nowhere unbound
                }]
            })
            with pytest.raises(PolicyConfigError, match="does not appear in the body"):
                load_policy(path)

    def test_unknown_decision_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, {
                "gate": [{"name": "g", "match_relation": "exposes", "decision": "MAYBE"}]
            })
            with pytest.raises(PolicyConfigError, match="decision must be one of"):
                load_policy(path)

    def test_gate_missing_relation_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, {
                "gate": [{"name": "g", "decision": "BLOCK"}]
            })
            with pytest.raises(PolicyConfigError, match="missing or invalid 'match_relation'"):
                load_policy(path)


class TestLoadedPolicyWorks:
    def test_loaded_rules_derive_correctly(self):
        from nomosguard.ledger import Claim, EvidenceLedger
        from nomosguard.rules import RuleEngine
        from nomosguard.gate import PolicyGate

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "policy.json"
            path.write_text(json.dumps({
                "rules": [{
                    "name": "expose",
                    "body": [
                        ["?agent", "calls", "?tool"],
                        ["?agent", "operates_on", "?component"],
                        ["?component", "has_vulnerability", "?cve"],
                    ],
                    "head": ["?agent", "exposes", "?component"],
                }],
                "gate": [{"name": "block", "match_relation": "exposes", "decision": "BLOCK"}],
            }))
            rules, gate_rules = load_policy(path)

            ledger = EvidenceLedger()
            ledger.append(Claim("tool_call", {"agent": "a", "tool": "t", "target": "db"}, "log"))
            ledger.append(Claim("vulnerability", {"component": "db", "cve": "CVE-1"}, "nvd"))

            engine = RuleEngine(rules=rules)
            engine.add_facts_from_ledger(ledger)
            engine.derive()
            derived = [f for f in engine.facts if f.relation == "exposes"]
            assert len(derived) == 1
            assert derived[0].object == "db"

            gate = PolicyGate(policy_rules=gate_rules)
            decision = gate.evaluate_with_fallback(engine)
            assert decision["decision"] == "BLOCK"
