"""Tests for declarative policy configuration: valid loads, fail-closed rejection."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from nomosguard.policy import (
    PolicyConfigError,
    default_policy,
    load_policy,
    policy_digest,
)


class TestDefaultPolicy:
    def test_default_policy_loads(self):
        rules, gate = default_policy()
        assert len(rules) == 5  # direct exposure + policy_denied + reaches_base + reaches_transitive + transitive_exposure
        assert len(gate) == 2


class TestLoadValidPolicy:
    def test_committed_default_file_loads(self):
        path = Path(__file__).resolve().parents[1] / "examples" / "default_policy.json"
        rules, gate = load_policy(path)
        assert len(rules) == 5
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
            with pytest.raises(PolicyConfigError, match="field 'name' is missing"):
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
            with pytest.raises(PolicyConfigError, match="field 'decision' must be one of"):
                load_policy(path)

    def test_gate_missing_relation_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, {
                "gate": [{"name": "g", "decision": "BLOCK"}]
            })
            with pytest.raises(PolicyConfigError, match="field 'match_relation' is missing"):
                load_policy(path)


class TestPolicyBundlePin:
    """A policy file is a bundle: digest-pinned and format-checked (M2).

    Before this, any structurally valid JSON was accepted as "the policy",
    whatever its provenance — a stale copy, a partially copied file, or a
    file written for another dialect. The pin makes the loaded policy the
    policy you reviewed.
    """

    def _write(self, td, data) -> Path:
        path = Path(td) / "policy.json"
        path.write_text(json.dumps(data))
        return path

    def _valid(self) -> dict:
        return {
            "rules": [{
                "name": "r1",
                "body": [["?a", "calls", "?t"], ["?a", "operates_on", "?c"]],
                "head": ["?a", "exposes", "?c"],
            }],
            "gate": [{"name": "g1", "match_relation": "exposes", "decision": "BLOCK"}],
        }

    def test_digest_is_reproducible(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, self._valid())
            digest = policy_digest(path)
            assert digest == policy_digest(path)
            assert digest.startswith("sha256:")

    def test_pinned_digest_loads(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, self._valid())
            rules, gate = load_policy(path, expected_digest=policy_digest(path))
            assert len(rules) == 1
            assert len(gate) == 1

    def test_corrupted_bundle_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, self._valid())
            pinned = policy_digest(path)
            # corrupt the bundle in place: one byte of one description
            data = json.loads(path.read_text())
            data["gate"][0]["decision"] = "ALERT"
            path.write_text(json.dumps(data))
            with pytest.raises(PolicyConfigError, match="digest mismatch"):
                load_policy(path, expected_digest=pinned)

    def test_whitespace_only_change_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, self._valid())
            pinned = policy_digest(path)
            path.write_text(path.read_text() + "\n")
            with pytest.raises(PolicyConfigError, match="digest mismatch"):
                load_policy(path, expected_digest=pinned)

    def test_unknown_format_name_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            data = self._valid()
            data["format"] = "someone-elses-policy"
            path = self._write(td, data)
            with pytest.raises(PolicyConfigError, match="declares format"):
                load_policy(path)

    def test_unknown_format_version_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            data = self._valid()
            data["format"] = "nomosguard-policy"
            data["format_version"] = 99
            path = self._write(td, data)
            with pytest.raises(PolicyConfigError, match="unsupported policy format version"):
                load_policy(path)

    def test_unpinned_legacy_file_still_loads(self):
        """A file with no format header is data, not a pinned bundle."""
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, self._valid())
            rules, _ = load_policy(path)
            assert len(rules) == 1

    def test_committed_bundle_matches_its_pinned_digest(self):
        """The shipped example carries the digest it claims to carry."""
        base = Path(__file__).resolve().parents[1] / "examples"
        manifest = (base / "policy_digests.txt").read_text(encoding="utf-8")
        pins = {
            line.split()[1]: line.split()[0]
            for line in manifest.splitlines()
            if line.strip() and not line.strip().startswith("#")
        }
        assert pins, "the digest manifest must not be empty"
        for name, digest in pins.items():
            assert policy_digest(base / name) == digest, (
                f"{name} changed without the digest manifest being updated"
            )

    def test_cli_reads_a_digest_manifest(self):
        from nomosguard.ingest.cli import _resolve_policy_digest

        base = Path(__file__).resolve().parents[1] / "examples"
        manifest = str(base / "policy_digests.txt")
        assert _resolve_policy_digest("@" + manifest) == policy_digest(
            base / "default_policy.json"
        )
        assert _resolve_policy_digest(
            "@" + manifest + ":default_policy.json"
        ) == policy_digest(base / "default_policy.json")
        with pytest.raises(PolicyConfigError, match="no entry for"):
            _resolve_policy_digest("@" + manifest + ":nope.json")

    def test_cli_requires_a_policy_for_a_digest_pin(self):
        from nomosguard.ingest.cli import main

        with tempfile.TemporaryDirectory() as td:
            logfile = Path(td) / "log.jsonl"
            logfile.write_text('{"agent": "a", "tool": "t"}\n', encoding="utf-8")
            assert main([str(logfile), "--policy-digest", "sha256:deadbeef"]) == 2


class TestLoadedPolicyWorks:
    def test_loaded_rules_derive_correctly(self):
        from nomosguard.gate import PolicyGate
        from nomosguard.ledger import Claim, EvidenceLedger
        from nomosguard.rules import RuleEngine

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


class TestDuplicateNamesAreRefused:
    """A duplicate rule name silently merges facts and drops decisions."""

    def _write(self, td, data) -> Path:
        path = Path(td) / "policy.json"
        path.write_text(json.dumps(data))
        return path

    def test_duplicate_rule_name_in_a_file_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, {"rules": [
                {"name": "r", "body": [["?a", "calls", "?t"]], "head": ["?a", "uses", "?t"]},
                {"name": "r", "body": [["?a", "operates_on", "?c"]], "head": ["?a", "reaches", "?c"]},
            ]})
            with pytest.raises(PolicyConfigError, match="duplicate name 'r'"):
                load_policy(path)

    def test_duplicate_gate_name_in_a_file_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, {"gate": [
                {"name": "g", "match_relation": "exposes", "decision": "ALERT"},
                {"name": "g", "match_relation": "exposes", "decision": "BLOCK"},
            ]})
            with pytest.raises(PolicyConfigError, match="duplicate name 'g'"):
                load_policy(path)

    def test_policy_gate_refuses_duplicate_names_too(self):
        """The same refusal on the programmatic path (PolicyRule list)."""
        from nomosguard.gate import Decision, GateDenied, PolicyGate, PolicyRule

        rules = [
            PolicyRule(name="dup", match_relation="exposes", decision=Decision.ALERT),
            PolicyRule(name="dup", match_relation="exposes", decision=Decision.BLOCK),
        ]
        with pytest.raises(GateDenied, match="duplicate policy rule name 'dup'"):
            PolicyGate(policy_rules=rules)


class TestUnknownFieldsAreRefused:
    """A typo'd key must be named, not skipped past."""

    def _write(self, td, data) -> Path:
        path = Path(td) / "policy.json"
        path.write_text(json.dumps(data))
        return path

    def test_unknown_top_level_key_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, {"rules": [], "gates": []})  # 'gate' typo
            with pytest.raises(PolicyConfigError, match="'gates' is not allowed"):
                load_policy(path)

    def test_unknown_rule_key_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, {"rules": [
                {"name": "r", "body": [["?a", "calls", "?t"]],
                 "head": ["?a", "uses", "?t"], "requiers": ["tool_call"]},
            ]})
            with pytest.raises(PolicyConfigError, match="'requiers' is not allowed"):
                load_policy(path)

    def test_unknown_gate_key_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, {"gate": [
                {"name": "g", "match_relation": "exposes", "decision": "BLOCK",
                 "match_objct": "db"},
            ]})
            with pytest.raises(PolicyConfigError, match="'match_objct' is not allowed"):
                load_policy(path)


class TestGateRequires:
    """`requires` was accepted by PolicyRule but not writable in a file."""

    def _write(self, td, data) -> Path:
        path = Path(td) / "policy.json"
        path.write_text(json.dumps(data))
        return path

    def _policy(self, requires):
        return {
            "rules": [{
                "name": "expose",
                "body": [["?a", "calls", "?t"], ["?a", "operates_on", "?c"],
                         ["?c", "has_vulnerability", "?v"]],
                "head": ["?a", "exposes", "?c"],
            }],
            "gate": [{"name": "block", "match_relation": "exposes",
                      "decision": "BLOCK", "requires": requires}],
        }

    def test_requires_round_trips_from_a_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, self._policy(["tool_call", "vulnerability"]))
            _, gate_rules = load_policy(path)
            assert gate_rules[0].requires == ("tool_call", "vulnerability")

    def test_unknown_claim_kind_in_requires_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, self._policy(["tool_call", "not_a_kind"]))
            with pytest.raises(PolicyConfigError, match="unknown claim kind 'not_a_kind'"):
                load_policy(path)

    def test_non_string_requires_entry_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, self._policy(["tool_call", 7]))
            with pytest.raises(PolicyConfigError, match=r"requires\[1\]"):
                load_policy(path)

    def test_missing_required_evidence_is_flagged_not_silent(self):
        """requires -> missing_evidence on the decision, end to end."""
        from nomosguard.gate import PolicyGate
        from nomosguard.ledger import Claim, EvidenceLedger
        from nomosguard.rules import RuleEngine

        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, self._policy(["tool_call", "vulnerability"]))
            rules, gate_rules = load_policy(path)
            ledger = EvidenceLedger()
            ledger.append(Claim("tool_call", {"agent": "a", "tool": "t", "target": "db"}, "log"))
            ledger.append(Claim("vulnerability", {"component": "db", "cve": "CVE-1"}, "nvd"))
            engine = RuleEngine(rules=rules)
            engine.add_facts_from_ledger(ledger)
            engine.derive()
            verdict = PolicyGate(policy_rules=gate_rules).evaluate_with_fallback(engine)
            assert verdict["decision"] == "BLOCK"
            assert verdict["missing_evidence"] == []

            # the same policy over a ledger missing the vulnerability claim
            # derives nothing -> the gate fails closed and names the gap
            ledger2 = EvidenceLedger()
            ledger2.append(Claim("tool_call", {"agent": "a", "tool": "t", "target": "db"}, "log"))
            ledger2.append(Claim("network", {"host": "db", "protocol": "tcp",
                                             "port": 5432, "allowed_from": "a"}, "fw"))
            import nomosguard.facts_security  # noqa: F401 — registers extractors
            engine2 = RuleEngine(rules=rules)
            engine2.add_facts_from_ledger(ledger2)
            engine2.derive()
            verdict2 = PolicyGate(policy_rules=gate_rules).evaluate_with_fallback(engine2)
            assert verdict2["decision"] == "BLOCK"
            assert verdict2["policy_rule"] == "FALLBACK"


class TestGateNoShadowing:
    """EVERY matching gate rule fires; the old `break` let a broad rule
    hide a specific one on the same relation."""

    def test_broad_and_specific_rules_both_fire(self):
        from nomosguard.gate import Decision, PolicyGate, PolicyRule
        from nomosguard.ledger import Claim, EvidenceLedger
        from nomosguard.rules import Pattern, Rule, RuleEngine

        rules = [
            PolicyRule(name="broad", match_relation="exposes", decision=Decision.ALERT),
            PolicyRule(name="specific", match_relation="exposes",
                       match_object="orders_db", decision=Decision.BLOCK),
        ]
        derive_exposes = Rule(
            "expose",
            body=(Pattern("?a", "calls", "?t"),
                  Pattern("?a", "operates_on", "?c"),
                  Pattern("?c", "has_vulnerability", "?v")),
            head=Pattern("?a", "exposes", "?c"),
        )
        ledger = EvidenceLedger()
        ledger.append(Claim("tool_call", {"agent": "a", "tool": "t", "target": "orders_db"}, "log"))
        ledger.append(Claim("vulnerability", {"component": "orders_db", "cve": "CVE-1"}, "nvd"))
        engine = RuleEngine(rules=[derive_exposes])
        engine.add_facts_from_ledger(ledger)
        engine.derive()

        gate = PolicyGate(policy_rules=rules)
        decisions = gate.evaluate(engine)
        fired = {d.policy_rule for d in decisions}
        assert fired == {"broad", "specific"}, (
            "a broad rule must not shadow a specific rule on the same relation"
        )
        # worst-wins merge: the specific BLOCK outranks the broad ALERT
        verdict = gate.evaluate_with_fallback(engine)
        assert verdict["decision"] == "BLOCK"
        assert verdict["policy_rule"] == "specific"
        assert "2 decision(s)" in verdict["reason"]
