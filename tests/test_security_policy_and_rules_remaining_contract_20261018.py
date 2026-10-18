"""Policy and rule-engine decisions remain typed, audited and fail closed."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from nomosguard import (
    log_normalize,
    policy,
    rules,
    schema,
    signature_bridge,
    signatures,
    temporal,
)
from nomosguard.gate import Decision, PolicyGate, PolicyRule
from nomosguard.ledger import EvidenceLedger


def _policy_file(tmp_path, payload):
    target = tmp_path / "policy.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def test_policy_requires_valid_nonempty_pattern_positions():
    with pytest.raises(policy.PolicyConfigError, match="non-empty strings"):
        policy._validate_pattern(["user", "calls", ""], "body[0]")
    with pytest.raises(policy.PolicyConfigError, match="non-empty strings"):
        policy._validate_pattern(["user", "calls", 1], "body[0]")


def test_gate_object_specific_policy_does_not_apply_to_another_object():
    gate = PolicyGate([PolicyRule("target-only", "calls", Decision.BLOCK, match_object="sensitive")])
    state = SimpleNamespace(facts=[rules.Fact("alice", "calls", "benign", ("tool_call",))])
    assert gate.evaluate(state) == []


def test_fact_identity_and_evidence_are_separate():
    a = rules.Fact("alice", "calls", "tool", ("source-1",))
    b = rules.Fact("alice", "calls", "tool", ("source-2",))
    c = rules.Fact("alice", "calls", "another", ("source-1",))
    assert a == b
    assert a != c
    assert a != "not a fact"
    assert hash(a) == hash(b)
    assert len({a, b, c}) == 2
    assert a.to_dict() == {"subject":"alice", "relation":"calls", "object":"tool", "sources":["source-1"]}


def test_unbound_pattern_variable_cannot_generate_a_new_subject():
    with pytest.raises(rules.RuleDefinitionError, match="unbound"):
        rules.Pattern("?user", "calls", "tool").substitute({})


def test_empty_body_rule_is_not_valid_evidence_for_conclusion():
    rule = rules.Rule(name="without-premises", body=(), head=rules.Pattern("alice", "calls", "tool"))
    with pytest.raises(rules.RuleDefinitionError, match="empty body"):
        rule.validate()


def test_gate_entry_requires_mapping_not_arbitrary_json():
    with pytest.raises(policy.PolicyConfigError, match="gate entry must be a JSON object"):
        policy._validate_gate_entry("not-object", 1)


def test_invalid_rule_list_is_not_silently_ignored(tmp_path):
    target = _policy_file(tmp_path, {"rules": "not-a-list", "gate": []})
    with pytest.raises(policy.PolicyConfigError, match="rules.*list"):
        policy.load_policy(target)


def test_invalid_gate_list_is_not_silently_ignored(tmp_path):
    target = _policy_file(tmp_path, {"rules": [], "gate": "not-a-list"})
    with pytest.raises(policy.PolicyConfigError, match="gate.*list"):
        policy.load_policy(target)


def test_unreadable_existing_policy_file_is_refused(tmp_path, monkeypatch):
    target = _policy_file(tmp_path, {"rules": [], "gate": []})
    original = Path.read_text
    def deny(self, *args, **kwargs):
        if self == target:
            raise PermissionError("not accessible")
        return original(self, *args, **kwargs)
    monkeypatch.setattr(Path, "read_text", deny)
    with pytest.raises(policy.PolicyConfigError, match="cannot read policy file"):
        policy.load_policy(target)


def test_unreadable_policy_digest_does_not_claim_integrity(tmp_path, monkeypatch):
    target = _policy_file(tmp_path, {"rules": [], "gate": []})
    original = Path.read_bytes
    def deny(self, *args, **kwargs):
        if self == target:
            raise OSError("simulated disk denial")
        return original(self, *args, **kwargs)
    monkeypatch.setattr(Path, "read_bytes", deny)
    with pytest.raises(policy.PolicyConfigError, match="cannot read policy file"):
        policy.policy_digest(target)


def test_bad_digest_descriptor_is_not_accepted():
    with pytest.raises(policy.PolicyConfigError, match="expected digest"):
        policy._digest_matches("sha256:123", "md5:123")


def test_schema_has_reports_presence_without_truthiness_coercion():
    doc = schema.RecordValidator({"flag": False}, "object")
    assert doc.has("flag") is True
    assert doc.has("missing") is False


def test_signature_id_empty_is_refused():
    with pytest.raises(signatures.SignatureError, match="non-empty string"):
        signatures.Signature(id="", title="sample").validate()


def test_signature_unknown_status_is_refused():
    with pytest.raises(signatures.SignatureError, match="status"):
        signatures.Signature(id="NG-1", title="sample", status="unknown-status").validate()


def test_signature_serialization_and_critical_decision_are_explicit():
    critical = signatures.Signature(id="NG-2", title="critical", level="critical", detection=(("src", "foo"),))
    critical.validate()
    assert critical.is_critical is True
    assert critical.to_dict()["detection"] == [["src", "foo"]]
    assert signatures.Signature(id="NG-3", title="low", level="low").is_critical is False
    assert signatures.Match("NG-2", "raw", ("capture",)).to_dict()["captured"] == ["capture"]


def test_signature_bridge_builds_new_ledger_on_absent_ledger():
    ledger, matches = signature_bridge.run_signatures_into_ledger([], [])
    assert isinstance(ledger, EvidenceLedger)
    assert matches == []


def test_temporal_invalid_iso_date_does_not_invent_valid_epoch():
    assert temporal._to_seconds("2026-99-99T12:13:14") is None


def test_log_normalize_branch_for_source_without_port():
    line = "Oct  9 08:14:01 host sshd: failed password from 192.0.2.1 to 198.51.100.1"
    out = log_normalize.normalize_syslog(line)
    assert out is not None
    assert out.src_port == ""
    assert out.dst_ip == "198.51.100.1"


def test_gelf_epoch_missing_uses_canonical_unknown_time():
    out = log_normalize.normalize_gelf(json.dumps({"version": "1.1", "host": "host", "timestamp": "", "short_message": "scan"}))
    assert out is not None
    assert out.time == "00:00:00"
