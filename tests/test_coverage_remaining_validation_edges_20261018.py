"""Real validation and ingestion failure paths, including optional-field contracts."""

from __future__ import annotations

import json

import pytest

from nomosguard.gate import Decision, PolicyGate, PolicyRule
from nomosguard.ingest.policy_jsonl import ingest_policy_jsonl
from nomosguard.ingest.vuln_jsonl import ingest_vuln_jsonl, parse_vuln_line
from nomosguard.ledger import EvidenceLedger
from nomosguard.schema import RecordValidator, SchemaError
from nomosguard.signature_bridge import _extract_signature_claim


def test_optional_object_missing_and_required_object_missing():
    check = RecordValidator({}, "policy item")
    assert check.object("payload") is None
    with pytest.raises(SchemaError, match="missing"):
        check.object("payload", required=True)


def test_string_lower_upper_and_type_enforced():
    check = RecordValidator({"action": "ALLoW", "effect": "Deny", "unexpected": 9}, "policy")
    assert check.string("action", fold="lower") == "allow"
    assert check.string("effect", fold="upper") == "DENY"
    with pytest.raises(SchemaError, match="string"):
        check.string("unexpected")


def test_enum_string_shape_rejected_without_coercion():
    check = RecordValidator({"effect": 1}, "policy")
    with pytest.raises(SchemaError, match="string"):
        check.enum("effect", ("deny", "allow"))


def test_list_field_wrong_type_is_denied():
    check = RecordValidator({"items": "not-a-list"}, "policy")
    with pytest.raises(SchemaError, match="list"):
        check.list_of("items")


def test_required_missing_list_is_denied():
    with pytest.raises(SchemaError, match="missing"):
        RecordValidator({}, "policy").list_of("items")


def test_optional_policy_fields_are_not_assumed():
    check = RecordValidator({}, "policy")
    assert check.string("description", required=False) is None


def test_valid_vulnerability_optional_description_is_preserved():
    item = parse_vuln_line(json.dumps({"component": "server", "cve": "CVE-2026-1234", "severity": "high", "description": "bounded evidence"}), 1)
    assert item["description"] == "bounded evidence"


def test_policy_ingest_ignores_blank_lines_and_deduplicates(tmp_path):
    path = tmp_path / "policies.jsonl"
    row = json.dumps({"subject": "alice", "action": "read", "resource": "db", "effect": "deny"})
    path.write_text(" \n" + row + "\n" + row + "\n", encoding="utf-8")
    ledger = EvidenceLedger()
    result = ingest_policy_jsonl(ledger, path)
    assert (result.total_lines, result.accepted, result.duplicates) == (2, 1, 1)
    assert not result.rejected


def test_vulnerability_ingest_ignores_blank_lines_and_deduplicates(tmp_path):
    path = tmp_path / "cve.jsonl"
    row = json.dumps({"component": "web", "cve": "CVE-2026-8888", "severity": "critical"})
    path.write_text("\n  \n" + row + "\n" + row + "\n", encoding="utf-8")
    ledger = EvidenceLedger()
    result = ingest_vuln_jsonl(ledger, path)
    assert (result.total_lines, result.accepted, result.duplicates) == (2, 1, 1)


def test_signature_empty_id_does_not_produce_an_evidence_fact():
    assert _extract_signature_claim({"subject": "actor", "signature_id": "", "level": "critical"}, "test evidence") == []


def test_default_deny_policy_cannot_resolve_unknown_rule_without_facts():
    gate = PolicyGate([PolicyRule(name="deny-on-match", match_relation="denied", decision=Decision.BLOCK)])
    assert gate.fallback == Decision.BLOCK
