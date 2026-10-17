"""Policy/schema refusal tests: unknown information must never become permission."""

from __future__ import annotations

import json

import pytest

from nomosguard.policy import (
    PolicyConfigError,
    _digest_matches,
    _validate_gate_entry,
    _validate_pattern,
    _validate_rule,
    load_policy,
    policy_digest,
)
from nomosguard.schema import RecordValidator, SchemaError


def test_schema_distinguishes_present_values_from_missing_ones():
    validator = RecordValidator({"present": "value"}, "line 1")
    assert validator.has("present")
    assert not validator.has("missing")


@pytest.mark.parametrize(
    ("value", "fold", "expected"),
    [("MixedCase", "lower", "mixedcase"), ("MixedCase", "upper", "MIXEDCASE")],
)
def test_explicit_schema_normalization_is_applied_only_to_a_validated_string(
    value, fold, expected
):
    assert (
        RecordValidator({"name": value}, "input").string("name", fold=fold) == expected
    )


@pytest.mark.parametrize(
    ("field_type", "data", "pattern"),
    [
        ("object", {}, "missing"),
        ("enum", {"decision": 3}, "must be a string"),
        ("list", {"items": {}}, "must be a list"),
    ],
)
def test_bad_policy_field_types_fail_closed_without_implicit_coercion(
    field_type, data, pattern
):
    v = RecordValidator(data, "policy")
    with pytest.raises(SchemaError, match=pattern):
        if field_type == "object":
            v.object("payload", required=True)
        elif field_type == "enum":
            v.enum("decision", {"ALLOW", "BLOCK"}, fold=None)
        else:
            v.list_of("items")


def test_policy_blank_pattern_positions_cannot_bind_to_implicit_wildcard():
    with pytest.raises(PolicyConfigError, match="non-empty strings"):
        _validate_pattern(["?agent", "calls", "  "], "rules[0]")


@pytest.mark.parametrize(
    ("fn", "message"),
    [
        (_validate_rule, "rule must be a JSON object"),
        (_validate_gate_entry, "gate entry must be a JSON object"),
    ],
)
def test_policy_rule_and_gate_both_refuse_nonobject_rules(fn, message):
    with pytest.raises(PolicyConfigError, match=message):
        fn([], 2)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("rules", {}, "rules"),
        ("gate", {}, "gate"),
    ],
)
def test_policy_bundle_rejects_wrong_container_types_at_load_boundary(
    tmp_path, field, value, message
):
    doc = {"rules": [], "gate": []}
    doc[field] = value
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(PolicyConfigError, match=message):
        load_policy(path)


def test_policy_digest_does_not_hash_unreadable_directory(tmp_path):
    with pytest.raises(PolicyConfigError, match="cannot read policy file"):
        policy_digest(tmp_path)


def test_policy_bundle_read_failure_after_isfile_check_fails_closed(
    tmp_path, monkeypatch
):
    path = tmp_path / "rules.json"
    path.write_text('{"rules":[],"gate":[]}', encoding="utf-8")
    orig_read = type(path).read_text

    def fail_target(self, *args, **kwargs):
        if self == path:
            raise OSError("simulated read failure")
        return orig_read(self, *args, **kwargs)

    monkeypatch.setattr(type(path), "read_text", fail_target)
    with pytest.raises(PolicyConfigError, match="cannot read policy file"):
        load_policy(path)


@pytest.mark.parametrize("pin", ["", "digest", 42, None])
def test_hash_pin_requires_explicit_sha256_namespace(pin):
    with pytest.raises(PolicyConfigError, match="expected digest must look"):
        _digest_matches("sha256:abc", pin)
