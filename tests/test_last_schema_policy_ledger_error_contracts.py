"""Direct evidence and policy error branches: no fake permissions or lost WAL evidence."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from nomosguard import ledger as ledger_module
from nomosguard.ledger import (
    Claim,
    EvidenceLedger,
    LedgerFileError,
    _atomic_write_lines,
    _finite_json_float,
    ledger_digest,
)
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


def claim():
    return Claim(
        kind="tool_call",
        payload={"agent": "operator", "tool": "inspect"},
        evidence="direct audit log line",
    )


def test_schema_has_reports_explicit_presence_in_record():
    v = RecordValidator({"item": "ok"}, "line 5")
    assert v.has("item") is True
    assert v.has("missing") is False


@pytest.mark.parametrize(
    ("data", "key", "fold", "expected"),
    [
        ({"value": "HeLLo"}, "value", "lower", "hello"),
        ({"value": "HeLLo"}, "value", "upper", "HELLO"),
        ({"value": " "}, "value", None, " "),
    ],
)
def test_policy_string_normalization_follows_user_declared_case_policy(
    data, key, fold, expected
):
    v = RecordValidator(data, "policy")
    assert v.string(key, fold=fold, allow_blank=True) == expected


def test_schema_required_missing_object_fails_closed():
    with pytest.raises(SchemaError, match="missing \\(required\\)"):
        RecordValidator({}, "record").object("inputs", required=True)


def test_schema_wrong_enum_type_fails_with_field_name():
    with pytest.raises(SchemaError, match="must be a string"):
        RecordValidator({"decision": 3}, "record").enum(
            "decision", {"BLOCK", "ALLOW"}, fold=None
        )


def test_schema_rejects_non_list_value_in_declared_list_field():
    with pytest.raises(SchemaError, match="must be a list"):
        RecordValidator({"scope": {}}, "record").list_of("scope")


def test_policy_pattern_positions_must_be_explicit_nonempty_strings():
    with pytest.raises(PolicyConfigError, match="non-empty strings"):
        _validate_pattern(["?x", "calls", " "], "rules[0].body[0]")


@pytest.mark.parametrize(
    ("entry", "validator", "message"),
    [
        ([], _validate_rule, "rule must be a JSON object"),
        ([], _validate_gate_entry, "gate entry must be a JSON object"),
    ],
)
def test_non_object_policy_rules_are_refused_before_decision(entry, validator, message):
    with pytest.raises(PolicyConfigError, match=message):
        validator(entry, 1)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"rules": {}, "gate": []}, "'rules' must be a list"),
        ({"rules": [], "gate": {}}, "'gate' must be a list"),
    ],
)
def test_policy_bundle_rejects_nonlist_rule_containers(tmp_path, payload, message):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(PolicyConfigError, match=message):
        load_policy(path)


def test_policy_digest_refuses_unreadable_directory_instead_of_merely_missing(tmp_path):
    with pytest.raises(PolicyConfigError, match="cannot read policy file"):
        policy_digest(tmp_path)


def test_policy_loader_raises_if_read_fails_after_is_file_check(tmp_path, monkeypatch):
    file = tmp_path / "policy.json"
    file.write_text('{"rules":[],"gate":[]}')
    original = type(file).read_text

    def broken(self, *args, **kwargs):
        if self == file:
            raise OSError("simulated read refusal")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(type(file), "read_text", broken)
    with pytest.raises(PolicyConfigError, match="cannot read policy file"):
        load_policy(file)


def test_policy_digest_requires_explicit_sha256_prefix():
    with pytest.raises(
        PolicyConfigError, match="expected digest must look like sha256"
    ):
        _digest_matches("sha256:abcdef", "naked-hash")


def test_ledger_valid_json_floating_number_is_accepted_with_original_value():
    assert _finite_json_float("1.2345") == pytest.approx(1.2345)


def test_ledger_digest_directory_read_error_is_not_hidden(tmp_path):
    with pytest.raises(LedgerFileError, match="cannot read ledger file"):
        ledger_digest(tmp_path)


def test_empty_ledger_head_is_none_and_valid_sha_head_is_recorded_only_after_append():
    ledger = EvidenceLedger()
    assert ledger.head is None
    assert ledger.head_hash == ""
    assert ledger.verify()[0] is True
    entry = ledger.append(claim())
    assert ledger.head == entry
    assert ledger.head_hash == entry.entry_hash


@pytest.mark.parametrize(
    ("property_name", "new_value", "message"),
    [
        ("seq", 2, "sequence broken"),
        ("prev_hash", "bad", "chain broken"),
    ],
)
def test_mutated_ledger_link_metadata_is_detected_without_normalization(
    property_name, new_value, message
):
    ledger = EvidenceLedger()
    entry = ledger.append(claim())
    ledger._entries[0] = replace(entry, **{property_name: new_value})
    valid, detail = ledger.verify()
    assert valid is False
    assert message in detail


def test_atomic_ledger_write_handles_directory_open_failure_as_best_effort(
    tmp_path, monkeypatch
):
    target = tmp_path / "entry.jsonl"
    original = ledger_module.os.open

    def failure(path, flags, *args, **kwargs):
        if str(path) == str(target.parent):
            raise OSError("simulated directory fsync unavailable")
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(ledger_module.os, "open", failure)
    _atomic_write_lines(target, ['{"record":"audited"}'])
    assert target.read_text().strip() == '{"record":"audited"}'


def test_atomic_ledger_write_handles_directory_fsync_failure_without_losing_file(
    tmp_path, monkeypatch
):
    target = tmp_path / "entry.jsonl"
    original = ledger_module.os.fsync
    calls = []

    def fail_directory(fd):
        calls.append(fd)
        if len(calls) > 1:
            raise OSError("directory fsync unsupported")
        return original(fd)

    monkeypatch.setattr(ledger_module.os, "fsync", fail_directory)
    _atomic_write_lines(target, ['{"record":"audited"}'])
    assert json.loads(target.read_text()) == {"record": "audited"}


def test_atomic_write_removes_temporary_file_after_replace_fails(tmp_path, monkeypatch):
    target = tmp_path / "entry.jsonl"

    def fail_replace(src, dest):
        raise OSError("simulated crash before atomic replace")

    monkeypatch.setattr(ledger_module.os, "replace", fail_replace)
    with pytest.raises(OSError, match="before atomic replace"):
        _atomic_write_lines(target, ['{"status":"new"}'])
    assert list(tmp_path.glob("*.tmp")) == []
    assert not target.exists()
