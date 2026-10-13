"""The validation message contract: one shape, every failure mode (H3).

Every rejection the project emits — a JSONL log line, a policy file, a
gate decision — must read the same way:

    <location>: field <name> <reason>[, got <value>]

This suite asserts the contract on the three most common failure modes
(missing required field, wrong type, closed-vocabulary violation) across
every consumer, so a message that names neither the field nor the reason
cannot come back.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from nomosguard.ingest import IngestError
from nomosguard.ingest.policy_jsonl import parse_policy_line
from nomosguard.ingest.toolcall_jsonl import parse_toolcall_line
from nomosguard.ingest.vuln_jsonl import parse_vuln_line
from nomosguard.policy import PolicyConfigError, load_policy
from nomosguard.schema import (
    RecordValidator,
    SchemaError,
    msg_blank,
    msg_enum,
    msg_missing,
    msg_not_json,
    msg_not_object,
    msg_pattern,
    msg_type,
)


class TestMessageShape:
    """The contract itself: location + field + reason + offending value."""

    def test_missing_field_names_the_field(self):
        assert msg_missing("line 7", "agent") == "line 7: field 'agent' is missing (required)"

    def test_type_error_names_field_and_value(self):
        assert msg_type("line 7", "agent", "a string", 42) == (
            "line 7: field 'agent' must be a string, got 42"
        )

    def test_blank_field_is_distinct_from_missing(self):
        assert msg_blank("line 7", "agent", "   ") == (
            "line 7: field 'agent' must be a non-empty string, got '   '"
        )

    def test_enum_error_lists_the_vocabulary(self):
        assert msg_enum("line 7", "effect", ("allow", "deny"), "maybe") == (
            "line 7: field 'effect' must be one of ['allow', 'deny'], got 'maybe'"
        )

    def test_pattern_error_names_the_expected_shape(self):
        assert msg_pattern("line 7", "cve", "CVE-YYYY-NNNN", "nope") == (
            "line 7: field 'cve' must match CVE-YYYY-NNNN, got 'nope'"
        )

    def test_every_message_names_location_and_field(self):
        messages = [
            msg_missing("line 1", "agent"),
            msg_type("line 1", "agent", "a string", 1),
            msg_blank("line 1", "agent", ""),
            msg_enum("line 1", "effect", ("allow",), "x"),
            msg_pattern("line 1", "cve", "CVE-YYYY-NNNN", "x"),
        ]
        for message in messages:
            assert message.startswith("line 1:"), message
            assert "field '" in message, message
        assert msg_not_json("line 1", ValueError("boom")).startswith("line 1:")
        assert msg_not_object("line 1", []).startswith("line 1:")


class TestToolcallContract:
    def test_missing_required_field(self):
        with pytest.raises(IngestError) as exc:
            parse_toolcall_line('{"tool": "t"}', 3)
        assert str(exc.value) == "line 3: field 'agent' is missing (required)"

    def test_wrong_type(self):
        with pytest.raises(IngestError) as exc:
            parse_toolcall_line('{"agent": 42, "tool": "t"}', 3)
        assert str(exc.value) == "line 3: field 'agent' must be a string, got 42"

    def test_blank_value(self):
        with pytest.raises(IngestError) as exc:
            parse_toolcall_line('{"agent": "  ", "tool": "t"}', 3)
        assert str(exc.value) == "line 3: field 'agent' must be a non-empty string, got '  '"

    def test_optional_field_of_the_wrong_type(self):
        with pytest.raises(IngestError) as exc:
            parse_toolcall_line('{"agent": "a", "tool": "t", "args": "nope"}', 3)
        assert str(exc.value) == "line 3: field 'args' must be an object, got 'nope'"

    def test_invalid_json(self):
        with pytest.raises(IngestError) as exc:
            parse_toolcall_line("{oops", 3)
        assert str(exc.value).startswith("line 3: record is not valid JSON:")

    def test_non_object_record(self):
        with pytest.raises(IngestError) as exc:
            parse_toolcall_line("[1, 2]", 3)
        assert str(exc.value) == "line 3: record must be a JSON object, got list"


class TestVulnContract:
    def test_missing_required_field(self):
        with pytest.raises(IngestError) as exc:
            parse_vuln_line('{"cve": "CVE-2026-1"}', 2)
        assert str(exc.value) == "line 2: field 'component' is missing (required)"

    def test_invalid_enum_value(self):
        with pytest.raises(IngestError) as exc:
            parse_vuln_line('{"component": "db", "cve": "CVE-2026-1", "severity": "bad"}', 2)
        assert str(exc.value) == (
            "line 2: field 'severity' must be one of "
            "['critical', 'high', 'low', 'medium', 'unknown'], got 'bad'"
        )

    def test_invalid_format_value(self):
        with pytest.raises(IngestError) as exc:
            parse_vuln_line('{"component": "db", "cve": "not-a-cve"}', 2)
        assert str(exc.value) == (
            "line 2: field 'cve' must match CVE-YYYY-NNNN, got 'not-a-cve'"
        )

    def test_wrong_type_on_optional_field(self):
        with pytest.raises(IngestError) as exc:
            parse_vuln_line(
                '{"component": "db", "cve": "CVE-2026-1", "description": 5}', 2
            )
        assert str(exc.value) == (
            "line 2: field 'description' must be a string, got 5"
        )


class TestPolicyContract:
    def test_missing_required_field(self):
        with pytest.raises(IngestError) as exc:
            parse_policy_line('{"action": "sql", "resource": "db", "effect": "deny"}', 9)
        assert str(exc.value) == "line 9: field 'subject' is missing (required)"

    def test_unknown_effect_is_refused(self):
        """No silent coercion: 'maybe' is neither allow nor deny."""
        with pytest.raises(IngestError) as exc:
            parse_policy_line(
                '{"subject": "a", "action": "sql", "resource": "db", "effect": "maybe"}', 9
            )
        assert str(exc.value) == (
            "line 9: field 'effect' must be one of ['allow', 'deny'], got 'maybe'"
        )

    def test_missing_effect_is_refused(self):
        with pytest.raises(IngestError) as exc:
            parse_policy_line('{"subject": "a", "action": "sql", "resource": "db"}', 9)
        assert str(exc.value) == "line 9: field 'effect' is missing (required)"


class TestPolicyFileContract:
    """The policy loader speaks the same contract as the ingest adapters."""

    def _write(self, td, data) -> Path:
        path = Path(td) / "policy.json"
        path.write_text(json.dumps(data))
        return path

    def test_missing_rule_name(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, {"rules": [{"body": [["?a", "calls", "?t"]],
                                                "head": ["?a", "x", "y"]}]})
            with pytest.raises(PolicyConfigError) as exc:
                load_policy(path)
            assert str(exc.value) == "rules[0]: field 'name' is missing (required)"

    def test_wrong_type_rule_name(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, {"rules": [{"name": 7, "body": [["?a", "calls", "?t"]],
                                                "head": ["?a", "x", "y"]}]})
            with pytest.raises(PolicyConfigError) as exc:
                load_policy(path)
            assert str(exc.value) == "rules[0]: field 'name' must be a string, got 7"

    def test_missing_body(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, {"rules": [{"name": "r", "head": ["?a", "x", "y"]}]})
            with pytest.raises(PolicyConfigError) as exc:
                load_policy(path)
            assert str(exc.value) == "rules[0]: field 'body' is missing (required)"

    def test_unknown_decision(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, {"gate": [{"name": "g", "match_relation": "exposes",
                                              "decision": "MAYBE"}]})
            with pytest.raises(PolicyConfigError) as exc:
                load_policy(path)
            assert str(exc.value) == (
                "gate[0]: field 'decision' must be one of ['ALERT', 'ALLOW', "
                "'BLOCK', 'ESCALATE', 'ISOLATE_HOST', 'REVOKE_ACCESS'], got 'MAYBE'"
            )

    def test_missing_gate_relation(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, {"gate": [{"name": "g", "decision": "BLOCK"}]})
            with pytest.raises(PolicyConfigError) as exc:
                load_policy(path)
            assert str(exc.value) == (
                "gate[0]: field 'match_relation' is missing (required)"
            )

    def test_non_object_rule(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, {"rules": ["not-a-rule"]})
            with pytest.raises(PolicyConfigError) as exc:
                load_policy(path)
            assert str(exc.value) == (
                "rules[0]: rule must be a JSON object, got str"
            )

    def test_invalid_json(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "policy.json"
            path.write_text("{oops")
            with pytest.raises(PolicyConfigError) as exc:
                load_policy(path)
            assert str(exc.value).startswith("policy file: record is not valid JSON:")

    def test_non_object_root(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "policy.json"
            path.write_text("[1, 2, 3]")
            with pytest.raises(PolicyConfigError) as exc:
                load_policy(path)
            assert str(exc.value) == (
                "policy file: record must be a JSON object, got list"
            )


class TestValidatorUnit:
    """The helper behind all of the above, used directly."""

    def test_returns_valid_values_untouched(self):
        v = RecordValidator({"a": "x", "b": "  y  "}, "loc")
        assert v.string("a") == "x"
        assert v.string("b", allow_blank=True) == "  y  "

    def test_optional_absent_returns_none(self):
        v = RecordValidator({}, "loc")
        assert v.string("missing", required=False) is None
        assert v.object("missing") is None

    def test_enum_folds_case_after_validation(self):
        v = RecordValidator({"effect": "DENY"}, "loc")
        assert v.enum("effect", ("allow", "deny")) == "deny"

    def test_error_type_is_the_caller_s(self):
        v = RecordValidator({}, "loc", error=ValueError)
        with pytest.raises(ValueError):
            v.string("nope")

    def test_non_dict_record_is_refused(self):
        with pytest.raises(SchemaError):
            RecordValidator([], "loc")
