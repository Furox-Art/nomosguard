"""One message contract for every record this project validates.

The ingest adapters and the policy loader validate records that come from
outside: JSONL log lines and policy files. Each one invented its own
phrasing for the same class of failure, so the operator reading a
rejection got a different message depending on which adapter they
happened to hit:

    line 3: missing or non-string 'agent'          (tool-call adapter)
    line 3: missing or invalid 'name'              (policy loader)
    line 3: 'target' must be a string when present (same adapter, other field)

Three problems with that: the field and the reason are fused into one
ambiguous phrase ("missing OR non-string" — which was it?), the offending
value is usually absent from the message, and only some messages are
machine-checkable. Auditing a rejected log became guesswork.

One contract, one shape::

    <location>: field <name> <reason>[, got <value>]

with `reason` drawn from a closed vocabulary (`is missing (required)`,
`must be a string`, `must be a non-empty string`, `must be an object`,
`must be one of ...`, `must match ...`). A caller can parse every message
this project emits, and every message names both the field and what was
wrong with it.

The helpers raise the *caller's* error type (`IngestError`,
`PolicyConfigError`, ...) via `RecordValidator`; nothing here knows about
the ledger semantics. Fail-closed stays fail-closed — the only change is
that the refusal is legible and uniform.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any


class SchemaError(ValueError):
    """Raised when a record violates the schema contract.

    Callers wrap this in their own domain error (see `RecordValidator`'s
    `error=` argument); the message shape is what matters, and it is the
    same for every validator in this project.
    """


# -- message builders ---------------------------------------------------------
# Kept public and pure so tests (and operators) can assert the contract
# without going through a validator.

def msg_missing(location: str, field: str) -> str:
    return f"{location}: field {field!r} is missing (required)"


def msg_type(location: str, field: str, expected: str, value: Any) -> str:
    return f"{location}: field {field!r} must be {expected}, got {value!r}"


def msg_blank(location: str, field: str, value: Any) -> str:
    return f"{location}: field {field!r} must be a non-empty string, got {value!r}"


def msg_enum(location: str, field: str, allowed: Iterable[str], value: Any) -> str:
    return (
        f"{location}: field {field!r} must be one of {sorted(allowed)}, "
        f"got {value!r}"
    )


def msg_pattern(location: str, field: str, pattern: str, value: Any) -> str:
    return f"{location}: field {field!r} must match {pattern}, got {value!r}"


def msg_unknown_field(location: str, field: str, allowed: Iterable[str]) -> str:
    return (
        f"{location}: field {field!r} is not allowed "
        f"(allowed fields: {sorted(allowed)}) — unknown fields are refused, "
        "not silently ignored"
    )


def msg_not_json(location: str, exc: Exception) -> str:
    return f"{location}: record is not valid JSON: {exc}"


def msg_not_object(location: str, value: Any) -> str:
    return f"{location}: record must be a JSON object, got {type(value).__name__}"


# -- the record shape ---------------------------------------------------------

def parse_json_record(text: str, location: str, *, error: type[ValueError] = SchemaError) -> dict[str, Any]:
    """Parse one JSON object, with the contract's messages for failures."""
    try:
        record = json.loads(text)
    except json.JSONDecodeError as exc:
        raise error(msg_not_json(location, exc)) from exc
    if not isinstance(record, dict):
        raise error(msg_not_object(location, record))
    return record


class RecordValidator:
    """Validate one already-parsed record against the message contract.

        v = RecordValidator(record, f"line {line_no}", error=IngestError)
        agent = v.string("agent")             # required, non-blank string
        target = v.string("target", required=False)
        args = v.object("args", required=False)
        effect = v.enum("effect", VALID_EFFECTS, fold=True)

    Every method raises `error` with a message in the one contract shape:
    the location, the field name, the reason, and the offending value.
    Nothing is coerced, defaulted, or guessed — a missing optional field
    returns None; a present-but-invalid one always raises.
    """

    __slots__ = ("error", "location", "record")

    def __init__(
        self,
        record: Any,
        location: str,
        *,
        error: type[ValueError] = SchemaError,
    ) -> None:
        if not isinstance(record, dict):
            raise error(msg_not_object(location, record))
        self.record = record
        self.location = location
        self.error = error

    # -- fields ---------------------------------------------------------------

    def has(self, field: str) -> bool:
        return field in self.record

    def string(
        self,
        field: str,
        *,
        required: bool = True,
        allow_blank: bool = False,
        fold: str | None = None,
        default: str | None = None,
    ) -> str | None:
        """A string field: required and non-blank unless stated otherwise.

        `fold` ("lower"/"upper") is applied AFTER validation, so the value
        is only ever normalised once it is known to be a valid string.
        """
        if field not in self.record:
            if required:
                raise self.error(msg_missing(self.location, field))
            return default
        value = self.record[field]
        if not isinstance(value, str):
            raise self.error(msg_type(self.location, field, "a string", value))
        if not allow_blank and not value.strip():
            raise self.error(msg_blank(self.location, field, value))
        if fold == "lower":
            return value.lower()
        if fold == "upper":
            return value.upper()
        return value

    def object(
        self, field: str, *, required: bool = False
    ) -> dict[str, Any] | None:
        """A JSON object field. Optional by default (payload-style fields)."""
        if field not in self.record:
            if required:
                raise self.error(msg_missing(self.location, field))
            return None
        value = self.record[field]
        if not isinstance(value, dict):
            raise self.error(msg_type(self.location, field, "an object", value))
        return value

    def enum(
        self,
        field: str,
        allowed: Iterable[str],
        *,
        required: bool = True,
        fold: str | None = "lower",
        default: str | None = None,
    ) -> str | None:
        """A closed-vocabulary field. An unknown value is an error, never a
        default — silently guessing a policy effect is exactly the kind of
        coercion this contract exists to prevent."""
        allowed = tuple(allowed)
        if field not in self.record:
            if required:
                raise self.error(msg_missing(self.location, field))
            return default
        value = self.record[field]
        if not isinstance(value, str):
            raise self.error(msg_type(self.location, field, "a string", value))
        candidate = value.lower() if fold == "lower" else value
        if candidate not in allowed:
            raise self.error(msg_enum(self.location, field, allowed, value))
        return candidate

    def pattern(
        self, field: str, pattern: str, *, predicate=None
    ) -> str:
        """A string field constrained by a human-readable pattern name.

        `predicate` is the boolean test; `pattern` is the NAME of the shape
        (e.g. "CVE-YYYY-NNNN"), which is what the message reports.
        """
        value = self.string(field)
        assert value is not None  # `string` raises when required is absent
        if predicate is not None and not predicate(value):
            raise self.error(msg_pattern(self.location, field, pattern, value))
        return value

    def unknown_fields(self, allowed: Iterable[str]) -> None:
        """Refuse any field outside `allowed`.

        A typo'd key (`match_relaton`) that is silently ignored is a policy
        written for nothing: the author believes a constraint is in force
        while the loader never saw it. The refusal names the offending
        field, so the fix is obvious from the message alone.
        """
        allowed = set(allowed)
        for field in self.record:
            if field not in allowed:
                raise self.error(msg_unknown_field(self.location, field, allowed))

    # -- containers -----------------------------------------------------------

    def list_of(
        self, field: str, *, required: bool = True, non_empty: bool = False
    ) -> list[Any] | None:
        if field not in self.record:
            if required:
                raise self.error(msg_missing(self.location, field))
            return None
        value = self.record[field]
        if not isinstance(value, list):
            raise self.error(msg_type(self.location, field, "a list", value))
        if non_empty and not value:
            raise self.error(
                f"{self.location}: field {field!r} must be a non-empty list"
            )
        return value
