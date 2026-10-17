"""Every declared export envelope boundary is checked independently of hashes."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path

import pytest

from nomosguard import evidence_export as export
from nomosguard.ledger import Claim, EvidenceLedger


@pytest.fixture
def bundle() -> dict:
    ledger = EvidenceLedger()
    ledger.append(
        Claim(
            "tool_call",
            {"agent": "a", "tool": "read", "target": "db"},
            "first observation",
        )
    )
    ledger.append(
        Claim(
            "tool_call",
            {"agent": "b", "tool": "write", "target": "db"},
            "second observation",
        )
    )
    return export.export_bundle(ledger)


def _write_bad(tmp_path: Path, payload: object) -> Path:
    path = tmp_path / "forged.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("format",), "another-export", "missing"),
        (("format_version",), 999, "unsupported"),
        (("metadata",), False, "metadata object"),
        (("metadata", "timestamp_format"), "naive", "timestamp_format"),
        (("metadata", "digest_algorithm"), "sha1", "digest_algorithm"),
        (("metadata", "digest_scope"), "everything", "digest_scope"),
        (("metadata", "entry_count"), 7, "entry_count"),
        (("metadata", "timestamps"), [], "timestamps must"),
        (("metadata", "timestamps"), {"1": "now"}, "timestamps"),
        (("digest",), 50, "digest must"),
        (("digest",), "md5:not-a-digest", "digest must"),
        (("entries",), None, "entries"),
        (("entries",), [{}], "missing"),
        (("entries",), ["invalid"], "JSON object"),
        (("entries", 0, "extra"), "strange", "undeclared"),
    ],
)
def test_bad_envelope_is_rejected_before_hash_verification(
    bundle: dict,
    path: tuple,
    value: object,
    message: str,
    tmp_path: Path,
) -> None:
    bad = copy.deepcopy(bundle)
    pointer = bad
    for key in path[:-1]:
        pointer = pointer[key]
    pointer[path[-1]] = value
    with pytest.raises(export.ExportError, match=message):
        export.verify_export_bundle(bad)
    persisted = _write_bad(tmp_path, bad)
    if path == ("metadata", "timestamps") and isinstance(value, dict):
        # Structural parsing can accept a mapping; verification is the
        # separate step that refuses incomplete timestamp coverage.
        assert export.read_export_bundle(persisted) == bad
    else:
        with pytest.raises(export.ExportError):
            export.read_export_bundle(persisted)


@pytest.mark.parametrize(
    "bad_time",
    [
        None,
        False,
        "2026-10-17T13:00:00",
        "2026-10-17T13:00:00+03:00",
        "2026-10-17T13:00:00.1234567Z",
    ],
)
def test_invalid_timestamp_does_not_inherit_digest_trust(
    bundle: dict,
    bad_time: object,
) -> None:
    forged = copy.deepcopy(bundle)
    forged["metadata"]["timestamps"]["1"] = bad_time
    with pytest.raises(export.ExportError, match="pinned iso-8601-utc"):
        export.verify_export_bundle(forged)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("seq", True, "integer"),
        ("seq", "1", "integer"),
        ("seq", 9, "sequence broken"),
        ("claim", [], "claim must"),
        ("claim", {"kind": "tool_call"}, "malformed claim"),
        (
            "claim",
            {"kind": "tool_call", "payload": {}, "evidence": ""},
            "invalid claim",
        ),
        ("prev_hash", "forged", "broken chain"),
        ("entry_hash", "not real", "hash mismatch"),
    ],
)
def test_signed_chain_fails_for_every_untrusted_field(
    bundle: dict,
    field: str,
    value: object,
    message: str,
) -> None:
    forged = copy.deepcopy(bundle)
    forged["entries"][0][field] = value
    with pytest.raises(export.ExportError, match=message):
        export.verify_export_bundle(forged)


def test_digest_tampering_detected_even_with_valid_entries(bundle: dict) -> None:
    forged = copy.deepcopy(bundle)
    forged["digest"] = "sha256:" + "0" * 64
    with pytest.raises(export.ExportError, match="digest mismatch"):
        export.verify_export_bundle(forged)


def test_reader_rejects_duplicate_json_and_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "bundle.json"
    for blob in (
        b'{"format":"wrong","format":"correct"}',
        b'{"text":NaN}',
        b'{"text":\xff}',
        b"",
        b"null",
    ):
        path.write_bytes(blob)
        with pytest.raises(export.ExportError):
            export.read_export_bundle(path)


def test_reader_refuses_missing_file_and_excessive_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(export.ExportError, match="cannot read"):
        export.read_export_bundle(tmp_path / "absent.json")
    path = tmp_path / "oversized.json"
    path.write_bytes(b"{}" * 9)
    monkeypatch.setattr(export, "MAX_EXPORT_BUNDLE_BYTES", 10)
    with pytest.raises(export.ExportError, match="byte limit"):
        export.read_export_bundle(path)


def test_chain_export_refuses_naive_timestamp_without_modifying_original(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = EvidenceLedger()
    ledger.append(
        Claim("tool_call", {"agent": "a", "tool": "read", "target": "db"}, "direct")
    )
    original = ledger.entries[0].timestamp
    ledger._entries[0] = replace(ledger.entries[0], timestamp="2026-10-17T13:00:00")
    with pytest.raises(export.ExportError, match="pinned iso-8601-utc"):
        export.export_bundle(ledger)
    assert original.endswith("+00:00")


def test_verifier_refuses_disagreement_with_ledger_verifier(
    bundle: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        EvidenceLedger, "verify", lambda self: (False, "independent rejection")
    )
    with pytest.raises(export.ExportError, match="independent rejection"):
        export.verify_export_bundle(bundle)


def test_export_ledger_file_writes_complete_reopenable_bundle(
    tmp_path: Path,
) -> None:
    ledger = EvidenceLedger()
    ledger.append(
        Claim("tool_call", {"agent": "a", "tool": "read", "target": "db"}, "direct")
    )
    output = tmp_path / "evidence.json"
    result = export.export_ledger_file(ledger, output)
    assert export.read_export_bundle(output) == result
    assert "1 entry intact" in export.verify_export_bundle(result)


def test_tempfile_creation_failure_does_not_leave_unrelated_artifact(
    tmp_path: Path,
    bundle: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def no_temp_file(**kwargs):
        raise PermissionError("read-only artifact directory")

    monkeypatch.setattr(export.tempfile, "NamedTemporaryFile", no_temp_file)
    destination = tmp_path / "bundle.json"
    with pytest.raises(export.ExportError, match="cannot atomically write"):
        export.write_export_bundle(destination, bundle)
    assert not destination.exists()
    assert not list(tmp_path.iterdir())
