"""Untrusted MCP and attestation inputs must be bounded before parsing."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from nomosguard import evidence_export, mcp_stdio
from nomosguard.evidence_export import ExportError, export_bundle, read_export_bundle
from nomosguard.ledger import Claim, EvidenceLedger
from nomosguard.mcp_server import (
    NomosGuardSession,
    default_policy_rules,
    default_rules,
)


def _run_frames(monkeypatch: pytest.MonkeyPatch, stream: str, limit: int) -> list[dict]:
    sink = io.StringIO()
    monkeypatch.setattr(sys, "stdin", io.StringIO(stream))
    monkeypatch.setattr(sys, "stdout", sink)
    monkeypatch.setattr(mcp_stdio, "_OUT", sink)
    monkeypatch.setattr(mcp_stdio, "MAX_MCP_FRAME_CHARS", limit)
    session = NomosGuardSession(rules=default_rules(), policy_rules=default_policy_rules())
    mcp_stdio._serve_loop(session)
    return [json.loads(line) for line in sink.getvalue().splitlines()]


def test_oversized_mcp_request_is_refused_but_next_frame_survives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oversized = '{"jsonrpc":"2.0","id":7,"method":"ping","padding":"' + "x" * 250 + '"}\n'
    valid = '{"jsonrpc":"2.0","id":8,"method":"ping"}\n'
    responses = _run_frames(monkeypatch, oversized + valid, 80)
    assert responses[0]["id"] is None
    assert responses[0]["error"]["code"] == -32600
    assert "too large" in responses[0]["error"]["message"]
    assert responses[1] == {"jsonrpc": "2.0", "id": 8, "result": {}}


def test_mcp_frame_exactly_at_declared_limit_remains_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid = '{"jsonrpc":"2.0","id":11,"method":"ping"}\n'
    replies = _run_frames(monkeypatch, valid, len(valid))
    assert replies == [{"jsonrpc": "2.0", "id": 11, "result": {}}]


def test_successive_large_mcp_frames_do_not_swallow_next_valid_frame(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oversized = '{"jsonrpc":"2.0","id":3,"method":"ping","padding":"' + "a" * 180 + '"}\n'
    valid = '{"jsonrpc":"2.0","id":9,"method":"ping"}\n'
    replies = _run_frames(monkeypatch, oversized * 3 + valid, 80)
    assert len(replies) == 4
    assert all(row["error"]["code"] == -32600 for row in replies[:3])
    assert replies[-1]["id"] == 9


def test_no_unbounded_readline_calls_for_oversized_frames(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class GuardedReader(io.StringIO):
        def readline(self, size: int = -1) -> str:
            assert 0 < size <= 81, f"unbounded read request: {size}"
            return super().readline(size)

    stream = '{"jsonrpc":"2.0","method":"ping","x":"' + "x" * 200 + '"}\n'
    monkeypatch.setattr(sys, "stdin", GuardedReader(stream))
    monkeypatch.setattr(mcp_stdio, "MAX_MCP_FRAME_CHARS", 80)
    assert list(mcp_stdio._stdin_lines()) == [("", True)]


def test_oversized_export_is_refused_before_json_parser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    file = tmp_path / "bundle.json"
    file.write_bytes(b"x" * 130)
    monkeypatch.setattr(evidence_export, "MAX_EXPORT_BUNDLE_BYTES", 32)

    def no_parse(_value: object) -> object:
        raise AssertionError("must never parse oversized files")

    monkeypatch.setattr(evidence_export, "_strict_loads", no_parse)
    with pytest.raises(ExportError, match="32 byte limit"):
        read_export_bundle(file)


def test_export_file_at_exact_limit_remains_compatible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = EvidenceLedger()
    ledger.append(Claim("audit", {"status": "PASS"}, "direct evidence"))
    bundle = export_bundle(ledger)
    file = tmp_path / "bundle.json"
    content = json.dumps(bundle, ensure_ascii=False).encode("utf-8")
    file.write_bytes(content)
    monkeypatch.setattr(evidence_export, "MAX_EXPORT_BUNDLE_BYTES", len(content))
    assert read_export_bundle(file) == bundle
