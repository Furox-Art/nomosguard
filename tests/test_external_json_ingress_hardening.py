"""MCP and export file boundaries never accept ambiguous security JSON."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from nomosguard import mcp_stdio
from nomosguard.evidence_export import (
    ExportError,
    export_bundle,
    read_export_bundle,
    verify_export_bundle,
)
from nomosguard.ledger import Claim, EvidenceLedger
from nomosguard.mcp_server import (
    NomosGuardSession,
    default_policy_rules,
    default_rules,
)


def _serve_raw(monkeypatch: pytest.MonkeyPatch, raw: str) -> tuple[list[dict], NomosGuardSession]:
    session = NomosGuardSession(rules=default_rules(), policy_rules=default_policy_rules())
    written = io.StringIO()
    monkeypatch.setattr(sys, "stdin", io.StringIO(raw))
    monkeypatch.setattr(sys, "stdout", written)
    monkeypatch.setattr(mcp_stdio, "_OUT", written)
    mcp_stdio._serve_loop(session)
    responses = [json.loads(line) for line in written.getvalue().splitlines() if line.strip()]
    return responses, session


@pytest.mark.parametrize(
    "raw",
    [
        '{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/list"}',
        '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"derive_paths","name":"decide"}}',
        '{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":1,"a":2}}',
        '{"jsonrpc":"2.0","id":1,"method":"ping","params":{"bad":NaN}}',
        '{"jsonrpc":"2.0","id":1,"method":"ping","params":{"bad":1e9999}}',
        r'{"jsonrpc":"2.0","id":"\ud800","method":"ping"}',
    ],
)
def test_mcp_rejects_ambiguous_json_and_recovers(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    valid = '{"jsonrpc":"2.0","id":8,"method":"ping"}'
    replies, session = _serve_raw(monkeypatch, raw + "\n" + valid + "\n")
    assert len(replies) == 2
    assert replies[0]["id"] is None
    assert replies[0]["error"]["code"] == -32700
    assert replies[1] == {"jsonrpc": "2.0", "id": 8, "result": {}}
    assert len(session.ledger.entries) == 0


@pytest.mark.parametrize(
    "transform",
    [
        lambda src: src.replace('"digest": ', '"digest": "sha256:0", "digest": ', 1),
        lambda src: src.replace('"entry_count": 1', '"entry_count": 900, "entry_count": 1', 1),
        lambda src: src.replace('"claim": {', '"claim": null, "claim": {', 1),
        lambda src: src.replace('"metadata": {', '"metadata": {"extra":NaN}, "metadata": {', 1),
        lambda src: src.replace('"entries": [', '"bad": 1e9999, "entries": [', 1),
        lambda src: src.replace('"format": ', r'"bad":"\ud800", "format": ', 1),
    ],
)
def test_export_file_refuses_ambiguous_json_even_if_valid_bundle_is_embedded(
    tmp_path: Path, transform
) -> None:
    ledger = EvidenceLedger()
    ledger.append(Claim("audit", {"status": "PASS"}, "direct observation"))
    valid = export_bundle(ledger)
    path = tmp_path / "bundle.json"
    original = json.dumps(valid, sort_keys=True, ensure_ascii=False)
    modified = transform(original)
    assert modified != original
    path.write_text(modified, encoding="utf-8")
    with pytest.raises(ExportError, match="not a valid JSON export bundle"):
        read_export_bundle(path)


def test_valid_multilingual_evidence_export_round_trip(tmp_path: Path) -> None:
    ledger = EvidenceLedger()
    ledger.append(Claim("denetim", {"açıklama": "Türkçe 日本語 😀"}, "somut kanıt"))
    valid = export_bundle(ledger)
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(valid, ensure_ascii=False), encoding="utf-8")
    loaded = read_export_bundle(path)
    assert loaded == valid
    assert "verified" in verify_export_bundle(loaded)
