"""Tests for the MCP server tools (session layer + stdio protocol)."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from nomosguard.ledger import LedgerFileError
from nomosguard.mcp_server import (
    NomosGuardSession,
    default_rules,
    default_policy_rules,
)
from nomosguard.mcp_stdio import TOOLS


class TestSessionTools:
    def _session(self) -> NomosGuardSession:
        return NomosGuardSession(rules=default_rules(), policy_rules=default_policy_rules())

    def test_ingest_and_decide(self):
        s = self._session()
        result = s.evidence_ingest(
            [
                {
                    "kind": "tool_call",
                    "payload": {"agent": "a1", "tool": "sql", "target": "db1"},
                    "evidence": "log: a1 invoked sql on db1",
                },
                {
                    "kind": "vulnerability",
                    "payload": {"component": "db1", "cve": "CVE-2026-999"},
                    "evidence": "NVD: CVE-2026-999 affects db1",
                },
            ]
        )
        assert result["accepted"] == 2
        assert result["rejected"] == []
        decision = s.decide()
        assert decision["decision"] == "BLOCK"
        assert decision["policy_rule"] == "block_vulnerable_exposure"

    def test_ingest_rejects_unevidenced(self):
        s = self._session()
        result = s.evidence_ingest(
            [
                {"kind": "tool_call", "payload": {"agent": "a"}, "evidence": ""},
                {"kind": "tool_call", "payload": {"agent": "b"}, "evidence": "log line"},
            ]
        )
        assert result["accepted"] == 1
        assert len(result["rejected"]) == 1

    def test_derive_paths(self):
        s = self._session()
        s.assert_claim(
            "tool_call",
            {"agent": "a1", "tool": "sql", "target": "db1"},
            "log: a1 invoked sql on db1",
        )
        s.assert_claim(
            "vulnerability", {"component": "db1", "cve": "CVE-1"}, "NVD record"
        )
        result = s.derive_paths()
        assert any("exposes" in f for f in result["derived_facts"])
        assert result["rules_fired"].get("tool_on_vulnerable_component") == 1

    def test_fail_closed_empty(self):
        s = self._session()
        decision = s.decide()
        assert decision["decision"] == "BLOCK"
        assert "fail-closed" in decision["reason"]

    def test_explain(self):
        s = self._session()
        s.assert_claim(
            "tool_call",
            {"agent": "a1", "tool": "sql", "target": "db1"},
            "log line",
        )
        result = s.explain()
        assert result["ledger_verified"] is True
        assert "Ledger" in result["summary"]

    def test_export(self):
        s = self._session()
        s.assert_claim("tool_call", {"agent": "a"}, "log line")
        export = s.export_ledger()
        assert export["verified"] is True
        assert len(export["entries"]) == 1


class TestToolSchemas:
    def test_five_tools_exposed(self):
        names = {t["name"] for t in TOOLS}
        assert names == {
            "evidence_ingest",
            "assert_claim",
            "derive_paths",
            "decide",
            "explain",
        }


class TestStdioProtocol:
    """End-to-end: spawn the stdio server, speak JSON-RPC."""

    def _spawn(self):
        return subprocess.Popen(
            [sys.executable, "-m", "nomosguard.mcp_stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _rpc(self, proc, payload):
        proc.stdin.write(json.dumps(payload) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        return json.loads(line)

    def test_full_flow(self):
        proc = self._spawn()
        try:
            # initialize
            resp = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
            })
            assert resp["result"]["serverInfo"]["name"] == "nomosguard"

            # notifications/initialized
            proc.stdin.write(json.dumps({
                "jsonrpc": "2.0", "method": "notifications/initialized"
            }) + "\n")
            proc.stdin.flush()

            # tools/list
            resp = self._rpc(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            assert len(resp["result"]["tools"]) == 5

            # assert_claim
            resp = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {
                    "name": "assert_claim",
                    "arguments": {
                        "kind": "tool_call",
                        "payload": {"agent": "a1", "tool": "sql", "target": "db1"},
                        "evidence": "log line 42",
                    },
                },
            })
            assert "accepted" in resp["result"]["content"][0]["text"]

            resp = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {
                    "name": "assert_claim",
                    "arguments": {
                        "kind": "vulnerability",
                        "payload": {"component": "db1", "cve": "CVE-X"},
                        "evidence": "NVD record",
                    },
                },
            })
            assert "accepted" in resp["result"]["content"][0]["text"]

            # derive
            resp = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 5, "method": "tools/call",
                "params": {"name": "derive_paths", "arguments": {}},
            })
            text = resp["result"]["content"][0]["text"]
            assert "exposes" in text

            # decide
            resp = self._rpc(proc, {
                "jsonrpc": "2.0", "id": 6, "method": "tools/call",
                "params": {"name": "decide", "arguments": {}},
            })
            assert '"BLOCK"' in resp["result"]["content"][0]["text"]
        finally:
            proc.kill()
            proc.wait()


class TestSessionPersistence:
    """A ledger-backed session survives restart — the audit trail endures."""

    def test_session_persists_and_resumes(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"

            s1 = NomosGuardSession(
                rules=default_rules(),
                policy_rules=default_policy_rules(),
                ledger_path=path,
            )
            r = s1.assert_claim(
                "tool_call",
                {"agent": "a1", "tool": "sql", "target": "db1"},
                "log line 42",
            )
            assert r["accepted"] is True
            assert path.is_file()

            # simulate restart: new session loads the same ledger file
            s2 = NomosGuardSession(
                rules=default_rules(),
                policy_rules=default_policy_rules(),
                ledger_path=path,
            )
            assert len(s2.ledger.entries) == 1
            ok, _ = s2.ledger.verify()
            assert ok

            # appending continues the chain
            r2 = s2.assert_claim(
                "vulnerability",
                {"component": "db1", "cve": "CVE-X"},
                "NVD record",
            )
            assert r2["seq"] == 2
            decision = s2.decide()
            assert decision["decision"] == "BLOCK"

    def test_corrupt_ledger_refused_at_startup(self):
        import tempfile
        from pathlib import Path
        import json

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            # write a header-only file with a lying hash
            header = {
                "format": "nomosguard-ledger",
                "format_version": 1,
                "entries": 1,
                "head_hash": "deadbeef",
            }
            path.write_text(json.dumps(header) + "\n")
            try:
                NomosGuardSession(ledger_path=path)
                assert False, "corrupt ledger must be refused"
            except LedgerFileError:
                pass
