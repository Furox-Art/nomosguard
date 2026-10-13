"""Tests for the MCP server tools (session layer + stdio protocol)."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from nomosguard.ledger import LedgerFileError
from nomosguard.mcp_server import (
    NomosGuardSession,
    default_policy_rules,
    default_rules,
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

            # creating a new ledger is an explicit opt-in (see
            # TestLedgerPathFailClosed below): the constructor never
            # invents an empty ledger behind the caller's back.
            s1 = NomosGuardSession(
                rules=default_rules(),
                policy_rules=default_policy_rules(),
                ledger_path=path,
                create_if_missing=True,
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
        import json
        import tempfile
        from pathlib import Path

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


class TestLedgerPathFailClosed:
    """A configured ledger path is loaded, or the session refuses to start.

    A silent empty ledger is the one failure mode that looks like success:
    the operator believes the evidence endures while every claim is being
    written nowhere (and, worse, an unrelated fresh ledger is created).
    """

    def _session(self, path) -> NomosGuardSession:
        return NomosGuardSession(
            rules=default_rules(), policy_rules=default_policy_rules(), ledger_path=path
        )

    def test_missing_file_refused(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "never_created.jsonl"
            with pytest.raises(LedgerFileError, match="not found"):
                self._session(path)

    def test_directory_path_refused(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            path = Path(td)
            with pytest.raises(LedgerFileError, match="not found"):
                self._session(path)

    def test_missing_parent_directory_refused(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "no" / "such" / "dir" / "ledger.jsonl"
            with pytest.raises(LedgerFileError, match="not found"):
                self._session(path)

    def test_explicit_creation_opt_in_still_works(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "new.jsonl"
            session = NomosGuardSession(
                rules=default_rules(),
                policy_rules=default_policy_rules(),
                ledger_path=path,
                create_if_missing=True,
            )
            assert session.ledger.entries == ()
            session.assert_claim("tool_call", {"agent": "a", "tool": "t"}, "log line")
            assert path.is_file()

    def test_directory_path_refused_even_with_opt_in(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            path = Path(td)
            with pytest.raises(LedgerFileError, match="is a directory"):
                NomosGuardSession(
                    rules=default_rules(), ledger_path=path, create_if_missing=True
                )

    def test_missing_parent_refused_even_with_opt_in(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "no" / "such" / "dir" / "ledger.jsonl"
            with pytest.raises(LedgerFileError, match="does not exist"):
                NomosGuardSession(
                    rules=default_rules(), ledger_path=path, create_if_missing=True
                )


class TestGateDeniedBoundary:
    """The gate refuses to invent a decision; the SDK converts that to a
    fail-closed GateResult instead of crashing the caller."""

    def test_unknown_fallback_raises_at_the_gate(self):
        from nomosguard.gate import GateDenied, PolicyGate

        # the refusal happens at construction: the gate never holds an
        # undecidable fallback, not even for a moment
        with pytest.raises(GateDenied, match="must be one of"):
            PolicyGate(policy_rules=[], fallback="NOT_A_DECISION")

    def test_resolve_decision_refuses_to_guess(self):
        from nomosguard.gate import Decision, GateDenied, resolve_decision

        assert resolve_decision(Decision.BLOCK) is Decision.BLOCK
        assert resolve_decision("ALERT") is Decision.ALERT
        for bad in ("block", "BLOK", 3, None, ["BLOCK"]):
            with pytest.raises(GateDenied):
                resolve_decision(bad)

    def test_unknown_fallback_caught_at_the_sdk_boundary(self):
        from nomosguard.mcp_server import NomosGuardSession

        session = NomosGuardSession(
            rules=default_rules(), policy_rules=default_policy_rules()
        )
        result = session.decide(fallback="NOT_A_DECISION")
        # a result, not an exception — and it denies
        assert result["decision"] == "BLOCK"
        assert result["denied"] is True
        assert result["policy_rule"] == "GATE_DENIED"
        assert "must be one of" in result["reason"]
        assert result["ledger_verified"] is True

    def test_valid_fallback_still_decides(self):
        from nomosguard.mcp_server import NomosGuardSession

        session = NomosGuardSession(
            rules=default_rules(), policy_rules=default_policy_rules()
        )
        result = session.decide(fallback="ALERT")
        assert result["decision"] == "ALERT"
        assert result["denied"] is False

    def test_malformed_rule_set_denies_instead_of_raising(self):
        from nomosguard.gate import Decision
        from nomosguard.rules import Pattern, Rule

        bad = Rule(
            name="never_fires",
            body=(Pattern("?a", "calls", "?b"),),
            # head variable is not in the body: the rule can never fire
            head=Pattern("?x", "exposes", "?y"),
        )
        session = NomosGuardSession(rules=[bad], policy_rules=default_policy_rules())
        with pytest.raises(Exception):
            RuleEngine(rules=[bad])
        result = session.decide()
        assert result["decision"] == "BLOCK"
        assert result["denied"] is True
        assert "malformed rule set" in result["reason"]
        # derive_paths reports the same refusal instead of raising
        derived = session.derive_paths()
        assert derived["denied"] is True
        assert derived["derived_facts"] == []

    def test_explain_survives_a_malformed_rule_set(self):
        from nomosguard.rules import Pattern, Rule

        bad = Rule(
            name="never_fires",
            body=(Pattern("?a", "calls", "?b"),),
            head=Pattern("?x", "exposes", "?y"),
        )
        session = NomosGuardSession(rules=[bad], policy_rules=default_policy_rules())
        result = session.explain()
        assert result["decision"] == "BLOCK"
        assert result["denied"] is True
