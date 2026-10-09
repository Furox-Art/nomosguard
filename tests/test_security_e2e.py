"""End-to-end test: the LLM flow through MCP tools with security evidence.

Simulates what an agent does when using the nomosguard skill:
1. assert_claim with security evidence (firewall, NVD, IAM)
2. derive_paths
3. decide (containment)
4. explain

The model's job is only to produce claims and read decisions — everything
in between is deterministic.
"""

from __future__ import annotations

import json
import subprocess
import sys


class TestSecurityFlowThroughMCP:
    """The full security triage flow through the stdio MCP server."""

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

    def test_threat_triage_end_to_end(self):
        proc = self._spawn()
        try:
            # initialize
            self._rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                             "params": {"protocolVersion": "2025-06-18", "capabilities": {}}})
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            # the agent asserts security claims (the LLM's only job)
            claims = [
                {"kind": "network",
                 "payload": {"host": "web01", "protocol": "tcp", "port": 443, "allowed_from": "10.0.0.5"},
                 "evidence": "firewall: 10.0.0.5 -> web01:443"},
                {"kind": "vuln_host",
                 "payload": {"host": "web01", "cve": "CVE-2026-1"},
                 "evidence": "NVD: CVE-2026-1 affects web01"},
                {"kind": "network",
                 "payload": {"host": "web02", "protocol": "tcp", "port": 443, "allowed_from": "internal"},
                 "evidence": "firewall: internal -> web02:443"},
            ]
            for c in claims:
                resp = self._rpc(proc, {"jsonrpc": "2.0", "id": 10, "method": "tools/call",
                                        "params": {"name": "assert_claim", "arguments": c}})
                text = resp["result"]["content"][0]["text"]
                result = json.loads(text)
                assert result["accepted"] is True

            # derive
            resp = self._rpc(proc, {"jsonrpc": "2.0", "id": 11, "method": "tools/call",
                                    "params": {"name": "derive_paths", "arguments": {}}})
            text = resp["result"]["content"][0]["text"]
            assert "execCode" in text
            assert "canAccessHost" in text

            # decide — containment
            resp = self._rpc(proc, {"jsonrpc": "2.0", "id": 12, "method": "tools/call",
                                    "params": {"name": "decide", "arguments": {}}})
            text = resp["result"]["content"][0]["text"]
            assert "ISOLATE_HOST" in text
            assert "REVOKE_ACCESS" in text

            # explain
            resp = self._rpc(proc, {"jsonrpc": "2.0", "id": 13, "method": "tools/call",
                                    "params": {"name": "explain", "arguments": {}}})
            text = resp["result"]["content"][0]["text"]
            assert "Ledger" in text
            assert "web01" in text
        finally:
            proc.kill()
            proc.wait()
