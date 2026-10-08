#!/usr/bin/env python3
"""NomosGuard MCP stdio server entry point.

Speaks JSON-RPC 2.0 over stdio (the MCP standard transport). Exposes the
deterministic core as five tools. No model is ever called by this server.

Run:  python -m nomosguard.mcp_stdio
Configure an MCP client (e.g. Claude Desktop, or any MCP SDK) with:

    {"command": "python", "args": ["-m", "nomosguard.mcp_stdio"]}
"""

from __future__ import annotations

import json
import sys
from typing import Any

from .mcp_server import (
    SERVER_INFO,
    PROTOCOL_VERSION,
    NomosGuardSession,
    default_rules,
    default_policy_rules,
)

TOOLS = [
    {
        "name": "evidence_ingest",
        "description": (
            "Ingest structured, evidence-citing claims into the hash-chained "
            "ledger. Each claim MUST cite an evidence fragment (log line, "
            "config text, CVE record). Claims without evidence are rejected."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "claims": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "kind": {"type": "string"},
                            "payload": {"type": "object"},
                            "evidence": {"type": "string"},
                        },
                        "required": ["kind", "payload", "evidence"],
                    },
                }
            },
            "required": ["claims"],
        },
    },
    {
        "name": "assert_claim",
        "description": (
            "Assert a single claim with evidence. Rejected fail-closed if "
            "evidence is missing or empty."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "kind": {"type": "string"},
                "payload": {"type": "object"},
                "evidence": {"type": "string"},
            },
            "required": ["kind", "payload", "evidence"],
        },
    },
    {
        "name": "derive_paths",
        "description": (
            "Run the deterministic rule engine over the ledger. Pure logical "
            "inference — no model, no randomness. Returns derived attack/access "
            "paths with their derivation traces."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "decide",
        "description": (
            "Run the fail-closed policy gate. Returns ALLOW / ALERT / BLOCK "
            "with the full derivation chain. Never consults a model."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "fallback": {"type": "string", "enum": ["BLOCK", "ALERT", "ALLOW"]},
            },
        },
    },
    {
        "name": "explain",
        "description": (
            "Render the current ledger, derivation, and gate decision as a "
            "human-readable audit summary. Narration only — the cited facts "
            "come from the ledger and cannot be altered."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _handle(request: dict[str, Any], session: NomosGuardSession) -> dict[str, Any] | None:
    method = request.get("method", "")
    req_id = request.get("id")
    params = request.get("params", {})

    # Notifications (no id) get no response
    is_notification = req_id is None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "serverInfo": SERVER_INFO,
                "capabilities": {"tools": {}},
            },
        }

    if method in ("notifications/initialized", "initialized"):
        return None  # notification

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}

    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments", {})
        try:
            if name == "evidence_ingest":
                result = session.evidence_ingest(args.get("claims", []))
            elif name == "assert_claim":
                result = session.assert_claim(
                    args.get("kind", ""), args.get("payload", {}), args.get("evidence", "")
                )
            elif name == "derive_paths":
                result = session.derive_paths()
            elif name == "decide":
                result = session.decide(args.get("fallback", "BLOCK"))
            elif name == "explain":
                result = session.explain()
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"unknown tool: {name}"},
                }
        except Exception as exc:  # fail closed on any internal error
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps({"error": str(exc)})}],
                    "isError": True,
                },
            }
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": json.dumps(result, indent=2, default=str)}]
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    # Unknown method
    if is_notification:
        return None
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"method not found: {method}"},
    }


def main() -> None:
    session = NomosGuardSession(
        rules=default_rules(),
        policy_rules=default_policy_rules(),
    )
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = _handle(request, session)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
