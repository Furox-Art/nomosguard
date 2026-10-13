#!/usr/bin/env python3
"""NomosGuard MCP stdio server entry point.

Speaks JSON-RPC 2.0 over stdio (the MCP standard transport). Exposes the
deterministic core as five tools. No model is ever called by this server.

Run:  python -m nomosguard.mcp_stdio
Configure an MCP client (e.g. Claude Desktop, or any MCP SDK) with:

    {"command": "python", "args": ["-m", "nomosguard.mcp_stdio"]}
"""

from __future__ import annotations

import io
import json
import sys
from typing import Any

from .mcp_server import (
    PROTOCOL_VERSION,
    SERVER_INFO,
    NomosGuardSession,
    default_policy_rules,
    default_rules,
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


def _utf8_stdout():
    """stdout as a UTF-8 writer, whatever the platform locale says.

    A claim's evidence is a raw log line: it can contain any character the
    log format allows. On a Windows console whose code page cannot encode
    that character, writing the response with the locale encoder raises
    UnicodeEncodeError — which kills the server mid-session and loses every
    answer it had not flushed yet. Writing UTF-8 explicitly removes that
    dependency (and the reader side agrees: JSON is UTF-8 by definition).
    """
    stream = sys.stdout
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is not None:
        try:
            reconfigure(encoding="utf-8", newline="\n")
            return stream
        except (ValueError, OSError):
            pass
    buffer = getattr(stream, "buffer", None)
    if buffer is not None:
        return io.TextIOWrapper(buffer, encoding="utf-8", newline="\n", write_through=True)
    return stream


def _write_response(response: dict[str, Any]) -> None:
    """One request -> one complete, flushed JSON line.

    The whole response is serialized first, then written with a single
    call and flushed immediately: a reader can never observe half a
    response interleaved with the next one, and the line does not sit in
    a buffer waiting for the next request. A write failure (the client
    closed the pipe) ends the loop cleanly instead of killing the process
    with a half-flushed line behind it.
    """
    try:
        payload = json.dumps(response) + "\n"
    except (TypeError, ValueError):  # a response we cannot serialize
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": response.get("id"),
            "error": {"code": -32603, "message": "response not serializable"},
        }) + "\n"
    try:
        _out().write(payload)
        _out().flush()
    except (BrokenPipeError, OSError):
        raise SystemExit(0) from None


_OUT: Any = None


def _out():
    global _OUT
    if _OUT is None:
        _OUT = _utf8_stdout()
    return _OUT


def _stdin_lines():
    """Yield request lines, and end the loop cleanly on a closed pipe."""
    try:
        for line in sys.stdin:
            yield line
    except (BrokenPipeError, OSError):
        return


def _parse_and_start(argv: list[str] | None = None) -> NomosGuardSession:
    """Parse the command line and build the session, or refuse to start.

    A ledger path that is missing (without --create-ledger), unreadable,
    or corrupt is a broken configuration: the server exits with a FATAL
    message instead of serving an empty ledger that answers every
    question with 'no evidence'.
    """
    import argparse

    parser = argparse.ArgumentParser(description="NomosGuard MCP stdio server")
    parser.add_argument(
        "--ledger",
        default=None,
        help="Path to a persistent JSONL evidence ledger. Loaded on start "
        "(chain verified; a corrupt or missing file is refused). Saved on "
        "every accepted claim. Omit for an in-memory-only session.",
    )
    parser.add_argument(
        "--create-ledger",
        action="store_true",
        help="With --ledger: start a NEW ledger at that path when no file "
        "exists yet. Without it, a --ledger path that is not there is a "
        "configuration error and the server refuses to start.",
    )
    args = parser.parse_args(argv)

    try:
        return NomosGuardSession(
            rules=default_rules(),
            policy_rules=default_policy_rules(),
            ledger_path=args.ledger,
            create_if_missing=args.create_ledger,
        )
    except Exception as exc:  # fail closed: never serve an empty ledger
        print(f"FATAL: refusing to start: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def _serve_loop(session: NomosGuardSession) -> None:
    """Read requests until stdin ends, one complete response per request."""
    for line in _stdin_lines():
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = _handle(request, session)
        if response is not None:
            _write_response(response)


def main() -> None:
    session = _parse_and_start()
    _serve_loop(session)


if __name__ == "__main__":
    main()
