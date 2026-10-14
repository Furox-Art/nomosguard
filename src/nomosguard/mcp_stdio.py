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

from .digest_pins import resolve_digest_pin
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
                # The fallback applies when no derived path exists. Only
                # fail-closed choices are offered: the audited agent must
                # not be able to lower the floor of its own review by
                # picking ALLOW as the default.
                "fallback": {"type": "string", "enum": ["BLOCK", "ALERT"]},
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


def _error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    """A JSON-RPC error response (id echoed; None when undeterminable)."""
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _handle(request: dict[str, Any], session: NomosGuardSession) -> dict[str, Any] | None:
    method = request.get("method", "")
    req_id = request.get("id")
    params = request.get("params", {})
    # A non-object `params` (a list, a string) must be answered, not
    # crash: `params.get` on a list is an AttributeError that would kill
    # the serve loop and leave every later request unanswered.
    if not isinstance(params, dict):
        if req_id is None:
            return None  # notifications get no response, valid or not
        return _error(req_id, -32602, "invalid params: 'params' must be an object")

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
        if not isinstance(args, dict):
            return _error(req_id, -32602, "invalid params: 'arguments' must be an object")
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
                fallback = args.get("fallback", "BLOCK")
                if fallback not in ("BLOCK", "ALERT"):
                    # The MCP surface offers only fail-closed fallbacks
                    # (see the tool schema): a per-call ALLOW default
                    # would let the audited agent lower the floor of its
                    # own review. Refused loudly, not coerced to BLOCK —
                    # a silent coercion would hide the client bug.
                    return _error(
                        req_id,
                        -32602,
                        "invalid params: 'fallback' must be one of "
                        "['ALERT', 'BLOCK'] (the MCP surface offers no "
                        "permissive fallback)",
                    )
                result = session.decide(fallback)
            elif name == "explain":
                result = session.explain()
            else:
                return _error(req_id, -32601, f"unknown tool: {name}")
        except Exception as exc:  # noqa: BLE001 - fail closed on any internal error
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
    return _error(req_id, -32601, f"method not found: {method}")


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
        yield from sys.stdin
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
    parser.add_argument(
        "--ledger-digest",
        default=None,
        help="Pin the ledger by digest (sha256:<hex>, or @PATH to read it "
        "from a manifest file). A file that is not the pinned one is "
        "refused; a truncated ledger is recovered only under a pin (the "
        "remaining bytes must be the reviewed ones) and healed on start.",
    )
    args = parser.parse_args(argv)

    if args.ledger_digest and not args.ledger:
        print(
            "FATAL: --ledger-digest requires --ledger (the in-memory "
            "session is not a file)",
            file=sys.stderr,
        )
        raise SystemExit(2)

    try:
        return NomosGuardSession(
            rules=default_rules(),
            policy_rules=default_policy_rules(),
            ledger_path=args.ledger,
            create_if_missing=args.create_ledger,
            ledger_digest=resolve_digest_pin(args.ledger_digest, noun="ledger"),
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
        if not isinstance(request, dict):
            # A JSON-RPC message must be an object. A bare array/number/
            # string would crash `request.get` (a list has no `.get`),
            # killing the loop mid-session and leaving every later request
            # unanswered — the exact failure mode this loop must not have.
            _write_response(
                _error(None, -32600, "invalid request: JSON-RPC request must be an object")
            )
            continue
        response = _handle(request, session)
        if response is not None:
            _write_response(response)


def main() -> None:
    session = _parse_and_start()
    _serve_loop(session)


if __name__ == "__main__":
    main()
