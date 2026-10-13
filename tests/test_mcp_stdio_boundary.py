"""The stdio server's request/response boundary (H5).

The protocol is one JSON-RPC request per line in, one response per line
out. The boundary must therefore be: serialize the whole response, write
it with a single call, flush before the next request is read. Anything
less lets a reader see a half-response interleaved with the next one, or
leaves a response sitting in a buffer when the process is asked to
answer.

This suite drives the protocol loop in-process over piped streams and
asserts the property that matters: for N requests (minus notifications),
exactly N complete, ordered responses come out — and the response
survives a terminal whose code page cannot encode the evidence that a
log line claim carries.
"""

from __future__ import annotations

import io
import json
import sys

import pytest

from nomosguard import mcp_stdio
from nomosguard.mcp_server import (
    NomosGuardSession,
    default_policy_rules,
    default_rules,
)


@pytest.fixture(autouse=True)
def _fresh_stdout():
    """The response writer is configured once per process; reset per test."""
    saved = mcp_stdio._OUT
    mcp_stdio._OUT = None
    try:
        yield
    finally:
        mcp_stdio._OUT = saved


def _request(method: str, req_id=None, **params) -> dict:
    payload = {"jsonrpc": "2.0", "method": method}
    if req_id is not None:
        payload["id"] = req_id
    if params:
        payload["params"] = params
    return payload


def _serve(requests: list[dict], out) -> str:
    """Run the protocol loop over piped input, capturing what it writes."""
    stdin = io.StringIO("".join(json.dumps(r) + "\n" for r in requests))
    session = NomosGuardSession(
        rules=default_rules(), policy_rules=default_policy_rules()
    )
    real_stdin, real_stdout = sys.stdin, sys.stdout
    sys.stdin, sys.stdout = stdin, out
    try:
        mcp_stdio._serve_loop(session)
        if hasattr(out, "flush"):
            out.flush()
    finally:
        sys.stdin, sys.stdout = real_stdin, real_stdout
    if hasattr(out, "buffer"):
        return out.buffer.getvalue().decode("utf-8")
    return out.getvalue()


def _run(requests: list[dict], *, stdout_encoding: str | None = None) -> str:
    if stdout_encoding is None:
        out: io.IOBase = io.StringIO()
    else:
        out = io.TextIOWrapper(io.BytesIO(), encoding=stdout_encoding, newline="\n")
    return _serve(requests, out)


def _responses(written: str) -> list[dict]:
    return [json.loads(ln) for ln in written.split("\n") if ln.strip()]


class TestPipedInput:
    def test_every_request_gets_exactly_one_response(self):
        written = _run([
            _request("initialize", 1),
            _request("notifications/initialized"),  # notification: no response
            _request("tools/list", 2),
            _request("tools/call", 3, name="assert_claim", arguments={
                "kind": "tool_call",
                "payload": {"agent": "a1", "tool": "sql", "target": "db1"},
                "evidence": "log line 42",
            }),
            _request("tools/call", 4, name="decide", arguments={}),
        ])
        # 5 requests, 1 notification -> 4 responses, one complete line each
        responses = _responses(written)
        assert len(responses) == 4
        assert [r["id"] for r in responses] == [1, 2, 3, 4]
        for r in responses:
            assert r["jsonrpc"] == "2.0"
            assert "result" in r or "error" in r

    def test_decision_survives_the_round_trip(self):
        written = _run([
            _request("initialize", 1),
            _request("tools/call", 2, name="assert_claim", arguments={
                "kind": "tool_call",
                "payload": {"agent": "a1", "tool": "sql", "target": "db1"},
                "evidence": "log line 42",
            }),
            _request("tools/call", 3, name="assert_claim", arguments={
                "kind": "vulnerability",
                "payload": {"component": "db1", "cve": "CVE-X"},
                "evidence": "NVD record",
            }),
            _request("tools/call", 4, name="decide", arguments={}),
        ])
        responses = _responses(written)
        assert len(responses) == 4
        decision = json.loads(responses[3]["result"]["content"][0]["text"])
        assert decision["decision"] == "BLOCK"

    def test_unevidenced_claim_is_refused_fail_closed(self):
        written = _run([
            _request("tools/call", 1, name="assert_claim", arguments={
                "kind": "tool_call", "payload": {"agent": "a"}, "evidence": "",
            }),
        ])
        responses = _responses(written)
        assert len(responses) == 1
        body = json.loads(responses[0]["result"]["content"][0]["text"])
        assert body["accepted"] is False

    def test_unknown_tool_is_an_error_not_a_crash(self):
        written = _run([_request("tools/call", 1, name="not_a_tool")])
        responses = _responses(written)
        assert len(responses) == 1
        assert responses[0]["error"]["code"] == -32601

    def test_invalid_json_line_does_not_kill_the_server(self):
        # a malformed prefix line is skipped; the request after it answers
        stdin = io.StringIO("{not json\n" + json.dumps(_request("ping", 7)) + "\n")
        session = NomosGuardSession(
            rules=default_rules(), policy_rules=default_policy_rules()
        )
        out = io.StringIO()
        real_stdin, real_stdout = sys.stdin, sys.stdout
        sys.stdin, sys.stdout = stdin, out
        try:
            mcp_stdio._serve_loop(session)
        finally:
            sys.stdin, sys.stdout = real_stdin, real_stdout
        responses = _responses(out.getvalue())
        assert len(responses) == 1
        assert responses[0]["id"] == 7

    def test_response_is_flushed_before_the_next_request(self):
        """Each response is a complete line at the moment it is flushed."""
        state: dict[str, str] = {"value": ""}

        class Recording(io.StringIO):
            def write(self, text):  # stdlib shim
                state["value"] = self.getvalue() + text
                return super().write(text)

            def flush(self):  # stdlib shim
                value = self.getvalue()
                assert value == "" or value.endswith("\n"), (
                    f"partial line flushed: {value[-40:]!r}"
                )
                return super().flush()

        out = Recording()
        written = _serve([_request("ping", 1)], out)
        assert written.endswith("\n")
        assert state["value"].endswith("\n")

    def test_unicode_evidence_survives_a_restrictive_locale(self):
        """A log line with characters the console cannot encode.

        The evidence field is a raw log line, so it can carry any
        character the log format allows. Writing the response with the
        LOCALE encoder (e.g. a cp1252 console) raises UnicodeEncodeError
        mid-session — which kills the server with every unflushed answer
        lost. The response path writes UTF-8 regardless of the locale.
        """
        evidence = "auth: failed password \u2014 \u65e5\u672c\u8a9e caf\u00e9"
        written = _run(
            [_request("tools/call", 1, name="assert_claim", arguments={
                "kind": "tool_call",
                "payload": {"agent": "a", "tool": "t", "target": "db"},
                "evidence": evidence,
            })],
            stdout_encoding="cp1252",
        )
        assert written, "no response was written"
        responses = _responses(written)
        assert len(responses) == 1
        body = json.loads(responses[0]["result"]["content"][0]["text"])
        assert body["accepted"] is True

    def test_write_failure_exits_cleanly(self):
        """A client that closes the pipe ends the loop cleanly."""
        class Closed(io.StringIO):
            def write(self, text):
                raise BrokenPipeError("closed")

            def flush(self):
                raise BrokenPipeError("closed")

        with pytest.raises(SystemExit) as exc:
            _serve([_request("ping", 1)], Closed())
        assert exc.value.code == 0


class TestServerStartupRefusal:
    """A broken ledger configuration must not start a silent server."""

    def test_missing_ledger_path_refuses_to_start(self, tmp_path, capsys):
        with pytest.raises(SystemExit) as exc:
            mcp_stdio._parse_and_start(["--ledger", str(tmp_path / "never.jsonl")])
        assert exc.value.code == 2
        assert "not found" in capsys.readouterr().err

    def test_corrupt_ledger_refuses_to_start(self, tmp_path, capsys):
        path = tmp_path / "ledger.jsonl"
        path.write_text(json.dumps({
            "format": "nomosguard-ledger", "format_version": 1,
            "entries": 1, "head_hash": "deadbeef",
        }) + "\n")
        with pytest.raises(SystemExit) as exc:
            mcp_stdio._parse_and_start(["--ledger", str(path)])
        assert exc.value.code == 2
        assert "refusing" in capsys.readouterr().err

    def test_create_flag_allows_a_new_ledger(self, tmp_path):
        path = tmp_path / "new.jsonl"
        session = mcp_stdio._parse_and_start(
            ["--ledger", str(path), "--create-ledger"]
        )
        assert session.ledger.entries == ()
        session.assert_claim("tool_call", {"agent": "a", "tool": "t"}, "log line")
        assert path.is_file()

    def test_directory_as_ledger_path_refuses_to_start(self, tmp_path, capsys):
        with pytest.raises(SystemExit) as exc:
            mcp_stdio._parse_and_start(["--ledger", str(tmp_path)])
        assert exc.value.code == 2
        assert "not found" in capsys.readouterr().err
