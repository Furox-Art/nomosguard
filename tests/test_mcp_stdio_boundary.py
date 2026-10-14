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


class TestJsonRpcObjectBoundary:
    """A JSON-RPC message that is not an object is answered, not crashed on.

    `_serve_loop` used to call `request.get(...)` on whatever json.loads
    produced: a bare 42, "x", or [1,2] line raised AttributeError, killing
    the serve loop mid-session and leaving every later request unanswered.
    The loop now answers -32600 (id null) and continues.
    """

    def _run_raw(self, raw: str) -> str:
        stdin = io.StringIO(raw)
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
        return out.getvalue()

    def test_non_object_json_is_an_error_and_the_loop_survives(self):
        raw = "\n".join([
            "42",
            '"just a string"',
            "[1, 2, 3]",
            json.dumps(_request("ping", 7)),
        ]) + "\n"
        responses = _responses(self._run_raw(raw))
        assert len(responses) == 4
        for r in responses[:3]:
            assert r["error"]["code"] == -32600
            assert r["id"] is None
        assert responses[3]["id"] == 7  # the loop survived; ping answered

    def test_non_object_params_is_a_protocol_error_not_a_crash(self):
        raw = json.dumps({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                          "params": [1, 2]}) + "\n" + json.dumps(_request("ping", 8)) + "\n"
        responses = _responses(self._run_raw(raw))
        assert responses[0]["error"]["code"] == -32602
        assert responses[0]["id"] == 5
        assert responses[1]["id"] == 8  # loop survived

    def test_non_object_arguments_is_invalid_params(self):
        raw = json.dumps({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                          "params": {"name": "decide", "arguments": "nope"}}) + "\n"
        responses = _responses(self._run_raw(raw))
        assert responses[0]["error"]["code"] == -32602

    def test_decide_refuses_a_permissive_fallback(self):
        """The MCP surface offers BLOCK/ALERT only: ALLOW is refused loudly,
        not silently upgraded to BLOCK (a hidden client bug becomes a
        lowered floor later)."""
        written = _run([_request("tools/call", 1, name="decide",
                                 arguments={"fallback": "ALLOW"})])
        responses = _responses(written)
        assert responses[0]["error"]["code"] == -32602
        assert "no permissive fallback" in responses[0]["error"]["message"]

    def test_decide_accepts_the_fail_closed_fallbacks(self):
        written = _run([_request("tools/call", 1, name="decide",
                                 arguments={"fallback": "ALERT"})])
        body = json.loads(_responses(written)[0]["result"]["content"][0]["text"])
        assert body["decision"] == "ALERT"


class TestLedgerDigestStartup:
    """--ledger-digest: a pin is an operator act, refused when meaningless."""

    @staticmethod
    def _build(path, entries: int = 2) -> None:
        from nomosguard.ledger import Claim, EvidenceLedger

        ledger = EvidenceLedger()
        for i in range(entries):
            ledger.append(Claim("tool_call",
                                {"agent": f"a{i}", "tool": "t", "target": "db"},
                                f"log line {i}"))
        ledger.save(path)

    def test_pin_without_ledger_refuses(self, capsys):
        with pytest.raises(SystemExit) as exc:
            mcp_stdio._parse_and_start(["--ledger-digest", "sha256:" + "0" * 64])
        assert exc.value.code == 2
        assert "--ledger-digest requires --ledger" in capsys.readouterr().err

    def test_pin_for_a_new_ledger_refuses(self, tmp_path, capsys):
        """A pin describes an existing file; it cannot bless a file about
        to be created — otherwise the pin would certify nothing."""
        with pytest.raises(SystemExit) as exc:
            mcp_stdio._parse_and_start([
                "--ledger", str(tmp_path / "none.jsonl"), "--create-ledger",
                "--ledger-digest", "sha256:" + "0" * 64,
            ])
        assert exc.value.code == 2
        assert "about to be created" in capsys.readouterr().err

    def test_wrong_pin_refuses_to_start(self, tmp_path, capsys):
        path = tmp_path / "ledger.jsonl"
        self._build(path)
        with pytest.raises(SystemExit) as exc:
            mcp_stdio._parse_and_start([
                "--ledger", str(path), "--ledger-digest", "sha256:" + "0" * 64,
            ])
        assert exc.value.code == 2
        assert "digest mismatch" in capsys.readouterr().err

    def test_correct_pin_loads_the_ledger(self, tmp_path):
        from nomosguard.ledger import ledger_digest

        path = tmp_path / "ledger.jsonl"
        self._build(path)
        session = mcp_stdio._parse_and_start([
            "--ledger", str(path), "--ledger-digest", ledger_digest(path),
        ])
        assert len(session.ledger.entries) == 2

    def test_pinned_torn_tail_is_healed_on_start(self, tmp_path):
        """The pinned recovery heals the file under the lock: the next
        unpinned reader sees a clean chain, not a poisoned one."""
        from nomosguard.ledger import EvidenceLedger, ledger_digest

        path = tmp_path / "ledger.jsonl"
        self._build(path)
        text = path.read_text(encoding="utf-8")
        path.write_text(text[: len(text) - 12], encoding="utf-8")  # torn tail
        session = mcp_stdio._parse_and_start([
            "--ledger", str(path), "--ledger-digest", ledger_digest(path),
        ])
        assert session.load_report.dropped_tail == 1
        reloaded = EvidenceLedger.load(path)  # healed: no refusal
        assert len(reloaded.entries) == 1

    def test_unpinned_torn_tail_refuses_to_start(self, tmp_path, capsys):
        path = tmp_path / "ledger.jsonl"
        self._build(path)
        text = path.read_text(encoding="utf-8")
        path.write_text(text[: len(text) - 12], encoding="utf-8")
        with pytest.raises(SystemExit) as exc:
            mcp_stdio._parse_and_start(["--ledger", str(path)])
        assert exc.value.code == 2
        assert "UNPINNED" in capsys.readouterr().err
