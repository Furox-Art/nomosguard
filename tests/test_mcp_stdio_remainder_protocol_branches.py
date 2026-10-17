"""MCP stdio framing and dispatch faults must not interrupt later requests."""

from __future__ import annotations

import io
import json
from types import SimpleNamespace

import pytest

from nomosguard import mcp_stdio
from nomosguard.mcp_server import NomosGuardSession


@pytest.fixture(autouse=True)
def isolated_writer():
    previous = mcp_stdio._OUT
    mcp_stdio._OUT = None
    try:
        yield
    finally:
        mcp_stdio._OUT = previous


@pytest.mark.parametrize(
    ("name", "parameters", "expected"),
    [
        ("evidence_ingest", {"claims": []}, False),
        (
            "assert_claim",
            {
                "kind": "tool_call",
                "payload": {"agent": "alice", "tool": "db", "target": "db"},
                "evidence": "observed",
            },
            False,
        ),
        ("derive_paths", {}, False),
        ("decide", {"fallback": "ALERT"}, False),
        ("explain", {}, False),
        ("invented_tool", {}, True),
    ],
)
def test_all_mcp_handlers_return_a_serialized_result_or_explicit_error(
    name: str,
    parameters: dict,
    expected: bool,
) -> None:
    session = NomosGuardSession()
    response = mcp_stdio._handle(
        {
            "jsonrpc": "2.0",
            "id": "case-1",
            "method": "tools/call",
            "params": {"name": name, "arguments": parameters},
        },
        session,
    )
    assert response["id"] == "case-1"
    if expected:
        assert response["error"]["code"] == -32601
    else:
        assert "result" in response
        assert "content" in response["result"]


def test_unknown_notifications_and_invalid_notification_params_do_not_reply() -> None:
    session = NomosGuardSession()
    assert mcp_stdio._handle({"method": "unknown"}, session) is None
    assert mcp_stdio._handle({"method": "tools/call", "params": []}, session) is None


def test_erroring_handler_stays_in_protocol_channel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = NomosGuardSession()
    monkeypatch.setattr(session, "derive_paths", lambda: 1 / 0)
    reply = mcp_stdio._handle(
        {
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "derive_paths",
                "arguments": {},
            },
        },
        session,
    )
    assert reply["result"]["isError"] is True
    assert "division by zero" in reply["result"]["content"][0]["text"]


@pytest.mark.parametrize("value", [[], "text", 12])
def test_non_object_arguments_do_not_dispatch(value: object) -> None:
    response = mcp_stdio._handle(
        {
            "id": 1,
            "method": "tools/call",
            "params": {"name": "assert_claim", "arguments": value},
        },
        NomosGuardSession(),
    )
    assert response["error"]["code"] == -32602


def test_utf8_writer_handles_reconfigure_failure_then_uses_binary_buffer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenReconfigure:
        buffer = io.BytesIO()

        def reconfigure(self, **kwargs):
            raise OSError("read-only stream")

    writer = BrokenReconfigure()
    monkeypatch.setattr(mcp_stdio.sys, "stdout", writer)
    obtained = mcp_stdio._utf8_stdout()
    obtained.write("量子\n")
    obtained.flush()
    assert writer.buffer.getvalue() == "量子\n".encode()


def test_utf8_writer_falls_back_to_plain_stream_without_buffer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = io.StringIO()
    monkeypatch.setattr(mcp_stdio.sys, "stdout", out)
    assert mcp_stdio._utf8_stdout() is out


def test_response_not_serializable_falls_back_to_json_rpc_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = io.StringIO()
    monkeypatch.setattr(mcp_stdio, "_OUT", out)
    mcp_stdio._write_response({"id": "one", "result": {1, 2}})
    response = json.loads(out.getvalue())
    assert response["error"]["code"] == -32603
    assert response["id"] == "one"


@pytest.mark.parametrize("exception", [BrokenPipeError, OSError])
def test_closed_stdout_is_graceful_not_unhandled(
    monkeypatch: pytest.MonkeyPatch,
    exception: type[Exception],
) -> None:
    class FailingOutput:
        def write(self, data):
            raise exception("receiver closed")

        def flush(self):
            return None

    monkeypatch.setattr(mcp_stdio, "_OUT", FailingOutput())
    with pytest.raises(SystemExit) as exc:
        mcp_stdio._write_response({"id": 2, "result": {}})
    assert exc.value.code == 0


def test_oversized_stdio_frame_drains_exactly_to_next_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mcp_stdio, "MAX_MCP_FRAME_CHARS", 15)
    payload = "x" * 38 + "\n" + '{"method":"ping"}\n'
    monkeypatch.setattr(mcp_stdio.sys, "stdin", io.StringIO(payload))
    frames = list(mcp_stdio._stdin_lines())
    assert frames == [("", True), ("", True)]
    # First long frame and second also oversized; neither escapes the bound.


def test_bounded_reader_swallow_early_stream_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Disconnected:
        def readline(self, size):
            raise BrokenPipeError("not writable")

    monkeypatch.setattr(mcp_stdio.sys, "stdin", Disconnected())
    assert list(mcp_stdio._stdin_lines()) == []


def test_rpc_loop_rejects_malformed_json_and_recovers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_data = '[]\n{"a":1,"a":2}\nNaN\n{"jsonrpc":"2.0","id":99,"method":"ping"}\n'
    output = io.StringIO()
    monkeypatch.setattr(mcp_stdio.sys, "stdin", io.StringIO(input_data))
    monkeypatch.setattr(mcp_stdio, "_OUT", output)
    mcp_stdio._serve_loop(NomosGuardSession())
    replies = [json.loads(row) for row in output.getvalue().splitlines()]
    assert replies[-1]["result"] == {}
    assert any(row.get("error", {}).get("code") == -32600 for row in replies)
    assert any(row.get("error", {}).get("code") == -32700 for row in replies)


def test_server_main_connects_validated_session_to_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []
    fake_session = SimpleNamespace()
    monkeypatch.setattr(mcp_stdio, "_parse_and_start", lambda: fake_session)
    monkeypatch.setattr(mcp_stdio, "_serve_loop", lambda session: calls.append(session))
    mcp_stdio.main()
    assert calls == [fake_session]


def test_unknown_identified_method_returns_method_not_found() -> None:
    reply = mcp_stdio._handle({"id": 99, "method": "unsupported"}, NomosGuardSession())
    assert reply["error"]["code"] == -32601


def test_empty_stdio_lines_are_ignored_before_valid_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_stream = io.StringIO('\n \n{"id":1,"method":"ping"}\n')
    out = io.StringIO()
    monkeypatch.setattr(mcp_stdio.sys, "stdin", input_stream)
    monkeypatch.setattr(mcp_stdio, "_OUT", out)
    mcp_stdio._serve_loop(NomosGuardSession())
    result = [json.loads(line) for line in out.getvalue().splitlines()]
    assert len(result) == 1
    assert result[0]["result"] == {}


def test_mcp_direct_module_entrypoint_dispatches_to_main(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import runpy

    monkeypatch.setattr(mcp_stdio.sys, "argv", ["mcp_stdio.py"])
    monkeypatch.setattr(mcp_stdio.sys, "stdin", io.StringIO(""))
    monkeypatch.setattr(mcp_stdio.sys, "stdout", io.StringIO())
    runpy.run_module("nomosguard.mcp_stdio", run_name="__main__")
