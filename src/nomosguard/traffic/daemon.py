"""Detached watch daemon: proxy plus one closing session record.

The daemon owns the ledger while it runs and appends the ``traffic_session``
claim exactly once on a graceful stop. ``watch stop`` uses a stop file rather
than a signal so the closing record is written on every platform; a hard kill
leaves the session without its closing record, which the report treats as
INCOMPLETE rather than success.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import os
import signal
import time
from pathlib import Path
from types import FrameType
from typing import Any

from ..ledger import EvidenceLedger, LedgerFileError
from .certs import CertificateAuthority
from .proxy import TrafficProxy
from .watch import (
    append_session,
    load_state,
    pki_dir,
    session_payload,
    stop_path,
    write_state,
)


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _stop_requested() -> bool:
    return stop_path(_workspace).exists() or _STOP_EVENT


_STOP_EVENT = False
_workspace = Path(".")


def _handle_signal(_signum: int, _frame: FrameType | None) -> None:
    global _STOP_EVENT
    _STOP_EVENT = True


def run(
    workspace: str | Path,
    *,
    port: int,
    ledger_path: str | Path,
    enforcement: bool,
    session_id: str,
    started_at: str,
) -> int:
    root = Path(workspace).resolve()
    ca = CertificateAuthority(pki_dir(root))
    # The parent records the trust decision before spawning; the daemon keeps
    # those fields instead of rewriting the state without them.
    parent = load_state(root) or {}
    trust_fields: dict[str, Any] = {
        key: parent[key]
        for key in ("trust_installed", "trust_detail")
        if key in parent
    }
    state_base = {
        "version": 1,
        "workspace": str(root),
        "session_id": session_id,
        "started_at": started_at,
        "ledger": str(Path(ledger_path)),
        "enforcement": bool(enforcement),
        "pid": os.getpid(),
        **trust_fields,
    }
    try:
        ledger = (
            EvidenceLedger.load(ledger_path)
            if Path(ledger_path).is_file()
            else EvidenceLedger()
        )
        ca.ensure()
        proxy = TrafficProxy(
            ca,
            listen_host="127.0.0.1",
            listen_port=port,
            ledger=ledger,
            ledger_path=ledger_path,
            enforcement=enforcement,
            session_id=session_id,
        )
        actual_port = proxy.start()
    except (LedgerFileError, OSError, RuntimeError) as exc:
        write_state(
            root,
            {
                **state_base,
                "running": False,
                "starting": False,
                "error": str(exc),
                "stopped_at": _now(),
            },
        )
        return 3

    write_state(
        root,
        {
            **state_base,
            "running": True,
            "starting": False,
            "port": actual_port,
            "ca_cert": str(ca.cert_path),
            "ca_fingerprint": ca.fingerprint(),
        },
    )
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handle_signal)
        except (ValueError, OSError):
            # A platform without this signal still has the stop file.
            pass

    global _workspace
    _workspace = root
    try:
        while not _stop_requested():
            time.sleep(0.1)
    finally:
        proxy.stop()
        stopped_at = _now()
        payload = session_payload(
            session_id=session_id,
            started_at=started_at,
            stopped_at=stopped_at,
            enforcement=enforcement,
            captures=proxy.captures,
        )
        try:
            append_session(ledger, payload, ledger_path=ledger_path)
            error = ""
        except (OSError, ValueError) as exc:
            error = f"could not persist the closing session record: {exc}"
        write_state(
            root,
            {
                **state_base,
                "running": False,
                "starting": False,
                "port": actual_port,
                "ca_cert": str(ca.cert_path),
                "ca_fingerprint": ca.fingerprint(),
                "stopped_at": stopped_at,
                "requests": payload["requests"],
                "classes": payload["classes"],
                "silent": payload["silent"],
                **({"error": error} if error else {}),
            },
        )
        with contextlib.suppress(OSError):
            stop_path(root).unlink()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nomosguard-watch-daemon")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--enforcement", action="store_true")
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--started-at", required=True)
    args = parser.parse_args(argv)
    return run(
        args.workspace,
        port=args.port,
        ledger_path=args.ledger,
        enforcement=args.enforcement,
        session_id=args.session_id,
        started_at=args.started_at,
    )


if __name__ == "__main__":
    raise SystemExit(main())
