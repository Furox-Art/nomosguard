"""``nomosguard`` command line: deterministic ingest and outbound-traffic watch.

Only the watch subcommands live here (the ingest tool keeps its own
``nomosguard-ingest`` entry point). Every command prints machine-readable JSON;
exit codes distinguish "verified", "silent/incomplete" and "unverified".
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .ledger import EvidenceLedger, LedgerFileError
from .traffic.certs import (
    CertificateAuthority,
    CertificateError,
    install_trust,
    uninstall_trust,
)
from .traffic.watch import (
    build_report,
    build_session_id,
    default_ledger_path,
    load_state,
    load_trust_marker,
    log_path,
    pid_is_alive,
    pki_dir,
    stop_path,
    trust_path,
    watch_dir,
    write_state,
    write_trust_marker,
)

START_TIMEOUT_SECONDS = 10.0
STOP_TIMEOUT_SECONDS = 15.0


def _print(value: dict[str, Any]) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, default=str))


def _error(message: str, code: int = 2) -> int:
    _print({"outcome": "ERROR", "error": message})
    return code


def _ledger_path(root: Path, raw: str | None) -> Path:
    if raw is None:
        return default_ledger_path(root)
    path = Path(raw).expanduser()
    return path if path.is_absolute() else root / path


def _old_state_running(state: dict[str, Any] | None) -> bool:
    return bool(
        isinstance(state, dict)
        and state.get("running") is True
        and pid_is_alive(state.get("pid"))
    )


def _tail(path: Path, limit: int = 1000) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return text[-limit:].strip()


def _spawn_daemon(
    root: Path, directory: Path, *, port: int, ledger: Path, enforcement: bool,
    session_id: str, started_at: str,
) -> subprocess.Popen[bytes]:
    directory.mkdir(parents=True, exist_ok=True)
    log = log_path(root).open("ab", buffering=0)
    kwargs: dict[str, Any] = {
        "cwd": str(root),
        "stdin": subprocess.DEVNULL,
        "stdout": log,
        "stderr": subprocess.STDOUT,
        "close_fds": True,
    }
    if os.name == "nt":
        kwargs["creationflags"] = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "DETACHED_PROCESS", 0)
        )
    else:
        kwargs["start_new_session"] = True
    argv = [
        sys.executable, "-m", "nomosguard.traffic.daemon",
        "--workspace", str(root),
        "--port", str(port),
        "--ledger", str(ledger),
        "--session-id", session_id,
        "--started-at", started_at,
    ]
    if enforcement:
        argv.append("--enforcement")
    try:
        return subprocess.Popen(argv, **kwargs)
    finally:
        log.close()


def cmd_start(args: argparse.Namespace) -> int:
    root = Path(args.dir).expanduser().resolve()
    if not root.is_dir():
        return _error(f"workspace directory not found: {root}")
    if not 0 <= args.port < 65536:
        return _error(f"port out of range: {args.port}")
    existing = load_state(root)
    if existing is not None and _old_state_running(existing):
        return _error(
            f"watch already running with pid {existing.get('pid')} "
            f"(stop it first: nomosguard watch stop {root})"
        )
    directory = watch_dir(root)
    try:
        ca = CertificateAuthority(pki_dir(root))
        ca.ensure()
    except CertificateError as exc:
        return _error(f"certificate authority setup failed: {exc}")

    ledger = _ledger_path(root, args.ledger)
    try:
        loaded = EvidenceLedger.load(ledger) if ledger.is_file() else EvidenceLedger()
        chain_ok, chain_detail = loaded.verify()
    except LedgerFileError as exc:
        return _error(f"refusing to use a watch ledger that does not verify: {exc}")
    if not chain_ok:
        return _error(f"refusing to use a watch ledger that does not verify: {chain_detail}")
    ledger.parent.mkdir(parents=True, exist_ok=True)

    trust_detail = ""
    trust_installed = False
    if args.install_ca:
        installed, trust_detail = install_trust(ca.cert_path, ca=ca)
        if not installed:
            return _error(
                f"CA trust installation failed: {trust_detail}; the watch was NOT "
                "started (run with --no-install-ca to trust the CA manually)"
            )
        write_trust_marker(
            root,
            {
                "fingerprint": ca.fingerprint(),
                "detail": trust_detail,
                "installed_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            },
        )
        trust_installed = True
    else:
        marker = load_trust_marker(root)
        trust_installed = bool(
            marker and marker.get("fingerprint") == ca.fingerprint()
        )
        trust_detail = (
            "installed by nomosguard"
            if trust_installed
            else "not installed; trust the CA manually or pass --install-ca"
        )

    started_at = _dt.datetime.now(_dt.timezone.utc).isoformat()
    session_id = build_session_id()
    try:
        stop_path(root).unlink()
    except OSError:
        pass
    write_state(
        root,
        {
            "version": 1,
            "workspace": str(root),
            "running": False,
            "starting": True,
            "pid": None,
            "port": None,
            "ledger": str(ledger),
            "started_at": started_at,
            "session_id": session_id,
            "enforcement": bool(args.enforcement),
            "ca_cert": str(ca.cert_path),
            "ca_fingerprint": ca.fingerprint(),
            "trust_installed": trust_installed,
            "trust_detail": trust_detail,
        },
    )
    try:
        child = _spawn_daemon(
            root, directory, port=args.port, ledger=ledger,
            enforcement=args.enforcement, session_id=session_id,
            started_at=started_at,
        )
    except OSError as exc:
        return _error(f"could not start the watch daemon: {exc}")

    deadline = time.monotonic() + START_TIMEOUT_SECONDS
    state: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        if child.poll() is not None:
            break
        candidate = load_state(root)
        if (
            candidate
            and candidate.get("running") is True
            and candidate.get("pid") == child.pid
        ):
            state = candidate
            break
        time.sleep(0.05)
    if state is None:
        if child.poll() is None:
            child.terminate()
        detail = _tail(log_path(root))
        return _error(
            "watch daemon did not become ready"
            + (f": {detail}" if detail else "")
        )
    _print(state)
    return 0


def _wait_stopped(root: Path, pid: int, timeout: float) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = load_state(root)
        if state and state.get("running") is False and state.get("pid") == pid:
            return state
        if not pid_is_alive(pid):
            state = load_state(root)
            if state and state.get("running") is False:
                return state
            return None
        time.sleep(0.05)
    return None


def cmd_stop(args: argparse.Namespace) -> int:
    root = Path(args.dir).expanduser().resolve()
    state = load_state(root)
    if state is None:
        return _error(f"no watch state under {watch_dir(root)}", code=1)
    pid = state.get("pid")
    running = state.get("running") is True and pid_is_alive(pid)
    if state.get("running") is True and not running:
        # A daemon killed hard never wrote its closing record; the state must
        # not keep claiming a live run that no longer exists.
        state = {
            **state,
            "running": False,
            "stale": True,
            "error": "watch daemon disappeared without closing its session",
        }
        write_state(root, state)
    if running and isinstance(pid, int):
        stop_path(root).write_text("stop\n", encoding="utf-8")
        state = _wait_stopped(root, pid, args.timeout)
        if state is None:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
            state = _wait_stopped(root, pid, 2.0)
            if state is None:
                return _error(
                    "watch daemon did not close its session within "
                    f"{args.timeout:.0f}s; the report will refuse to call this run complete",
                    code=2,
                )

    if not args.remove_ca:
        _print(state)
        return 0

    ca = CertificateAuthority(pki_dir(root))
    marker = load_trust_marker(root)
    trust_removed = False
    trust_detail = "no nomosguard trust-install marker; nothing removed from a store"
    if marker is not None:
        if not ca.cert_path.is_file():
            return _error(
                "cannot remove trust: the CA certificate is missing but an install "
                "marker exists; restore the certificate and retry"
            )
        removed, trust_detail = uninstall_trust(ca.cert_path, ca=ca)
        if not removed:
            return _error(
                f"CA trust removal failed: {trust_detail}; the CA files were kept "
                "so the removal can be retried"
            )
        trust_removed = True
        with contextlib.suppress(OSError):
            trust_path(root).unlink()
    ca.remove()
    if ca.cert_path.exists() or ca.key_path.exists():
        return _error("CA files could not be removed completely", code=2)
    state = load_state(root) or state
    state.update(
        {
            "ca_removed": True,
            "trust_installed": False,
            "trust_removed": trust_removed,
            "trust_detail": trust_detail,
        }
    )
    write_state(root, state)
    _print(state)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    root = Path(args.dir).expanduser().resolve()
    state = load_state(root)
    if state is None:
        return _error(f"no watch state under {watch_dir(root)}", code=1)
    alive = state.get("running") is True and pid_is_alive(state.get("pid"))
    port_open = False
    port = state.get("port")
    if alive and isinstance(port, int):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                port_open = True
        except OSError:
            port_open = False
    marker = load_trust_marker(root)
    result = {
        **state,
        "alive": alive,
        "port_open": port_open,
        "trust_installed": bool(
            marker and marker.get("fingerprint") == state.get("ca_fingerprint")
        ),
    }
    _print(result)
    return 0 if alive else 1


def cmd_report(args: argparse.Namespace) -> int:
    root = Path(args.dir).expanduser().resolve()
    ledger = _ledger_path(root, args.ledger)
    try:
        report = build_report(root, ledger_path=ledger, day=args.day)
    except ValueError as exc:
        return _error(str(exc))
    _print(report)
    outcome = report.get("outcome")
    if outcome == "OK":
        return 0
    return 2 if outcome in {"UNVERIFIED", "TAMPERED"} else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nomosguard")
    watch = parser.add_subparsers(dest="cmd", required=True).add_parser(
        "watch", help="local HTTPS observation of agent API traffic"
    )
    watch_sub = watch.add_subparsers(dest="action", required=True)

    start = watch_sub.add_parser("start", help="start the loopback proxy")
    start.add_argument("dir", nargs="?", default=".")
    start.add_argument("--port", type=int, default=0)
    start.add_argument("--ledger", default=None)
    start.add_argument("--enforcement", action="store_true")
    start.add_argument("--install-ca", action="store_true")

    stop = watch_sub.add_parser("stop", help="stop the proxy and close its session")
    stop.add_argument("dir", nargs="?", default=".")
    stop.add_argument("--remove-ca", action="store_true")
    stop.add_argument("--timeout", type=float, default=STOP_TIMEOUT_SECONDS)

    status = watch_sub.add_parser("status", help="show watch state")
    status.add_argument("dir", nargs="?", default=".")

    report = watch_sub.add_parser("report", help="aggregate the watch ledger")
    report.add_argument("dir", nargs="?", default=".")
    report.add_argument("--ledger", default=None)
    report.add_argument("--day", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.action == "start":
        return cmd_start(args)
    if args.action == "stop":
        return cmd_stop(args)
    if args.action == "status":
        return cmd_status(args)
    return cmd_report(args)


if __name__ == "__main__":
    raise SystemExit(main())
