"""Watch state, session records, and the fail-closed traffic report.

The report's success condition is deliberately not "no findings". A watch that
captured nothing, a session that never wrote its closing record, or a session
whose observed request count disagrees with its own closing record is reported
as a failure. Silence is never promoted to success.
"""

from __future__ import annotations

import ctypes
import datetime as _dt
import json
import os
import sys
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from ..constants import (
    CLAIM_KIND_TRAFFIC_REQUEST,
    CLAIM_KIND_TRAFFIC_SESSION,
    TRAFFIC_CLASS_UNKNOWN,
    TRAFFIC_CLASSES,
)
from ..ledger import Claim, EvidenceLedger, LedgerFileError

WATCH_DIR = ".nomosguard/watch"
PKI_DIR = "pki"
STATE_FILE = "state.json"
STOP_FILE = "stop.flag"
LOG_FILE = "watch.log"
LEDGER_FILE = "ledger.jsonl"
TRUST_FILE = "trust.json"
REPORT_SCHEMA = "nomosguard-watch-report/v1"


def watch_dir(workspace: str | Path) -> Path:
    return Path(workspace).resolve() / WATCH_DIR


def pki_dir(workspace: str | Path) -> Path:
    """CA material lives in its own subtree so ``ca.remove`` cannot touch the ledger."""
    return watch_dir(workspace) / PKI_DIR


def state_path(workspace: str | Path) -> Path:
    return watch_dir(workspace) / STATE_FILE


def stop_path(workspace: str | Path) -> Path:
    return watch_dir(workspace) / STOP_FILE


def log_path(workspace: str | Path) -> Path:
    return watch_dir(workspace) / LOG_FILE


def default_ledger_path(workspace: str | Path) -> Path:
    return watch_dir(workspace) / LEDGER_FILE


def trust_path(workspace: str | Path) -> Path:
    return watch_dir(workspace) / TRUST_FILE


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    text = json.dumps(value, indent=2, sort_keys=True) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(tmp, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def write_state(workspace: str | Path, state: dict[str, Any]) -> Path:
    path = state_path(workspace)
    _atomic_json(path, state)
    return path


def load_state(workspace: str | Path) -> dict[str, Any] | None:
    try:
        value = json.loads(state_path(workspace).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def write_trust_marker(workspace: str | Path, detail: dict[str, Any]) -> Path:
    path = trust_path(workspace)
    _atomic_json(path, detail)
    return path


def load_trust_marker(workspace: str | Path) -> dict[str, Any] | None:
    try:
        value = json.loads(trust_path(workspace).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_ERROR_INVALID_PARAMETER = 87
_STILL_ACTIVE = 259


def _posix_pid_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        # EPERM means the process exists under another owner; only a
        # provably missing PID may report dead.
        return True
    return True


def _win_kernel32() -> Any:
    return ctypes.windll.kernel32  # type: ignore[attr-defined]


def _win_pid_is_alive(pid: int, api: Any = None) -> bool:
    """Ask kernel32 whether the PID exists, without signalling it.

    os.kill(pid, 0) cannot be the probe here: CTRL_C_EVENT *is* 0, so that
    call broadcasts a console Ctrl+C to the PID's process group and interrupts
    every process sharing the console — a liveness check must not do that.
    """
    api = _win_kernel32() if api is None else api
    try:
        handle = api.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            # A PID that refuses to open still exists; only
            # ERROR_INVALID_PARAMETER proves that it is gone.
            return bool(api.GetLastError() != _ERROR_INVALID_PARAMETER)
        try:
            code = ctypes.c_ulong(_STILL_ACTIVE)
            if api.GetExitCodeProcess(handle, ctypes.pointer(code)):
                return code.value == _STILL_ACTIVE
            return True
        finally:
            api.CloseHandle(handle)
    except OSError:
        return True


# A dict lookup, not an `if sys.platform` branch: the Windows probe stays
# reachable (and covered) on every platform.
_PID_PROBES: dict[str, Callable[[int], bool]] = {"win32": _win_pid_is_alive}
_PLATFORM_PROBE = _PID_PROBES.get(sys.platform, _posix_pid_is_alive)


def pid_is_alive(pid: object) -> bool:
    """Only a provably dead PID reports dead (same discipline as the core)."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return False
    return _PLATFORM_PROBE(pid)


def build_session_id(now: _dt.datetime | None = None, pid: int | None = None) -> str:
    moment = now or _dt.datetime.now(_dt.timezone.utc)
    return f"watch-{moment.strftime('%Y%m%dT%H%M%S%fZ')}-{pid or os.getpid()}"


def session_payload(
    *,
    session_id: str,
    started_at: str,
    stopped_at: str,
    enforcement: bool,
    captures: Iterable[Any],
) -> dict[str, Any]:
    classes = {name: 0 for name in TRAFFIC_CLASSES}
    hosts: dict[str, int] = {}
    requests = 0
    for capture in captures:
        requests += 1
        payload = capture.payload
        classification = str(payload.get("class", TRAFFIC_CLASS_UNKNOWN))
        if classification not in classes:
            classification = TRAFFIC_CLASS_UNKNOWN
        classes[classification] += 1
        host = str(payload.get("host", ""))
        if host:
            hosts[host] = hosts.get(host, 0) + 1
    return {
        "session_id": session_id,
        "requests": requests,
        "classes": classes,
        "hosts": dict(sorted(hosts.items())),
        "enforcement": bool(enforcement),
        "started_at": started_at,
        "stopped_at": stopped_at,
        "silent": requests == 0,
    }


def append_session(
    ledger: EvidenceLedger,
    payload: dict[str, Any],
    *,
    ledger_path: str | Path | None = None,
) -> Any:
    entry = ledger.append(
        Claim(
            kind=CLAIM_KIND_TRAFFIC_SESSION,
            payload=payload,
            evidence=(
                f"watch session {payload.get('session_id', '')} closed with "
                f"{payload.get('requests', 0)} captured request(s)"
            ),
        )
    )
    if ledger_path is not None:
        ledger.save(ledger_path)
    return entry


def _unrecognized(value: Any) -> str:
    return value if isinstance(value, str) and value else ""


def build_report(
    workspace: str | Path,
    *,
    ledger_path: str | Path | None = None,
    day: str | None = None,
) -> dict[str, Any]:
    """Aggregate the watch ledger. Fail-closed on silence or missing evidence."""
    if day is not None:
        try:
            _dt.date.fromisoformat(day)
        except ValueError as exc:
            raise ValueError(f"--day must be an ISO date (YYYY-MM-DD): {exc}") from exc

    state = load_state(workspace)
    path = Path(ledger_path) if ledger_path is not None else (
        Path(str(state.get("ledger"))) if state and state.get("ledger")
        else default_ledger_path(workspace)
    )
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "ledger": str(path),
        "day": day,
        "requests": 0,
        "total_requests": 0,
        "by_day": {},
        "by_class": {name: 0 for name in TRAFFIC_CLASSES},
        "hosts": {},
        "secret_hits": [],
        "sessions": [],
        "silent_sessions": [],
        "mismatched_sessions": [],
        "unrecognized_classes": [],
        "chain": {"valid": False, "detail": ""},
    }
    try:
        ledger = EvidenceLedger.load(path)
    except LedgerFileError as exc:
        report.update({"outcome": "UNVERIFIED", "ok": False, "error": str(exc)})
        return report

    chain_ok, chain_detail = ledger.verify()
    report["chain"] = {"valid": chain_ok, "detail": chain_detail}
    if not chain_ok:
        report.update({"outcome": "TAMPERED", "ok": False})
        return report

    by_day: dict[str, dict[str, Any]] = {}
    hosts: dict[str, int] = {}
    hit_totals: dict[tuple[str, str], int] = {}
    per_session: dict[str, int] = {}
    unrecognized: set[str] = set()
    total = 0
    for entry in ledger.entries:
        if entry.claim.kind != CLAIM_KIND_TRAFFIC_REQUEST:
            continue
        total += 1
        payload = entry.claim.payload
        classification = _unrecognized(payload.get("class"))
        if classification not in TRAFFIC_CLASSES:
            if classification:
                unrecognized.add(classification)
            classification = TRAFFIC_CLASS_UNKNOWN
        session_id = str(payload.get("session_id", ""))
        per_session[session_id] = per_session.get(session_id, 0) + 1
        date = entry.timestamp[:10]
        bucket = by_day.setdefault(
            date,
            {"requests": 0, "classes": {name: 0 for name in TRAFFIC_CLASSES}, "hosts": {}},
        )
        bucket["requests"] += 1
        bucket["classes"][classification] += 1
        host = str(payload.get("host", ""))
        if host:
            bucket["hosts"][host] = bucket["hosts"].get(host, 0) + 1
            hosts[host] = hosts.get(host, 0) + 1
        for hit in payload.get("secret_hits", []) or []:
            if not isinstance(hit, dict):
                continue
            name = _unrecognized(hit.get("name"))
            masked = _unrecognized(hit.get("masked"))
            if name and masked:
                key = (name, masked)
                hit_totals[key] = hit_totals.get(key, 0) + 1
        if day is not None and date != day:
            # Counters below are global; the per-day view keeps the filter.
            continue
        report["requests"] += 1
        report["by_class"][classification] += 1

    report["total_requests"] = total
    report["by_day"] = {
        date: {
            "requests": item["requests"],
            "classes": dict(item["classes"]),
            "hosts": dict(sorted(item["hosts"].items())),
        }
        for date, item in sorted(by_day.items())
    }
    report["hosts"] = dict(sorted(hosts.items()))
    report["secret_hits"] = [
        {"name": name, "masked": masked, "count": count}
        for (name, masked), count in sorted(hit_totals.items())
    ]
    report["unrecognized_classes"] = sorted(unrecognized)

    sessions: list[dict[str, Any]] = []
    for entry in ledger.entries:
        if entry.claim.kind != CLAIM_KIND_TRAFFIC_SESSION:
            continue
        payload = entry.claim.payload
        session_id = str(payload.get("session_id", ""))
        declared = payload.get("requests")
        if isinstance(declared, bool) or not isinstance(declared, int) or declared < 0:
            declared = -1
        observed = per_session.get(session_id, 0)
        item = {
            "session_id": session_id,
            "declared_requests": declared,
            "observed_requests": observed,
            "enforcement": bool(payload.get("enforcement", False)),
            "started_at": payload.get("started_at"),
            "stopped_at": payload.get("stopped_at"),
            "classes": payload.get("classes", {}),
            "hosts": payload.get("hosts", {}),
            "seq": entry.seq,
        }
        sessions.append(item)
        if observed == 0 or declared == 0:
            report["silent_sessions"].append(session_id)
        if observed != declared:
            report["mismatched_sessions"].append(session_id)
    report["sessions"] = sessions

    if total == 0:
        outcome = "SILENT"
    elif not sessions or report["mismatched_sessions"]:
        outcome = "INCOMPLETE"
    elif report["silent_sessions"]:
        outcome = "SILENT"
    else:
        outcome = "OK"
    report["outcome"] = outcome
    report["ok"] = outcome == "OK"
    return report
