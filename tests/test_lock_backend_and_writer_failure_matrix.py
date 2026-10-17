"""Concurrent ledger locking failure paths and cross-platform backend contract."""

from __future__ import annotations

import runpy
import sys
import tempfile
import types
from pathlib import Path

import pytest

from nomosguard import ledger_lock as locks
from nomosguard.ledger import Claim, EvidenceLedger, UnevidencedClaimError


def _claim() -> Claim:
    return Claim(
        "tool_call", {"agent": "a", "tool": "read", "target": "db"}, "observed"
    )


def test_lock_context_and_release_are_idempotent(tmp_path: Path) -> None:
    file = tmp_path / "ledger.jsonl"
    guard = locks.LedgerLock(file)
    assert not guard.locked
    assert guard.acquire() is guard
    assert guard.acquire() is guard
    assert guard.locked
    guard.release()
    guard.release()
    assert not guard.locked
    with locks.ledger_lock(file) as held:
        assert held.locked
    assert not held.locked


def test_lock_nonblocking_attempt_times_out_and_closes_handle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def busy(*args, **kwargs):
        raise OSError("simulated busy file lock")

    monkeypatch.setattr(locks, "_lock_ex", busy)
    target = locks.LedgerLock(tmp_path / "ledger.jsonl", timeout=0.0)
    with pytest.raises(locks.LedgerLockError, match="could not acquire"):
        target.acquire()
    assert not target.locked


def test_lock_retries_while_deadline_has_not_expired(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    attempts = []
    real_lock = locks._lock_ex

    def transient(fh, *, blocking):
        attempts.append(blocking)
        if len(attempts) == 1:
            raise OSError("contended")
        return real_lock(fh, blocking=blocking)

    monkeypatch.setattr(locks, "_lock_ex", transient)
    lock = locks.LedgerLock(tmp_path / "ledger.jsonl", timeout=2.0)
    with lock:
        assert lock.locked
    assert attempts == [False, False]


def test_release_swallow_kernel_unlock_failure_without_leaking_descriptor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lock = locks.LedgerLock(tmp_path / "ledger.jsonl").acquire()

    def denied(fh):
        raise OSError("file handle already revoked")

    monkeypatch.setattr(locks, "_lock_un", denied)
    lock.release()
    assert not lock.locked


def test_append_locked_refuses_unsupported_backend(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(locks, "_BACKEND", "none")
    with pytest.raises(NotImplementedError, match="file-locking backend"):
        locks.append_locked(tmp_path / "ledger.jsonl", _claim())


def test_append_without_wal_and_preheld_lock_uses_current_chain(
    tmp_path: Path,
) -> None:
    file = tmp_path / "ledger.jsonl"
    with locks.LedgerLock(file) as held:
        first = locks.append_locked(file, _claim(), lock=held, wal=False)
        assert first.seq == 1
        second = locks.append_locked(file, _claim(), lock=held, wal=False)
        assert second.seq == 2
        assert held.locked
    assert [entry.seq for entry in EvidenceLedger.load(file).entries] == [1, 2]


def test_append_unlocks_if_underlying_claim_is_refused(
    tmp_path: Path,
) -> None:
    file = tmp_path / "ledger.jsonl"
    with pytest.raises(UnevidencedClaimError):
        locks.append_locked(
            file,
            Claim("tool_call", {"agent": "a"}, ""),
            timeout=1.0,
        )
    with locks.LedgerLock(file, timeout=1.0) as recovered:
        assert recovered.locked


def test_windows_compatible_locking_backend_uses_real_byte_lock_modes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []
    pseudo = types.ModuleType("msvcrt")
    pseudo.LK_NBLCK = 1
    pseudo.LK_LOCK = 2
    pseudo.LK_UNLCK = 3
    pseudo.locking = lambda fd, mode, size: calls.append((fd, mode, size))
    with monkeypatch.context() as patch:
        patch.setitem(sys.modules, "fcntl", None)
        patch.setitem(sys.modules, "msvcrt", pseudo)
        loaded = runpy.run_module(
            "nomosguard.ledger_lock", run_name="nomosguard.fake_windows_lock"
        )
        with tempfile.TemporaryFile(mode="w+") as fake_fh:
            loaded["_lock_ex"](fake_fh, blocking=False)
            loaded["_lock_ex"](fake_fh, blocking=True)
            loaded["_lock_un"](fake_fh)
    assert [call[1] for call in calls] == [1, 2, 3]
    assert all(size == 1 for _, _, size in calls)


def test_unsupported_operating_system_refuses_unlocked_multiwriter_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as patch:
        patch.setitem(sys.modules, "fcntl", None)
        patch.setitem(sys.modules, "msvcrt", None)
        with pytest.raises(NotImplementedError, match="neither is available"):
            runpy.run_module(
                "nomosguard.ledger_lock", run_name="nomosguard.fake_unsupported_lock"
            )
