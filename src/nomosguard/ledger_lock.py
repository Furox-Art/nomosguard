"""Exclusive file locking for concurrent ledger writers.

The ledger is append-only, and appends must be serialized: two processes
that each read the head hash, append, and write back will produce a chain
in which one writer's entry is silently lost — and worse, the two files
will disagree about the head, so the next reader rejects one of them.

`LedgerLock` serializes writers on a dedicated lock file (`<path>.lock`)
using `fcntl.flock` — POSIX advisory locking from the stdlib. The lock is
held across the whole read-modify-write cycle (see `append_locked`), which
is what makes the sequence check safe.

Non-POSIX platforms
-------------------
Two backends, same semantics:

- POSIX: `fcntl.flock` — dropped by the kernel when the fd closes, so a
  crashed writer cannot wedge the ledger.
- Windows: `msvcrt.locking` — locks a byte range of the lock file. Note
  Windows locks are NOT released on process death (no kernel cleanup
  like flock); a hard-killed writer on Windows can leave the lock file
  locked until the OS releases the handle. The timeout parameter is the
  practical remedy: callers should always pass a finite `timeout`.

A platform with neither backend raises `NotImplementedError` at import —
never a silent no-op, which would let concurrent writers lose entries.
"""

from __future__ import annotations

import json
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Iterator

from .ledger import Claim, EvidenceLedger, LedgerEntry, _atomic_write_lines, wal_path_for

# -- lock backend: POSIX fcntl, or Windows msvcrt ----------------------------
# A silent no-op lock is worse than a loud failure: two processes could
# clobber each other's entries. Both platforms get a real, kernel-backed
# exclusive lock; unsupported platforms raise at import, not silently.
try:
    import fcntl

    _BACKEND = "fcntl"

    def _lock_ex(fh: IO[str], *, blocking: bool) -> None:
        if blocking:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        else:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _lock_un(fh: IO[str]) -> None:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

except ImportError:
    try:
        import msvcrt

        _BACKEND = "msvcrt"

        def _lock_ex(fh: IO[str], *, blocking: bool) -> None:
            # msvcrt.locking locks a byte RANGE, not the file: one byte is
            # enough. LK_NBLCK retries for ~10s then fails; LK_LOCK blocks
            # indefinitely. We emulate non-blocking with LK_NBLCK (which
            # fails immediately) and blocking with a retry loop.
            mode = msvcrt.LK_NBLCK if not blocking else msvcrt.LK_LOCK
            msvcrt.locking(fh.fileno(), mode, 1)

        def _lock_un(fh: IO[str]) -> None:
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)

    except ImportError as _exc:  # a platform with neither
        raise NotImplementedError(
            "nomosguard.ledger_lock requires either POSIX advisory file "
            f"locking (fcntl) or Windows locking (msvcrt); neither is "
            f"available on {sys.platform!r}: {_exc}. Multi-writer ledger "
            "appends are unsupported here; a silent no-op lock would let "
            "concurrent writers lose entries."
        ) from _exc

__all__ = ["LedgerLock", "append_locked", "lock_path_for", "LedgerLockError"]


class LedgerLockError(OSError):
    """Raised when the ledger lock cannot be acquired within the timeout."""


def lock_path_for(ledger_path: str | Path) -> Path:
    """The lock file guarding `ledger_path` (a sibling, never the data file)."""
    return wal_path_for(ledger_path).with_name(wal_path_for(ledger_path).stem + ".lock")


class LedgerLock:
    """Exclusive advisory lock on `<ledger_path>.lock`.

    Usable as a context manager (preferred) or with explicit
    acquire/release. Acquiring blocks until the lock is free; a `timeout`
    (seconds) turns an indefinite wait into `LedgerLockError`, which is
    what makes lock-contention testable without deadlocking CI.

    The lock is released on `__exit__` (or process death — `flock` is
    dropped by the kernel when the fd closes, so a crashed writer cannot
    wedge the ledger forever).
    """

    def __init__(self, path: str | Path, *, timeout: float | None = None) -> None:
        self._lock_path = lock_path_for(path)
        self._timeout = timeout
        self._fh: IO[str] | None = None

    @property
    def path(self) -> Path:
        return self._lock_path

    @property
    def locked(self) -> bool:
        return self._fh is not None

    def acquire(self) -> "LedgerLock":
        if self._fh is not None:
            return self
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(self._lock_path, "a+", encoding="utf-8")
        try:
            if self._timeout is None:
                _lock_ex(fh, blocking=True)  # blocks until free
            else:
                import time

                deadline = time.monotonic() + self._timeout
                while True:
                    try:
                        _lock_ex(fh, blocking=False)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise LedgerLockError(
                                f"could not acquire ledger lock {self._lock_path} "
                                f"within {self._timeout}s — another writer holds it"
                            ) from None
                        time.sleep(0.005)
        except LedgerLockError:
            fh.close()
            raise
        self._fh = fh
        return self

    def release(self) -> None:
        if self._fh is None:
            return
        try:
            _lock_un(self._fh)
        except OSError:
            pass
        finally:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> "LedgerLock":
        return self.acquire()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()


@contextmanager
def ledger_lock(path: str | Path, *, timeout: float | None = None) -> Iterator[LedgerLock]:
    """`with ledger_lock(p) as lock:` — acquire, yield, always release."""
    lock = LedgerLock(path, timeout=timeout).acquire()
    try:
        yield lock
    finally:
        lock.release()


def append_locked(
    ledger_path: str | Path,
    claim: Claim,
    *,
    lock: LedgerLock | None = None,
    timeout: float | None = None,
    wal: bool = True,
) -> LedgerEntry:
    """Append one claim to the on-disk ledger, serialized against other writers.

    Protocol — everything under one exclusive lock, so the sequence check
    is meaningful:

    1. acquire the lock
    2. re-read the ledger file (the head may have moved since our caller
       loaded it) and recompute the chain
    3. append the claim; the new entry links to the *current* head
    4. write-ahead to the WAL (fsync'd), then atomically rewrite the main
       file and checkpoint the WAL
    5. release the lock

    Returns the appended `LedgerEntry`. Two processes appending
    concurrently therefore serialize and both entries survive, with a
    valid chain and no gap in the sequence.
    """
    if _BACKEND not in ("fcntl", "msvcrt"):
        raise NotImplementedError(
            f"append_locked requires a file-locking backend; none available on {sys.platform!r}"
        )

    ledger_path = Path(ledger_path)
    own_lock = lock is None
    lock = LedgerLock(ledger_path, timeout=timeout) if own_lock else lock
    lock.acquire()
    try:
        # Re-read under the lock: another writer may have appended.
        if ledger_path.is_file():
            ledger = EvidenceLedger.load(ledger_path)
        else:
            ledger = EvidenceLedger()
        entry = ledger.append(claim)  # rejects unevidenced claims

        if wal:
            from .ledger_wal import durable_save

            durable_save(ledger, ledger_path)
        else:
            ledger.save(ledger_path)
        return entry
    finally:
        if own_lock:
            lock.release()
