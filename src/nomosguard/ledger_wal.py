"""Write-ahead log for the evidence ledger.

The main ledger file is rewritten atomically in full (`EvidenceLedger.save`),
which is crash-safe but coarse: a process that dies between appending an
entry and checkpointing the file loses that entry unless something recorded
it first. The WAL is that something.

Protocol
--------
1. Before the main ledger file is rewritten, every entry not yet present in
   it is appended to `<ledger_path>.wal`, one JSON object per line, using
   the *same schema* as a ledger body line (`LedgerEntry.to_dict`). Each WAL
   write is flushed and fsync'd before the caller touches the main file, so
   the WAL is durable before the main file changes: that ordering is the
   whole point of a write-ahead log.
2. `recover(ledger_path)` reads the WAL and returns the entries the main
   file never got. It does NOT mutate the main file — the caller decides
   whether to replay them (typically via `append_locked`).
3. `checkpoint(ledger_path)` truncates the WAL once the main file holds
   every entry the WAL does. It is the clean, expected steady state: an
   empty WAL.

Torn WAL lines
--------------
A WAL line that cannot be parsed as JSON is a write that was interrupted —
the process died mid-`write()`. It is DROPPED, not replayed. Rationale: a
partial line's hash cannot be verified, so replaying it would either be
rejected later (harmless) or, worse, accepted as a chain link whose content
we silently guessed. Because the WAL is append-only in seq order, a torn
line can only ever be the last one; anything after it is gone too. The drop
is reported in `WalRecovery.dropped` and described in `.detail`, so recovery
is never silent.

Determinism
-----------
Nothing here changes how entry hashes are computed. WAL records carry the
entry's own `entry_hash` and `prev_hash` verbatim; `recover` re-verifies the
linkage and refuses an entry whose stored hash does not match its content,
but it never recomputes a hash with different inputs. Same evidence -> same
hash, always.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .ledger import (
    Claim,
    EvidenceLedger,
    LedgerEntry,
    _atomic_write_lines,
    wal_path_for,
)

WAL_FORMAT_VERSION = 1


class WalError(ValueError):
    """Raised when the WAL cannot be used as written (bad record, bad link)."""


@dataclass
class WalRecovery:
    """The outcome of `recover(ledger_path)`.

    `pending`  — entries present in the WAL but NOT yet in the main ledger
                 file, in seq order, ready to replay.
    `applied`  — WAL entries already reflected in the main file (they are
                 counted, not returned: the main file is the source of truth).
    `dropped`  — WAL records discarded because the line was torn.
    `truncated_after` — seq after which everything was discarded (torn line).
    `detail`   — human-readable summary of the recovery, drops included.
    """

    pending: list[LedgerEntry] = field(default_factory=list)
    applied: int = 0
    dropped: int = 0
    truncated_after: int | None = None
    detail: str = ""


def _wal_path(ledger_path: str | Path) -> Path:
    return wal_path_for(ledger_path)


def _durable_append(path: Path, line: str) -> None:
    """Append one line to the WAL and force it to stable storage.

    Opened in append mode so concurrent WAL writers cannot overwrite each
    other's bytes, and a crash can never leave a hole in the middle.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def write_wal(
    ledger_path: str | Path,
    entries: list[LedgerEntry] | tuple[LedgerEntry, ...],
) -> int:
    """Write-ahead: durably record entries the main file does not have yet.

    Returns the number of WAL records written. Only entries whose seq is
    beyond what the main ledger file already holds are written — the WAL
    is an append-only log of *new* entries, not a mirror of the chain, so
    repeated calls between checkpoints never duplicate records. Call this
    BEFORE rewriting the main ledger file.
    """
    ledger_path = Path(ledger_path)
    if ledger_path.is_file():
        main = EvidenceLedger.load(ledger_path)
        max_main_seq = max((e.seq for e in main.entries), default=0)
    else:
        max_main_seq = 0

    # Also skip anything the WAL already holds — during replay the main
    # file has not been rewritten yet, so the main-file check alone would
    # re-WAL an entry that is already durably recorded.
    wal_path = _wal_path(ledger_path)
    wal_seqs: set[int] = set()
    if wal_path.is_file():
        for line in wal_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    rec = json.loads(line)
                    if isinstance(rec.get("seq"), int):
                        wal_seqs.add(rec["seq"])
                except json.JSONDecodeError:
                    break  # torn tail: stop scanning

    written = 0
    for entry in entries:
        if entry.seq <= max_main_seq:
            continue  # already in the main file: not a new entry
        if entry.seq in wal_seqs:
            continue  # already durably recorded in the WAL: not new
        _durable_append(wal_path, json.dumps(entry.to_dict(), sort_keys=True))
        wal_seqs.add(entry.seq)
        written += 1
    return written


def _parse_wal_line(
    text: str, lineno: int, *, torn_allowed: bool
) -> dict[str, Any] | None:
    """Parse one WAL line. Returns None for a torn (dropped) final line."""
    body = text.rstrip("\n").rstrip("\r")
    if not body.strip():
        return None
    try:
        record = json.loads(body)
    except json.JSONDecodeError:
        if torn_allowed:
            return None
        raise WalError(
            f"WAL line {lineno} is not valid JSON (torn write in the "
            "middle of the WAL is not recoverable)"
        ) from None
    if not isinstance(record, dict):
        raise WalError(f"WAL line {lineno} is not a JSON object")
    return record


def recover(ledger_path: str | Path) -> WalRecovery:
    """Read the WAL and report what the main ledger file never got.

    Returns a `WalRecovery` with `.pending` (entries to replay, in seq
    order), `.applied` (count already in the main file), and `.dropped`
    (torn records discarded, with `.truncated_after` naming the seq the
    chain was cut at).

    Linkage is verified as we go: each WAL entry must carry a `prev_hash`
    equal to the previous WAL entry's `entry_hash`, and its own
    `entry_hash` must recompute from its content. The first WAL entry must
    either be the file's next seq (prev_hash == the main head) or follow
    on from entries already in the file. A failure here STOPS the scan and
    raises `WalError` — a broken WAL link is evidence of a real problem
    (a partial replay, an edited WAL), not something to skip past silently.
    """
    ledger_path = Path(ledger_path)
    wal_path = _wal_path(ledger_path)

    # What does the main file already hold?
    if ledger_path.is_file():
        main = EvidenceLedger.load(ledger_path)
        main_seqs = {e.seq for e in main.entries}
        head_hash = main.head_hash
        max_main_seq = max(main_seqs) if main_seqs else 0
    else:
        main_seqs = set()
        head_hash = ""
        max_main_seq = 0

    result = WalRecovery()
    if not wal_path.is_file():
        result.detail = "no WAL file; nothing to recover"
        return result

    # Read the WAL with a one-line lookahead so we know which line is last.
    raw_lines: list[str] = []
    with wal_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip():
                raw_lines.append(line)

    # The WAL walk starts at its first record; that record's predecessor
    # is at seq first_seq - 1. Set the running chain pointer there:
    # - first_seq == 1: the genesis entry, predecessor is the empty head
    # - first_seq - 1 <= max_main_seq: the predecessor is in the main file
    # - first_seq - 1 > max_main_seq: the predecessor is NOT in the main
    #   file (main was written from a later checkpoint); the chain check
    #   below will catch any inconsistency rather than guess.
    first = (
        _parse_wal_line(raw_lines[0], 1, torn_allowed=len(raw_lines) == 1)
        if raw_lines else None
    )
    prev_hash = head_hash
    prev_seq = max_main_seq
    if first is not None and isinstance(first.get("seq"), int):
        first_seq = first["seq"]
        if first_seq == 1:
            prev_seq = 0
            prev_hash = "" if not main_seqs else head_hash
            # genesis: prev_hash is empty ONLY when the main file is also
            # empty; if main holds entries, the genesis hash is in main
            # (the main file's first entry), but the WAL's first entry at
            # seq 1 IS that entry, so it is already_applied and its
            # prev_hash must be "".
            prev_hash = ""
        elif 1 <= first_seq - 1 <= max_main_seq and ledger_path.is_file():
            prev_entry = main.entries[first_seq - 2]  # 0-indexed
            prev_hash = prev_entry.entry_hash
            prev_seq = first_seq - 1
    torn_detail: str | None = None

    for idx, raw in enumerate(raw_lines):
        is_last = idx == len(raw_lines) - 1
        lineno = idx + 1
        record = _parse_wal_line(raw, lineno, torn_allowed=is_last)
        if record is None:
            # Torn final line: dropped, never replayed. Its hash cannot be
            # verified, and everything after it is lost with it.
            result.dropped += 1
            result.truncated_after = prev_seq
            torn_detail = (
                f"dropped torn WAL line {lineno} (crash mid-write); "
                f"WAL entries after seq {prev_seq} were discarded"
            )
            break

        claim_data = record.get("claim")
        if not isinstance(claim_data, dict):
            raise WalError(f"WAL line {lineno}: malformed claim")
        missing = [k for k in ("kind", "payload", "evidence") if k not in claim_data]
        if missing:
            raise WalError(f"WAL line {lineno}: claim missing {missing}")
        try:
            claim = Claim(
                kind=claim_data["kind"],
                payload=claim_data["payload"],
                evidence=claim_data["evidence"],
            )
        except (KeyError, TypeError) as exc:
            raise WalError(f"WAL line {lineno}: malformed claim: {exc}") from exc

        seq = record.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise WalError(f"WAL line {lineno}: seq must be an integer, got {seq!r}")

        # -- chain verification ------------------------------------------------
        # WAL entries chain to EACH OTHER: the first links to the main
        # ledger head (or the chain point if the WAL starts mid-chain),
        # each subsequent one to the previous WAL entry. `prev_hash` is
        # the running WAL-internal chain pointer, NOT the main head.
        already_applied = seq <= max_main_seq
        if seq != prev_seq + 1:
            raise WalError(
                f"WAL line {lineno}: sequence gap in WAL — expected seq "
                f"{prev_seq + 1}, got {seq}"
            )
        if record.get("prev_hash") != prev_hash:
            raise WalError(
                f"WAL line {lineno} (seq {seq}): broken chain link — prev_hash "
                f"does not match seq {prev_seq}; refusing to replay a WAL that "
                "does not link to the ledger head"
            )
        recomputed = EvidenceLedger._entry_hash(seq, claim, record["prev_hash"])
        if recomputed != record.get("entry_hash"):
            raise WalError(
                f"WAL line {lineno} (seq {seq}): hash mismatch — the WAL entry "
                "does not verify against its own content"
            )

        entry = LedgerEntry(
            seq=seq,
            timestamp=record["timestamp"],
            claim=claim,
            entry_hash=recomputed,
            prev_hash=record["prev_hash"],
        )
        prev_hash = entry.entry_hash
        prev_seq = seq

        if already_applied:
            result.applied += 1
        else:
            result.pending.append(entry)

    parts = [f"{len(result.pending)} pending, {result.applied} already applied"]
    if result.dropped:
        parts.append(f"{result.dropped} dropped (torn)")
    result.detail = "; ".join(parts)
    if torn_detail:
        result.detail = f"{result.detail}; {torn_detail}"
    return result


def checkpoint(ledger_path: str | Path) -> int:
    """Truncate the WAL once the main file holds every entry it does.

    Returns the number of WAL entries discarded. Safe to call when there
    is no WAL (returns 0). This is the clean steady state: the main file
    is the complete chain and the WAL is empty.

    Called under the ledger lock, alongside `EvidenceLedger.save`, so a
    concurrent writer cannot slip an entry into the WAL between the save
    and the truncate.
    """
    wal_path = _wal_path(ledger_path)
    if not wal_path.is_file():
        return 0
    recovery = recover(ledger_path)
    if recovery.pending:
        raise WalError(
            f"refusing to checkpoint: {len(recovery.pending)} WAL entries are "
            "not in the main ledger file (checkpoint would lose them)"
        )
    # Empty in place: the file stays (so an in-flight writer holding the fd
    # still appends to a valid file) but records nothing.
    with open(wal_path, "w", encoding="utf-8") as fh:
        fh.flush()
        os.fsync(fh.fileno())
    return recovery.applied + recovery.dropped


def durable_save(
    ledger: EvidenceLedger, ledger_path: str | Path
) -> int:
    """Save the ledger with a WAL: record, then rewrite, then checkpoint.

    This is the durable counterpart of `EvidenceLedger.save` for callers
    that care about crash recovery:

    1. `write_wal` records any entry the file does not have (fsync'd).
    2. `ledger.save` atomically rewrites the main file (fsync'd + rename).
    3. `checkpoint` empties the WAL, now redundant.

    A crash before step 2 completes leaves the entries in the WAL, where
    `recover` will find them. A crash after step 2 leaves a stale-but-
    harmless WAL that `recover` reports as already applied.
    """
    ledger_path = Path(ledger_path)
    written = write_wal(ledger_path, ledger.entries)
    ledger.save(ledger_path)
    try:
        checkpoint(ledger_path)
    except WalError:
        # The WAL still holds entries the main file does not have — this
        # happens during replay (appending recovered entries one at a
        # time while later recovered entries remain WAL-only). That is
        # the CORRECT state: those entries must survive until they too
        # are replayed. The next replay (or an explicit checkpoint once
        # the file catches up) will clear them.
        pass
    return written
