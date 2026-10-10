"""Append-only, SHA-256 hash-chained evidence ledger.

The ledger is the trust root of NomosGuard. Every entry stores a claim
(a structured, machine-checkable assertion about the security state) plus
the exact evidence fragment that supports it. Entries are hash-chained:
each entry's hash covers the previous entry's hash, so any retroactive
edit breaks verification — the transcript is tamper-evident.

Design rules (enforced here, not by convention):
1. Append-only. There is no delete, no update. Corrections are new entries.
2. A claim without reproducible evidence is rejected at insert time.
3. Verification walks the whole chain and fails loudly on any mismatch.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any, Iterator


LEDGER_FORMAT_VERSION = 1


class UnevidencedClaimError(ValueError):
    """Raised when a claim is inserted without a non-empty evidence fragment."""


class ChainVerificationError(ValueError):
    """Raised when the hash chain fails to verify (tamper or corruption)."""


class LedgerFileError(ValueError):
    """Raised when a ledger file cannot be loaded or is inconsistent."""


def _canonical(obj: Any) -> str:
    """Deterministic serialization: sorted keys, no incidental whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def wal_path_for(ledger_path: str | Path) -> Path:
    """The write-ahead sidecar path for a ledger file: `<path>.wal`.

    The WAL is a sibling of the ledger, never inside it — it must live on
    the same filesystem so a rename stays atomic, and it must be trivially
    associable with its ledger. `ledger.jsonl` -> `ledger.jsonl.wal`.
    """
    return Path(str(ledger_path) + ".wal")


@dataclass(frozen=True)
class Claim:
    """A structured, machine-checkable assertion about the security state.

    `kind` names the assertion type (e.g. "tool_call", "vulnerability",
    "policy_rule", "network_path"). `payload` is kind-specific structured
    data. `evidence` is the exact supporting fragment (log line, config
    text, CVE record) — never empty, never a paraphrase.
    """

    kind: str
    payload: dict[str, Any]
    evidence: str

    def validate(self) -> None:
        if not isinstance(self.kind, str) or not self.kind:
            raise UnevidencedClaimError("claim.kind must be a non-empty string")
        if not isinstance(self.payload, dict):
            raise UnevidencedClaimError("claim.payload must be a dict")
        if not isinstance(self.evidence, str) or not self.evidence.strip():
            raise UnevidencedClaimError(
                "claim.evidence must be a non-empty string: "
                "an LLM assertion without a cited evidence fragment is rejected"
            )


@dataclass(frozen=True)
class LedgerEntry:
    """One chain link: sequence number, timestamp, claim, hashes."""

    seq: int
    timestamp: str
    claim: Claim
    entry_hash: str  # hash of this entry's content
    prev_hash: str   # hash of the previous entry ("" for the genesis entry)

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "claim": asdict(self.claim),
            "entry_hash": self.entry_hash,
            "prev_hash": self.prev_hash,
        }


def _atomic_write_lines(path: Path, lines: list[str]) -> None:
    """Durably replace `path` with `lines` (JSONL, one item per line).

    Write order matters for crash safety:
      1. write everything to `<path>.tmp` in the SAME directory
      2. flush the Python buffers, then fsync the fd (data reaches the
         device, not just the page cache)
      3. fsync the parent directory, so the rename itself is durable
      4. os.replace(tmp, path) — atomic on POSIX and Windows

    A crash at any point leaves either the old file intact or the new
    file complete: the reader never observes a half-written ledger. A
    torn *final line* (a crash mid-write, or an interrupted append) is
    handled at load time — see `iter_ledger_records`, which drops a
    truncated tail and reports how many bytes/records it discarded.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)  # atomic on POSIX and Windows
        # Make the rename durable: without a directory fsync, a power loss
        # can resurrect the old directory entry.
        try:
            dir_fd = os.open(str(path.parent), os.O_RDONLY)
        except OSError:
            dir_fd = None
        if dir_fd is not None:
            try:
                os.fsync(dir_fd)
            except OSError:
                pass
            finally:
                os.close(dir_fd)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


@dataclass
class LedgerLoadReport:
    """What `iter_ledger_records` saw on the way in.

    `entries` are the records that verified. `dropped_tail` counts
    records thrown away because the file ended mid-write: a JSON decode
    failure or a hash/link mismatch on the final line. A torn tail is
    expected after a crash and is *not* tamper evidence; a mismatch
    anywhere else raises immediately. `tail_detail` explains the drop.
    """

    entries: list[LedgerEntry]
    header: dict[str, Any]
    dropped_tail: int = 0
    tail_detail: str | None = None


def iter_ledger_records(
    fh: IO[str], *, path: Any = "<stream>"
) -> Iterator[dict[str, Any]]:
    """Yield one item per non-blank body line, in file order.

    Each item is a dict with `lineno` (1-based, header is line 1) and one of:
      - ``{"lineno", "record": <dict>, "torn": False}``  — parsed cleanly
      - ``{"lineno", "record": None, "torn": True, "error": <str>}`` — the
        FINAL line could not be parsed, i.e. the file ends mid-write.

    Memory is O(1) per entry: only a single line is buffered at a time
    (a one-line lookahead is what makes "is this the last line?"
    answerable). A torn tail is reported to the caller, which decides
    whether to drop it; a malformed line anywhere else raises
    LedgerFileError, because a hole in the middle of a chain is
    corruption, not a crash.
    """
    lineno = 1  # the header occupies line 1
    pending: str | None = None  # one-line lookahead

    def nonblank(text: str | None) -> str | None:
        return None if text is None or not text.strip() else text

    while True:
        nxt = fh.readline()
        if not nxt:
            break
        nxt = nonblank(nxt)
        if nxt is None:
            continue
        if pending is not None:
            lineno += 1
            yield _parse_line(pending, lineno, path, torn_allowed=False)
        pending = nxt

    if pending is not None:
        lineno += 1
        yield _parse_line(pending, lineno, path, torn_allowed=True)


def _parse_line(
    text: str, lineno: int, path: Any, *, torn_allowed: bool
) -> dict[str, Any]:
    body = text.rstrip("\n").rstrip("\r")
    try:
        record = json.loads(body)
    except json.JSONDecodeError as exc:
        if torn_allowed:
            return {
                "lineno": lineno,
                "record": None,
                "torn": True,
                "error": f"line {lineno} is not valid JSON: {exc}",
            }
        raise LedgerFileError(
            f"{path}: line {lineno} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(record, dict):
        msg = f"{path}: line {lineno} is not a JSON object"
        if torn_allowed:
            return {"lineno": lineno, "record": None, "torn": True, "error": msg}
        raise LedgerFileError(msg)
    return {"lineno": lineno, "record": record, "torn": False}


class EvidenceLedger:
    """Append-only hash-chained ledger of evidenced claims."""

    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []

    # -- construction helpers -------------------------------------------------

    @staticmethod
    def _entry_hash(seq: int, claim: Claim, prev_hash: str) -> str:
        """Content-addressed hash: identical claims -> identical hash.

        Deliberately excludes the wall-clock timestamp: the chain must be
        reproducible, so the same evidence always yields the same hash.
        The timestamp is kept on the entry for audit but never hashed.
        """
        body = _canonical(
            {
                "seq": seq,
                "claim": asdict(claim),
                "prev_hash": prev_hash,
            }
        )
        return _sha256_hex(body)

    # -- public API -----------------------------------------------------------

    @property
    def entries(self) -> tuple[LedgerEntry, ...]:
        """All entries, in insertion order (immutable view)."""
        return tuple(self._entries)

    @property
    def head(self) -> LedgerEntry | None:
        """The most recent entry, or None for an empty ledger."""
        return self._entries[-1] if self._entries else None

    @property
    def head_hash(self) -> str:
        """Hash of the most recent entry, or "" for an empty ledger."""
        return self._entries[-1].entry_hash if self._entries else ""

    def append(self, claim: Claim) -> LedgerEntry:
        """Append a claim. Rejects unevidenced claims.

        Returns the stored entry (with its computed hashes).
        """
        claim.validate()
        seq = len(self._entries) + 1
        timestamp = datetime.now(timezone.utc).isoformat()
        prev_hash = self.head_hash
        entry_hash = self._entry_hash(seq, claim, prev_hash)
        entry = LedgerEntry(
            seq=seq,
            timestamp=timestamp,
            claim=claim,
            entry_hash=entry_hash,
            prev_hash=prev_hash,
        )
        self._entries.append(entry)
        return entry

    # -- verification ---------------------------------------------------------

    def verify(self) -> tuple[bool, str]:
        """Walk the entire chain. Returns (ok, detail).

        Fails loudly: the first mismatch (bad hash, broken link, wrong
        sequence) stops the walk and is reported.
        """
        prev_hash = ""
        for i, entry in enumerate(self._entries):
            # sequence must be strictly increasing from 1
            if entry.seq != i + 1:
                return False, f"sequence broken at index {i}: seq={entry.seq}, expected {i + 1}"
            # prev_hash must link to the previous entry
            if entry.prev_hash != prev_hash:
                return False, f"chain broken at seq {entry.seq}: prev_hash mismatch"
            # entry_hash must be recomputable from content
            recomputed = self._entry_hash(entry.seq, entry.claim, entry.prev_hash)
            if recomputed != entry.entry_hash:
                return False, f"tamper detected at seq {entry.seq}: entry_hash mismatch"
            prev_hash = entry.entry_hash
        return True, f"chain verified: {len(self._entries)} entries intact"

    # -- persistence -----------------------------------------------------------

    def save(self, path: str | Path) -> None:
        """Persist the full ledger to a JSONL file.

        Crash-safe by construction: the bytes are written to a temp file
        in the same directory, fsync'd, then atomically renamed over
        `path`. A crash mid-write leaves either the previous file or the
        new one complete — never a half-truthful chain.

        The on-disk format is unchanged from 0.5.0 (header line + one
        JSON entry per line), so ledgers written by 0.5.0 load directly
        into this version.
        """
        path = Path(path)
        header = {
            "format": "nomosguard-ledger",
            "format_version": LEDGER_FORMAT_VERSION,
            "entries": len(self._entries),
            "head_hash": self.head_hash,
        }
        lines = [json.dumps(header, sort_keys=True)]
        lines.extend(json.dumps(entry.to_dict(), sort_keys=True) for entry in self._entries)
        _atomic_write_lines(path, lines)

    @classmethod
    def load(
        cls,
        path: str | Path,
        *,
        allow_torn_tail: bool = True,
        report: LedgerLoadReport | None = None,
    ) -> "EvidenceLedger":
        """Load a ledger from disk, verifying the full chain.

        Refuses (raises LedgerFileError) when:
        - the file is missing, unreadable, or not valid JSONL
        - the header is missing or has an unknown format version
        - an entry is not valid JSON, or its claim is malformed
        - a sequence number is duplicated or skips a value
        - a prev_hash link does not match the previous entry
        - an entry_hash does not recompute from its content (tamper)
        - the entry count or head_hash in the header does not match

        `allow_torn_tail` (default True) is the crash-recovery escape
        hatch: if the FINAL line of the file is truncated — a crash
        mid-write, or an append that never finished — it is dropped and
        the count is recorded on the `report` object instead of raising.
        A torn tail is indistinguishable from a crash and is not treated
        as tamper evidence; anything wrong anywhere else raises.

        On success the ledger is open for appending: new entries continue
        from the loaded head hash.
        """
        path = Path(path)
        if not path.is_file():
            raise LedgerFileError(f"ledger file not found: {path}")

        try:
            fh = path.open("r", encoding="utf-8")
        except OSError as exc:
            raise LedgerFileError(f"cannot read ledger file: {exc}") from exc

        dropped_tail = 0
        tail_detail: str | None = None
        with fh:
            header_line = fh.readline()
            if not header_line.strip():
                raise LedgerFileError("ledger file is empty")
            try:
                header = json.loads(header_line)
            except json.JSONDecodeError as exc:
                raise LedgerFileError(f"ledger header is not valid JSON: {exc}") from exc
            if not isinstance(header, dict):
                raise LedgerFileError("ledger header is not a JSON object")

            if header.get("format") != "nomosguard-ledger":
                raise LedgerFileError("missing nomosguard-ledger header")
            version = header.get("format_version")
            if version != LEDGER_FORMAT_VERSION:
                raise LedgerFileError(
                    f"unsupported ledger format version {version!r} "
                    f"(expected {LEDGER_FORMAT_VERSION})"
                )

            ledger = cls()
            expected_prev = ""       # genesis links to the empty string
            for item in iter_ledger_records(fh, path=path):
                lineno = item["lineno"]
                if item["torn"]:
                    if not allow_torn_tail:
                        raise LedgerFileError(
                            f"{path}: {item['error']} (truncated final entry; "
                            "pass allow_torn_tail=True to drop it and recover)"
                        )
                    dropped_tail += 1
                    tail_detail = item["error"]
                    break  # nothing can follow a torn tail
                record = item["record"]
                i = lineno - 1  # human-facing entry index

                claim_data = record.get("claim")
                if not isinstance(claim_data, dict):
                    raise LedgerFileError(f"entry {i} has a malformed claim: expected an object")
                missing = [k for k in ("kind", "payload", "evidence") if k not in claim_data]
                if missing:
                    raise LedgerFileError(
                        f"entry {i} has a malformed claim: missing {missing}"
                    )
                try:
                    claim = Claim(
                        kind=claim_data["kind"],
                        payload=claim_data["payload"],
                        evidence=claim_data["evidence"],
                    )
                except (KeyError, TypeError) as exc:
                    raise LedgerFileError(
                        f"entry {i} has a malformed claim: {exc}"
                    ) from exc

                seq = record.get("seq")
                if not isinstance(seq, int) or isinstance(seq, bool):
                    raise LedgerFileError(f"entry {i}: seq must be an integer, got {seq!r}")

                # -- load-time conflict detection --------------------------------
                expected_seq = len(ledger._entries) + 1
                if seq < expected_seq:
                    raise LedgerFileError(
                        f"entry {i}: duplicate sequence number {seq} "
                        f"(entry {seq} is already present)"
                    )
                if seq > expected_seq:
                    if seq == expected_seq + 1:
                        missing_range = str(expected_seq)
                    else:
                        missing_range = f"{expected_seq}..{seq - 1}"
                    raise LedgerFileError(
                        f"entry {i}: sequence gap — expected seq {expected_seq}, "
                        f"got {seq}; missing seq {missing_range}"
                    )

                # Recompute hashes from content; never trust the stored hashes.
                recomputed = EvidenceLedger._entry_hash(expected_seq, claim, expected_prev)
                if record.get("entry_hash") != recomputed:
                    raise LedgerFileError(
                        f"entry {i} (seq {expected_seq}): hash mismatch — the chain "
                        "does not verify (tamper or corruption)"
                    )
                if record.get("prev_hash") != expected_prev:
                    raise LedgerFileError(
                        f"entry {i} (seq {expected_seq}): broken chain link — "
                        f"prev_hash does not match entry {expected_seq - 1}"
                    )
                if "timestamp" not in record:
                    raise LedgerFileError(f"entry {i}: missing timestamp")

                ledger._entries.append(
                    LedgerEntry(
                        seq=expected_seq,
                        timestamp=record["timestamp"],
                        claim=claim,
                        entry_hash=recomputed,
                        prev_hash=expected_prev,
                    )
                )
                expected_prev = recomputed

            if dropped_tail:
                # A torn tail means the header's count was written for a
                # chain we no longer fully have. Re-derive the header so
                # the recovered ledger is internally consistent, and keep
                # the drop count for the caller to report.
                if report is not None:
                    report.dropped_tail = dropped_tail
                    report.tail_detail = tail_detail
                    report.header = {
                        "format": "nomosguard-ledger",
                        "format_version": LEDGER_FORMAT_VERSION,
                        "entries": len(ledger._entries),
                        "head_hash": ledger.head_hash,
                    }
            else:
                if len(ledger._entries) != header.get("entries"):
                    raise LedgerFileError(
                        f"header declares {header.get('entries')} entries, "
                        f"file contains {len(ledger._entries)}"
                    )
                if ledger.head_hash != header.get("head_hash"):
                    raise LedgerFileError(
                        "header head_hash does not match the recomputed chain head"
                    )
                if report is not None:
                    report.header = header

            if report is not None:
                report.entries = list(ledger._entries)
            return ledger

    def export(self) -> list[dict[str, Any]]:
        """Export the ledger as JSON-serializable dicts (for audit/archive)."""
        return [entry.to_dict() for entry in self._entries]
