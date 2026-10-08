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
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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


class EvidenceLedger:
    """Append-only hash-chained ledger of evidenced claims."""

    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []

    # -- construction helpers -------------------------------------------------

    @staticmethod
    def _entry_hash(seq: int, timestamp: str, claim: Claim, prev_hash: str) -> str:
        body = _canonical(
            {
                "seq": seq,
                "timestamp": timestamp,
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
        entry_hash = self._entry_hash(seq, timestamp, claim, prev_hash)
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
            recomputed = self._entry_hash(entry.seq, entry.timestamp, entry.claim, entry.prev_hash)
            if recomputed != entry.entry_hash:
                return False, f"tamper detected at seq {entry.seq}: entry_hash mismatch"
            prev_hash = entry.entry_hash
        return True, f"chain verified: {len(self._entries)} entries intact"

    # -- persistence -----------------------------------------------------------

    def save(self, path: str | Path) -> None:
        """Persist the full ledger to a JSONL file.

        The file is written atomically: a temp file in the same directory,
        then os.replace. A crash mid-write never leaves a half-truthful
        chain on disk. The file is the complete chain — loading it and
        appending continues from the head.
        """
        import json
        import os
        import tempfile

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        header = {
            "format": "nomosguard-ledger",
            "format_version": LEDGER_FORMAT_VERSION,
            "entries": len(self._entries),
            "head_hash": self.head_hash,
        }
        lines = [json.dumps(header, sort_keys=True)]
        lines.extend(json.dumps(entry.to_dict(), sort_keys=True) for entry in self._entries)

        fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            os.replace(tmp, path)  # atomic on POSIX and Windows
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    @classmethod
    def load(cls, path: str | Path) -> "EvidenceLedger":
        """Load a ledger from disk, verifying the full chain.

        Refuses (raises LedgerFileError) when:
        - the file is missing, unreadable, or not valid JSONL
        - the header is missing or has an unknown format version
        - the entry count in the header does not match the body
        - the chain fails verification (tamper or corruption)

        On success the ledger is open for appending: new entries continue
        from the loaded head hash.
        """
        import json

        path = Path(path)
        if not path.is_file():
            raise LedgerFileError(f"ledger file not found: {path}")

        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise LedgerFileError(f"cannot read ledger file: {exc}") from exc

        lines = [ln for ln in raw.splitlines() if ln.strip()]
        if not lines:
            raise LedgerFileError("ledger file is empty")

        try:
            header = json.loads(lines[0])
        except json.JSONDecodeError as exc:
            raise LedgerFileError(f"ledger header is not valid JSON: {exc}") from exc

        if header.get("format") != "nomosguard-ledger":
            raise LedgerFileError("missing nomosguard-ledger header")
        version = header.get("format_version")
        if version != LEDGER_FORMAT_VERSION:
            raise LedgerFileError(
                f"unsupported ledger format version {version!r} "
                f"(expected {LEDGER_FORMAT_VERSION})"
            )

        body = lines[1:]
        if len(body) != header.get("entries"):
            raise LedgerFileError(
                f"header declares {header.get('entries')} entries, "
                f"file contains {len(body)}"
            )

        ledger = cls()
        for i, ln in enumerate(body, start=1):
            try:
                record = json.loads(ln)
            except json.JSONDecodeError as exc:
                raise LedgerFileError(f"entry {i} is not valid JSON: {exc}") from exc
            try:
                claim_data = record["claim"]
                claim = Claim(
                    kind=claim_data["kind"],
                    payload=claim_data["payload"],
                    evidence=claim_data["evidence"],
                )
            except (KeyError, TypeError) as exc:
                raise LedgerFileError(f"entry {i} has a malformed claim: {exc}") from exc

            expected_seq = len(ledger._entries) + 1
            if record.get("seq") != expected_seq:
                raise LedgerFileError(
                    f"entry {i}: expected seq {expected_seq}, got {record.get('seq')}"
                )
            # Recompute hashes from content; never trust the stored hashes.
            prev_hash = ledger.head_hash
            recomputed = EvidenceLedger._entry_hash(
                expected_seq, record["timestamp"], claim, prev_hash
            )
            if recomputed != record.get("entry_hash"):
                raise LedgerFileError(
                    f"entry {i}: hash mismatch — the chain does not verify "
                    "(tamper or corruption)"
                )
            if record.get("prev_hash") != prev_hash:
                raise LedgerFileError(f"entry {i}: broken chain link")
            entry = LedgerEntry(
                seq=expected_seq,
                timestamp=record["timestamp"],
                claim=claim,
                entry_hash=recomputed,
                prev_hash=prev_hash,
            )
            ledger._entries.append(entry)

        if ledger.head_hash != header.get("head_hash"):
            raise LedgerFileError(
                "header head_hash does not match the recomputed chain head"
            )
        return ledger

    def export(self) -> list[dict[str, Any]]:
        """Export the ledger as JSON-serializable dicts (for audit/archive)."""
        return [entry.to_dict() for entry in self._entries]
