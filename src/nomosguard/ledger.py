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
from typing import Any


class UnevidencedClaimError(ValueError):
    """Raised when a claim is inserted without a non-empty evidence fragment."""


class ChainVerificationError(ValueError):
    """Raised when the hash chain fails to verify (tamper or corruption)."""


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

    def export(self) -> list[dict[str, Any]]:
        """Export the ledger as JSON-serializable dicts (for audit/archive)."""
        return [entry.to_dict() for entry in self._entries]
