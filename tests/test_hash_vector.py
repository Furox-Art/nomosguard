"""Golden hash vectors: the chain format is frozen, byte for byte.

A hash chain is only as strong as its construction. If a refactor changes
the canonical serialization, the hash function, or a field name, every
old ledger still "verifies" against ITSELF — the chain is self-consistent
either way — while silently meaning something else, and a digest pin
taken before the change no longer certifies the same bytes.

These vectors pin the exact values: the per-entry hashes, a handcrafted
ledger file that must keep loading and verifying, and the whole-file
digest of that file. Breaking one of these is a FORMAT CHANGE — a
deliberate, version-bumping act — never an accident of refactoring.
"""

from __future__ import annotations

import json

from nomosguard.ledger import (
    Claim,
    EvidenceLedger,
    ledger_digest,
)

# golden entry hashes (independent of platform, timestamp, and file I/O)
GOLDEN_H1 = "2107213806459da891b6bd27ed8521aacb7a01ff843d430b40d2dccd561638bd"
GOLDEN_H2 = "5eb9f555d8738dfe377f78f97fe54dbe57d6f165701a1fec2be0682d6ed805be"

_CLAIM_1 = Claim(
    kind="tool_call",
    payload={"agent": "a1", "tool": "sql", "target": "db1"},
    evidence="sha256:abc",
)
_CLAIM_2 = Claim(
    kind="vulnerability",
    payload={"component": "db1", "cve": "CVE-2026-999"},
    evidence="NVD record",
)

# a handcrafted ledger: fixed timestamps (they are never hashed), the
# golden hashes, sorted-key JSON — exactly the bytes `save` produces
_GOLDEN_FILE = "\n".join([
    json.dumps({
        "format": "nomosguard-ledger", "format_version": 1,
        "entries": 2, "head_hash": GOLDEN_H2,
    }, sort_keys=True),
    json.dumps({
        "seq": 1, "timestamp": "2026-01-01T00:00:00Z",
        "claim": {"kind": "tool_call",
                  "payload": {"agent": "a1", "tool": "sql", "target": "db1"},
                  "evidence": "sha256:abc"},
        "entry_hash": GOLDEN_H1, "prev_hash": "",
    }, sort_keys=True),
    json.dumps({
        "seq": 2, "timestamp": "2026-01-01T00:00:01Z",
        "claim": {"kind": "vulnerability",
                  "payload": {"component": "db1", "cve": "CVE-2026-999"},
                  "evidence": "NVD record"},
        "entry_hash": GOLDEN_H2, "prev_hash": GOLDEN_H1,
    }, sort_keys=True),
]) + "\n"

GOLDEN_FILE_DIGEST = "sha256:f681cdf23fd6ad089e4d4f184518751e4cb91a49c6d0ad464f3ebd53974e3ce7"


class TestEntryHashVectors:
    def test_first_entry_hash_is_pinned(self):
        assert EvidenceLedger._entry_hash(1, _CLAIM_1, "") == GOLDEN_H1

    def test_second_entry_hash_chains_from_the_first(self):
        assert EvidenceLedger._entry_hash(2, _CLAIM_2, GOLDEN_H1) == GOLDEN_H2

    def test_a_changed_byte_changes_the_hash(self):
        tampered = Claim(
            kind="tool_call",
            payload={"agent": "a1", "tool": "sql", "target": "dbX"},  # db1 -> dbX
            evidence="sha256:abc",
        )
        assert EvidenceLedger._entry_hash(1, tampered, "") != GOLDEN_H1


class TestGoldenFileStillLoads:
    """The on-disk format (header fields, entry fields, sorted keys) is part
    of the contract: a file written by 0.5.0+ must keep loading."""

    def _write(self, tmp_path):
        path = tmp_path / "golden.jsonl"
        path.write_text(_GOLDEN_FILE, encoding="utf-8")
        return path

    def test_handcrafted_ledger_loads_and_verifies(self, tmp_path):
        path = self._write(tmp_path)
        ledger = EvidenceLedger.load(path)
        assert len(ledger.entries) == 2
        ok, detail = ledger.verify()
        assert ok, detail

    def test_file_digest_is_pinned(self, tmp_path):
        path = self._write(tmp_path)
        assert ledger_digest(path) == GOLDEN_FILE_DIGEST

    def test_the_pin_blesses_exactly_these_bytes(self, tmp_path):
        path = self._write(tmp_path)
        loaded = EvidenceLedger.load(path, expected_digest=GOLDEN_FILE_DIGEST)
        assert len(loaded.entries) == 2
