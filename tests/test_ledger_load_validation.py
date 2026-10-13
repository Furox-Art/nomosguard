"""Load-path claim validation (C1): a tampered file must not be accepted.

`append` refuses an unevidenced claim; `save` now re-validates on the way
out; `load` validates on the way in. The load path used to check only
that the claim had the right KEYS — so a file rewritten with a consistent
hash chain but invalid claim bodies (empty evidence, a non-dict payload,
an empty kind) loaded silently. The chain proves consistency, never
well-formedness: this suite pins the fixed behaviour.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from nomosguard.ledger import (
    Claim,
    EvidenceLedger,
    LedgerFileError,
    UnevidencedClaimError,
)


def _rewrite_with_valid_chain(path: Path, claims: list[dict]) -> None:
    """Rewrite a ledger file so every hash is internally consistent.

    This is what an attacker with the file and the algorithm can do: keep
    the chain verifiable while replacing the claim bodies. The load path
    must still refuse it, because the CLAIMS are invalid.
    """
    lines = []
    prev_hash = ""
    for seq, claim in enumerate(claims, start=1):
        body = json.dumps(
            {"seq": seq, "claim": claim, "prev_hash": prev_hash},
            sort_keys=True,
            separators=(",", ":"),
        )
        entry_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        record = {
            "seq": seq,
            "timestamp": "2026-01-01T00:00:00+00:00",
            "claim": claim,
            "entry_hash": entry_hash,
            "prev_hash": prev_hash,
        }
        lines.append(json.dumps(record, sort_keys=True))
        prev_hash = entry_hash
    header = {
        "format": "nomosguard-ledger",
        "format_version": 1,
        "entries": len(claims),
        "head_hash": prev_hash,
    }
    path.write_text(
        "\n".join([json.dumps(header, sort_keys=True)] + lines) + "\n",
        encoding="utf-8",
    )


class TestSaveValidatesEveryClaim:
    def test_save_refuses_an_invalid_claim(self):
        ledger = EvidenceLedger()
        ledger.append(Claim("tool_call", {"agent": "a", "tool": "t"}, "log line 1"))
        # forge an invalid claim straight into the in-memory chain
        from nomosguard.ledger import LedgerEntry

        forged_entry = LedgerEntry(
            seq=len(ledger.entries) + 1,
            timestamp="2026-01-01T00:00:00+00:00",
            claim=Claim("tool_call", {"agent": "b", "tool": "t"}, "  "),
            entry_hash="deadbeef",
            prev_hash=ledger.head_hash,
        )
        ledger._entries.append(forged_entry)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            with pytest.raises(UnevidencedClaimError):
                ledger.save(path)


class TestLoadValidatesEveryClaim:
    def _valid_claims(self) -> list[dict]:
        return [
            {"kind": "tool_call", "payload": {"agent": "a"}, "evidence": "log line 1"},
            {"kind": "tool_call", "payload": {"agent": "b"}, "evidence": "log line 2"},
        ]

    def test_valid_ledger_still_loads(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = EvidenceLedger()
            ledger.append(Claim("tool_call", {"agent": "a"}, "log line 1"))
            ledger.append(Claim("tool_call", {"agent": "b"}, "log line 2"))
            ledger.save(path)
            loaded = EvidenceLedger.load(path)
            assert len(loaded.entries) == 2
            ok, _ = loaded.verify()
            assert ok

    def test_self_consistent_empty_evidence_is_refused(self):
        """The exact tamper the old load path accepted."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            claims = self._valid_claims()
            claims[0]["evidence"] = ""
            _rewrite_with_valid_chain(path, claims)
            with pytest.raises(LedgerFileError, match="invalid claim"):
                EvidenceLedger.load(path)

    def test_self_consistent_non_dict_payload_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            claims = self._valid_claims()
            claims[0]["payload"] = "not-a-dict"
            _rewrite_with_valid_chain(path, claims)
            with pytest.raises(LedgerFileError, match="invalid claim"):
                EvidenceLedger.load(path)

    def test_self_consistent_empty_kind_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            claims = self._valid_claims()
            claims[1]["kind"] = ""
            _rewrite_with_valid_chain(path, claims)
            with pytest.raises(LedgerFileError, match="invalid claim"):
                EvidenceLedger.load(path)

    def test_whitespace_only_evidence_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            claims = self._valid_claims()
            claims[1]["evidence"] = "   \n  "
            _rewrite_with_valid_chain(path, claims)
            with pytest.raises(LedgerFileError, match="invalid claim"):
                EvidenceLedger.load(path)

    def test_non_string_kind_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            claims = self._valid_claims()
            claims[0]["kind"] = 7
            _rewrite_with_valid_chain(path, claims)
            with pytest.raises(LedgerFileError):
                EvidenceLedger.load(path)

    def test_missing_claim_field_is_still_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            claims = self._valid_claims()
            del claims[0]["evidence"]
            _rewrite_with_valid_chain(path, claims)
            with pytest.raises(LedgerFileError, match="missing"):
                EvidenceLedger.load(path)

    def test_append_after_load_still_enforces_validation(self):
        """A loaded ledger stays closed: it cannot grow an invalid claim."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = EvidenceLedger()
            ledger.append(Claim("tool_call", {"agent": "a"}, "log line 1"))
            ledger.save(path)
            loaded = EvidenceLedger.load(path)
            with pytest.raises(UnevidencedClaimError):
                loaded.append(Claim("tool_call", {"agent": "b"}, ""))


class TestWalValidatesEveryClaim:
    """The same gap on the WAL replay path (ledger_wal.recover)."""

    def test_forged_wal_record_with_invalid_claim_is_refused(self):
        from nomosguard.ledger_wal import WalError
        from nomosguard.ledger import wal_path_for

        with tempfile.TemporaryDirectory() as td:
            ledger_path = Path(td) / "ledger.jsonl"
            ledger = EvidenceLedger()
            ledger.append(Claim("tool_call", {"agent": "a"}, "log line 1"))
            ledger.save(ledger_path)

            # forge WAL records: consistent chain, empty evidence
            claims = [
                {"kind": "tool_call", "payload": {"agent": "b"}, "evidence": ""},
            ]
            lines = []
            prev_hash = ledger.head_hash
            for seq, claim in enumerate(claims, start=2):
                body = json.dumps(
                    {"seq": seq, "claim": claim, "prev_hash": prev_hash},
                    sort_keys=True,
                    separators=(",", ":"),
                )
                entry_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
                record = {
                    "seq": seq,
                    "timestamp": "2026-01-01T00:00:00+00:00",
                    "claim": claim,
                    "entry_hash": entry_hash,
                    "prev_hash": prev_hash,
                }
                lines.append(json.dumps(record, sort_keys=True))
                prev_hash = entry_hash
            wal_path_for(ledger_path).write_text(
                "\n".join(lines) + "\n", encoding="utf-8"
            )

            from nomosguard.ledger_wal import recover

            with pytest.raises(WalError, match="invalid claim"):
                recover(ledger_path)
