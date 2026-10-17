"""The tamper matrix: every way this ledger can be attacked, in one file.

The ledger's hash chain, the claim validation added in 0.7.8, and the
append_locked persistence each had their own scattered tests. This file
is the single adversarial matrix: for every tamper kind — a mutated claim
field, a reorder, a truncated tail, a duplicated record, a forged hash or
header, an emptied mid-block line, a corrupted WAL — the loader or the
recovery path must fail CLOSED with a typed error and must never produce
a partial PASS (a ledger that loads with entries dropped, deciding over
what is left).

Two tamper kinds are currently ACCEPTED by an internally-verified chain,
and they are pinned here as findings with their fix, not hidden:

- a full, consistent REWRITE of the file (every record, link and header
  re-sealed): the chain proves the records agree with each other, so
  only a digest held outside the file catches it — `ledger_digest` /
  `load(expected_digest=...)` / `NomosGuardSession(ledger_digest=...)`.
  Both variants are tested: accepted unpinned (the documented boundary),
  refused pinned (the fix).
- a torn FINAL line on an UNPINNED ledger: the main file is only ever
  rewritten atomically, so a torn tail was NOT produced by a crash of
  this writer — an unpinned torn load is refused outright. Recovery is
  an explicit operator act: pin the reviewed bytes
  (`load(expected_digest=...)`), the drop must be REPORTED
  (`LedgerLoadReport`, surfaced as `session.load_report`), and a strict
  load must still refuse.

Everything else in the matrix must raise the typed error named by its
case, before AND after any future change.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from nomosguard.ledger import (
    Claim,
    EvidenceLedger,
    LedgerFileError,
    ledger_digest,
    wal_path_for,
)
from nomosguard.ledger_lock import append_locked
from nomosguard.ledger_wal import WalError, recover, write_wal
from nomosguard.mcp_server import (
    NomosGuardSession,
    default_policy_rules,
    default_rules,
)

# -- helpers -------------------------------------------------------------------


def _build(path: Path, entries: int = 3) -> EvidenceLedger:
    """A small valid ledger saved to `path` (the pre-tamper original)."""
    ledger = EvidenceLedger()
    ledger.append(Claim("tool_call", {"agent": "a1", "tool": "t1"}, "log line 1"))
    if entries > 1:
        ledger.append(Claim("tool_call", {"agent": "a2", "tool": "t2"}, "log line 2"))
    if entries > 2:
        ledger.append(
            Claim("vulnerability", {"component": "db1", "cve": "CVE-1"}, "NVD record")
        )
    ledger.save(path)
    return ledger


def _read(path: Path) -> list:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _write(path: Path, records: list) -> None:
    path.write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n",
        encoding="utf-8",
    )


def _rehash(records: list) -> list:
    """Re-seal a record list: consistent hashes, links and header.

    This is what an attacker with the file and the algorithm can do.
    """
    header = dict(records[0])
    body = [dict(r) for r in records[1:]]
    prev_hash = ""
    for record in body:
        chain_body = json.dumps(
            {"seq": record["seq"], "claim": record["claim"], "prev_hash": prev_hash},
            sort_keys=True,
            separators=(",", ":"),
        )
        record["entry_hash"] = hashlib.sha256(chain_body.encode("utf-8")).hexdigest()
        record["prev_hash"] = prev_hash
        prev_hash = record["entry_hash"]
    header["entries"] = len(body)
    header["head_hash"] = prev_hash
    return [header] + body


# -- the matrix -----------------------------------------------------------------


@dataclass(frozen=True)
class TamperCase:
    """One tamper kind: how to apply it, and what the loader must raise.

    The session-level assertion (`test_tamper_never_produces_a_partial_pass`)
    runs for every kind: the refusal must also stop a session from starting,
    so the gate never runs over a partially loaded ledger.
    """

    name: str
    apply: Callable[[Path], None]
    error: type[BaseException]
    match: str = ""


def _valid_claim(agent: str = "c") -> dict:
    return {"kind": "tool_call", "payload": {"agent": agent}, "evidence": "log line 3"}


def _wal_record(seq: int, claim: dict, prev_hash: str) -> dict:
    body = json.dumps(
        {"seq": seq, "claim": claim, "prev_hash": prev_hash},
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "seq": seq,
        "timestamp": "2026-01-01T00:00:00+00:00",
        "claim": claim,
        "entry_hash": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "prev_hash": prev_hash,
    }


def _case_mutate_claim_payload(path: Path) -> None:
    records = _read(path)
    records[2]["claim"]["payload"]["agent"] = "attacker"
    _write(path, records)


def _case_mutate_claim_evidence(path: Path) -> None:
    records = _read(path)
    records[1]["claim"]["evidence"] = "a fragment nobody cited"
    _write(path, records)


def _case_mutate_claim_kind(path: Path) -> None:
    records = _read(path)
    records[1]["claim"]["kind"] = "policy_rule"  # the kind is hashed too
    _write(path, records)


def _case_mutate_claim_field_rehashed(path: Path) -> None:
    """The 0.7.8 finding: mutate AND re-seal — the claim is still invalid."""
    records = _read(path)
    records[1]["claim"]["evidence"] = "   "  # whitespace: not evidence
    _write(path, _rehash(records))


def _case_reorder_adjacent(path: Path) -> None:
    records = _read(path)
    records[1], records[2] = records[2], records[1]
    _write(path, records)


def _case_reorder_first_last(path: Path) -> None:
    records = _read(path)
    records[1], records[-1] = records[-1], records[1]
    _write(path, records)


def _case_truncate_tail(path: Path) -> None:
    records = _read(path)[:-1]  # drop the final record, header still lies
    _write(path, records)


def _case_truncate_body_completely(path: Path) -> None:
    records = _read(path)[:1]  # header only, header still lies
    _write(path, records)


def _case_duplicate_record(path: Path) -> None:
    records = _read(path)
    records.insert(2, records[1])  # seq 2 twice
    _write(path, records)


def _case_duplicate_last_record(path: Path) -> None:
    records = _read(path)
    records.append(records[-1])  # seq 3 twice
    _write(path, records)


def _case_forge_entry_hash(path: Path) -> None:
    records = _read(path)
    records[2]["entry_hash"] = "0" * 64
    _write(path, records)


def _case_forge_prev_hash(path: Path) -> None:
    records = _read(path)
    records[2]["prev_hash"] = "0" * 64
    _write(path, records)


def _case_forge_header_head_hash(path: Path) -> None:
    records = _read(path)
    records[0]["head_hash"] = "0" * 64
    _write(path, records)


def _case_forge_header_entries(path: Path) -> None:
    records = _read(path)
    records[0]["entries"] = 99
    _write(path, records)


def _case_forge_header_format(path: Path) -> None:
    records = _read(path)
    records[0]["format"] = "someone-elses-ledger"
    _write(path, records)


def _case_forge_header_version(path: Path) -> None:
    records = _read(path)
    records[0]["format_version"] = 99
    _write(path, records)


def _case_drop_header(path: Path) -> None:
    _write(path, _read(path)[1:])  # records with no header line


def _case_empty_midblock_line(path: Path) -> None:
    records = _read(path)
    records[1] = ""  # a blank line where a record used to be
    path.write_text(
        "\n".join(json.dumps(r, sort_keys=True) if isinstance(r, dict) else r
                  for r in records) + "\n",
        encoding="utf-8",
    )


def _case_remove_midblock_record(path: Path) -> None:
    _write(path, _read(path)[:1] + _read(path)[2:])  # a hole in the chain


def _case_whitespace_midblock_record(path: Path) -> None:
    records = _read(path)
    records[2] = "   "
    path.write_text(
        "\n".join(json.dumps(r, sort_keys=True) if isinstance(r, dict) else r
                  for r in records) + "\n",
        encoding="utf-8",
    )


def _case_non_object_record_midfile(path: Path) -> None:
    records = _read(path)
    records[1] = ["not", "an", "object"]
    _write(path, records)


def _case_bad_json_record_midfile(path: Path) -> None:
    records = _read(path)
    lines = [json.dumps(r, sort_keys=True) for r in records]
    lines[1] = '{"seq": 2, "claim": '  # truncated JSON, mid-file
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _case_missing_claim_field(path: Path) -> None:
    records = _read(path)
    del records[1]["claim"]["evidence"]
    _write(path, records)


def _case_non_dict_claim(path: Path) -> None:
    records = _read(path)
    records[1]["claim"] = "tool_call"
    _write(path, records)


def _case_bad_seq_type(path: Path) -> None:
    records = _read(path)
    records[1]["seq"] = "2"
    _write(path, records)


def _case_missing_timestamp(path: Path) -> None:
    records = _read(path)
    del records[1]["timestamp"]
    _write(path, records)


def _case_empty_file(path: Path) -> None:
    path.write_text("", encoding="utf-8")


def _case_whitespace_only_file(path: Path) -> None:
    path.write_text("   \n\n", encoding="utf-8")


def _case_header_not_json(path: Path) -> None:
    path.write_text("not json at all\n", encoding="utf-8")


def _case_header_not_object(path: Path) -> None:
    path.write_text("[1, 2, 3]\n", encoding="utf-8")


LEDGER_TAMPER_CASES: tuple[TamperCase, ...] = (
    TamperCase("mutate_claim_payload", _case_mutate_claim_payload, LedgerFileError,
               "hash mismatch"),
    TamperCase("mutate_claim_evidence", _case_mutate_claim_evidence, LedgerFileError,
               "hash mismatch"),
    TamperCase("mutate_claim_kind", _case_mutate_claim_kind, LedgerFileError,
               "hash mismatch"),
    TamperCase("mutate_claim_field_rehashed", _case_mutate_claim_field_rehashed,
               LedgerFileError, "invalid claim"),
    TamperCase("reorder_adjacent", _case_reorder_adjacent, LedgerFileError,
               "sequence gap"),
    TamperCase("reorder_first_last", _case_reorder_first_last, LedgerFileError,
               "sequence gap"),
    TamperCase("truncate_tail", _case_truncate_tail, LedgerFileError,
               "header declares"),
    TamperCase("truncate_body_completely", _case_truncate_body_completely,
               LedgerFileError, "header declares"),
    TamperCase("duplicate_record", _case_duplicate_record, LedgerFileError,
               "duplicate sequence number"),
    TamperCase("duplicate_last_record", _case_duplicate_last_record, LedgerFileError,
               "duplicate sequence number"),
    TamperCase("forge_entry_hash", _case_forge_entry_hash, LedgerFileError,
               "hash mismatch"),
    TamperCase("forge_prev_hash", _case_forge_prev_hash, LedgerFileError,
               "broken chain link"),
    TamperCase("forge_header_head_hash", _case_forge_header_head_hash,
               LedgerFileError, "head_hash"),
    TamperCase("forge_header_entries", _case_forge_header_entries,
               LedgerFileError, "header declares"),
    TamperCase("forge_header_format", _case_forge_header_format, LedgerFileError,
               "missing nomosguard-ledger header"),
    TamperCase("forge_header_version", _case_forge_header_version, LedgerFileError,
               "unsupported ledger format version"),
    TamperCase("drop_header", _case_drop_header, LedgerFileError,
               "missing nomosguard-ledger header"),
    TamperCase("empty_midblock_line", _case_empty_midblock_line, LedgerFileError,
               "sequence gap"),
    TamperCase("remove_midblock_record", _case_remove_midblock_record,
               LedgerFileError, "sequence gap"),
    TamperCase("whitespace_midblock_record", _case_whitespace_midblock_record,
               LedgerFileError, "sequence gap"),
    TamperCase("non_object_record_midfile", _case_non_object_record_midfile,
               LedgerFileError, "not a JSON object"),
    TamperCase("bad_json_record_midfile", _case_bad_json_record_midfile,
               LedgerFileError, "not valid JSON"),
    TamperCase("missing_claim_field", _case_missing_claim_field, LedgerFileError,
               "missing"),
    TamperCase("non_dict_claim", _case_non_dict_claim, LedgerFileError,
               "malformed claim"),
    TamperCase("bad_seq_type", _case_bad_seq_type, LedgerFileError,
               "seq must be an integer"),
    TamperCase("missing_timestamp", _case_missing_timestamp, LedgerFileError,
               "missing timestamp"),
    TamperCase("empty_file", _case_empty_file, LedgerFileError,
               "ledger file is empty"),
    TamperCase("whitespace_only_file", _case_whitespace_only_file, LedgerFileError,
               "ledger file is empty"),
    TamperCase("header_not_json", _case_header_not_json, LedgerFileError,
               "header is not valid JSON"),
    TamperCase("header_not_object", _case_header_not_object, LedgerFileError,
               "header is not a JSON object"),
)


class TestLedgerFileTamperMatrix:
    """Every ledger-file tamper kind fails closed, typed, and never partial."""

    @pytest.mark.parametrize(
        "case", LEDGER_TAMPER_CASES, ids=[c.name for c in LEDGER_TAMPER_CASES]
    )
    def test_tamper_refused_by_the_loader(self, tmp_path, case: TamperCase):
        path = tmp_path / "ledger.jsonl"
        _build(path)
        case.apply(path)
        with pytest.raises(case.error, match=case.match):
            EvidenceLedger.load(path)

    @pytest.mark.parametrize(
        "case", LEDGER_TAMPER_CASES, ids=[c.name for c in LEDGER_TAMPER_CASES]
    )
    def test_tamper_never_produces_a_partial_pass(self, tmp_path, case: TamperCase):
        """The session must refuse to start over a tampered file.

        A partial PASS would be a session that loaded what it could and
        decided over the remainder: the loader raises, so no decision —
        not a weaker one — is ever produced.
        """
        path = tmp_path / "ledger.jsonl"
        _build(path)
        case.apply(path)
        with pytest.raises(LedgerFileError):
            NomosGuardSession(
                rules=default_rules(),
                policy_rules=default_policy_rules(),
                ledger_path=path,
            )

    def test_untampered_ledger_still_loads_and_decides(self, tmp_path):
        """The control: the same path, untouched, loads and decides."""
        path = tmp_path / "ledger.jsonl"
        _build(path)
        session = NomosGuardSession(
            rules=default_rules(),
            policy_rules=default_policy_rules(),
            ledger_path=path,
        )
        assert len(session.ledger.entries) == 3
        assert session.load_report is not None
        assert session.load_report.dropped_tail == 0
        # nothing derives, so the gate falls back — and denies
        decision = session.decide()
        assert decision["decision"] == "BLOCK"
        assert decision["policy_rule"] == "FALLBACK"


class TestTamperBoundaries:
    """The two tamper kinds an internal chain cannot see — pinned, not hidden.

    A full consistent rewrite and a truncation-with-recomputed-header are
    byte-for-byte what a legitimate shorter ledger looks like. The chain
    alone accepts both; the digest pin refuses both. Both halves are
    tested so the boundary can never silently move.
    """

    def _rewritten(self, tmp_path) -> tuple[Path, str]:
        path = tmp_path / "ledger.jsonl"
        _build(path)
        pinned = ledger_digest(path)
        records = _read(path)
        for record in records[1:]:
            record["claim"]["payload"]["agent"] = "attacker"
        _write(path, _rehash(records))
        # the rewritten file verifies against ITSELF: that is the finding
        loaded = EvidenceLedger.load(path)
        ok, _ = loaded.verify()
        assert ok
        return path, pinned

    def test_full_consistent_rewrite_is_accepted_without_a_pin(self, tmp_path):
        """The documented boundary, pinned so it cannot drift silently.

        This is not a defect to be ashamed of: a hash chain proves the
        records agree with each OTHER. It is exactly why
        `ledger_digest` exists — and why the pin test below must hold.
        """
        path, _ = self._rewritten(tmp_path)
        loaded = EvidenceLedger.load(path)
        assert loaded.entries[0].claim.payload["agent"] == "attacker"

    def test_full_consistent_rewrite_refused_with_a_pin(self, tmp_path):
        path, pinned = self._rewritten(tmp_path)
        with pytest.raises(LedgerFileError, match="digest mismatch"):
            EvidenceLedger.load(path, expected_digest=pinned)

    def test_full_consistent_rewrite_refuses_the_session(self, tmp_path):
        path, pinned = self._rewritten(tmp_path)
        with pytest.raises(LedgerFileError, match="digest mismatch"):
            NomosGuardSession(
                rules=default_rules(),
                policy_rules=default_policy_rules(),
                ledger_path=path,
                ledger_digest=pinned,
            )

    def test_pinned_untampered_ledger_loads(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        _build(path)
        pinned = ledger_digest(path)
        loaded = EvidenceLedger.load(path, expected_digest=pinned)
        assert len(loaded.entries) == 3

    def test_truncated_tail_with_recomputed_header_is_the_boundary(self, tmp_path):
        """A truncation whose header was re-sealed too: accepted unpinned,
        refused pinned. The header pin (`entries`, `head_hash`) only
        catches a truncation that forgot to fix the header."""
        path = tmp_path / "ledger.jsonl"
        _build(path)
        pinned = ledger_digest(path)
        records = _rehash(_read(path)[:-1])
        _write(path, records)
        loaded = EvidenceLedger.load(path)  # accepted: the boundary
        assert len(loaded.entries) == 2
        with pytest.raises(LedgerFileError, match="digest mismatch"):
            EvidenceLedger.load(path, expected_digest=pinned)

    def test_bad_pin_format_is_refused_loudly(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        _build(path)
        for bad in ("deadbeef", "", 42):
            with pytest.raises(LedgerFileError, match="expected digest"):
                EvidenceLedger.load(path, expected_digest=bad)
        # a well-formed but wrong pin is a mismatch, not a format error
        with pytest.raises(LedgerFileError, match="digest mismatch"):
            EvidenceLedger.load(path, expected_digest="sha256:" + "0" * 64)


class TestTornTailIsRecoveredAndReported:
    """A torn FINAL line is refused unpinned; under an explicit digest pin
    it is dropped, reported, and healed — never silently."""

    def _torn(self, tmp_path) -> Path:
        path = tmp_path / "ledger.jsonl"
        _build(path)
        text = path.read_text(encoding="utf-8")
        path.write_text(text[: len(text) - 12], encoding="utf-8")  # cut mid-line
        return path

    def test_unpinned_torn_tail_is_refused(self, tmp_path):
        path = self._torn(tmp_path)
        with pytest.raises(LedgerFileError, match="UNPINNED"):
            EvidenceLedger.load(path)

    def test_pinned_load_recovers_and_reports_the_drop(self, tmp_path):
        from nomosguard.ledger import LedgerLoadReport

        path = self._torn(tmp_path)
        pinned = ledger_digest(path)  # the operator pins the reviewed bytes
        report = LedgerLoadReport(entries=[], header={})
        loaded = EvidenceLedger.load(path, report=report, expected_digest=pinned)
        assert len(loaded.entries) == 2
        assert report.dropped_tail == 1
        assert report.tail_detail

    def test_strict_load_refuses_a_torn_tail(self, tmp_path):
        path = self._torn(tmp_path)
        with pytest.raises(LedgerFileError, match="truncated final entry"):
            EvidenceLedger.load(path, allow_torn_tail=False)

    def test_session_surfaces_the_recovery_instead_of_hiding_it(self, tmp_path):
        """No silent degradation: the drop is visible on the session."""
        path = self._torn(tmp_path)
        pinned = ledger_digest(path)
        session = NomosGuardSession(
            rules=default_rules(),
            policy_rules=default_policy_rules(),
            ledger_path=path,
            ledger_digest=pinned,
        )
        assert session.load_report is not None
        assert session.load_report.dropped_tail == 1
        # the recovered remainder derives nothing -> the gate still denies
        decision = session.decide()
        assert decision["decision"] == "BLOCK"

    def test_session_heals_the_file_after_pinned_recovery(self, tmp_path):
        """The pinned recovery heals the file on disk (under the lock), so a
        later unpinned reader sees a clean chain — not a poisoned one."""
        path = self._torn(tmp_path)
        pinned = ledger_digest(path)
        NomosGuardSession(
            rules=default_rules(),
            policy_rules=default_policy_rules(),
            ledger_path=path,
            ledger_digest=pinned,
        )
        reloaded = EvidenceLedger.load(path)  # now clean: no refusal
        assert len(reloaded.entries) == 2

    def test_append_after_recovery_continues_a_valid_chain(self, tmp_path):
        path = self._torn(tmp_path)
        pinned = ledger_digest(path)
        loaded = EvidenceLedger.load(path, expected_digest=pinned)
        entry = loaded.append(Claim("tool_call", {"agent": "z", "tool": "t"}, "line"))
        assert entry.seq == 3
        ok, _ = loaded.verify()
        assert ok


# -- the WAL matrix ---------------------------------------------------------------


def _case_wal_forge_entry_hash(path: Path) -> None:
    ledger = EvidenceLedger.load(path)
    record = _wal_record(4, _valid_claim(), ledger.head_hash)
    record["entry_hash"] = "0" * 64
    wal_path_for(path).write_text(json.dumps(record, sort_keys=True) + "\n",
                                  encoding="utf-8")


def _case_wal_forge_prev_hash(path: Path) -> None:
    ledger = EvidenceLedger.load(path)
    record = _wal_record(4, _valid_claim(), ledger.head_hash)
    record["prev_hash"] = "0" * 64
    wal_path_for(path).write_text(json.dumps(record, sort_keys=True) + "\n",
                                  encoding="utf-8")


def _case_wal_invalid_claim(path: Path) -> None:
    ledger = EvidenceLedger.load(path)
    # consistent hashes, empty evidence: the 0.7.8 WAL finding — a forged
    # record must be refused, never replayed into the chain
    record = _wal_record(4, {"kind": "tool_call", "payload": {}, "evidence": ""},
                         ledger.head_hash)
    wal_path_for(path).write_text(json.dumps(record, sort_keys=True) + "\n",
                                  encoding="utf-8")


def _case_wal_missing_timestamp(path: Path) -> None:
    ledger = EvidenceLedger.load(path)
    record = _wal_record(4, _valid_claim(), ledger.head_hash)
    del record["timestamp"]
    wal_path_for(path).write_text(json.dumps(record, sort_keys=True) + "\n",
                                  encoding="utf-8")


def _case_wal_seq_gap(path: Path) -> None:
    ledger = EvidenceLedger.load(path)
    record = _wal_record(5, _valid_claim(), ledger.head_hash)
    wal_path_for(path).write_text(json.dumps(record, sort_keys=True) + "\n",
                                  encoding="utf-8")


def _case_wal_duplicate_seq(path: Path) -> None:
    ledger = EvidenceLedger.load(path)
    first = _wal_record(4, _valid_claim("c"), ledger.head_hash)
    duplicate = _wal_record(4, _valid_claim("d"), first["entry_hash"])
    # first record is fine (pending); the duplicate seq must be refused
    duplicate["entry_hash"] = hashlib.sha256(json.dumps(
        {"seq": 4, "claim": _valid_claim("d"), "prev_hash": first["entry_hash"]},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    wal_path_for(path).write_text(
        json.dumps(first, sort_keys=True) + "\n"
        + json.dumps(duplicate, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _case_wal_non_object_record(path: Path) -> None:
    wal_path_for(path).write_text("[1, 2, 3]\n", encoding="utf-8")


WAL_TAMPER_CASES: tuple[TamperCase, ...] = (
    TamperCase("wal_forge_entry_hash", _case_wal_forge_entry_hash, WalError,
               "hash mismatch"),
    TamperCase("wal_forge_prev_hash", _case_wal_forge_prev_hash, WalError,
               "broken chain link"),
    TamperCase("wal_invalid_claim", _case_wal_invalid_claim, WalError,
               "invalid claim"),
    TamperCase("wal_missing_timestamp", _case_wal_missing_timestamp, WalError,
               "missing timestamp"),
    TamperCase("wal_seq_gap", _case_wal_seq_gap, WalError, "sequence gap in WAL"),
    TamperCase("wal_duplicate_seq", _case_wal_duplicate_seq, WalError,
               "sequence gap in WAL"),
    TamperCase("wal_non_object_record", _case_wal_non_object_record, WalError,
               "not a JSON object"),
)


class TestWalTamperMatrix:
    """Every WAL tamper kind fails closed with the typed WalError."""

    @pytest.mark.parametrize(
        "case", WAL_TAMPER_CASES, ids=[c.name for c in WAL_TAMPER_CASES]
    )
    def test_wal_tamper_refused_by_recovery(self, tmp_path, case: TamperCase):
        path = tmp_path / "ledger.jsonl"
        _build(path)
        case.apply(path)
        with pytest.raises(case.error, match=case.match):
            recover(path)

    def test_torn_wal_final_line_is_dropped_and_reported_never_replayed(
        self, tmp_path
    ):
        """A torn FINAL line is a crash, not tamper — but the drop is
        REPORTED: the entry before the tear is still recovered, the torn
        record is counted in `dropped` with `truncated_after`, and the
        recovery detail names it. Recovery never mutates the main file.
        """
        path = tmp_path / "ledger.jsonl"
        ledger = _build(path)
        first = _wal_record(4, _valid_claim("c"), ledger.head_hash)
        wal_path_for(path).write_text(
            json.dumps(first, sort_keys=True) + "\n"
            + '{"seq": 5, "clai',  # the torn final line
            encoding="utf-8",
        )
        recovery = recover(path)
        assert [e.seq for e in recovery.pending] == [4]
        assert recovery.dropped == 1
        assert recovery.truncated_after == 4
        assert "dropped torn WAL line 2" in recovery.detail
        assert len(EvidenceLedger.load(path).entries) == 3

    def test_torn_wal_line_midfile_is_refused_typed(self, tmp_path):
        """A torn line anywhere but the end is tamper, not a crash: the
        WAL is append-only, so a mid-file hole cannot be a write that was
        interrupted. It raises WalError — the typed, fail-closed answer.
        """
        path = tmp_path / "ledger.jsonl"
        ledger = _build(path)
        first = _wal_record(4, _valid_claim("c"), ledger.head_hash)
        after = _wal_record(5, _valid_claim("d"), first["entry_hash"])
        wal_path_for(path).write_text(
            json.dumps(first, sort_keys=True) + "\n"
            + '{"seq": 5, "clai' + "\n"  # a hole in the middle
            + json.dumps(after, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with pytest.raises(WalError, match="not valid JSON"):
            recover(path)

    def test_a_clean_wal_is_replayed_not_refused(self, tmp_path):
        """The control: a well-formed WAL recovers its pending entry."""
        path = tmp_path / "ledger.jsonl"
        ledger = _build(path)
        extra = ledger.append(
            Claim("tool_call", {"agent": "c", "tool": "t"}, "log line 4")
        )
        # write the entry to the WAL only (the main file still holds 3)
        write_wal(path, [extra])
        recovery = recover(path)
        assert [e.seq for e in recovery.pending] == [4]
        assert recovery.applied == 0
        assert recovery.dropped == 0
        # and the main chain is untouched by recovery
        assert len(EvidenceLedger.load(path).entries) == 3


class TestAppendLockedFailsClosed:
    """The append path never launders a tampered file into a new chain."""

    def test_append_locked_refuses_a_tampered_ledger(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        _build(path)
        records = _read(path)
        records[1]["claim"]["payload"]["agent"] = "attacker"
        _write(path, records)
        before = path.read_bytes()  # the tampered bytes must survive untouched
        with pytest.raises(LedgerFileError):
            append_locked(path, Claim("tool_call", {"agent": "z", "tool": "t"}, "line"))
        # the tampered file was not silently overwritten with a new chain
        assert path.read_bytes() == before

    def test_append_locked_over_a_forged_wal_never_launders_it(self, tmp_path):
        """A forged WAL blocks all appends; neither file may be mutated."""
        path = tmp_path / "ledger.jsonl"
        ledger = _build(path)
        forged = _wal_record(4, _valid_claim("forged"), ledger.head_hash)
        forged["entry_hash"] = "0" * 64
        wal_path = wal_path_for(path)
        wal_path.write_text(json.dumps(forged, sort_keys=True) + "\n", encoding="utf-8")
        previous_ledger = path.read_bytes()
        previous_wal = wal_path.read_bytes()

        with pytest.raises(WalError, match="hash mismatch"):
            append_locked(path, Claim("tool_call", {"agent": "z", "tool": "t"}, "log line 4"))
        assert path.read_bytes() == previous_ledger
        assert wal_path.read_bytes() == previous_wal
        with pytest.raises(WalError, match="hash mismatch"):
            recover(path)
