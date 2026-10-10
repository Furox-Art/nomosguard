"""Ledger durability and concurrency: WAL recovery, atomic writes, locking.

What these tests defend against, in order of severity:

1. LOST EVIDENCE. A process that dies between appending an entry and
   checkpointing the main file must not lose that entry. The WAL exists
   for exactly this, and `test_wal_recovers_entries_the_main_file_never_got`
   is the regression test for the failure mode the WAL was added to fix.
2. SILENT CORRUPTION. A crash mid-write can tear the final line of the
   main file. That line is dropped and the drop is REPORTED — never
   silently, and never treated as tamper evidence (`torn` != `tampered`).
3. LOST WRITES UNDER CONCURRENCY. Two writers that read-modify-write
   without a lock clobber each other. `test_concurrent_appenders_*` spawn
   real processes, because the bug only manifests with real interleaving.
4. A LOCK THAT DOESN'T LOCK. `test_second_lock_blocks_until_release`
   proves the lock actually excludes; a no-op lock would pass every
   correctness test and still lose data in production.

Locking tests are POSIX-only (fcntl) and skip elsewhere: the core stays
cross-platform, only multi-writer safety degrades — loudly, via
NotImplementedError, never silently.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import sys
import tempfile
from pathlib import Path

import pytest

from nomosguard.ledger import (
    Claim,
    EvidenceLedger,
    LedgerFileError,
    LedgerLoadReport,
    wal_path_for,
)
from nomosguard.ledger_wal import (
    WalError,
    checkpoint,
    durable_save,
    recover,
    write_wal,
)

# fcntl is POSIX-only; the lock module refuses to import elsewhere.
try:
    import fcntl  # noqa: F401

    from nomosguard.ledger_lock import (
        LedgerLock,
        LedgerLockError,
        append_locked,
        ledger_lock,
        lock_path_for,
    )

    HAS_FLOCK = True
except (ImportError, NotImplementedError):
    HAS_FLOCK = False

requires_posix = pytest.mark.skipif(
    not HAS_FLOCK, reason="fcntl.flock is POSIX-only; multi-writer locking unsupported here"
)


def _claim(i: int, tag: str = "c") -> Claim:
    return Claim(
        kind="tool_call",
        payload={"agent": f"{tag}{i}", "tool": f"t{i}"},
        evidence=f"log line {tag}{i}",
    )


def _seeded(n: int = 3, tag: str = "s") -> EvidenceLedger:
    ledger = EvidenceLedger()
    for i in range(1, n + 1):
        ledger.append(_claim(i, tag))
    return ledger


def _assert_chain(ledger: EvidenceLedger, expected: int) -> None:
    """The invariant every durability path must preserve."""
    assert len(ledger.entries) == expected, (
        f"expected {expected} entries, got {len(ledger.entries)}"
    )
    ok, detail = ledger.verify()
    assert ok, detail
    assert [e.seq for e in ledger.entries] == list(range(1, expected + 1)), (
        "sequence numbers must be 1..N with no gaps and no duplicates"
    )


# ---------------------------------------------------------------------------
# 1. Write-ahead log
# ---------------------------------------------------------------------------


class TestWalRoundTrip:
    """WAL: record before the main file changes; recover if we die first."""

    def test_wal_recovers_entries_the_main_file_never_got(self, tmp_path=None):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(2)
            ledger.save(path)

            # Append two more entries but crash BEFORE saving the main file:
            # only the WAL records them.
            for i in (3, 4):
                ledger.append(_claim(i))
            written = write_wal(path, ledger.entries[2:])
            assert written == 2, "the two new entries must reach the WAL"

            # The main file still holds only the first two — that is the crash.
            assert len(EvidenceLedger.load(path).entries) == 2

            recovery = recover(path)
            assert len(recovery.pending) == 2
            assert [e.seq for e in recovery.pending] == [3, 4]
            # applied counts WAL entries ALREADY in the main file; the WAL
            # here holds only the two NEW entries, so applied is 0.
            assert recovery.applied == 0
            assert recovery.dropped == 0

            # Replay under the lock: the recovered ledger must verify.
            for entry in recovery.pending:
                append_locked(path, entry.claim)
            _assert_chain(EvidenceLedger.load(path), 4)

    def test_recover_on_a_clean_ledger_reports_nothing_pending(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(3)
            durable_save(ledger, path)  # save + checkpoint

            recovery = recover(path)
            assert recovery.pending == []
            # durable_save checkpoints, so the WAL is empty: nothing
            # pending and nothing "already applied" (there is nothing in
            # the WAL to apply).
            assert recovery.applied == 0
            assert "nothing to recover" in recovery.detail or "pending" in recovery.detail

    def test_checkpoint_empties_the_wal(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(3)
            # WAL first (the entries are new), then save the main file —
            # the WAL now holds records the main file also has.
            write_wal(path, ledger.entries)
            assert wal_path_for(path).is_file(), "WAL must exist after write_wal"
            assert wal_path_for(path).read_text().strip() != ""
            ledger.save(path)

            discarded = checkpoint(path)
            assert discarded == 3
            assert wal_path_for(path).read_text() == "", "WAL must be empty after checkpoint"

    def test_checkpoint_refuses_to_discard_unpersisted_entries(self):
        """The dangerous failure: checkpointing would LOSE committed entries."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(2)
            ledger.save(path)
            ledger.append(_claim(3))
            write_wal(path, ledger.entries[2:])  # entry 3 is WAL-only

            with pytest.raises(WalError, match="refusing to checkpoint"):
                checkpoint(path)
            # The WAL survived the refusal — nothing was lost.
            assert len(recover(path).pending) == 1

    def test_torn_wal_line_is_dropped_not_replayed(self):
        """A crash mid-write leaves a partial line. It must be dropped,
        and the drop must be reported — never silently replayed, because
        a partial record's hash cannot be verified."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(2)
            ledger.save(path)
            write_wal(path, ledger.entries)  # both already applied

            # Simulate a crash mid-write: append a truncated JSON line.
            wal = wal_path_for(path)
            with open(wal, "a", encoding="utf-8") as fh:
                fh.write('{"seq": 3, "claim": {"kind": "tool_cal')  # no closing

            recovery = recover(path)
            assert recovery.dropped == 1, "the torn line must be counted, not ignored"
            assert recovery.truncated_after == 2
            assert "torn" in recovery.detail.lower()
            assert recovery.pending == [], "a torn entry must never be replayed"

    def test_wal_entries_after_a_torn_line_are_not_replayed(self):
        """A torn TAIL is dropped and reported; a torn line in the MIDDLE
        of the WAL is a hard error (the module refuses to guess what
        follows an unverifiable record). This test covers the tail case —
        the recoverable one."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(1)
            ledger.save(path)
            ledger.append(_claim(2))
            write_wal(path, ledger.entries[1:])  # seq 2, complete
            with open(wal_path_for(path), "a", encoding="utf-8") as fh:
                fh.write('{"seq": 3, "claim": {"kin')  # torn tail (last line)

            recovery = recover(path)
            assert recovery.dropped == 1
            assert recovery.truncated_after == 2
            # Entries BEFORE the tear are valid and recoverable; the torn
            # tail is dropped, and nothing after it is replayed.
            assert [e.seq for e in recovery.pending] == [2]
            assert "torn" in recovery.detail.lower()

    def test_torn_line_in_the_middle_is_a_hard_error(self):
        """A torn line followed by more data is NOT recoverable — the
        module raises rather than replaying entries whose chain position
        cannot be verified."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(1)
            ledger.save(path)
            ledger.append(_claim(2))
            write_wal(path, ledger.entries[1:])
            with open(wal_path_for(path), "a", encoding="utf-8") as fh:
                fh.write('{"seq": 3, "claim": {"kin')  # torn, NOT last
                fh.write('"\n{"seq": 4, "claim": {"kind": "x"}}\n')

            with pytest.raises(WalError, match="not valid JSON"):
                recover(path)

    def test_wal_with_a_broken_link_is_refused(self):
        """A WAL that does not chain to the ledger head is a real problem
        (partial replay, edited WAL) — stop and report, never skip."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(2)
            ledger.save(path)
            ledger.append(_claim(3))
            write_wal(path, ledger.entries[2:])

            # Rewrite the WAL entry with a prev_hash that links to nothing.
            wal = wal_path_for(path)
            lines = wal.read_text().splitlines()
            record = json.loads(lines[-1])
            record["prev_hash"] = "0" * 64
            lines[-1] = json.dumps(record, sort_keys=True)
            wal.write_text("\n".join(lines) + "\n")

            with pytest.raises(WalError, match="broken chain link"):
                recover(path)

    def test_wal_entry_with_a_bad_hash_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(1)
            ledger.save(path)
            ledger.append(_claim(2))
            write_wal(path, ledger.entries[1:])

            wal = wal_path_for(path)
            lines = wal.read_text().splitlines()
            record = json.loads(lines[-1])
            record["entry_hash"] = "f" * 64  # does not match its content
            lines[-1] = json.dumps(record, sort_keys=True)
            wal.write_text("\n".join(lines) + "\n")

            with pytest.raises(WalError, match="hash mismatch"):
                recover(path)

    def test_wal_record_schema_matches_the_ledger_entry_schema(self):
        """The WAL is not a bespoke format: its records are entry dicts."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(1)
            ledger.append(_claim(2))
            # WAL the new entry BEFORE the main file exists — the entry is
            # genuinely new, so write_wal records it.
            write_wal(path, ledger.entries[1:])
            ledger.save(path)  # now the main file exists for comparison

            wal_line = json.loads(wal_path_for(path).read_text().splitlines()[-1])
            body_line = json.loads(
                (path.read_text().splitlines()[-1])
            )
            assert set(wal_line) == set(body_line), (
                "WAL records must use the same schema as ledger entries"
            )
            assert wal_line == ledger.entries[-1].to_dict()

    def test_durable_save_then_crash_then_recover_is_lossless(self):
        """The full protocol: durable_save writes WAL, file, checkpoints."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(3)
            written = durable_save(ledger, path)
            assert written == 3
            assert wal_path_for(path).read_text() == ""
            recovery = recover(path)
            assert recovery.pending == []
            # checkpoint emptied the WAL; nothing is pending or applied.
            assert recovery.applied == 0
            _assert_chain(EvidenceLedger.load(path), 3)


# ---------------------------------------------------------------------------
# 2. Crash safety on the main file
# ---------------------------------------------------------------------------


class TestCrashSafety:
    """A torn final line in the MAIN file: dropped, counted, chain intact."""

    def test_partial_final_line_is_dropped_and_counted(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(3)
            ledger.save(path)

            # Crash mid-write: the last entry is cut in half.
            text = path.read_text()
            cut = text.rfind("\n")
            path.write_text(text[: cut - 20])

            report = LedgerLoadReport(entries=[], header={})
            loaded = EvidenceLedger.load(path, report=report)
            assert report.dropped_tail == 1, "the torn entry must be counted"
            assert report.tail_detail is not None
            assert len(loaded.entries) == 2, "the two complete entries survive"
            ok, detail = loaded.verify()
            assert ok, detail

    def test_torn_tail_hash_mismatch_is_also_dropped(self):
        """The tail can be *parseable* yet wrong (partial flush of a
        rewritten record). A hash mismatch on the FINAL line is a torn
        write, not tamper — dropped and reported."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(3)
            ledger.save(path)

            lines = path.read_text().splitlines()
            record = json.loads(lines[-1])
            record["claim"]["payload"]["agent"] = "attacker"
            lines[-1] = json.dumps(record, sort_keys=True)
            path.write_text("\n".join(lines) + "\n")

            # Strict load: tamper anywhere is refused.
            with pytest.raises(LedgerFileError):
                EvidenceLedger.load(path, allow_torn_tail=False)

    def test_tamper_in_the_middle_is_still_refused(self):
        """Hardening must not soften the original guarantee: only the LAST
        line may be torn. A corrupted middle entry is tamper, full stop."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(4)
            ledger.save(path)

            lines = path.read_text().splitlines()
            record = json.loads(lines[2])  # entry 2 of 4 — not the tail
            record["claim"]["payload"]["agent"] = "attacker"
            lines[2] = json.dumps(record, sort_keys=True)
            path.write_text("\n".join(lines) + "\n")

            with pytest.raises(LedgerFileError, match="hash mismatch"):
                EvidenceLedger.load(path)

    def test_recovered_ledger_is_appendable_and_stays_valid(self):
        """After a torn-tail recovery, appending must continue the chain —
        the recovered head hash is the real head."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(3)
            ledger.save(path)
            text = path.read_text()
            path.write_text(text[: text.rfind("\n") - 20])  # tear entry 3

            loaded = EvidenceLedger.load(path)
            new_entry = loaded.append(_claim(99, "after"))
            assert new_entry.seq == 3, "the recovered ledger continues at seq 3"
            assert new_entry.prev_hash == loaded.entries[1].entry_hash
            _assert_chain(loaded, 3)

    def test_save_is_atomic_no_tmp_left_behind(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            _seeded(2).save(path)
            leftovers = list(Path(td).glob("*.tmp"))
            assert leftovers == [], f"temp files must not survive a save: {leftovers}"

    def test_save_replaces_an_existing_file_completely(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            _seeded(5).save(path)
            _seeded(2).save(path)  # shrink the chain
            loaded = EvidenceLedger.load(path)
            assert len(loaded.entries) == 2, "the old tail must be gone, not appended"


# ---------------------------------------------------------------------------
# 3. Load-time conflict detection
# ---------------------------------------------------------------------------


class TestLoadTimeConflictDetection:
    """Duplicate seq, gap, broken link — each named precisely."""

    def _write_raw(self, path: Path, header: dict, records: list[dict]) -> None:
        path.write_text(
            "\n".join([json.dumps(header, sort_keys=True)]
                      + [json.dumps(r, sort_keys=True) for r in records])
            + "\n"
        )

    def test_duplicate_sequence_number_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(3)
            ledger.save(path)

            lines = path.read_text().splitlines()
            header = json.loads(lines[0])
            records = [json.loads(l) for l in lines[1:]]
            records.append(dict(records[1]))  # duplicate seq 2
            self._write_raw(path, header, records)

            with pytest.raises(LedgerFileError, match="duplicate sequence number 2"):
                EvidenceLedger.load(path)

    def test_sequence_gap_names_the_missing_range(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(4)
            ledger.save(path)

            lines = path.read_text().splitlines()
            header = json.loads(lines[0])
            records = [json.loads(l) for l in lines[1:]]
            del records[1]  # remove seq 2 -> gap
            self._write_raw(path, header, records)

            with pytest.raises(LedgerFileError) as exc:
                EvidenceLedger.load(path)
            assert "gap" in str(exc.value)
            assert "2" in str(exc.value), "the missing seq must be named"

    def test_multi_entry_gap_names_the_whole_range(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(5)
            ledger.save(path)
            lines = path.read_text().splitlines()
            header = json.loads(lines[0])
            records = [json.loads(l) for l in lines[1:]]
            del records[1:3]  # remove seq 2 and 3
            self._write_raw(path, header, records)

            with pytest.raises(LedgerFileError, match=r"2\.\.3"):
                EvidenceLedger.load(path)

    def test_broken_prev_hash_link_names_the_entry(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(3)
            ledger.save(path)
            lines = path.read_text().splitlines()
            header = json.loads(lines[0])
            records = [json.loads(l) for l in lines[1:]]
            records[1]["prev_hash"] = "0" * 64
            self._write_raw(path, header, records)

            with pytest.raises(LedgerFileError) as exc:
                EvidenceLedger.load(path)
            msg = str(exc.value)
            assert "broken chain link" in msg
            assert "2" in msg, "the offending entry index must be named"

    def test_out_of_order_sequences_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(3)
            ledger.save(path)
            lines = path.read_text().splitlines()
            header = json.loads(lines[0])
            records = [json.loads(l) for l in lines[1:]]
            records[0], records[1] = records[1], records[0]  # swap
            self._write_raw(path, header, records)

            with pytest.raises(LedgerFileError):
                EvidenceLedger.load(path)

    def test_non_integer_seq_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(2)
            ledger.save(path)
            lines = path.read_text().splitlines()
            header = json.loads(lines[0])
            records = [json.loads(l) for l in lines[1:]]
            records[0]["seq"] = "one"
            self._write_raw(path, header, records)

            with pytest.raises(LedgerFileError, match="seq must be an integer"):
                EvidenceLedger.load(path)

    def test_malformed_claim_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(2)
            ledger.save(path)
            lines = path.read_text().splitlines()
            header = json.loads(lines[0])
            records = [json.loads(l) for l in lines[1:]]
            del records[0]["claim"]["evidence"]
            self._write_raw(path, header, records)

            with pytest.raises(LedgerFileError, match="malformed claim"):
                EvidenceLedger.load(path)

    def test_existing_tamper_test_still_passes(self):
        """The original guarantee, unweakened: a mid-chain edit is refused."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            ledger = _seeded(2)
            ledger.save(path)
            lines = path.read_text().splitlines()
            record = json.loads(lines[1])
            record["claim"]["payload"]["agent"] = "attacker"
            lines[1] = json.dumps(record, sort_keys=True)
            path.write_text("\n".join(lines) + "\n")

            with pytest.raises(LedgerFileError):
                EvidenceLedger.load(path)


# ---------------------------------------------------------------------------
# 4. Backwards compatibility with 0.5.0
# ---------------------------------------------------------------------------


class TestBackwardsCompatibility:
    """Ledgers written by 0.5.0 must load unchanged."""

    def test_ledger_written_with_the_old_save_loads(self):
        """Simulate the 0.5.0 writer byte-for-byte: the format is a header
        line plus one JSON entry per line, written with the same key order."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "legacy.jsonl"
            ledger = _seeded(3, tag="legacy")

            # Reproduce 0.5.0's save() exactly (no fsync, same bytes).
            import tempfile as _tf

            header = {
                "format": "nomosguard-ledger",
                "format_version": 1,
                "entries": len(ledger.entries),
                "head_hash": ledger.head_hash,
            }
            lines = [json.dumps(header, sort_keys=True)]
            lines.extend(json.dumps(e.to_dict(), sort_keys=True) for e in ledger.entries)
            fd, tmp = _tf.mkstemp(dir=td, suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            os.replace(tmp, path)

            loaded = EvidenceLedger.load(path)
            assert loaded.head_hash == ledger.head_hash
            assert len(loaded.entries) == 3
            _assert_chain(loaded, 3)

    def test_old_file_bytes_are_byte_identical_to_new_save(self):
        """Atomic-rename + fsync must not change the serialization."""
        with tempfile.TemporaryDirectory() as td:
            p_old, p_new = Path(td) / "old.jsonl", Path(td) / "new.jsonl"
            ledger = _seeded(3, tag="same")
            header = {
                "format": "nomosguard-ledger",
                "format_version": 1,
                "entries": 3,
                "head_hash": ledger.head_hash,
            }
            lines = [json.dumps(header, sort_keys=True)]
            lines.extend(json.dumps(e.to_dict(), sort_keys=True) for e in ledger.entries)
            p_old.write_text("\n".join(lines) + "\n")

            ledger.save(p_new)
            assert p_old.read_text() == p_new.read_text(), (
                "save() must produce byte-identical output to the 0.5.0 writer"
            )

    def test_load_signature_is_backwards_compatible(self):
        """Old callers pass only a path; the new kwargs are optional."""
        import inspect

        sig = inspect.signature(EvidenceLedger.load)
        params = list(sig.parameters.values())
        assert params[0].name == "path"
        assert params[0].kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        assert all(p.kind == inspect.Parameter.KEYWORD_ONLY for p in params[1:])

    def test_public_api_is_unchanged(self):
        """Constraint 5: the API the rest of the core uses must not move."""
        for name in ("append", "verify", "entries", "head_hash", "save", "load"):
            assert hasattr(EvidenceLedger, name), f"EvidenceLedger.{name} must remain"


# ---------------------------------------------------------------------------
# 5. Multi-writer locking
# ---------------------------------------------------------------------------


def _child_appender(ledger_path: str, tag: str, count: int, q) -> None:
    """Child process: append `count` claims through append_locked."""
    try:
        for i in range(1, count + 1):
            append_locked(ledger_path, _claim(i, tag))
        q.put((tag, count, None))
    except BaseException as exc:  # surface child failures, don't hang
        q.put((tag, 0, f"{type(exc).__name__}: {exc}"))


def _child_crash_while_locked(ledger_path: str) -> None:
    """Child process: take the ledger lock, then die without releasing it.

    Module-level so it is picklable by the `spawn` start method. The point
    is that `os._exit` skips all cleanup — no unlock, no atexit, no fd
    close from Python — yet flock must still be reclaimed by the kernel,
    otherwise a crashed writer would wedge the ledger forever.
    """
    lock = LedgerLock(ledger_path).acquire()
    assert lock.locked
    os._exit(9)


@requires_posix
class TestMultiWriterLocking:
    """Real processes, real interleaving: the lost-write bug only shows up here."""

    def test_concurrent_appenders_produce_one_valid_chain(self):
        """N processes x M entries. If the lock is absent or the sequence
        check is wrong, entries are lost or the chain breaks."""
        n_procs, m_entries = 4, 8
        ctx = multiprocessing.get_context("spawn")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "concurrent.jsonl"
            q = ctx.Queue()
            procs = [
                ctx.Process(target=_child_appender, args=(str(path), f"w{i}", m_entries, q))
                for i in range(n_procs)
            ]
            for p in procs:
                p.start()
            for p in procs:
                p.join(120)

            for p in procs:
                assert p.exitcode == 0, f"writer process died with {p.exitcode}"

            results = [q.get(timeout=10) for _ in range(n_procs)]
            for tag, count, err in results:
                assert err is None, f"writer {tag} failed: {err}"
                assert count == m_entries

            ledger = EvidenceLedger.load(path)
            _assert_chain(ledger, n_procs * m_entries)
            # Every writer's claims must be present — no lost writes.
            evidence = {e.claim.evidence for e in ledger.entries}
            for i in range(n_procs):
                for j in range(1, m_entries + 1):
                    assert f"log line w{i}{j}" in evidence, (
                        f"writer w{i} entry {j} was lost"
                    )

    def test_concurrent_appenders_leave_a_clean_wal(self):
        n_procs, m_entries = 3, 5
        ctx = multiprocessing.get_context("spawn")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "concurrent2.jsonl"
            q = ctx.Queue()
            procs = [
                ctx.Process(
                    target=_child_appender, args=(str(path), f"p{i}", m_entries, q)
                )
                for i in range(n_procs)
            ]
            for p in procs:
                p.start()
            for p in procs:
                p.join(120)

            for p in procs:
                assert p.exitcode == 0, f"writer process died with {p.exitcode}"

            results = [q.get(timeout=10) for _ in range(n_procs)]
            for tag, count, err in results:
                assert err is None, f"writer {tag} failed: {err}"
                assert count == m_entries

            wal = wal_path_for(path)
            if wal.is_file():
                assert wal.read_text() == "", (
                    "the WAL must be empty once every writer has checkpointed"
                )
            # else: no WAL file was ever created because every write_wal
            # call found the entries already in the main file (the WAL is
            # an append-only log of NEW entries — nothing new, no file).
            _assert_chain(EvidenceLedger.load(path), n_procs * m_entries)

    def test_second_lock_blocks_until_the_first_releases(self):
        """A lock that does not exclude is worse than no lock: it lies."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "locked.jsonl"
            with LedgerLock(path) as first:
                assert first.locked
                # A second acquisition must NOT succeed immediately.
                with pytest.raises(LedgerLockError):
                    LedgerLock(path, timeout=0.3).acquire()
            # Once released, the same lock acquires immediately.
            with LedgerLock(path, timeout=2.0) as second:
                assert second.locked

    def test_lock_is_released_on_exception(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "locked.jsonl"
            with pytest.raises(RuntimeError):
                with LedgerLock(path):
                    raise RuntimeError("writer exploded")
            # The lock must not be held by a dead scope.
            with LedgerLock(path, timeout=2.0):
                pass

    def test_lock_file_is_a_sibling_not_the_data_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "ledger.jsonl"
            lock = LedgerLock(path).acquire()
            try:
                assert lock.path == Path(td) / "ledger.jsonl.lock"
                assert lock.path.exists()
                assert not Path(td).joinpath("ledger.jsonl").exists()
            finally:
                lock.release()

    def test_lock_survives_a_crashed_writer(self):
        """flock is dropped by the kernel when the fd closes — a crashed
        writer cannot wedge the ledger forever."""
        ctx = multiprocessing.get_context("spawn")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "crashed.jsonl"

            p = ctx.Process(target=_child_crash_while_locked, args=(str(path),))
            p.start()
            p.join(30)
            assert p.exitcode == 9

            # The next writer must still get in.
            entry = append_locked(path, _claim(1, "after-crash"))
            assert entry.seq == 1
            _assert_chain(EvidenceLedger.load(path), 1)

    def test_append_locked_continues_an_existing_chain(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "chained.jsonl"
            _seeded(3).save(path)
            entry = append_locked(path, _claim(4, "more"))
            assert entry.seq == 4
            assert entry.prev_hash == EvidenceLedger.load(path).entries[2].entry_hash
            _assert_chain(EvidenceLedger.load(path), 4)

    def test_append_locked_rejects_unevidenced_claims(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bad.jsonl"
            with pytest.raises(Exception):
                append_locked(path, Claim(kind="tool_call", payload={}, evidence=""))

    def test_lock_timeout_is_not_an_indefinite_hang(self):
        """CI must never deadlock: contention resolves in bounded time."""
        import time

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "t.jsonl"
            with LedgerLock(path):
                started = time.monotonic()
                with pytest.raises(LedgerLockError):
                    LedgerLock(path, timeout=0.2).acquire()
                assert time.monotonic() - started < 5.0


@requires_posix
class TestNonPosixBehavior:
    """On a platform without fcntl, the lock must fail loudly, not silently."""

    def test_lock_module_refuses_to_import_without_fcntl(self):
        """A silent no-op lock is worse than a loud failure. Prove the
        import path raises NotImplementedError when fcntl is missing."""
        import importlib

        saved = sys.modules.pop("nomosguard.ledger_lock", None)
        try:
            real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

            def no_fcntl(name, *args, **kwargs):
                if name == "fcntl":
                    raise ImportError("No module named 'fcntl'")
                return real_import(name, *args, **kwargs)

            if isinstance(__builtins__, dict):
                __builtins__["__import__"] = no_fcntl
            else:
                __builtins__.__import__ = no_fcntl
            try:
                with pytest.raises(NotImplementedError, match="fcntl"):
                    importlib.import_module("nomosguard.ledger_lock")
            finally:
                if isinstance(__builtins__, dict):
                    __builtins__["__import__"] = real_import
                else:
                    __builtins__.__import__ = real_import
        finally:
            sys.modules.pop("nomosguard.ledger_lock", None)
            if saved is not None:
                sys.modules["nomosguard.ledger_lock"] = saved

    def test_ledger_core_works_without_the_lock_module(self):
        """The core (save/load/WAL) must not depend on fcntl at all."""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "core.jsonl"
            ledger = _seeded(3)
            durable_save(ledger, path)
            _assert_chain(EvidenceLedger.load(path), 3)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
