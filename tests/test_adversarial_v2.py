"""Adversarial probes v2: WAL forgery, locks, file format, rule validation.

Extends test_adversarial.py with attacks on the durability and
inference layers. Each test asserts the invariant holds.
"""

from __future__ import annotations

import json
import multiprocessing

import pytest

from nomosguard.ledger import EvidenceLedger, Claim
from nomosguard.rules import Rule, Pattern, RuleEngine, RuleDefinitionError
from nomosguard.gate import PolicyGate, Decision


def _net_claim(host: str, evidence: str = "e") -> Claim:
    return Claim(kind="network",
                 payload={"host": host, "port": 22, "allowed_from": "x",
                          "protocol": "tcp"},
                 evidence=evidence)


class TestWalForgery:
    def test_forged_wal_entry_hash_rejected(self, tmp_path=None):
        import tempfile
        from pathlib import Path as _P
        from nomosguard.ledger_wal import write_wal, recover, WalError
        with tempfile.TemporaryDirectory() as td:
            path = _P(td) / "l.jsonl"
            led = EvidenceLedger()
            led.append(_net_claim("a", "e1"))
            led.save(path)
            led.append(_net_claim("b", "e2"))
            write_wal(path, led.entries[1:])
            wal = _P(str(path) + ".wal")
            lines = wal.read_text().splitlines()
            rec = json.loads(lines[-1])
            rec["entry_hash"] = "f" * 64
            lines[-1] = json.dumps(rec, sort_keys=True)
            wal.write_text("\n".join(lines) + "\n")
            with pytest.raises(WalError):
                recover(path)

    def test_wal_replay_returns_correct_pending(self, tmp_path=None):
        import tempfile
        from pathlib import Path as _P
        from nomosguard.ledger_wal import write_wal, recover
        with tempfile.TemporaryDirectory() as td:
            path = _P(td) / "l.jsonl"
            led = EvidenceLedger()
            for i in range(3):
                led.append(_net_claim(f"h{i}", f"e{i}"))
            led.save(path)
            led.append(_net_claim("h3", "e3"))
            write_wal(path, led.entries[3:])
            rec = recover(path)
            assert [e.seq for e in rec.pending] == [4]


class TestLedgerFileForgery:
    def test_injected_bogus_line_rejected(self, tmp_path=None):
        import tempfile
        from pathlib import Path as _P
        with tempfile.TemporaryDirectory() as td:
            path = _P(td) / "l.jsonl"
            led = EvidenceLedger()
            led.append(_net_claim("a", "e1"))
            led.append(_net_claim("b", "e2"))
            led.save(path)
            with open(path, "a") as fh:
                fh.write(json.dumps({
                    "seq": 99, "timestamp": "x",
                    "claim": {"kind": "network", "payload": {}, "evidence": "z"},
                    "entry_hash": "0" * 64, "prev_hash": "0" * 64,
                }) + "\n")
            # a sequence gap / broken chain must be caught on load or verify
            with pytest.raises(Exception):
                loaded = EvidenceLedger.load(path)
                ok, _ = loaded.verify()
                assert not ok


class TestLockExclusion:
    def test_second_lock_blocked_while_first_held(self, tmp_path=None):
        import tempfile
        from pathlib import Path as _P
        from nomosguard.ledger_lock import LedgerLock, LedgerLockError
        with tempfile.TemporaryDirectory() as td:
            path = _P(td) / "l.jsonl"
            with LedgerLock(path):
                with pytest.raises(LedgerLockError):
                    LedgerLock(path, timeout=0.3).acquire()

    def test_lock_reacquirable_after_release(self, tmp_path=None):
        import tempfile
        from pathlib import Path as _P
        from nomosguard.ledger_lock import LedgerLock
        with tempfile.TemporaryDirectory() as td:
            path = _P(td) / "l.jsonl"
            lock = LedgerLock(path).acquire()
            lock.release()
            with LedgerLock(path, timeout=2.0):
                pass  # reacquires cleanly


def _writer(args):
    path, tag = args
    from nomosguard.ledger_lock import append_locked
    for i in range(8):
        append_locked(path, Claim(kind="network",
                                  payload={"host": f"{tag}{i}", "port": 22,
                                           "allowed_from": "x", "protocol": "tcp"},
                                  evidence="e"))
    return tag


class TestConcurrentWriters:
    def test_four_procs_x_eight_entries_one_chain(self, tmp_path=None):
        import tempfile
        from pathlib import Path as _P
        try:
            import fcntl  # noqa: F401
        except ImportError:
            pytest.skip("POSIX locking only")
        with tempfile.TemporaryDirectory() as td:
            path = str(_P(td) / "c.jsonl")
            ctx = multiprocessing.get_context("spawn")
            with ctx.Pool(4) as pool:
                pool.map(_writer, [(path, f"w{i}") for i in range(4)])
            led = EvidenceLedger.load(path)
            ok, detail = led.verify()
            assert ok, detail
            assert len(led.entries) == 32


class TestRuleValidation:
    def test_unbound_head_variable_rejected_at_construction(self):
        with pytest.raises(RuleDefinitionError):
            RuleEngine(rules=[Rule(
                name="bad",
                body=(Pattern("?a", "rel", "?b"),),
                head=Pattern("?c", "rel2", "?d"),
            )])

    def test_empty_body_rejected(self):
        with pytest.raises(RuleDefinitionError):
            RuleEngine(rules=[Rule(name="empty", body=(), head=Pattern("?a", "r", "?b"))])

    def test_valid_rule_accepted(self):
        eng = RuleEngine(rules=[Rule(
            name="ok", body=(Pattern("?a", "rel", "?b"),), head=Pattern("?a", "rel2", "?b"),
        )])
        assert eng.rules


class TestFailClosed:
    def test_empty_gate_defaults_to_fallback(self):
        eng = RuleEngine(rules=[])
        led = EvidenceLedger()
        led.append(_net_claim("a"))
        eng.add_facts_from_ledger(led)
        eng.derive()
        gate = PolicyGate(policy_rules=[], fallback=Decision.BLOCK)
        r = gate.evaluate_with_fallback(eng)
        assert r["decision"] == "BLOCK"
