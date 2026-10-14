"""The evidence export is reproducible and re-verifiable from scratch.

The export claim has two halves that must both hold mechanically:

1. **reproducible** — the same ledger exports byte-identical bytes, every
   time; and because the entry hash excludes the wall-clock timestamp,
   the same EVIDENCE yields the same digest in any process, at any time.
   The timestamps are therefore isolated in one declared metadata block
   in one pinned format (`iso-8601-utc`), checked on verification.
2. **verifiable from scratch** — a fresh process, given nothing but the
   bundle file, re-verifies the whole chain and the digest. The
   round-trip test below spawns a REAL subprocess: same interpreter, no
   in-process state, no import side-channel.

Every way of making the bundle lie (mutated claim, forged hash, wrong
digest, naive timestamp, missing entry) is refused with the typed
`ExportError` — in-process AND in the fresh-process path.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from nomosguard.evidence_export import (
    DIGEST_SCOPE,
    EXPORT_FORMAT,
    EXPORT_FORMAT_VERSION,
    TIMESTAMP_FORMAT,
    ExportError,
    bundle_bytes,
    bundle_digest,
    export_bundle,
    read_export_bundle,
    verify_export_bundle,
    write_export_bundle,
)
from nomosguard.ledger import Claim, EvidenceLedger
from nomosguard.mcp_server import (
    NomosGuardSession,
    default_policy_rules,
    default_rules,
)


def _seeded(entries: int = 3) -> EvidenceLedger:
    ledger = EvidenceLedger()
    for i in range(1, entries + 1):
        ledger.append(
            Claim(
                kind="tool_call" if i % 2 else "vulnerability",
                payload={"agent": f"a{i}", "tool": "t", "target": f"db{i}"},
                evidence=f"log line {i}",
            )
        )
    return ledger


class TestReproducible:
    def test_two_exports_of_the_same_ledger_are_byte_identical(self):
        ledger = _seeded()
        first, second = export_bundle(ledger), export_bundle(ledger)
        assert bundle_bytes(first) == bundle_bytes(second)
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)

    def test_same_evidence_yields_the_same_digest_any_process_any_time(self):
        """The timestamp is excluded from the entry hash, so it must also be
        excluded from the digest: two ledgers built moments apart from the
        same claims pin the same attestation."""
        first, second = _seeded(), _seeded()
        assert export_bundle(first)["digest"] == export_bundle(second)["digest"]
        assert bundle_digest(export_bundle(first)) == bundle_digest(export_bundle(second))

    def test_entries_carry_only_what_the_chain_authenticates(self):
        bundle = export_bundle(_seeded())
        for entry in bundle["entries"]:
            assert set(entry) == {"seq", "claim", "entry_hash", "prev_hash"}
        # and the timestamps live in the declared metadata block
        assert set(bundle) == {"format", "format_version", "metadata", "entries", "digest"}
        assert bundle["metadata"]["timestamp_format"] == TIMESTAMP_FORMAT
        assert bundle["metadata"]["digest_algorithm"] == "sha256"
        assert bundle["metadata"]["digest_scope"] == DIGEST_SCOPE
        assert set(bundle["metadata"]["timestamps"]) == {"1", "2", "3"}

    def test_the_format_is_pinned(self):
        bundle = export_bundle(_seeded())
        assert bundle["format"] == EXPORT_FORMAT
        assert bundle["format_version"] == EXPORT_FORMAT_VERSION
        assert bundle["digest"].startswith("sha256:")


class TestVerifiableFromScratch:
    def test_a_clean_bundle_verifies(self):
        ledger = _seeded()
        detail = verify_export_bundle(export_bundle(ledger))
        assert "verified" in detail
        assert bundle_digest(export_bundle(ledger)) == export_bundle(ledger)["digest"]

    def test_the_empty_ledger_exports_and_verifies(self):
        detail = verify_export_bundle(export_bundle(EvidenceLedger()))
        assert "0 entries intact" in detail

    def test_round_trip_in_a_fresh_process(self, tmp_path):
        """export -> write -> verify in a fresh interpreter -> digest match.

        The subprocess shares nothing with this one: the only input is the
        file on disk. If verification needed in-process state, this test
        would fail.
        """
        ledger = _seeded()
        bundle = export_bundle(ledger)
        path = tmp_path / "bundle.json"
        write_export_bundle(path, bundle)

        code = (
            "import sys\n"
            "from nomosguard.evidence_export import "
            "read_export_bundle, verify_export_bundle\n"
            "bundle = read_export_bundle(sys.argv[1])\n"
            "detail = verify_export_bundle(bundle)\n"
            "print(detail)\n"
            "print(bundle['digest'])\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code, str(path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
        detail, digest = proc.stdout.strip().splitlines()
        assert digest == bundle["digest"]
        assert "3 entries intact" in detail

    def test_bundle_bytes_are_stable_on_disk(self, tmp_path):
        """Writing twice produces identical bytes: no PLATFORM newline, no
        key-order drift."""
        bundle = export_bundle(_seeded())
        first, second = tmp_path / "a.json", tmp_path / "b.json"
        write_export_bundle(first, bundle)
        write_export_bundle(second, bundle)
        assert first.read_bytes() == second.read_bytes()
        assert first.read_bytes() == bundle_bytes(bundle)


class TestExportFailsClosed:
    """Every way a bundle can lie is refused with the typed ExportError."""

    def _tampered(self, tmp_path, mutate):
        bundle = export_bundle(_seeded())
        mutate(bundle)
        path = tmp_path / "bundle.json"
        write_export_bundle(path, bundle)
        return bundle, path

    def test_mutated_claim_refused(self, tmp_path):
        bundle, path = self._tampered(
            tmp_path,
            lambda b: b["entries"][1]["claim"]["payload"].update(agent="attacker"),
        )
        with pytest.raises(ExportError, match="hash mismatch"):
            verify_export_bundle(bundle)
        with pytest.raises(ExportError, match="hash mismatch"):
            verify_export_bundle(read_export_bundle(path))

    def test_forged_entry_hash_refused(self, tmp_path):
        def mutate(b):
            b["entries"][1]["entry_hash"] = "0" * 64

        bundle, _ = self._tampered(tmp_path, mutate)
        with pytest.raises(ExportError, match="hash mismatch"):
            verify_export_bundle(bundle)

    def test_forged_digest_refused(self, tmp_path):
        def mutate(b):
            b["digest"] = "sha256:" + "0" * 64

        bundle, _ = self._tampered(tmp_path, mutate)
        with pytest.raises(ExportError, match="digest mismatch"):
            verify_export_bundle(bundle)

    def test_missing_entry_refused(self, tmp_path):
        """A dropped tail entry, with the metadata kept consistent (the
        count, the timestamps): the entries no longer hash to the declared
        digest — the digest is what catches it."""

        def mutate(b):
            del b["entries"][-1]
            del b["metadata"]["timestamps"]["3"]
            b["metadata"]["entry_count"] = 2  # the attacker tidies up

        bundle, _ = self._tampered(tmp_path, mutate)
        with pytest.raises(ExportError, match="digest mismatch"):
            verify_export_bundle(bundle)

    def test_lying_entry_count_refused(self, tmp_path):
        def mutate(b):
            b["metadata"]["entry_count"] = 99

        bundle, path = self._tampered(tmp_path, mutate)
        with pytest.raises(ExportError, match="entry_count"):
            read_export_bundle(path)

    def test_dropped_entry_with_its_timestamp_left_behind_refused(self, tmp_path):
        """Sneakier: the entry is gone but the metadata still claims it.
        The coverage check catches the discrepancy — the metadata block is
        checked, not trusted."""

        def mutate(b):
            del b["entries"][1]
            b["metadata"]["entry_count"] = 2  # the attacker tidies up

        bundle, _ = self._tampered(tmp_path, mutate)
        with pytest.raises(ExportError, match="does not cover the entries exactly"):
            verify_export_bundle(bundle)

    def test_extra_timestamp_without_an_entry_refused(self, tmp_path):
        def mutate(b):
            b["metadata"]["timestamps"]["99"] = "2026-01-01T00:00:00Z"

        bundle, _ = self._tampered(tmp_path, mutate)
        with pytest.raises(ExportError, match="does not cover the entries exactly"):
            verify_export_bundle(bundle)

    def test_naive_timestamp_refused(self, tmp_path):
        """The pinned format has an explicit UTC designator: a timestamp
        without one is refused, not normalised in silence."""

        def mutate(b):
            b["metadata"]["timestamps"]["1"] = "2026-10-14T02:08:01"

        bundle, _ = self._tampered(tmp_path, mutate)
        with pytest.raises(ExportError, match="iso-8601-utc"):
            verify_export_bundle(bundle)

    def test_undeclared_timestamp_block_refused(self, tmp_path):
        def mutate(b):
            b["metadata"]["timestamp_format"] = "whatever-we-feel-like"

        bundle, path = self._tampered(tmp_path, mutate)
        with pytest.raises(ExportError, match="timestamp_format"):
            read_export_bundle(path)
        with pytest.raises(ExportError, match="timestamp_format"):
            verify_export_bundle(bundle)

    def test_truncated_file_refused_typed(self, tmp_path):
        bundle = export_bundle(_seeded())
        path = tmp_path / "bundle.json"
        path.write_bytes(bundle_bytes(bundle)[:40])  # cut mid-JSON
        with pytest.raises(ExportError, match="not a valid JSON export bundle"):
            read_export_bundle(path)

    def test_tamper_fails_closed_in_a_fresh_process(self, tmp_path):
        bundle = export_bundle(_seeded())
        bundle["entries"][0]["claim"]["payload"]["agent"] = "attacker"
        path = tmp_path / "bundle.json"
        write_export_bundle(path, bundle)
        code = (
            "import sys\n"
            "from nomosguard.evidence_export import "
            "read_export_bundle, verify_export_bundle\n"
            "verify_export_bundle(read_export_bundle(sys.argv[1]))\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code, str(path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert proc.returncode != 0
        assert "ExportError" in proc.stderr
        assert "hash mismatch" in proc.stderr


class TestSessionExport:
    """The SDK export tool returns the reproducible bundle."""

    def test_export_ledger_returns_a_verifiable_bundle(self):
        session = NomosGuardSession(
            rules=default_rules(), policy_rules=default_policy_rules()
        )
        session.assert_claim(
            "tool_call", {"agent": "a", "tool": "t", "target": "db"}, "log line"
        )
        export = session.export_ledger()
        # the legacy shape the MCP tool has always returned ...
        assert export["verified"] is True
        assert len(export["entries"]) == 1
        # ... plus the attestation bundle
        assert export["bundle_digest"] == export["bundle"]["digest"]
        assert "verified" in verify_export_bundle(export["bundle"])

    def test_two_export_tool_calls_are_identical(self):
        session = NomosGuardSession(
            rules=default_rules(), policy_rules=default_policy_rules()
        )
        session.assert_claim(
            "tool_call", {"agent": "a", "tool": "t", "target": "db"}, "log line"
        )
        first, second = session.export_ledger(), session.export_ledger()
        assert first["bundle_digest"] == second["bundle_digest"]
        assert bundle_bytes(first["bundle"]) == bundle_bytes(second["bundle"])
        # the raw entries shape is stable too
        assert json.dumps(first["entries"], sort_keys=True) == json.dumps(
            second["entries"], sort_keys=True
        )
