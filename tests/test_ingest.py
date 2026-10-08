"""Tests for tool-call JSONL ingestion: fail-closed, evidence-citing, idempotent."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from nomosguard.ledger import Claim, EvidenceLedger
from nomosguard.ingest import IngestError, ingest_toolcall_jsonl
from nomosguard.ingest.toolcall_jsonl import parse_toolcall_line, _line_hash


class TestParseToolcallLine:
    def test_well_formed(self):
        payload = parse_toolcall_line(
            '{"agent": "a", "tool": "t", "target": "db", "args": {"q": 1}}', 1
        )
        assert payload == {"agent": "a", "tool": "t", "target": "db", "args": {"q": 1}}

    def test_optional_fields_absent(self):
        payload = parse_toolcall_line('{"agent": "a", "tool": "t"}', 1)
        assert payload == {"agent": "a", "tool": "t"}

    def test_malformed_json_rejected(self):
        with pytest.raises(IngestError, match="not valid JSON"):
            parse_toolcall_line("{not json", 5)

    def test_non_object_rejected(self):
        with pytest.raises(IngestError, match="must be a JSON object"):
            parse_toolcall_line("[1, 2, 3]", 1)

    def test_missing_agent_rejected(self):
        with pytest.raises(IngestError, match="missing or non-string 'agent'"):
            parse_toolcall_line('{"tool": "t"}', 3)

    def test_missing_tool_rejected(self):
        with pytest.raises(IngestError, match="missing or non-string 'tool'"):
            parse_toolcall_line('{"agent": "a"}', 3)

    def test_non_string_target_rejected(self):
        with pytest.raises(IngestError, match="'target' must be a string"):
            parse_toolcall_line('{"agent": "a", "tool": "t", "target": 42}', 1)

    def test_non_object_args_rejected(self):
        with pytest.raises(IngestError, match="'args' must be an object"):
            parse_toolcall_line('{"agent": "a", "tool": "t", "args": "nope"}', 1)


class TestLineHash:
    def test_hash_is_deterministic(self):
        line = '{"agent": "a", "tool": "t"}'
        assert _line_hash(line) == _line_hash(line)

    def test_hash_has_prefix(self):
        assert _line_hash("x").startswith("sha256:")

    def test_different_lines_different_hashes(self):
        assert _line_hash("a") != _line_hash("b")


class TestIngestFile:
    def _write(self, td: Path, content: str) -> Path:
        path = td / "log.jsonl"
        path.write_text(content, encoding="utf-8")
        return path

    def test_ingest_well_formed(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(
                Path(td),
                '{"agent": "a", "tool": "t", "target": "db"}\n'
                '{"agent": "b", "tool": "u"}\n',
            )
            ledger = EvidenceLedger()
            result = ingest_toolcall_jsonl(ledger, path)
            assert result.accepted == 2
            assert result.rejected == []
            assert len(ledger.entries) == 2

    def test_evidence_is_verifiable_hash(self):
        with tempfile.TemporaryDirectory() as td:
            line = '{"agent": "a", "tool": "t", "target": "db"}'
            path = self._write(Path(td), line + "\n")
            ledger = EvidenceLedger()
            ingest_toolcall_jsonl(ledger, path)
            entry = ledger.entries[0]
            assert entry.claim.evidence == _line_hash(line)
            assert entry.claim.evidence.startswith("sha256:")

    def test_malformed_lines_rejected_with_line_numbers(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(
                Path(td),
                '{"agent": "a", "tool": "t"}\n'
                "{not json}\n"
                '{"agent": "c"}\n',
            )
            ledger = EvidenceLedger()
            result = ingest_toolcall_jsonl(ledger, path)
            assert result.accepted == 1
            assert len(result.rejected) == 2
            assert result.rejected[0]["line"] == 2
            assert result.rejected[1]["line"] == 3

    def test_blank_lines_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(
                Path(td),
                '{"agent": "a", "tool": "t"}\n\n   \n{"agent": "b", "tool": "u"}\n',
            )
            ledger = EvidenceLedger()
            result = ingest_toolcall_jsonl(ledger, path)
            assert result.accepted == 2
            assert result.total_lines == 2

    def test_duplicate_lines_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            line = '{"agent": "a", "tool": "t"}'
            path = self._write(Path(td), line + "\n" + line + "\n")
            ledger = EvidenceLedger()
            result = ingest_toolcall_jsonl(ledger, path)
            assert result.accepted == 1
            assert result.duplicates == 1
            assert len(ledger.entries) == 1

    def test_reingest_same_file_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(Path(td), '{"agent": "a", "tool": "t"}\n')
            ledger = EvidenceLedger()
            r1 = ingest_toolcall_jsonl(ledger, path)
            r2 = ingest_toolcall_jsonl(ledger, path)
            assert r1.accepted == 1
            assert r2.accepted == 0
            assert r2.duplicates == 1
            assert len(ledger.entries) == 1

    def test_missing_file_raises(self):
        with pytest.raises(IngestError, match="log file not found"):
            ingest_toolcall_jsonl(EvidenceLedger(), Path("/nonexistent/log.jsonl"))


class TestIngestEndToEnd:
    """Ingested facts feed the rule engine — the whole chain works."""

    def test_ingested_log_derives_path(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "log.jsonl"
            path.write_text(
                '{"agent": "researcher", "tool": "sql_query", "target": "orders_db"}\n',
                encoding="utf-8",
            )
            ledger = EvidenceLedger()
            ingest_toolcall_jsonl(ledger, path)
            # vulnerability claim (as an MCP caller would add it)
            ledger.append(
                Claim(
                    kind="vulnerability",
                    payload={"component": "orders_db", "cve": "CVE-2026-1234"},
                    evidence="NVD record CVE-2026-1234",
                )
            )
            from nomosguard.rules import Pattern, Rule, RuleEngine

            engine = RuleEngine(
                rules=[
                    Rule(
                        name="expose",
                        body=(
                            Pattern("?agent", "calls", "?tool"),
                            Pattern("?tool", "operates_on", "?component"),
                            Pattern("?component", "has_vulnerability", "?cve"),
                        ),
                        head=Pattern("?agent", "exposes", "?component"),
                    )
                ]
            )
            engine.add_facts_from_ledger(ledger)
            engine.derive()
            derived = [f for f in engine.facts if f.relation == "exposes"]
            assert len(derived) == 1
            assert derived[0].subject == "researcher"
            assert derived[0].object == "orders_db"
