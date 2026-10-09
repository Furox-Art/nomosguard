"""Tests for CVE and policy-rule ingestion: same discipline as tool-call."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from nomosguard.ledger import EvidenceLedger
from nomosguard.ingest import (
    IngestError,
    ingest_vuln_jsonl,
    ingest_policy_jsonl,
)
from nomosguard.ingest.vuln_jsonl import parse_vuln_line
from nomosguard.ingest.policy_jsonl import parse_policy_line


class TestParseVulnLine:
    def test_well_formed(self):
        payload = parse_vuln_line(
            '{"component": "db", "cve": "CVE-2026-1", "severity": "high"}', 1
        )
        assert payload == {"component": "db", "cve": "CVE-2026-1", "severity": "high"}

    def test_severity_defaults_to_unknown(self):
        payload = parse_vuln_line('{"component": "db", "cve": "CVE-2026-1"}', 1)
        assert payload["severity"] == "unknown"

    def test_severity_case_insensitive(self):
        payload = parse_vuln_line('{"component": "db", "cve": "CVE-2026-1", "severity": "HIGH"}', 1)
        assert payload["severity"] == "high"

    def test_missing_component_rejected(self):
        with pytest.raises(IngestError, match="missing or non-string 'component'"):
            parse_vuln_line('{"cve": "CVE-2026-1"}', 1)

    def test_missing_cve_rejected(self):
        with pytest.raises(IngestError, match="missing or non-string 'cve'"):
            parse_vuln_line('{"component": "db"}', 1)

    def test_cve_format_rejected(self):
        with pytest.raises(IngestError, match="must look like CVE-"):
            parse_vuln_line('{"component": "db", "cve": "not-a-cve"}', 1)

    def test_invalid_severity_rejected(self):
        with pytest.raises(IngestError, match="'severity' must be one of"):
            parse_vuln_line('{"component": "db", "cve": "CVE-2026-1", "severity": "catastrophic"}', 1)

    def test_malformed_json_rejected(self):
        with pytest.raises(IngestError, match="not valid JSON"):
            parse_vuln_line("{oops", 7)


class TestIngestVulnFile:
    def _write(self, td, content):
        path = Path(td) / "cves.jsonl"
        path.write_text(content, encoding="utf-8")
        return path

    def test_ingest_well_formed(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, '{"component": "db", "cve": "CVE-2026-1", "severity": "high"}\n')
            ledger = EvidenceLedger()
            result = ingest_vuln_jsonl(ledger, path)
            assert result.accepted == 1
            assert ledger.entries[0].claim.kind == "vulnerability"
            assert ledger.entries[0].claim.evidence.startswith("sha256:")

    def test_malformed_rejected_with_line(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(
                td,
                '{"component": "db", "cve": "CVE-2026-1"}\n'
                '{"component": "broken"}\n',
            )
            ledger = EvidenceLedger()
            result = ingest_vuln_jsonl(ledger, path)
            assert result.accepted == 1
            assert result.rejected[0]["line"] == 2

    def test_duplicate_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            line = '{"component": "db", "cve": "CVE-2026-1"}'
            path = self._write(td, line + "\n" + line + "\n")
            ledger = EvidenceLedger()
            result = ingest_vuln_jsonl(ledger, path)
            assert result.accepted == 1
            assert result.duplicates == 1

    def test_reingest_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._write(td, '{"component": "db", "cve": "CVE-2026-1"}\n')
            ledger = EvidenceLedger()
            ingest_vuln_jsonl(ledger, path)
            r2 = ingest_vuln_jsonl(ledger, path)
            assert r2.accepted == 0
            assert r2.duplicates == 1
            assert len(ledger.entries) == 1

    def test_missing_file_raises(self):
        with pytest.raises(IngestError, match="log file not found"):
            ingest_vuln_jsonl(EvidenceLedger(), Path("/nonexistent/cves.jsonl"))


class TestParsePolicyLine:
    def test_well_formed(self):
        payload = parse_policy_line(
            '{"subject": "a", "action": "sql", "resource": "db", "effect": "deny"}', 1
        )
        assert payload == {"subject": "a", "action": "sql", "resource": "db", "effect": "deny"}

    def test_effect_case_insensitive(self):
        payload = parse_policy_line(
            '{"subject": "a", "action": "sql", "resource": "db", "effect": "DENY"}', 1
        )
        assert payload["effect"] == "deny"

    def test_missing_effect_rejected(self):
        with pytest.raises(IngestError, match="'effect' must be one of"):
            parse_policy_line('{"subject": "a", "action": "sql", "resource": "db"}', 1)

    def test_invalid_effect_rejected(self):
        with pytest.raises(IngestError, match="'effect' must be one of"):
            parse_policy_line(
                '{"subject": "a", "action": "sql", "resource": "db", "effect": "maybe"}', 1
            )

    def test_missing_subject_rejected(self):
        with pytest.raises(IngestError, match="missing or non-string 'subject'"):
            parse_policy_line('{"action": "sql", "resource": "db", "effect": "allow"}', 1)

    def test_missing_resource_rejected(self):
        with pytest.raises(IngestError, match="missing or non-string 'resource'"):
            parse_policy_line('{"subject": "a", "action": "sql", "effect": "allow"}', 1)


class TestIngestPolicyFile:
    def test_ingest_and_reingest(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "policies.jsonl"
            path.write_text(
                '{"subject": "a", "action": "sql", "resource": "db", "effect": "deny"}\n'
                '{"subject": "b", "action": "file", "resource": "/x", "effect": "allow"}\n',
                encoding="utf-8",
            )
            ledger = EvidenceLedger()
            r1 = ingest_policy_jsonl(ledger, path)
            assert r1.accepted == 2
            r2 = ingest_policy_jsonl(ledger, path)
            assert r2.accepted == 0
            assert r2.duplicates == 2

    def test_missing_file_raises(self):
        with pytest.raises(IngestError, match="log file not found"):
            ingest_policy_jsonl(EvidenceLedger(), Path("/nonexistent/policies.jsonl"))


class TestThreeEvidenceTypesTogether:
    """All three ingestion paths coexist in one ledger and derive."""

    def test_full_ingestion_derives_exposure(self):
        from nomosguard.rules import Pattern, Rule, RuleEngine
        from nomosguard.gate import Decision, PolicyGate

        with tempfile.TemporaryDirectory() as td:
            from nomosguard.ingest import ingest_toolcall_jsonl

            tc = Path(td) / "tc.jsonl"
            tc.write_text('{"agent": "researcher", "tool": "sql_query", "target": "orders_db"}\n', encoding="utf-8")
            cve = Path(td) / "cve.jsonl"
            cve.write_text('{"component": "orders_db", "cve": "CVE-2026-1234", "severity": "high"}\n', encoding="utf-8")
            pol = Path(td) / "pol.jsonl"
            pol.write_text('{"subject": "researcher", "action": "sql_query", "resource": "orders_db", "effect": "deny"}\n', encoding="utf-8")

            ledger = EvidenceLedger()
            r1 = ingest_toolcall_jsonl(ledger, tc)
            r2 = ingest_vuln_jsonl(ledger, cve)
            r3 = ingest_policy_jsonl(ledger, pol)
            assert (r1.accepted, r2.accepted, r3.accepted) == (1, 1, 1)

            engine = RuleEngine(rules=[
                Rule("expose",
                    body=(Pattern("?agent", "calls", "?tool"),
                          Pattern("?agent", "operates_on", "?component"),
                          Pattern("?component", "has_vulnerability", "?cve")),
                    head=Pattern("?agent", "exposes", "?component")),
                Rule("violate",
                    body=(Pattern("?agent", "calls", "?tool"),
                          Pattern("?agent", "policy_denies", "?action")),
                    head=Pattern("?agent", "violates", "policy")),
            ])
            engine.add_facts_from_ledger(ledger)
            engine.derive()
            exposed = [f for f in engine.facts if f.relation == "exposes"]
            violations = [f for f in engine.facts if f.relation == "violates"]
            assert len(exposed) == 1 and exposed[0].object == "orders_db"
            assert len(violations) == 1

            gate = PolicyGate(policy_rules=[
                __import__("nomosguard.gate", fromlist=["PolicyRule"]).PolicyRule(
                    "block", "exposes", Decision.BLOCK)
            ])
            decision = gate.evaluate_with_fallback(engine)
            assert decision["decision"] == "BLOCK"
