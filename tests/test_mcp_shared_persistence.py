from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from nomosguard import constants
from nomosguard.mcp_server import NomosGuardSession


class TwoSessionEvidenceTest(TestCase):
    """Two MCP sessions sharing one ledger path must interleave, not overwrite."""

    def test_second_session_keeps_first_session_entries(self):
        # H-1 pin. The old `_persist` rewrote the file from each session's
        # in-memory copy, so the second writer's save dropped everything the
        # first one had appended. Evidence loss on an audit product.
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.json"
            first = NomosGuardSession(ledger_path=path, create_if_missing=True)
            result = first.assert_claim(
                constants.CLAIM_KIND_VULNERABILITY,
                {"cve_id": "CVE-2024-1234"},
                "first session evidence",
            )
            self.assertTrue(result["accepted"], result)

            second = NomosGuardSession(ledger_path=path)
            result = second.assert_claim(
                constants.CLAIM_KIND_VULNERABILITY,
                {"cve_id": "CVE-2024-5678"},
                "second session evidence",
            )
            self.assertTrue(result["accepted"], result)

            from nomosguard.ledger import EvidenceLedger
            disk = EvidenceLedger.load(path)
            self.assertEqual(len(disk.entries), 2)
            evidence = {entry.claim.evidence for entry in disk.entries}
            self.assertIn("first session evidence", evidence)
            self.assertIn("second session evidence", evidence)

    def test_ingest_persists_per_claim_not_per_batch(self):
        # M-1 pin: a rejected claim after accepted ones must not discard the
        # accepted ones from disk.
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.json"
            session = NomosGuardSession(ledger_path=path, create_if_missing=True)
            session.evidence_ingest([
                {
                    "kind": constants.CLAIM_KIND_VULNERABILITY,
                    "payload": {"cve_id": "CVE-2024-1111"},
                    "evidence": "first",
                },
                {
                    "kind": constants.CLAIM_KIND_VULNERABILITY,
                    "payload": {"cve_id": "CVE-2024-2222"},
                    "evidence": "second",
                },
                {
                    "kind": constants.CLAIM_KIND_VULNERABILITY,
                    "payload": {},
                    "evidence": "",
                },
            ])
            from nomosguard.ledger import EvidenceLedger
            disk = EvidenceLedger.load(path)
            self.assertEqual(len(disk.entries), 2)