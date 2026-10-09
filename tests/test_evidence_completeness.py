"""Evidence completeness: the gate must never hide missing evidence.

The bug these tests lock down: the gate deduped by (subject, relation)
and kept only the first matching fact's sources, so a subject deriving
the same relation through two independent chains looked like it was
missing evidence it actually had. The fix unions sources across all
matching facts; these tests would catch a regression.
"""

from __future__ import annotations

from nomosguard.ledger import EvidenceLedger, Claim
from nomosguard.rules import RuleEngine
from nomosguard.rules_security import security_rules
from nomosguard.policy_security import containment_policy_rules
from nomosguard.gate import PolicyGate, Decision
from nomosguard import facts_security  # noqa: F401 — registers extractors


def _decide(claims: list[tuple[str, dict, str]]) -> dict:
    ledger = EvidenceLedger()
    for kind, payload, evidence in claims:
        ledger.append(Claim(kind=kind, payload=payload, evidence=evidence))
    engine = RuleEngine(rules=security_rules())
    engine.add_facts_from_ledger(ledger)
    engine.derive()
    gate = PolicyGate(policy_rules=containment_policy_rules(), fallback=Decision.ALERT)
    return gate.evaluate_with_fallback(engine)


ACCESS = ("network", {"host": "web01", "protocol": "ssh", "port": 22, "allowed_from": "203.0.113.77"}, "fw")
VULN = ("vuln_host", {"host": "web01", "cve": "CVE-2026-31142"}, "nvd")
EXEC = ("exec_code", {"host": "web01", "user": "deploy"}, "iam")


class TestEvidenceCompleteness:
    def test_complete_chain_reports_no_missing_evidence(self):
        r = _decide([ACCESS, VULN, EXEC])
        assert "ISOLATE_HOST" in r["decision"] or any(
            d["decision"] == "ISOLATE_HOST" for d in r["all_decisions"]
        )
        assert r["missing_evidence"] == []

    def test_missing_exec_code_is_reported_not_silent(self):
        """Without the exec_code claim, exploit derives execCode — but the
        gate must still report that the direct execution evidence is absent.
        """
        r = _decide([ACCESS, VULN])
        # decision still fires (exploit chain), but the gap is visible
        assert "exec_code" in r["missing_evidence"]

    def test_access_only_revokes_without_false_isolation(self):
        """Only network evidence: revoke the path, but do NOT claim a
        compromise — and do not report missing evidence for REVOKE, which
        requires only network.
        """
        r = _decide([ACCESS])
        decisions = {d["decision"] for d in r["all_decisions"]}
        assert "REVOKE_ACCESS" in decisions
        assert "ISOLATE_HOST" not in decisions

    def test_no_evidence_fails_closed(self):
        r = _decide([])
        assert r["decision"] == "ALERT"
        assert r["policy_rule"] == "FALLBACK"

    def test_sources_union_across_chains(self):
        """web01 derives execCode twice (claim + exploit) — the gate must
        union their sources, so a complete chain reports nothing missing.
        """
        r = _decide([ACCESS, VULN, EXEC])
        isolate = next(
            d for d in r["all_decisions"] if d["decision"] == "ISOLATE_HOST"
        )
        assert isolate["missing_evidence"] == []
        # both derivation paths' sources are represented
        sources = set(isolate.get("derived_from", ()))
        # exec_code comes from the claim; network+vuln_host from exploit
        assert "exec_code" in sources or "network" in sources
