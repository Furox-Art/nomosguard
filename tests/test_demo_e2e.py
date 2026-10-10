"""End-to-end demo test: the whole chain runs and is deterministic."""

from __future__ import annotations

from nomosguard.demo_e2e import RAW_LOGS, NETWORK_CLAIMS, VULN_CLAIMS

from nomosguard.ledger import EvidenceLedger, Claim
from nomosguard.rules import RuleEngine
from nomosguard.rules_security import security_rules
from nomosguard.gate import PolicyGate, Decision
from nomosguard.policy_security import containment_policy_rules
from nomosguard.containment import render_plan

from nomosguard import facts_security, temporal_bridge, signature_bridge  # noqa: F401
from nomosguard.temporal_bridge import run_temporal_into_ledger
from nomosguard.temporal import default_temporal_rules
from nomosguard.signatures import match_all
from nomosguard.signatures_builtin import builtin_signatures


def _run_chain() -> dict:
    ledger = EvidenceLedger()
    ledger, _ = run_temporal_into_ledger(RAW_LOGS, default_temporal_rules(), ledger)
    for kind, payload, evidence in NETWORK_CLAIMS + VULN_CLAIMS:
        ledger.append(Claim(kind=kind, payload=payload, evidence=evidence))

    engine = RuleEngine(rules=security_rules())
    engine.add_facts_from_ledger(ledger)
    engine.derive()
    gate = PolicyGate(policy_rules=containment_policy_rules(),
                      fallback=Decision.ALERT)
    result = gate.evaluate_with_fallback(engine)
    plan = render_plan(result)
    return {
        "ledger_ok": ledger.verify()[0],
        "derived": sorted(str(f) for f in engine.facts if f.sources),
        "decision": result["decision"],
        "all_decisions": sorted(
            (d["subject"], d["decision"]) for d in result.get("all_decisions", [])
        ),
        "missing_evidence": result["missing_evidence"],
        "plan_commands": len(plan["commands"]),
    }


class TestEndToEndDemo:
    def test_all_evidence_layers_produce_facts(self):
        r = _run_chain()
        # temporal evidence
        assert any("bruteForceDetected" in f for f in r["derived"])
        # network evidence
        assert any("canAccessHost" in f for f in r["derived"])
        # vulnerability severity
        assert any("vulnSeverity" in f for f in r["derived"])
        # temporal + network rule fired
        assert any("accessAttemptInProgress" in f for f in r["derived"])

    def test_gate_escalates_and_revokes(self):
        r = _run_chain()
        decisions = {d[1] for d in r["all_decisions"]}
        assert "ESCALATE" in decisions
        assert "REVOKE_ACCESS" in decisions

    def test_ledger_chain_verifies(self):
        r = _run_chain()
        assert r["ledger_ok"] is True

    def test_containment_plan_rendered(self):
        r = _run_chain()
        assert r["plan_commands"] >= 2  # escalate + revoke

    def test_decision_is_deterministic(self):
        r1 = _run_chain()
        r2 = _run_chain()
        assert r1 == r2

    def test_signatures_fire_on_raw_logs(self):
        sigs = builtin_signatures()
        matches = match_all(RAW_LOGS, sigs)
        assert len(matches) >= 3  # failed auth x5, large transfer, burst
        ids = {m.signature_id for m in matches}
        assert "NG-0001" in ids  # SSH failed authentication
        assert "NG-0005" in ids  # large outbound transfer

    def test_missing_evidence_reported(self):
        """The chain is complete here; missing_evidence must be empty."""
        r = _run_chain()
        assert r["missing_evidence"] == []
