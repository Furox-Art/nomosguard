"""End-to-end demo test: the whole chain runs and is deterministic.

`failure_modes()` is the demo's failure-path stage: the narrative used to
claim every failure mode fails closed while exercising only the happy
path, so this suite pins each failure mode's outcome as well.
"""

from __future__ import annotations

import json

import pytest

from nomosguard import (  # noqa: F401  — register the security extractors
    facts_security,
    signature_bridge,
    temporal_bridge,
)
from nomosguard.containment import render_plan
from nomosguard.demo_e2e import (
    NETWORK_CLAIMS,
    RAW_LOGS,
    VULN_CLAIMS,
    failure_modes,
    main,
)
from nomosguard.gate import Decision, PolicyGate
from nomosguard.ledger import (
    Claim,
    EvidenceLedger,
    LedgerFileError,
    UnevidencedClaimError,
)
from nomosguard.mcp_server import NomosGuardSession
from nomosguard.policy import PolicyConfigError, default_policy, load_policy, policy_digest
from nomosguard.policy_security import containment_policy_rules
from nomosguard.rules import RuleEngine
from nomosguard.rules_security import security_rules
from nomosguard.signatures import match_all
from nomosguard.signatures_builtin import builtin_signatures
from nomosguard.temporal import default_temporal_rules
from nomosguard.temporal_bridge import run_temporal_into_ledger


class TestFailureModesFailClosed:
    """Stage 8: each failure mode is triggered, and fails closed."""

    def test_stage_reports_success_for_every_mode(self, capsys):
        assert failure_modes() == 0
        out = capsys.readouterr().out
        assert "7 failure modes exercised, all fail closed" in out
        assert "[FAIL" not in out

    def test_unevidenced_claim_refused_at_the_ledger(self):
        ledger = EvidenceLedger()
        with pytest.raises(UnevidencedClaimError):
            ledger.append(Claim("tool_call", {"agent": "a", "tool": "t"}, ""))

    def test_tampered_ledger_file_refused_on_load(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        ledger = EvidenceLedger()
        ledger.append(Claim("tool_call", {"agent": "a", "tool": "t"}, "log line 1"))
        ledger.save(path)
        records = [json.loads(line) for line in path.read_text().splitlines()]
        records[1]["claim"]["evidence"] = ""
        path.write_text("\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n")
        with pytest.raises(LedgerFileError):
            EvidenceLedger.load(path)

    def test_missing_ledger_path_refuses_to_start(self, tmp_path):
        with pytest.raises(LedgerFileError, match="not found"):
            NomosGuardSession(
                rules=security_rules(),
                policy_rules=containment_policy_rules(),
                ledger_path=tmp_path / "never_created.jsonl",
            )

    def test_gate_denies_when_nothing_is_derived(self):
        rules, gate_rules = default_policy()
        session = NomosGuardSession(rules=rules, policy_rules=gate_rules)
        result = session.decide()
        assert result["decision"] == "BLOCK"
        assert "fail-closed" in result["reason"]

    def test_changed_policy_bundle_refused_under_the_digest_pin(self, tmp_path):
        path = tmp_path / "policy.json"
        path.write_text(json.dumps({"rules": [{
            "name": "r", "body": [["?a", "calls", "?t"]],
            "head": ["?a", "calls", "?t"],
        }], "gate": []}))
        pinned = policy_digest(path)
        path.write_text(json.dumps({"rules": [{
            "name": "r", "body": [["?a", "calls", "?t"]],
            "head": ["?a", "exposes", "?t"],
        }], "gate": []}))
        with pytest.raises(PolicyConfigError, match="digest mismatch"):
            load_policy(path, expected_digest=pinned)

    def test_unknown_fallback_decision_denied_not_guessed(self):
        rules, gate_rules = default_policy()
        session = NomosGuardSession(rules=rules, policy_rules=gate_rules)
        result = session.decide(fallback="NOT_A_DECISION")
        assert result["denied"] is True
        assert result["decision"] == "BLOCK"

    def test_uninterpretable_claim_refused_not_coerced(self):
        rules, gate_rules = default_policy()
        session = NomosGuardSession(rules=rules, policy_rules=gate_rules)
        session.assert_claim(
            "policy_rule",
            {"subject": "a", "action": "sql", "resource": "db", "effect": "maybe"},
            "policy doc line 1",
        )
        # the claim is on the ledger (evidence is evidence) ...
        assert len(session.ledger.entries) == 1
        # ... but no fact was invented from it, and the gate denied
        decision = session.decide()
        assert decision["denied"] is True
        assert decision["decision"] == "BLOCK"
        assert "uninterpretable claim" in decision["reason"]

    def test_main_runs_the_failure_stage_and_succeeds(self, capsys):
        assert main() == 0
        out = capsys.readouterr().out
        assert "STAGE 8" in out
        assert "all fail closed" in out


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
