"""End-to-end demo test: the whole chain runs and is deterministic.

`failure_modes()` is the demo's failure-path stage: the narrative used to
claim every failure mode fails closed while exercising only the happy
path, so this suite pins each failure mode's outcome as well. The modes
are one registry (`failure_mode_scenarios`), so the demo, this suite and
the README's fail-closed table cannot drift apart.
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
    failure_mode_scenarios,
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
        expected = (
            f"{len(failure_mode_scenarios())} failure modes exercised, "
            "all fail closed"
        )
        assert expected in out
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


class TestFailureModeParity:
    """The demo claim, the README table, and the gate agree.

    The README says "every failure mode fails closed". This suite holds
    that claim to the registry: every mode is triggered, the gate returns
    BLOCK (never PASS/ALLOW), the ledger still records what came before,
    and every README row names a scenario the demo actually runs.
    """

    def test_every_scenario_fails_closed(self):
        for scenario in failure_mode_scenarios():
            outcome = scenario.run()
            assert outcome.fails_closed(), f"{scenario.name}: {outcome.detail}"

    def test_no_failure_mode_produces_a_pass_or_allow(self):
        """A failure mode never yields ALLOW/ALERT/PASS: silence from the
        chain is a denial, not a shrug."""
        for scenario in failure_mode_scenarios():
            outcome = scenario.run()
            assert outcome.decision in (None, "BLOCK"), (
                f"{scenario.name} produced {outcome.decision}"
            )

    def test_the_ledger_survives_every_refusal(self):
        """The recorded evidence still verifies after each refusal: a
        fail-closed outcome never quietly discards what came before."""
        for scenario in failure_mode_scenarios():
            outcome = scenario.run()
            if outcome.ledger_entries is not None:
                assert outcome.ledger_verified is True, scenario.name

    def test_the_registry_covers_both_gate_refusals_and_startup_refusals(self):
        names = {s.name for s in failure_mode_scenarios()}
        # startup refusals: no decision is ever produced
        assert "missing ledger path" in names
        assert "ledger path is a directory" in names
        assert "ledger parent is not a directory" in names
        assert "tampered WAL" in names
        assert "ledger digest pin" in names
        # gate refusals: BLOCK at the SDK boundary
        assert "unknown fallback decision" in names
        assert "uninterpretable claim" in names
        assert "malformed rule set" in names
        assert "gate with no derived path" in names

    def test_unwritable_ledger_directory_refused(self, tmp_path, monkeypatch):
        """The README's 'unwritable' path, exercised hermetically.

        The startup probe writes a test file into the ledger directory;
        a directory that refuses it is a broken configuration, refused
        with LedgerFileError instead of failing at the first save.
        """
        from pathlib import Path as _Path

        from nomosguard.mcp_server import (
            default_policy_rules,
            default_rules,
            _writable_ledger_target,
        )

        target = tmp_path / "ledger.jsonl"
        real_open = _Path.open

        def _read_only_dir_open(self, *args, **kwargs):
            if self.name.endswith(".write-test"):
                raise PermissionError("simulated read-only directory")
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr(_Path, "open", _read_only_dir_open)
        with pytest.raises(LedgerFileError, match="not writable"):
            _writable_ledger_target(target)
        with pytest.raises(LedgerFileError, match="not writable"):
            NomosGuardSession(
                rules=default_rules(),
                policy_rules=default_policy_rules(),
                ledger_path=target,
                create_if_missing=True,
            )


#: Every README fail-closed table row, mapped to the demo scenario(s) that
#: exercise it. A row added to the README without a mapping here fails the
#: suite — the docs and the demo cannot drift apart again.
README_FAIL_CLOSED_ROWS = {
    "claim without evidence": {"unevidenced claim"},
    "claim with empty evidence / non-dict payload / empty kind in a **saved file**": {
        "tampered ledger file"
    },
    "same tampering in the WAL": {"tampered WAL"},
    "corrupted / tampered ledger file": {"tampered ledger file"},
    "ledger path that is missing / a directory / unwritable": {
        "missing ledger path",
        "ledger path is a directory",
        "ledger parent is not a directory",
    },
    "gate with nothing derived": {"gate with no derived path"},
    "unknown fallback decision": {"unknown fallback decision"},
    "malformed rule set / claim the extractors cannot read": {
        "malformed rule set",
        "uninterpretable claim",
    },
    "policy file that is not the one you pinned": {"policy bundle digest pin"},
    "ledger file that is not the one you pinned": {"ledger digest pin"},
    "malformed log line / policy record": {"malformed log line"},
}


def _readme_failure_rows() -> list[str]:
    """The first column of the README's fail-closed table, verbatim."""
    from pathlib import Path

    readme = Path(__file__).resolve().parents[1] / "README.md"
    text = readme.read_text(encoding="utf-8")
    after = text.split("## Fail-closed paths")[1]
    # stop at the next heading of ANY level (## or ###)
    ends = [after.find("\n## "), after.find("\n### ")]
    ends = [e for e in ends if e != -1]
    section = after[: min(ends)] if ends else after
    rows: list[str] = []
    for line in section.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 3 or cells[0] == "failure mode":
            continue
        if set(cells[0]) <= set("-: "):
            continue  # the markdown separator row
        rows.append(cells[0])
    return rows


class TestReadmeParity:
    """The README's fail-closed table is pinned to the demo registry."""

    def test_every_readme_row_names_a_scenario_that_runs(self):
        scenario_names = {s.name for s in failure_mode_scenarios()}
        rows = _readme_failure_rows()
        assert len(rows) >= 10, f"expected the full fail-closed table, got {rows}"
        for row in rows:
            assert row in README_FAIL_CLOSED_ROWS, (
                f"README row {row!r} has no demo scenario mapping — either "
                "exercise it in demo_e2e.failure_mode_scenarios or drop the row"
            )
            mapped = README_FAIL_CLOSED_ROWS[row]
            assert mapped <= scenario_names, (
                f"{row} maps to scenarios that do not exist: {mapped - scenario_names}"
            )

    def test_every_scenario_is_documented_in_the_readme(self):
        documented: set[str] = set()
        for names in README_FAIL_CLOSED_ROWS.values():
            documented |= names
        for scenario in failure_mode_scenarios():
            assert scenario.name in documented, (
                f"{scenario.name!r} runs in the demo but no README row names it"
            )


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
